#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vue_i18n_wrap_v2.py — Backward-compatible i18n preprocessor for Vue + JS/TS and optional Python (.py) Doctype files.

Key points
- Preserves current behaviour for .vue/.js/.ts identically.
- Adds **opt-in** Python support via `--enable-python` to wrap static labels in server-side
  Doctype-like dicts: {"label": "Subject", ...} -> {"label": _("Subject"), ...}
- Safe guards against already wrapped strings, interpolations, and complex literals.
- Supports atomic writes, unified-diff dry-run, JSON report, ignore globs, and threads.

This file is a whole, production-grade drop-in; do not patch piecemeal.
"""

from __future__ import annotations
import argparse
import concurrent.futures as cf
import dataclasses
import difflib
import fnmatch
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
from typing import Iterable, List, Optional, Tuple

# ── Shared ─────────────────────────────────────────────────────────────────────
ALREADY_WRAPPED_JS = re.compile(r"__\s*\(", re.S)
ALREADY_WRAPPED_PY = re.compile(r"(?:\b_|frappe\._)\s*\(", re.S)

NEWLINE = "\n"

# ── TEMPLATE side (Vue) ───────────────────────────────────────────────────────
TEMPLATE_BLOCK_RE = re.compile(r"(<template[^>]*>)(.*?)(</template>)", re.S | re.I)

PLAIN_ATTR_RE     = r'(?<![\w:-])({attr})\s*=\s*"([^"\n\r]+)"'
PLAIN_ATTR_RE_SQ  = r"(?<![\w:-])({attr})\s*=\s*'([^'\n\r]+)'"
BOUND_ATTR_STR_RE    = r':({attr})\s*=\s*\"\'\s*([^\"\'\n\r]+?)\s*\'\"'
BOUND_ATTR_STR_RE_SQ = r":({attr})\s*=\s*'\"\s*([^\"'\n\r]+?)\s*\"'"
BOUND_ATTR_TPL_RE = r":({attr})\s*=\s*`([^`]+?)`"


def _wrap_template_attr(m: re.Match) -> str:
    attr, text = m.group(1), m.group(2)
    if ALREADY_WRAPPED_JS.search(text):
        return m.group(0)
    if re.search(r"{{|}}|`", text):  # interpolation / template literal
        return m.group(0)
    safe = text.replace("\\", "\\\\").replace("'", "\\'")
    return f":{attr}=\"__(\\'{safe}\\')\""  # v-bind


def _wrap_attrs_in_text(block: str, attrs: Iterable[str]) -> str:
    s = block
    for attr in attrs:
        a = re.escape(attr)
        s = re.sub(PLAIN_ATTR_RE.format(attr=a), _wrap_template_attr, s)
        s = re.sub(PLAIN_ATTR_RE_SQ.format(attr=a), _wrap_template_attr, s)
        s = re.sub(BOUND_ATTR_STR_RE.format(attr=a), _wrap_template_attr, s)
        s = re.sub(BOUND_ATTR_STR_RE_SQ.format(attr=a), _wrap_template_attr, s)
        s = re.sub(BOUND_ATTR_TPL_RE.format(attr=a), _wrap_template_attr, s)
    return s


def process_template(html: str, attrs: Iterable[str]) -> str:
    def repl(m: re.Match) -> str:
        start, inner, end = m.group(1), m.group(2), m.group(3)
        return f"{start}{_wrap_attrs_in_text(inner, attrs)}{end}"

    return TEMPLATE_BLOCK_RE.sub(repl, html)


# ── Global tag pass (covers outside <template> too) ────────────────────────────
TAG_RE = re.compile(r"(<(?!/|!)[^>\s][^>]*>)", re.S)  # excludes closing and comments/doctype


def process_all_tags(text: str, attrs: Iterable[str]) -> str:
    def repl(m: re.Match) -> str:
        tag = m.group(1)
        new_tag = _wrap_attrs_in_text(tag, attrs)
        return new_tag

    return TAG_RE.sub(repl, text)


# ── SCRIPT side (<script> in .vue + standalone .ts/.js) ───────────────────────
SCRIPT_BLOCK_RE = re.compile(r"(<script[\s\S]*?>)([\s\S]*?)(</script>)", re.I)

JS_PROP_SQ_TMPL = r"(\b{key}\b)\s*:\s*'([^'\\\n\r]+)'"
JS_PROP_DQ_TMPL = r'(\b{key}\b)\s*:\s*"([^"\\\n\r]+)"'


def _wrap_js_prop(m: re.Match) -> str:
    key, text = m.group(1), m.group(2)
    if ALREADY_WRAPPED_JS.search(text):
        return m.group(0)
    if re.search(r"[`]|{{|}}", text):
        return m.group(0)
    safe = text.replace("\\", "\\\\").replace("'", "\\'")
    return f"{key}: __('{safe}')"


def process_js_code(js_text: str, keys: Iterable[str]) -> str:
    s = js_text
    for k in keys:
        kk = re.escape(k)
        s = re.sub(JS_PROP_SQ_TMPL.format(key=kk), _wrap_js_prop, s)
        s = re.sub(JS_PROP_DQ_TMPL.format(key=kk), _wrap_js_prop, s)
    return s


def process_vue_file(text: str, attr_keys: Iterable[str], js_keys: Iterable[str]) -> str:
    out = process_template(text, attr_keys)

    def s_repl(m: re.Match) -> str:
        start, inner, end = m.group(1), m.group(2), m.group(3)
        return f"{start}{process_js_code(inner, js_keys)}{end}"

    out = SCRIPT_BLOCK_RE.sub(s_repl, out)
    out = process_all_tags(out, attr_keys)
    out = fix_v_model_accidents(out)
    return out


# ── Python (.py) Doctype-side support (opt-in) ────────────────────────────────
# We only touch simple literal string values of specific keys (default: 'label').
# Example: {"label": "Subject"} -> {"label": _("Subject")}
# We avoid touching complex expressions, f-strings, format strings, and already wrapped values.

# "label": 'Text' OR 'label': "Text"
PY_PROP_SQ_TMPL = r"([\"']{key}[\"'])\s*:\s*'([^'\\\n\r]+)'"
PY_PROP_DQ_TMPL = r"([\"']{key}[\"'])\s*:\s*\"([^\"\\\n\r]+)\""



@dataclasses.dataclass
class PyWrapConfig:
    func: str = "_"  # i18n function name
    qualify: Optional[str] = "frappe._"  # also accept qualified existing calls
    keys: Tuple[str, ...] = ("label",)
    inject_import: bool = True


def _already_wrapped_py(text: str, cfg: PyWrapConfig) -> bool:
    if cfg.func != "_":
        pattern = re.compile(rf"\b{re.escape(cfg.func)}\s*\(")
        return bool(pattern.search(text))
    return bool(ALREADY_WRAPPED_PY.search(text))


def _py_string_is_simple(text: str) -> bool:
    # Conservative skip for f-strings/format placeholders/brace-rich strings.
    if any(sym in text for sym in ("{", "}", "%(", "\n", "\r")):
        return False
    return True


def _wrap_py_prop_factory(cfg: PyWrapConfig):
    def _wrap(m: re.Match) -> str:
        key_tok, val = m.group(1), m.group(2)
        if _already_wrapped_py(val, cfg):
            return m.group(0)
        if not _py_string_is_simple(val):
            return m.group(0)
        safe = val.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'")
        # Preserve original quote style by not reusing it (wrap with cfg.func call)
        return f"{key_tok}: {cfg.func}(\"{safe}\")"

    return _wrap


def process_python_code(py_text: str, cfg: PyWrapConfig) -> str:
    s = py_text
    for k in cfg.keys:
        kk = re.escape(k)
        s = re.sub(PY_PROP_SQ_TMPL.format(key=kk), _wrap_py_prop_factory(cfg), s)
        s = re.sub(PY_PROP_DQ_TMPL.format(key=kk), _wrap_py_prop_factory(cfg), s)
    # Optionally inject `from frappe import _` if we created at least one call and it's missing.
    if cfg.inject_import and cfg.func == "_":
        if "_\(" in s and not re.search(r"^\s*from\s+frappe\s+import\s+_\s*$", s, re.M):
            s = _inject_import(s, line="from frappe import _")
    return s


def _inject_import(text: str, line: str) -> str:
    # Insert after shebang/encoding/comments at the top, before first non-comment code.
    lines = text.splitlines()
    insert_at = 0
    # Shebang
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    # Encoding cookie
    if insert_at < len(lines) and re.match(r"^#.*coding[:=]", lines[insert_at] or ""):
        insert_at += 1
    # Skip initial block of comments/empty lines
    while insert_at < len(lines) and (not lines[insert_at].strip() or lines[insert_at].lstrip().startswith("#")):
        insert_at += 1
    lines.insert(insert_at, line)
    return NEWLINE.join(lines) + (NEWLINE if text.endswith(("\n", "\r")) else "")


# ── v-model accident fixer ────────────────────────────────────────────────────

def fix_v_model_accidents(text: str) -> str:
    # v-model::title="__('x.y')" -> v-model:title="x.y"
    text = re.sub(
        r"v-model::(\w+)\s*=\s*\"__\(\s*'([^'\"]+?)'\s*\)\"",
        r'v-model:\1="\2"',
        text,
    )
    return text


# ── Filesystem ops (atomic, reporting, ignore) ────────────────────────────────
@dataclasses.dataclass
class ProcessStats:
    scanned: int = 0
    changed: int = 0
    wrapped_strings: int = 0
    skipped_interpolations: int = 0


@dataclasses.dataclass
class WorkItem:
    path: pathlib.Path


def is_ignored(base: pathlib.Path, path: pathlib.Path, ignore_globs: List[str]) -> bool:
    try:
        rel = str(path.relative_to(base)).replace("\\", "/")
    except ValueError:
        return True
    return any(fnmatch.fnmatch(rel, pat) for pat in ignore_globs)


def atomic_write(path: pathlib.Path, data: str) -> None:
    tmp_dir = path.parent
    with tempfile.NamedTemporaryFile("w", delete=False, dir=tmp_dir, encoding="utf-8", newline=NEWLINE) as tf:
        tf.write(data)
        tf.flush()
        os.fsync(tf.fileno())
        tmp_name = tf.name
    os.replace(tmp_name, path)


def unified_diff(a: str, b: str, path: pathlib.Path) -> str:
    return "".join(
        difflib.unified_diff(
            a.splitlines(keepends=True),
            b.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


# ── Main processing ──────────────────────────────────────────────────────────

def process_file(
    p: pathlib.Path,
    attr_keys: Iterable[str],
    js_keys: Iterable[str],
    dry: bool = False,
    no_backup: bool = False,
    enable_python: bool = False,
    py_cfg: Optional[PyWrapConfig] = None,
    emit_diff: bool = False,
) -> Tuple[int, Optional[str]]:
    text = p.read_text(encoding="utf-8")
    new_text = text

    if p.suffix == ".vue":
        new_text = process_vue_file(text, attr_keys, js_keys)
    elif p.suffix in (".ts", ".js"):
        new_text = process_js_code(text, js_keys)
    elif enable_python and p.suffix == ".py":
        assert py_cfg is not None
        new_text = process_python_code(text, py_cfg)

    if new_text != text:
        if dry:
            diff = unified_diff(text, new_text, p) if emit_diff else None
            return 1, diff
        else:
            if not no_backup:
                backup_name = f"{p.name}.{hashlib.sha1(text.encode('utf-8')).hexdigest()[:8]}.bak"
                p.with_name(backup_name).write_text(text, encoding="utf-8")
            atomic_write(p, new_text)
            return 1, None

    return 0, None


def discover_files(base: pathlib.Path, include_exts: Tuple[str, ...]) -> Iterable[pathlib.Path]:
    for ext in include_exts:
        yield from base.rglob(f"*{ext}")


def run(args: argparse.Namespace) -> int:
    base = pathlib.Path(args.target).resolve()
    assert base.exists() and base.is_dir(), f"Target not found: {base}"

    attr_keys = [a.strip() for a in args.attrs.split(",") if a.strip()]
    js_keys = [a.strip() for a in args.js_keys.split(",") if a.strip()]

    ignore_globs = args.ignore or []

    include_exts: Tuple[str, ...] = (".vue", ".ts", ".js")
    if args.enable_python:
        include_exts = include_exts + (".py",)

    py_cfg = None
    if args.enable_python:
        py_keys = tuple([a.strip() for a in args.py_keys.split(",") if a.strip()]) or ("label",)
        py_cfg = PyWrapConfig(func=args.py_func, qualify="frappe._", keys=py_keys, inject_import=not args.no_import_inject)

    files = list(discover_files(base, include_exts))

    changed = 0
    diffs: List[str] = []

    def _work(p: pathlib.Path):
        if is_ignored(base, p, ignore_globs):
            return 0, None
        return process_file(
            p,
            attr_keys,
            js_keys,
            dry=args.dry_run,
            no_backup=args.no_backup,
            enable_python=args.enable_python,
            py_cfg=py_cfg,
            emit_diff=args.diff,
        )

    # Threaded I/O for speed
    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        for c, d in ex.map(_work, files):
            changed += c
            if d:
                diffs.append(d)

    if args.diff and diffs:
        sys.stdout.write("\n".join(d for d in diffs if d))

    print(f"\nDone. Files changed: {changed}")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="Scan root directory (e.g., apps/helpdesk/desk/src or apps/helpdesk/helpdesk)")
    ap.add_argument("--attrs", default="label,title,placeholder,tooltip,aria-label", help="Template attributes (comma-separated)")
    ap.add_argument("--js-keys", default="label,title,placeholder,tooltip,aria-label,ariaLabel", help="Script-side property keys (comma-separated)")
    ap.add_argument("--dry-run", action="store_true", help="Report only; no writes")
    ap.add_argument("--no-backup", action="store_true", help="Do not write .bak backups")
    ap.add_argument("--ignore", action="append", default=[], help="Glob patterns to exclude (repeatable)")
    ap.add_argument("--threads", type=int, default=os.cpu_count() or 4, help="Parallel file workers")
    ap.add_argument("--diff", action="store_true", help="Print unified diff for changes (with --dry-run)")

    # Python support (opt-in)
    ap.add_argument("--enable-python", action="store_true", help="Enable Python (.py) wrapping for Doctype dict labels")
    ap.add_argument("--py-keys", default="label", help="Python dict keys to wrap (comma-separated)")
    ap.add_argument("--py-func", default="_", help="Python i18n function name (default: _)")
    ap.add_argument("--no-import-inject", action="store_true", help="Do not auto-inject `from frappe import _` when needed")

    return ap


def main():
    args = build_arg_parser().parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
