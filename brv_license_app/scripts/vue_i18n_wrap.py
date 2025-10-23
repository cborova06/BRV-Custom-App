#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import pathlib
import re
from typing import Iterable
import fnmatch

# ── Ortak ──────────────────────────────────────────────────────────────────────
ALREADY_WRAPPED_RE = re.compile(r"__\s*\(", re.S)

# ── TEMPLATE tarafı ────────────────────────────────────────────────────────────
TEMPLATE_BLOCK_RE = re.compile(r"(<template[^>]*>)(.*?)(</template>)", re.S | re.I)

PLAIN_ATTR_RE     = r'(?<![\w:-])({attr})\s*=\s*"([^"\n\r]+)"'
PLAIN_ATTR_RE_SQ  = r"(?<![\w:-])({attr})\s*=\s*'([^'\n\r]+)'"
BOUND_ATTR_STR_RE    = r':({attr})\s*=\s*\"\'\s*([^\"\'\n\r]+?)\s*\'\"'
BOUND_ATTR_STR_RE_SQ = r":({attr})\s*=\s*'\"\s*([^\"'\n\r]+?)\s*\"'"
BOUND_ATTR_TPL_RE = r":({attr})\s*=\s*`([^`]+?)`"

def _wrap_template_attr(m: re.Match) -> str:
    attr, text = m.group(1), m.group(2)
    if ALREADY_WRAPPED_RE.search(text):
        return m.group(0)
    if re.search(r"{{|}}|`", text):  # interpolation / template literal
        return m.group(0)
    safe = text.replace("\\", "\\\\").replace("'", "\\'")
    return f':{attr}="__(\'{safe}\')"'  # v-bind

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

# ── Tüm tag’lerde ikinci geçiş (template dışını da kapsar) ────────────────────
TAG_RE = re.compile(r"(<(?!/|!)[^>\s][^>]*>)", re.S)  # kapanış ve yorum/doctype hariç

def process_all_tags(text: str, attrs: Iterable[str]) -> str:
    def repl(m: re.Match) -> str:
        tag = m.group(1)
        new_tag = _wrap_attrs_in_text(tag, attrs)
        return new_tag
    return TAG_RE.sub(repl, text)

# ── SCRIPT tarafı (.vue içi <script>, ayrıca .ts/.js dosyaları) ───────────────
SCRIPT_BLOCK_RE = re.compile(r"(<script[\s\S]*?>)([\s\S]*?)(</script>)", re.I)

JS_PROP_SQ_TMPL = r"(\b{key}\b)\s*:\s*'([^'\\\n\r]+)'"
JS_PROP_DQ_TMPL = r'(\b{key}\b)\s*:\s*"([^"\\\n\r]+)"'

def _wrap_js_prop(m: re.Match) -> str:
    key, text = m.group(1), m.group(2)
    if ALREADY_WRAPPED_RE.search(text):
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
    # <script> blokları
    def s_repl(m: re.Match) -> str:
        start, inner, end = m.group(1), m.group(2), m.group(3)
        return f"{start}{process_js_code(inner, js_keys)}{end}"
    out = SCRIPT_BLOCK_RE.sub(s_repl, out)
    # template dışında kalan tag öznitelikleri için ikinci pas
    out = process_all_tags(out, attr_keys)
    out = fix_v_model_accidents(out)
    return out

# ── Dosya işleme ──────────────────────────────────────────────────────────────
def process_file(p: pathlib.Path, attr_keys: Iterable[str], js_keys: Iterable[str],
                 dry=False, no_backup=False) -> int:
    text = p.read_text(encoding="utf-8")
    if p.suffix == ".vue":
        new_text = process_vue_file(text, attr_keys, js_keys)
    else:
        new_text = process_js_code(text, js_keys)

    if new_text != text:
        if dry:
            print(f"[DRY] would change: {p}")
        else:
            if not no_backup:
                p.with_suffix(p.suffix + ".bak").write_text(text, encoding="utf-8")
            p.write_text(new_text, encoding="utf-8")
            print(f"[OK ] updated: {p}")
        return 1
    return 0

def fix_v_model_accidents(text: str) -> str:
    # v-model::title="__('x.y')" -> v-model:title="x.y"
    text = re.sub(
        r'v-model::(\w+)\s*=\s*"__\(\s*\'([^\'"]+?)\'\s*\)"',
        r'v-model:\1="\2"',
        text
    )
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="Taranacak klasör (örn. apps/helpdesk/desk/src)")
    ap.add_argument("--attrs", default="label,title,placeholder,tooltip,aria-label",
                    help="Template öznitelikleri (virgüllü)")
    ap.add_argument("--js-keys", default="label,title,placeholder,tooltip,aria-label,ariaLabel",
                    help="Script tarafında sarılacak özellik adları (virgüllü)")
    ap.add_argument("--dry-run", action="store_true", help="Sadece raporla, yazma")
    ap.add_argument("--no-backup", action="store_true", help=".bak yedeği bırakma")
    ap.add_argument("--ignore", action="append", default=[], help="Glob deseniyle hariç tut (çoklu)")
    args = ap.parse_args()

    attr_keys = [a.strip() for a in args.attrs.split(",") if a.strip()]
    js_keys   = [a.strip() for a in args.js_keys.split(",") if a.strip()]
    ignore_globs = args.ignore or []
    base = pathlib.Path(args.target).resolve()

    def is_ignored(path: pathlib.Path) -> bool:
        rel = str(path.relative_to(base)).replace("\\", "/")
        return any(fnmatch.fnmatch(rel, pat) for pat in ignore_globs)

    changed = 0
    for pattern in ("*.vue", "*.ts", "*.js"):
        for p in base.rglob(pattern):
            if is_ignored(p):
                continue
            changed += process_file(p, attr_keys, js_keys,
                                    dry=args.dry_run, no_backup=args.no_backup)

    print(f"\nDone. Files changed: {changed}")

if __name__ == "__main__":
    main()


"""
** /home/frappe/frappe-bench/apps/helpdesk/desk/package.json
  "scripts": {
    "prebuild": "python3 /home/frappe/frappe-bench/apps/brv_license_app/brv_license_app/scripts/vue_i18n_wrap.py --target ./src --attrs label,title,placeholder,tooltip,aria-label --ignore 'src/pages/MobileNotifications.vue' --ignore 'src/pages/knowledge-base/*.vue' --no-backup || python3 ../../brv_license_app/brv_license_app/scripts/vue_i18n_wrap.py --target ./src --attrs label,title,placeholder,tooltip,aria-label --ignore 'src/pages/MobileNotifications.vue' --ignore 'src/pages/knowledge-base/*.vue' --no-backup",
    "dev": "vite",
    "build": "vite build",
    "serve": "vite preview"
  },

prebuild kısmı eklemek şart. Ayrıa tr.po dosyasını güncelle.
"""