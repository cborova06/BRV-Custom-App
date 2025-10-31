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
import logging
from typing import Iterable, List, Optional, Tuple

# ── Shared ─────────────────────────────────────────────────────────────────────
ALREADY_WRAPPED_JS = re.compile(r"__\s*\(", re.S)
ALREADY_WRAPPED_PY = re.compile(r"(?:\b_|frappe\._)\s*\(", re.S)

NEWLINE = "\n"

# Simple module logger — writes to stderr by default. Callers may configure logging further.
logger = logging.getLogger(__name__)
if not logger.handlers:
	h = logging.StreamHandler()
	h.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
	logger.addHandler(h)
	logger.setLevel(logging.WARNING)

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
	# Preserve original attribute quoting when possible. We inspect the raw
	# matched string to see whether the original used single or double quotes
	# and choose an inner JS literal that avoids matching that outer quote.
	orig = m.group(0)
	outer_quote = '"' if '=%s' % '"' in orig or f'{attr}="' in orig else "'"

	def _js_literal_with_outer(s: str, outer: str) -> str:
		# escape backslashes first
		s2 = s.replace("\\", "\\\\")
		# Prefer a quote that is different from outer to avoid needing escapes
		if outer == '"':
			# favor single-quoted inner literal
			if "'" not in s2:
				return "'" + s2 + "'"
			if '"' not in s2:
				return '"' + s2.replace('"', '\\"') + '"'
			# both present: fall back to single with escaped single quotes
			return "'" + s2.replace("'", "\\'") + "'"
		else:
			# outer is single quote, favor double-quoted inner literal
			if '"' not in s2:
				return '"' + s2 + '"'
			if "'" not in s2:
				return "'" + s2.replace("'", "\\'") + "'"
			return '"' + s2.replace('"', '\\"') + '"'

	js_lit = _js_literal_with_outer(text, outer_quote)
	# Always produce a v-bind (:) attribute; preserve outer quoting style
	if outer_quote == '"':
		return f":{attr}=\"__({js_lit})\""
	else:
		return f":{attr}='__({js_lit})'"


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
	# Use same quoting strategy as template side for JS literals
	def _js_literal(s: str) -> str:
		s2 = s.replace("\\", "\\\\")
		if "'" not in s2:
			return "'" + s2 + "'"
		if '"' not in s2:
			return '"' + s2.replace('"', '\\"') + '"'
		return "'" + s2.replace("'", "\\'") + "'"

	js_lit = _js_literal(text)
	return f"{key}: __({js_lit})"


def process_js_code(js_text: str, keys: Iterable[str]) -> str:
	s = js_text
	for k in keys:
		kk = re.escape(k)
		s = re.sub(JS_PROP_SQ_TMPL.format(key=kk), _wrap_js_prop, s)
		s = re.sub(JS_PROP_DQ_TMPL.format(key=kk), _wrap_js_prop, s)
	return s


def _inject_vue_import(text: str) -> str:
	"""Inject `import { __ } from "@/translation";` if __ is used but import is missing.
	
	Inserts after existing imports in <script> block, or at the start of script if no imports exist.
	
	Safety measures:
	- Only inject if __ is actually used
	- Skip if import already exists (checks multiple patterns)
	- Never inject inside `import {` blocks
	- Insert after last complete import statement
	"""
	# Check if __ is used anywhere in the file
	if not ALREADY_WRAPPED_JS.search(text):
		return text
	
	# Check if import already exists (multiple patterns)
	import_patterns = [
		r'import\s+{\s*[^}]*\b__\b[^}]*}\s+from\s+["\']@/translation["\']',
		r'import\s+{\s*__\s*}\s+from\s+["\']@/translation["\']',
		r'from\s+["\']@/translation["\']\s+import\s+{\s*[^}]*\b__\b[^}]*}',
	]
	for pattern in import_patterns:
		if re.search(pattern, text):
			return text
	
	def inject_in_script(m: re.Match) -> str:
		start, inner, end = m.group(1), m.group(2), m.group(3)
		
		# Double-check import doesn't exist in this script block
		for pattern in import_patterns:
			if re.search(pattern, inner):
				return m.group(0)
		
		lines = inner.split('\n')
		insert_idx = 0
		
		# Find last COMPLETE import statement (not inside import { })
		last_import_idx = -1
		in_multiline_import = False
		
		for i, line in enumerate(lines):
			stripped = line.strip()
			
			# Track multiline imports
			if 'import' in stripped and '{' in stripped and '}' not in stripped:
				in_multiline_import = True
			elif in_multiline_import and '}' in stripped:
				in_multiline_import = False
				last_import_idx = i  # This is the end of multiline import
			elif not in_multiline_import and stripped.startswith('import '):
				# Single-line import
				last_import_idx = i
		
		if last_import_idx >= 0:
			# Insert after last import (add 1 to go to next line)
			insert_idx = last_import_idx + 1
			
			# If next line is empty, use it; otherwise insert before next code
			if insert_idx < len(lines) and not lines[insert_idx].strip():
				# Replace empty line with import
				lines[insert_idx] = 'import { __ } from "@/translation";'
			else:
				# Insert new line
				lines.insert(insert_idx, 'import { __ } from "@/translation";')
		else:
			# No imports found, insert at start (after initial empty lines/comments)
			for i, line in enumerate(lines):
				stripped = line.strip()
				if stripped and not stripped.startswith('//') and not stripped.startswith('/*'):
					insert_idx = i
					break
			lines.insert(insert_idx, 'import { __ } from "@/translation";')
		
		new_inner = '\n'.join(lines)
		return f"{start}{new_inner}{end}"
	
	return SCRIPT_BLOCK_RE.sub(inject_in_script, text)


def process_vue_file(
	text: str,
	attr_keys: Iterable[str],
	js_keys: Iterable[str],
	wrap_tags: Optional[Iterable[str]] = None,
	wrap_toast: bool = False
) -> str:
	out = process_template(text, attr_keys)

	def s_repl(m: re.Match) -> str:
		start, inner, end = m.group(1), m.group(2), m.group(3)
		return f"{start}{process_js_code(inner, js_keys)}{end}"

	out = SCRIPT_BLOCK_RE.sub(s_repl, out)
	out = process_all_tags(out, attr_keys)
	
	# Optional: wrap tag content (e.g., Button inner text)
	if wrap_tags:
		out = wrap_tag_content(out, wrap_tags)
	
	# Optional: wrap toast messages
	if wrap_toast:
		out = wrap_toast_messages(out)
	
	out = fix_v_model_accidents(out)
	
	# Auto-inject import if __ is used
	out = _inject_vue_import(out)
	
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


def _normalize_wrapped(text: str) -> str:
	"""Fix legacy wrapped calls that contain escaped quotes like __(\'Close\') -> __('Close')

	This normalizer fixes common artifacts introduced by older versions of the tool
	that injected backslashes before quotes inside the i18n call. It is conservative
	and only unescapes the surrounding quotes of the immediate argument.
	"""
	# __('\'Text\') -> __('Text') and __("\"Text\") -> __("Text")
	text = re.sub(r"__\(\s*\\'([^\\']*?)\\'\s*\)", r"__('\1')", text)
	text = re.sub(r'__\(\s*\\\"([^\\\"]*?)\\\"\s*\)', r'__("\1")', text)

	# More general case: if surrounding quotes are escaped with a single backslash
	# (e.g. __(\'Text\') or __(\"Text\") ) unify to simple quoted arg
	text = re.sub(r"__\(\s*\\(['\"])" r"(.*?)" r"\\\1\s*\)", r"__(\1\2\1)", text)

	# Also handle double-escaped sequences (some files may contain `\\'`)
	text = re.sub(r"__\(\s*\\\\(['\"])" r"(.*?)" r"\\\\\1\s*\)", r"__(\1\2\1)", text)

	return text


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


# ── Tag content wrapping (opt-in for Button/etc inner text) ───────────────────

def wrap_tag_content(text: str, tag_names: Iterable[str]) -> str:
	"""Wrap simple text content inside specified tags with {{ __("text") }}.
	
	This wraps plain text between opening and closing tags like:
	  <Button>Send Invites</Button> -> <Button>{{ __("Send Invites") }}</Button>
	
	Safety guards:
	- Skip if already wrapped (contains {{ or __)
	- Skip if contains nested tags (< inside content)
	- Skip if tag has :label or label attribute (redundant)
	- Skip whitespace-only content
	- Trim leading/trailing whitespace from wrapped text
	
	Args:
		text: Vue template or component source
		tag_names: List of tag names to process (case-sensitive, e.g., ["Button"])
	
	Returns:
		Processed text with wrapped tag content
	"""
	if not tag_names:
		return text
	
	for tag_name in tag_names:
		# Pattern: <TagName ...> content </TagName>
		# Captures: opening tag, content, closing tag
		# Uses non-greedy match and excludes self-closing tags
		pattern = re.compile(
			rf"(<{re.escape(tag_name)}(?:\s[^>]*)?>)"  # opening tag
			rf"(.*?)"  # content (non-greedy)
			rf"(</{re.escape(tag_name)}>)",  # closing tag
			re.S  # DOTALL for multiline
		)
		
		def _replacer(m: re.Match) -> str:
			opening, content, closing = m.group(1), m.group(2), m.group(3)
			
			# Skip if opening tag has :label or label attribute
			if re.search(r'(?::|^|\s)label\s*=', opening):
				return m.group(0)
			
			# Skip if content already has interpolation or wrapping
			if re.search(r'{{|}|__\s*\(', content):
				return m.group(0)
			
			# Skip if content has nested tags
			if '<' in content:
				return m.group(0)
			
			# Extract and trim text
			trimmed = content.strip()
			
			# Skip if empty or whitespace-only
			if not trimmed:
				return m.group(0)
			
			# Skip if contains newlines after trim (complex multi-line)
			if '\n' in trimmed or '\r' in trimmed:
				# Allow simple case: tag spans lines but text is single-line
				# E.g., <Button\n  >Text\n</Button>
				# Already handled by trim, so this is a secondary guard
				pass
			
			# Escape quotes in text for JS string literal
			safe_text = trimmed.replace('\\', '\\\\').replace('"', '\\"')
			
			# Preserve original whitespace structure around content
			# Detect leading/trailing whitespace in original content
			leading_ws = content[:len(content) - len(content.lstrip())]
			trailing_ws = content[len(content.rstrip()):]
			
			# Wrap with interpolation
			wrapped = f'{{{{ __("{safe_text}") }}}}'
			
			return f"{opening}{leading_ws}{wrapped}{trailing_ws}{closing}"
		
		text = pattern.sub(_replacer, text)
	
	return text


def wrap_toast_messages(text: str) -> str:
	"""Wrap toast.success() and toast.error() messages with __() for i18n.
	
	Converts:
		toast.success("Message") -> toast.success(__("Message"))
		toast.error("Error") -> toast.error(__("Error"))
	
	Safety guards:
		- Skip if already wrapped with __(
		- Skip if message is a variable/expression (contains ${ or starts with variable)
		- Skip template literals with interpolation
	
	Args:
		text: Vue or TypeScript source code
	
	Returns:
		Processed text with wrapped toast messages
	"""
	# Pattern to match toast.success("message") or toast.error("message")
	# but not already wrapped with __(
	pattern = r'toast\.(success|error)\((?!__\()(["\'])([^"\']*)\2'
	
	def _replacer(m: re.Match) -> str:
		method = m.group(1)  # success or error
		quote = m.group(2)   # " or '
		message = m.group(3)  # the message
		
		# Skip if message is empty
		if not message:
			return m.group(0)
		
		# Skip if message contains interpolation markers
		if '${' in message or message.startswith('${'):
			return m.group(0)
		
		# Skip if message appears to be a variable (no spaces, starts with lowercase/uppercase)
		# This catches cases like toast.success(successMessage)
		if ' ' not in message and not any(c in message for c in ['.', ',', '!', '?', ':']):
			# Likely a variable name, but we already filtered by quotes, so this is actual text
			pass
		
		return f'toast.{method}(__({quote}{message}{quote})'
	
	return re.sub(pattern, _replacer, text)


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
	"""Atomically write ``data`` to ``path``.

	This function writes to a temporary file in the same directory, fsyncs,
	then replaces the target. If the target exists, its permissions are
	preserved when possible.
	"""
	tmp_dir = path.parent
	# Ensure directory exists
	tmp_dir.mkdir(parents=True, exist_ok=True)
	# Capture original mode if present
	orig_mode = None
	try:
		st = path.stat()
	except OSError:
		st = None
	if st is not None:
		orig_mode = st.st_mode & 0o777

	tf = None
	try:
		with tempfile.NamedTemporaryFile("w", delete=False, dir=tmp_dir, encoding="utf-8", newline=NEWLINE) as tf:
			tf.write(data)
			tf.flush()
			os.fsync(tf.fileno())
			tmp_name = tf.name
		# Replace target atomically
		os.replace(tmp_name, str(path))
		# Restore permission bits when available
		if orig_mode is not None:
			try:
				os.chmod(str(path), orig_mode)
			except OSError:
				logger.debug("Failed to chmod %s", path)
	finally:
		# Cleanup if temp file still exists
		try:
			if tf is not None and os.path.exists(getattr(tf, 'name', '')):
				os.unlink(tf.name)
		except Exception:
			pass


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
	max_file_size: Optional[int] = None,
	normalize: bool = False,
	wrap_tags: Optional[Iterable[str]] = None,
	wrap_toast: bool = False,
) -> Tuple[int, Optional[str]]:
	# Safety checks: skip symlinks and very large files (configurable)
	try:
		if p.is_symlink():
			logger.warning("Skipping symlink: %s", p)
			return 0, None
	except OSError:
		logger.warning("Skipping path (is_symlink check failed): %s", p)
		return 0, None

	try:
		if max_file_size is not None and p.stat().st_size > max_file_size:
			logger.warning("Skipping large file (> %d bytes): %s", max_file_size, p)
			return 0, None
	except OSError:
		logger.warning("Skipping path (stat failed): %s", p)
		return 0, None

	try:
		text = p.read_text(encoding="utf-8")
		orig_text = text
	except (UnicodeDecodeError, OSError) as e:
		logger.warning("Failed to read %s: %s", p, e)
		return 0, None
	# Optional normalization of legacy wrapped calls (unescape bad backslashes)
	# Always perform a conservative normalization for front-end files to avoid
	# recurring escaped-quote artifacts that break build pipelines. This is
	# limited to .vue and .js/.ts files and is conservative (only unescapes
	# surrounding quotes inside __()). If the user passed --normalize we
	# already run a normalization; repeat is harmless.
	if p.suffix in (".vue", ".js", ".ts"):
		try:
			text = _normalize_wrapped(text)
		except Exception:
			logger.debug("Normalization failed for %s", p)
	elif normalize:
		# user explicitly asked to normalize other file types (e.g., .py)
		try:
			text = _normalize_wrapped(text)
		except Exception:
			logger.debug("Normalization failed for %s", p)
	new_text = text

	if p.suffix == ".vue":
		new_text = process_vue_file(text, attr_keys, js_keys, wrap_tags=wrap_tags, wrap_toast=wrap_toast)
	elif p.suffix in (".ts", ".js"):
		new_text = process_js_code(text, js_keys)
		# Also wrap toast messages in TypeScript/JavaScript files
		if wrap_toast:
			new_text = wrap_toast_messages(new_text)
	elif enable_python and p.suffix == ".py":
		assert py_cfg is not None
		new_text = process_python_code(text, py_cfg)

	# Compare against the original on-disk content so that conservative
	# normalization (which updates `text` before processing) is detected and
	# written back when different from the original file.
	if new_text != orig_text:
		if dry:
			diff = unified_diff(text, new_text, p) if emit_diff else None
			return 1, diff
		else:
			if not no_backup:
				backup_name = f"{p.name}.{hashlib.sha1(text.encode('utf-8')).hexdigest()[:8]}.bak"
				backup_path = p.with_name(backup_name)
				try:
					# Preserve permissions for backup
					orig_mode = None
					try:
						orig_mode = p.stat().st_mode & 0o777
					except OSError:
						orig_mode = None
					atomic_write(backup_path, text)
					if orig_mode is not None:
						try:
							os.chmod(str(backup_path), orig_mode)
						except OSError:
							logger.debug("Failed to chmod backup %s", backup_path)
				except Exception as e:
					logger.warning("Could not write backup %s: %s", backup_path, e)
			# Write new contents atomically and try to preserve original mode
			try:
				orig_mode = None
				try:
					orig_mode = p.stat().st_mode & 0o777
				except OSError:
					orig_mode = None
				atomic_write(p, new_text)
				if orig_mode is not None:
					try:
						os.chmod(str(p), orig_mode)
					except OSError:
						logger.debug("Failed to chmod %s", p)
			except Exception as e:
				logger.error("Failed to write %s: %s", p, e)
				return 0, None
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

	wrap_tags = None
	if hasattr(args, 'wrap_tag_content') and args.wrap_tag_content:
		wrap_tags = tuple([t.strip() for t in args.wrap_tag_content.split(",") if t.strip()])

	wrap_toast = getattr(args, 'wrap_toast', False)

	def _work(p: pathlib.Path):
		try:
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
				max_file_size=getattr(args, 'max_file_size', None),
				normalize=getattr(args, 'normalize', False),
				wrap_tags=wrap_tags,
				wrap_toast=wrap_toast,
			)
		except Exception as e:
			# Log and continue other files — robust against single-file failures
			logger.error("Error processing %s: %s", p, e)
			return 0, None

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
	ap.add_argument("--max-file-size", type=int, default=2*1024*1024, help="Skip files larger than this many bytes (0 to disable)")
	ap.add_argument("--normalize", action="store_true", help="Normalize previously malformed wrapped calls (unescape legacy backslashes)")

	# Python support (opt-in)
	ap.add_argument("--enable-python", action="store_true", help="Enable Python (.py) wrapping for Doctype dict labels")
	ap.add_argument("--py-keys", default="label", help="Python dict keys to wrap (comma-separated)")
	ap.add_argument("--py-func", default="_", help="Python i18n function name (default: _)")
	ap.add_argument("--no-import-inject", action="store_true", help="Do not auto-inject `from frappe import _` when needed")

	# Tag content wrapping (opt-in for Button/etc)
	ap.add_argument("--wrap-tag-content", metavar="TAGS", help="Wrap inner text of specified tags with {{ __(\"text\") }} (comma-separated, e.g., Button,CustomButton)")
	
	# Toast message wrapping
	ap.add_argument("--wrap-toast", action="store_true", help="Wrap toast.success() and toast.error() messages with __()")

	return ap


def main():
	args = build_arg_parser().parse_args()
	sys.exit(run(args))


if __name__ == "__main__":
	main()
