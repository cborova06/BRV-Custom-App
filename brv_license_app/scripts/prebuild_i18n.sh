#!/usr/bin/env bash
# Safe prebuild wrapper for vue_i18n_wrap.py placed inside brv_license_app
# Flow:
# 1) Run dry-run + diff and capture output
# 2) If diffs present, run actual script to apply changes (backups are created by the script)
# 3) Print diff output so CI/devs can see what changed

set -euo pipefail

# Config (edit if needed or override via environment)
TARGET="${TARGET:-desk/src}"
ATTRS="${ATTRS:-label,title,placeholder,tooltip,aria-label}"
MAX_FILE_SIZE=${MAX_FILE_SIZE:-2097152}
PY_TARGET="${PY_TARGET:-helpdesk}"
PY_KEYS="${PY_KEYS:-label,title,subject,options,placeholder,tooltip,aria-label}"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WRAP="$SCRIPT_DIR/vue_i18n_wrap.py"
IGN1="src/pages/MobileNotifications.vue"
IGN2="src/pages/knowledge-base/*.vue"

# Resolve apps directory (three levels up from scripts) so targets are absolute.
# Use the script's real path so resolution is independent of the current working directory.
APPS_DIR=$(cd "$SCRIPT_DIR/../../.." && pwd)

# Normalize TARGET and PY_TARGET to absolute locations under the helpdesk app
# Default frontend target (relative to app) is 'desk/src'
FRONTEND_REL="${TARGET:-desk/src}"
if [[ "$FRONTEND_REL" = /* ]]; then
    TARGET_ABS="$FRONTEND_REL"
else
    TARGET_ABS="$APPS_DIR/helpdesk/$FRONTEND_REL"
fi

# Default python target (relative to app) is 'helpdesk' package
PY_REL="${PY_TARGET:-helpdesk}"
if [[ "$PY_REL" = /* ]]; then
    PY_TARGET_ABS="$PY_REL"
else
    PY_TARGET_ABS="$APPS_DIR/helpdesk/$PY_REL"
fi

# Files in the helpdesk python package that must never be modified by the i18n wrapper
# (keep these exact):
PY_IGNORE_1="search_sqlite.py"
PY_IGNORE_2="hooks.py"

run_dry() {
    # $1 = script path
    python3 "$1" --target "$TARGET_ABS" --attrs "$ATTRS" --dry-run --diff --max-file-size "$MAX_FILE_SIZE" --ignore "$IGN1" --ignore "$IGN2"
}

run_apply() {
    # $1 = script path
    # Do not pass --no-backup so backups are kept
    python3 "$1" --target "$TARGET_ABS" --attrs "$ATTRS" --max-file-size "$MAX_FILE_SIZE" --ignore "$IGN1" --ignore "$IGN2" --normalize
}

run_dry_python() {
    # $1 = script path
    python3 "$1" --target "$PY_TARGET_ABS" --attrs "$ATTRS" --dry-run --diff --max-file-size "$MAX_FILE_SIZE" --enable-python --py-keys "$PY_KEYS" --ignore "$PY_IGNORE_1" --ignore "$PY_IGNORE_2"
}

run_apply_python() {
    # $1 = script path
    python3 "$1" --target "$PY_TARGET_ABS" --attrs "$ATTRS" --max-file-size "$MAX_FILE_SIZE" --enable-python --py-keys "$PY_KEYS" --normalize --ignore "$PY_IGNORE_1" --ignore "$PY_IGNORE_2"
}

TMP=$(mktemp 2>/dev/null || echo "/tmp/vue_i18n_diff.$$")

if [ ! -x "$(command -v python3)" ]; then
    echo "python3 not found in PATH" >&2
    exit 2
fi

if [ ! -f "$WRAP" ]; then
    echo "vue_i18n_wrap.py not found at $WRAP" >&2
    exit 2
fi

# Run dry-run
if run_dry "$WRAP" >"$TMP" 2>&1; then
    :
else
    # Capture output from dry-run even on non-zero
    run_dry "$WRAP" >"$TMP" 2>&1 || true
fi

if [ -s "$TMP" ]; then
    echo "i18n changes detected — applying with backups"
    if run_apply "$WRAP"; then
        :
    else
        echo "apply failed with local script" >&2
        cat "$TMP" >&2
        rm -f "$TMP"
        exit 2
    fi
    cat "$TMP"
else
    rm -f "$TMP"
fi

# Now run a second pass for Python sources (wrap strings in .py files)
PY_TMP=$(mktemp 2>/dev/null || echo "/tmp/vue_i18n_py_diff.$$")

if run_dry_python "$WRAP" >"$PY_TMP" 2>&1; then
    :
else
    run_dry_python "$WRAP" >"$PY_TMP" 2>&1 || true
fi

if [ -s "$PY_TMP" ]; then
    echo "i18n changes detected in python sources — applying with backups"
    if run_apply_python "$WRAP"; then
        :
    else
        echo "apply failed for python sources" >&2
        cat "$PY_TMP" >&2
        rm -f "$PY_TMP"
        exit 2
    fi
    cat "$PY_TMP"
else
    rm -f "$PY_TMP"
fi

# Generate tr.csv from tr.po for Frappe translations
HELPDESK_LOCALE="$APPS_DIR/helpdesk/helpdesk/locale"
HELPDESK_TRANSLATIONS="$APPS_DIR/helpdesk/helpdesk/translations"
TR_PO="$HELPDESK_LOCALE/tr.po"
TR_CSV="$HELPDESK_TRANSLATIONS/tr.csv"

if [ -f "$TR_PO" ]; then
    echo "Generating tr.csv from tr.po..."
    mkdir -p "$HELPDESK_TRANSLATIONS"
    
    python3 << PYEOF
import re, csv

po_file = '$TR_PO'
csv_file = '$TR_CSV'

with open(po_file, 'r', encoding='utf-8') as f:
    content = f.read()

matches = re.findall(r'msgid "(.*?)"\nmsgstr "(.*?)"', content, re.DOTALL)
count = 0

with open(csv_file, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    for mid, mstr in matches:
        mid = mid.replace('"\n"', '').replace('\\\\n', '\n')
        mstr = mstr.replace('"\n"', '').replace('\\\\n', '\n')
        if mid and mstr and mid != mstr:
            w.writerow([mid, mstr, ''])
            count += 1

print(f"✓ tr.csv generated with {count} translations")
PYEOF
fi

exit 0
