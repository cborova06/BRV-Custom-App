# FILE: brv_license_app/utils/logging.py
"""
Unified logging helpers for BRV License App (Frappe v15+)

- Uses frappe.utils.logger.get_logger to create a site-scoped rotating log.
- Honors log level from site_config.json via "brv_license_log_level" (e.g. "INFO", "DEBUG").
- Provides small helpers to mask secrets/tokens and compact JSON for log lines.
- Tiny HTTP request/response logging helpers for consistent client traces.
"""

import logging
from contextlib import contextmanager
from typing import Any, Dict, Optional

from frappe.utils.logger import get_logger

try:
    import frappe  # type: ignore
except Exception:  # pragma: no cover
    frappe = None  # type: ignore


# ---------------------------
# Level helpers
# ---------------------------

def _level_from_string(level_str: str) -> int:
    """Map string level to logging constant; defaults to INFO on unknown."""
    try:
        return getattr(logging, str(level_str).upper())
    except Exception:
        return logging.INFO


def _level_from_site_config(default: int = logging.INFO) -> int:
    """Read desired log level from site_config.json (key: brv_license_log_level)."""
    if not frappe:
        return default
    try:
        cfg = frappe.get_site_config()  # type: ignore[attr-defined]
        if not isinstance(cfg, dict):
            return default
        val = cfg.get("brv_license_log_level")
        return _level_from_string(val) if val else default
    except Exception:
        return default


# ---------------------------
# Public logger factory
# ---------------------------

def get_license_logger(
    name: str = "brv_license_app.license",
    *,
    file_count: int = 5,
    default_level: int = logging.INFO,
) -> logging.Logger:
    """
    Create or return a site-scoped rotating logger.

    Frappe v15 get_logger() automatically:
      - Writes to sites/<site>/logs/<name>.log
      - Rotates with file_count
    """
    logger = get_logger(name, file_count=file_count)
    # Respect site-config override (brv_license_log_level: "DEBUG"/"INFO"/...)
    level = _level_from_site_config(default=default_level)
    logger.setLevel(level)
    return logger


# Singleton logger used across the app
license_logger = get_license_logger()


# ---------------------------
# Mask/format utilities
# ---------------------------

def mask_token(tok: Optional[str], *, keep: int = 6) -> str:
    """Mask a token/secret for logs, keeping first `keep` chars."""
    if not tok:
        return "<none>"
    t = str(tok)
    if len(t) <= keep:
        return "*" * len(t)
    return t[:keep] + "…" + ("*" * max(0, len(t) - keep - 1))


def mask_key(key: Optional[str], *, keep: int = 6) -> str:
    """Alias for mask_token (semantic)."""
    return mask_token(key, keep=keep)


def compact_json(obj: Any, limit: int = 1200) -> str:
    """Compact JSON string for logging; truncate if too long."""
    import json
    try:
        s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        s = str(obj)
    return s if len(s) <= limit else s[:limit] + "…(truncated)"


# ---------------------------
# HTTP trace helpers
# ---------------------------

def log_http_request(
    logger: logging.Logger,
    *,
    method: str,
    url: str,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, Any]] = None,
) -> None:
    """Consistent request breadcrumb."""
    safe_params = dict(params or {})
    # Never log raw credentials
    for k in list(safe_params.keys()):
        if k.lower() in {"password", "secret", "token", "authorization"}:
            safe_params[k] = mask_token(str(safe_params[k]))
    logger.info("HTTP %s %s params=%s", method.upper(), url, compact_json(safe_params))
    if headers:
        logger.debug("Headers=%s", compact_json({k: ("<redacted>" if k.lower() == "authorization" else v) for k, v in headers.items()}))


def log_http_response(
    logger: logging.Logger,
    *,
    url: str,
    status: int,
    body: Any,
) -> None:
    """Consistent response breadcrumb."""
    level = logging.INFO if 200 <= status < 400 else logging.ERROR
    logger.log(level, "HTTP %s status=%s body=%s", url, status, compact_json(body))


def log_contract_error(
    logger: logging.Logger,
    *,
    code: str,
    status: Optional[int],
    message: str,
    body: Any,
) -> None:
    """Specialized breadcrumb for 'success=true but errors in data' pattern."""
    logger.error(
        "ContractError code=%s status=%s msg=%s body=%s",
        code,
        status,
        message,
        compact_json(body),
    )


# ---------------------------
# Temporary level override
# ---------------------------

@contextmanager
def temporarily(level: int):
    """
    Temporarily raise/lower the license logger level.

    Example:
        with temporarily(logging.DEBUG):
            # noisy section
            ...
    """
    logger = license_logger
    old = logger.level
    try:
        logger.setLevel(level)
        yield logger
    finally:
        logger.setLevel(old)
