# -*- coding: utf-8 -*-
"""BRV License App – LMFWC License Client (with structured logging)

Single-file, production-grade client to integrate License Manager for WooCommerce (LMFWC)
with Frappe/ERPNext. Reads configuration from site_config and exposes four endpoints:
- activate
- reactivate (alias of activate with token)
- deactivate (bulk or single by token)
- validate

Design principles
- Secure by default (HTTPS verify, timeouts, no credential leakage)
- Robust error handling (HTTP errors + 200-with-error-body pattern)
- Idempotency guard for activate (short TTL lock via frappe.cache)
- Minimal, well-typed public API
- First-class observability via structured logs

Configuration (from site_config.json)
- lmfwc_base_url (string, required)
- lmfwc_consumer_key (string, required)
- lmfwc_consumer_secret (string, required)
- lmfwc_allow_insecure_http (0/1, optional; default 0)

Usage
-----
from brv_license_app.license_client import LMFWCClient, LMFWCError
client = LMFWCClient()  # reads from site_config
client.activate("LICENSE-KEY-123")
client.reactivate("LICENSE-KEY-123", token="...")
client.deactivate("LICENSE-KEY-123")
client.deactivate("LICENSE-KEY-123", token="...")
client.validate("LICENSE-KEY-123")
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth

try:  # Frappe runtime
    import frappe  # type: ignore
except Exception:  # pragma: no cover
    frappe = None  # type: ignore

# --------------------------------------------------------------------
# Logging helpers (use app logger if available)
# --------------------------------------------------------------------
try:
    from brv_license_app.utils.logging import license_logger as LOG  # type: ignore
    from brv_license_app.utils.logging import mask_token as _mask_token  # type: ignore
    from brv_license_app.utils.logging import compact_json as _compact  # type: ignore
except Exception:  # pragma: no cover
    def _fallback_logger(name: str):
        if frappe is not None:
            return frappe.logger(name)
        import logging
        logger = logging.getLogger(name)
        if not logger.handlers:
            logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.INFO)
        return logger

    LOG = _fallback_logger("brv_license_app.license_client")

    def _mask_token(tok: Optional[str], *, keep: int = 6) -> str:
        if not tok:
            return "<none>"
        t = str(tok)
        if len(t) <= keep:
            return "*" * len(t)
        return t[:keep] + "…" + ("*" * max(0, len(t) - keep - 1))

    def _compact(obj: Any, limit: int = 1200) -> str:
        try:
            s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            s = str(obj)
        return s if len(s) <= limit else s[:limit] + "…(truncated)"

__all__ = [
    "LMFWCClient",
    "LMFWCError",
    "LMFWCConfigError",
    "LMFWCRequestError",
    "LMFWCContractError",
]


# -------------------------
# Exceptions
# -------------------------
class LMFWCError(Exception):
    """Base exception for LMFWC client."""


class LMFWCConfigError(LMFWCError):
    """Raised when configuration is missing or invalid."""


class LMFWCRequestError(LMFWCError):
    """Raised on HTTP-level or transport-level failures."""

    def __init__(self, message: str, status: Optional[int] = None, payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.status = status
        self.payload = payload or {}


class LMFWCContractError(LMFWCError):
    """Raised when response body reports an error even with HTTP 200."""

    def __init__(self, message: str, status: Optional[int] = None, payload: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.status = status
        self.payload = payload or {}


# -------------------------
# Helpers
# -------------------------
_LICENSE_RE = re.compile(r"^[A-Z0-9\-]{10,}$")
_TOKEN_RE = re.compile(r"^[A-Fa-f0-9]{16,128}$")


def _get_site_config() -> Dict[str, Any]:
    """Load LMFWC config from Frappe site_config.

    Falls back to environment variables if frappe is unavailable (useful for tests).
    """
    cfg: Dict[str, Any] = {}
    if frappe is not None:
        try:
            cfg = frappe.get_site_config()  # type: ignore[attr-defined]
        except Exception as e:  # pragma: no cover
            LOG.error(f"site_config read failed: {e}")
            raise LMFWCConfigError(f"Failed to read site_config: {e}")
    else:  # pragma: no cover
        import os
        LOG.info("_get_site_config: running outside Frappe; reading from environment")
        cfg = {
            "lmfwc_base_url": os.getenv("LMFWC_BASE_URL"),
            "lmfwc_consumer_key": os.getenv("LMFWC_CONSUMER_KEY"),
            "lmfwc_consumer_secret": os.getenv("LMFWC_CONSUMER_SECRET"),
            "lmfwc_allow_insecure_http": int(os.getenv("LMFWC_ALLOW_INSECURE_HTTP", "0")),
        }

    base = cfg.get("lmfwc_base_url")
    ck = cfg.get("lmfwc_consumer_key")
    cs = cfg.get("lmfwc_consumer_secret")
    if not base or not ck or not cs:
        LOG.error("_get_site_config: missing base/ck/cs in site_config")
        raise LMFWCConfigError(
            "Missing lmfwc_base_url / lmfwc_consumer_key / lmfwc_consumer_secret in site_config.json"
        )

    allow_insecure = bool(int(cfg.get("lmfwc_allow_insecure_http", 0)))
    resolved = {
        "base": str(base).rstrip("/"),
        "ck": ck,
        "cs": cs,
        "verify": not allow_insecure,
    }
    LOG.info(f"_get_site_config: base={resolved['base']!r} verify_tls={resolved['verify']}")
    return resolved


def _frappe_cache_setnx(key: str, ttl_seconds: int) -> bool:
    """Set a short-lived lock key in frappe.cache; return True if acquired.

    Prevents accidental double-clicks / duplicate activate calls within a small window.
    If frappe is unavailable, acts as a no-op and returns True.
    """
    if frappe is None:  # pragma: no cover
        LOG.info(f"cache_setnx(no-frappe): key={key!r} → True")
        return True
    try:
        cache = frappe.cache()  # type: ignore[attr-defined]
        with cache.pipeline() as p:  # type: ignore[attr-defined]
            p.setnx(key, int(time.time()))
            p.expire(key, ttl_seconds)
            res = p.execute()
        acquired = bool(res and res[0] == 1)
        LOG.info(f"cache_setnx: key={key!r} ttl={ttl_seconds}s acquired={acquired}")
        return acquired
    except Exception as e:  # pragma: no cover
        LOG.warning(f"cache_setnx: pipeline failed ({e}); failing open")
        return True  # fail-open to not block legitimate calls


# -------------------------
# Client
# -------------------------
@dataclass
class LMFWCClient:
    base_url: str | None = None
    consumer_key: str | None = None
    consumer_secret: str | None = None
    verify_tls: bool | None = None
    timeout_seconds: int = 15
    user_agent: str = "BRVLicenseApp/1.0 (+helpdeskai.com)"
    retry_count: int = 2  # only for transient errors (5xx, timeouts)
    retry_backoff_seconds: float = 0.6

    def __post_init__(self) -> None:
        if not self.base_url or not self.consumer_key or not self.consumer_secret or self.verify_tls is None:
            cfg = _get_site_config()
            self.base_url = self.base_url or cfg["base"]
            self.consumer_key = self.consumer_key or cfg["ck"]
            self.consumer_secret = self.consumer_secret or cfg["cs"]
            self.verify_tls = self.verify_tls if self.verify_tls is not None else cfg["verify"]

        # Final validations
        assert isinstance(self.base_url, str) and self.base_url.startswith("http"), "Invalid base_url"
        assert isinstance(self.consumer_key, str) and self.consumer_key, "Invalid consumer_key"
        assert isinstance(self.consumer_secret, str) and self.consumer_secret, "Invalid consumer_secret"

        LOG.info(
            f"LMFWCClient.init: base_url={self.base_url!r} verify_tls={self.verify_tls} timeout={self.timeout_seconds}s UA={self.user_agent!r}"
        )

    # ---------------------
    # Public API
    # ---------------------
    def activate(self, license_key: str, token: Optional[str] = None, *, idempotent_window_s: int = 8) -> Dict[str, Any]:
        self._validate_license_key(license_key)
        if token is not None:
            self._validate_token(token)

        tokfrag = (token or "none")[:16]
        lock_key = f"brv_license_app:activate_lock:v2:activate:{license_key}:{tokfrag}"
        LOG.info(f"activate: lk={license_key!r} token={_mask_token(token)} lock={lock_key!r}")
        if not _frappe_cache_setnx(lock_key, idempotent_window_s):
            LOG.error("activate: idempotency guard hit")
            raise LMFWCRequestError("Duplicate activate blocked by idempotency guard", status=409)

        path = f"/wp-json/lmfwc/v2/licenses/activate/{license_key}"
        params = {"token": token.strip()} if token else None
        resp = self._get(path, params=params)
        LOG.info(f"activate: response={_compact(resp)}")
        return resp

    def reactivate(self, license_key: str, token: str, *, idempotent_window_s: int = 8) -> Dict[str, Any]:
        LOG.info(f"reactivate: lk={license_key!r} token={_mask_token(token)}")
        return self.activate(license_key, token=token, idempotent_window_s=idempotent_window_s)

    def deactivate(self, license_key: str, token: Optional[str] = None) -> Dict[str, Any]:
        self._validate_license_key(license_key)
        if token is not None:
            self._validate_token(token)
        LOG.info(f"deactivate: lk={license_key!r} token={_mask_token(token)}")

        path = f"/wp-json/lmfwc/v2/licenses/deactivate/{license_key}"
        params = {"token": token.strip()} if token else None
        resp = self._get(path, params=params)
        LOG.info(f"deactivate: response={_compact(resp)}")
        return resp

    def validate(self, license_key: str) -> Dict[str, Any]:
        self._validate_license_key(license_key)
        LOG.info(f"validate: lk={license_key!r}")
        path = f"/wp-json/lmfwc/v2/licenses/validate/{license_key}"
        resp = self._get(path)
        LOG.info(f"validate: response={_compact(resp)}")
        return resp

    # ---------------------
    # Internals
    # ---------------------
    def _validate_license_key(self, license_key: str) -> None:
        if not isinstance(license_key, str) or not license_key:
            LOG.error("validate_license_key: empty or non-str")
            raise LMFWCConfigError("license_key must be a non-empty string")
        if not _LICENSE_RE.match(license_key):
            LOG.error(f"validate_license_key: invalid format lk={license_key!r}")
            raise LMFWCConfigError("license_key format looks invalid (expect A–Z, 0–9 and dashes)")

    def _validate_token(self, token: str) -> None:
        if not isinstance(token, str) or not token:
            LOG.error("validate_token: token is empty/non-str")
            raise LMFWCConfigError("token must be a non-empty string")
        if not _TOKEN_RE.match(token):
            LOG.error(f"validate_token: invalid token format token={_mask_token(token)}")
            raise LMFWCConfigError("token format looks invalid (expect hex-like string)")

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }


    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        auth = HTTPBasicAuth(self.consumer_key or "", self.consumer_secret or "")
        LOG.info(f"HTTP GET {url} params={_compact(params)} verify_tls={self.verify_tls} timeout={self.timeout_seconds}")

        attempt = 0
        last_exc: Optional[Exception] = None
        while attempt <= self.retry_count:
            try:
                # cache-busting
                if params is None:
                    params = {}
                params["_"] = str(int(time.time() * 1000))
                resp = requests.get(
                    url,
                    headers=self._headers(),
                    params=params,
                    auth=auth,
                    timeout=self.timeout_seconds,
                    verify=self.verify_tls,
                )
                LOG.info(f"HTTP {resp.status_code} {url}")
                return self._handle_response(resp)
            except (requests.Timeout, requests.ConnectionError) as e:
                last_exc = e
                LOG.warning(f"network error on GET {url} attempt={attempt}/{self.retry_count}: {e}")
                if attempt == self.retry_count:
                    raise LMFWCRequestError(f"Network error: {e}") from e
                time.sleep(self.retry_backoff_seconds * (2 ** attempt))
                attempt += 1
            except LMFWCRequestError:
                LOG.error(f"_get: LMFWCRequestError on {url}")
                raise
            except LMFWCContractError:
                LOG.error(f"_get: LMFWCContractError on {url}")
                raise

        raise LMFWCRequestError(f"Unreachable after retries: {last_exc}")

    def _handle_response(self, resp: requests.Response) -> Dict[str, Any]:
        status = resp.status_code
        content_type = resp.headers.get("Content-Type", "")
        text = resp.text or ""
        LOG.info(f"handle_response: status={status} content_type={content_type!r}")

        # HTTP layer errors first
        if status >= 400:
            payload: Dict[str, Any] = {}
            try:
                payload = resp.json() if "json" in content_type else {"raw": text}
            except Exception:
                payload = {"raw": text}
            message = self._extract_http_error_message(payload) or f"HTTP {status}"
            LOG.error(f"http_error: status={status} message={message} payload={_compact(payload)}")
            raise LMFWCRequestError(message, status=status, payload=payload)

        # Now attempt to parse success (or 200-with-error-body) payload
        try:
            body = resp.json()
        except Exception as e:  # Non-JSON on 200 is unexpected
            LOG.error(f"invalid_json: {e}; raw={_compact(text)}")
            raise LMFWCContractError(f"Invalid JSON response: {e}", status=status, payload={"raw": text})

        # Pattern A: canonical success flag present
        if isinstance(body, dict) and "data" in body:
            data = body.get("data")
            # Some servers return success:true but embed errors in data
            if isinstance(data, dict) and ("errors" in data or "error_data" in data):
                err_dict = data.get("errors") or {}
                ed = data.get("error_data") or {}
                code, err_msg, err_status = self._extract_embedded_error(err_dict, ed)
                msg = err_msg or "Operation failed"
                LOG.error(f"contract_error: code={code} status={err_status} msg={msg} body={_compact(body)}")
                raise LMFWCContractError(msg, status=err_status, payload=body)
            return body  # happy path

        # Pattern B: some validate endpoints may return a shortened object; still pass through
        LOG.info(f"handle_response: non-wrapper body={_compact(body)}")
        return body

    @staticmethod
    def _extract_http_error_message(payload: Dict[str, Any]) -> Optional[str]:
        # Typical WP error: {"code": "...", "message": "...", "data": {"status": 404}}
        if not isinstance(payload, dict):
            return None
        if payload.get("message"):
            return str(payload.get("message"))
        # Fallback to first error string inside nested structures
        try:
            return next(
                iter(
                    s
                    for v in payload.values()
                    for s in (v if isinstance(v, (list, tuple)) else [])
                    if isinstance(s, str)
                )
            )
        except Exception:
            return None

    @staticmethod
    def _extract_embedded_error(errs: Dict[str, Any], err_data: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[int]]:
        code = next(iter(errs.keys()), "lmfwc_error") if isinstance(errs, dict) else "lmfwc_error"
        # Value could be list[str]
        val = errs.get(code) if isinstance(errs, dict) else None
        msg = None
        if isinstance(val, list) and val:
            msg = str(val[0])
        status = None
        if isinstance(err_data, dict):
            ed = err_data.get(code)
            if isinstance(ed, dict) and "status" in ed:
                try:
                    status = int(ed.get("status"))
                except Exception:
                    status = None
        return code, msg, status


# Optional: convenience function for whitelisted usage

def get_client() -> LMFWCClient:
    """Factory to obtain a configured client. May be used in whitelisted methods."""
    return LMFWCClient()
