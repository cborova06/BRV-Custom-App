from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
import json

import frappe
from frappe.model.document import Document
from frappe.utils import now_datetime, get_datetime
import re

from brv_license_app.license_client import (
    get_client,
    LMFWCContractError,
    LMFWCRequestError,
)
from brv_license_app.utils.logging import (
    license_logger as LOG,
    mask_token,
    compact_json,
)

STATUS_UNCONFIGURED = "UNCONFIGURED"
STATUS_ACTIVE = "ACTIVE"
STATUS_VALIDATED = "VALIDATED"
STATUS_DEACTIVATED = "DEACTIVATED"
STATUS_EXPIRED = "EXPIRED"
STATUS_REVOKED = "REVOKED"
STATUS_GRACE_SOFT = "GRACE_SOFT"
STATUS_LOCK_HARD = "LOCK_HARD"

class LicenseSettings(Document):
    """Server-side controller for Single DocType."""
    pass

# NOTE: escape '-' inside the character class to avoid bad range like ':'-"\s"
_EXP_RE = re.compile(r"expired on\s+([\d:\-\s]+)\s*\(UTC\)", re.I)

def _parse_expiry_from_msg(msg: str):
    try:
        m = _EXP_RE.search(msg or "")
        if not m:
            return None
        return get_datetime(m.group(1).strip())
    except Exception:
        return None

# -----------------------------
# Whitelisted API
# -----------------------------

@frappe.whitelist()
def activate_license(license_key: Optional[str] = None, token: Optional[str] = None) -> Dict[str, Any]:
    """Licensi aktif et. Expired hatası gelirse dokümanı EXPIRED olarak işaretler ve expires_at'ı doldurur."""
    doc = frappe.get_single("License Settings")
    lk = (license_key or getattr(doc, "license_key", "") or "").strip()
    LOG.info(f"activate_license: start lk={lk!r} token={mask_token(token)}")
    if not lk:
        frappe.throw("License Key is required in settings or as parameter.")

    client = get_client()

    try:
        resp = client.activate(lk, token=token)
        LOG.info(f"activate_license: response={compact_json(resp)}")
        _write_last_raw(doc, resp)
        payload = _extract_data(resp)
        _apply_activation_update(doc, payload)
        changed = _maybe_update_token_from_payload(doc, resp)
        LOG.info(
            f"activate_license: token_changed={changed} current_token={mask_token(getattr(doc,'activation_token',None))}"
        )
        doc.save(ignore_permissions=True)
        return payload

    except (LMFWCRequestError, LMFWCContractError) as e:
        # ---- Hata detayını topla (expired mi?) ----
        expired = False
        err_code = None
        err_status = None
        msg = str(e) or ""

        # payload içindeki canonical yapı: {"success":true,"data":{"errors":{code:[...]},"error_data":{code:{"status":..}}}
        try:
            data = (getattr(e, "payload", {}) or {}).get("data") or {}
            errs = data.get("errors") or {}
            if isinstance(errs, dict):
                err_code = next(iter(errs.keys()), None)
                if "lmfwc_rest_license_expired" in errs:
                    expired = True
            ed = data.get("error_data") or {}
            if isinstance(ed, dict) and err_code in ed and isinstance(ed[err_code], dict):
                err_status = ed[err_code].get("status")
        except Exception:
            pass

        if "expire" in msg.lower():
            expired = True

        if expired:
            # Mesajdan UTC tarihi yakalamaya çalış (örn: "... expired on 2025-10-10 00:00:00 (UTC)")
            try:
                dt = _parse_expiry_from_msg(msg)
                if dt:
                    doc.expires_at = dt
            except Exception:
                pass

            doc.status = STATUS_EXPIRED
            doc.reason = msg or "License expired"
            if not getattr(doc, "grace_until", None):
                doc.grace_until = now_datetime()
            doc.last_validated = now_datetime()

            # son hatayı debug için sakla (opsiyonel)
            try:
                doc.set(
                    "last_error_raw",
                    json.dumps(
                        {"ts": str(now_datetime()), "code": err_code, "status": err_status, "message": msg},
                        ensure_ascii=False,
                    ),
                )
            except Exception:
                pass

            doc.save(ignore_permissions=True)
            frappe.throw("License is expired. Please renew your license.")

        # expired değilse genel hata akışı
        LOG.error(f"{frappe.get_traceback()}\nAPI error: {e}")
        try:
            frappe.log_error(title="license_api_error", message=str(e))
        except Exception:
            pass
        frappe.throw("Operation failed. See Error Log for details.")

    except Exception as e:
        LOG.exception(f"activate_license: unexpected error: {e}")
        try:
            frappe.log_error(title="license_unexpected_error", message=frappe.get_traceback())
        except Exception:
            pass
        frappe.throw("Operation failed due to unexpected error. See logs for details.")



@frappe.whitelist()
def reactivate_license(token: Optional[str] = None, license_key: Optional[str] = None) -> Dict[str, Any]:
    """Reactivate with the freshest token: preflight VALIDATE then ACTIVATE(token).
    Burada, `activate_license` yerine doğrudan client.activate çağrılır ki
    LMFWCContractError (özellikle "maximum activation") yakalanıp retry yapılabilsin.
    """
    doc = frappe.get_single("License Settings")
    lk = (license_key or getattr(doc, "license_key", "") or "").strip()
    LOG.info(
        f"reactivate_license: start lk={lk!r} incoming_token={mask_token(token)} saved_token={mask_token(getattr(doc,'activation_token',None))}"
    )
    if not lk:
        frappe.throw("License Key is required in settings or as parameter.")

    # Preflight: token tazele
    _preflight_refresh_token(doc, lk)

    # Efektif token: önce preflight'tan gelen; sonra kullanıcıdan gelen
    eff_token = (getattr(doc, "activation_token", "") or "").strip() or (token or "").strip()
    LOG.info(f"reactivate_license: effective_token={mask_token(eff_token)}")
    if not eff_token:
        frappe.throw("Activation token is required (not found in settings or validation response).")

    client = get_client()

    # İlk deneme
    try:
        return _activate_via_client(doc, lk, eff_token, client)
    except LMFWCContractError as e:
        msg = str(e)
        if _is_expired_error(msg):
            _mark_expired(doc, msg)
            doc.save(ignore_permissions=True)
            LOG.warning(f"reactivate_license: expired → status set EXPIRED. msg={msg}")
            frappe.throw("License is expired. Please renew your license.")
        LOG.warning(f"reactivate_license: first attempt failed with: {msg}")
        # Aktivasyon limitine takıldıysak: preflight + yeni token ile bir kez daha dene
        if ("Activation limit" in msg) or ("maximum activation" in msg):
            _preflight_refresh_token(doc, lk)
            eff_token2 = (getattr(doc, "activation_token", "") or "").strip() or eff_token
            if eff_token2 and eff_token2 != eff_token:
                LOG.info(f"reactivate_license: retry with token={mask_token(eff_token2)}")
                try:
                    return _activate_via_client(doc, lk, eff_token2, client)
                except LMFWCRequestError as re:
                    if "idempotency guard" in str(re).lower():
                        LOG.warning("reactivate_license: idempotency guard hit on retry; advise user to retry shortly")
                        frappe.throw("Another activation attempt is still settling. Please retry in a few seconds.")
                    raise
            LOG.info("reactivate_license: retry skipped (no fresh token from preflight)")
            frappe.throw("Activation limit reached on the server and no fresh token was issued. Please deactivate an existing activation or increase the limit.")
        # Diğer sözleşme hatalarında üst katmana aynı şekilde iletme yerine
        # kullanıcıya genel hata sunulur
        LOG.error(f"reactivate_license: non-retryable contract error: {e}")
        frappe.throw("Operation failed. See Error Log for details.")

@frappe.whitelist()
def deactivate_license(token: Optional[str] = None, license_key: Optional[str] = None) -> Dict[str, Any]:
    doc = frappe.get_single("License Settings")
    lk = (license_key or getattr(doc, "license_key", "") or "").strip()
    LOG.info(
        f"deactivate_license: start lk={lk!r} incoming_token={mask_token(token)} saved_token={mask_token(getattr(doc,'activation_token',None))}"
    )
    if not lk:
        frappe.throw("License Key is required in settings or as parameter.")

    tok = (token or "").strip()
    if not tok:
        _preflight_refresh_token(doc, lk)
        tok = (getattr(doc, "activation_token", "") or "").strip() or None
        LOG.info(f"deactivate_license: token after preflight={mask_token(tok)} (None means bulk)")

    client = get_client()
    try:
        resp = client.deactivate(lk, token=tok or None)
        LOG.info(f"deactivate_license: response={compact_json(resp)}")
        _write_last_raw(doc, resp)
        payload = _extract_data(resp)
        _apply_deactivation_update(doc, payload)
        doc.status = STATUS_LOCK_HARD
        doc.reason = "License deactivated"
        doc.grace_until = now_datetime()

        # ekle:
        # 1) mümkünse token'ı temizle – artık bu cihaz için geçersiz
        if getattr(doc, "activation_token", None):
            doc.activation_token = ""

        # 2) sunucu durumunu senkron görmek için hemen validate çağır (best-effort)
        try:
            v = client.validate(lk)
            LOG.info(f"deactivate_license: post-validate response={compact_json(v)}")
            _write_last_raw(doc, v)
            # burada yalnız counters/expiry güncellenir; UI zaten LOCK_HARD gösterecek
            payload2 = _extract_data(v)
            _apply_validation_update(doc, payload2)
        except Exception as _e:
            LOG.warning(f"deactivate_license: post-validate skipped due to: {_e}")
        # Policy: set hard lock immediately
        doc.status = STATUS_LOCK_HARD
        doc.reason = "License deactivated"
        doc.grace_until = now_datetime()
        doc.save(ignore_permissions=True)
        return payload
    except (LMFWCRequestError, LMFWCContractError) as e:
        LOG.error(f"{frappe.get_traceback()}\nAPI error: {e}")
        doc.status = STATUS_LOCK_HARD
        doc.reason = f"Deactivate failed: {e}"
        doc.grace_until = now_datetime()
        doc.save(ignore_permissions=True)
        frappe.throw("Operation failed. See log file or Error Log for details.")
    except Exception as e:
        LOG.exception(f"deactivate_license: unexpected error: {e}")
        doc.status = STATUS_LOCK_HARD
        doc.reason = f"Deactivate unexpected error: {e}"
        doc.grace_until = now_datetime()
        doc.save(ignore_permissions=True)
        frappe.throw(str(e))

@frappe.whitelist()
def validate_license(license_key: Optional[str] = None) -> Dict[str, Any]:
    """Licensi doğrula. Eğer doküman zaten EXPIRED ise uzaktan çağrı yapmadan EXPIRED’ı korur."""
    doc = frappe.get_single("License Settings")
    lk = (license_key or getattr(doc, "license_key", "") or "").strip()
    LOG.info(f"validate_license: start lk={lk!r}")
    if not lk:
        frappe.throw("License Key is required in settings or as parameter.")

    # --- Zaten EXPIRED ise validate ile yeşile dönmesin (erken çıkış) ---
    if getattr(doc, "status", None) == STATUS_EXPIRED:
        doc.last_validated = now_datetime()
        doc.save(ignore_permissions=True)
        LOG.info("validate_license: short-circuit (kept EXPIRED)")
        return {
            "status": STATUS_EXPIRED,
            "reason": getattr(doc, "reason", None),
            "expiresAt": getattr(doc, "expires_at", None),
            "grace_until": getattr(doc, "grace_until", None),
        }

    client = get_client()

    try:
        resp = client.validate(lk)
        LOG.info(f"validate_license: response={compact_json(resp)}")
        _write_last_raw(doc, resp)
        payload = _extract_data(resp)

        # `_apply_validation_update` içinde:
        # - expires_at geçmişse EXPIRED’a çevir ve döndür
        # - yoksa VALIDATED/DEACTIVATED akışı uygulanır
        _apply_validation_update(doc, payload)

        changed = _maybe_update_token_from_payload(doc, resp)
        LOG.info(
            f"validate_license: token_changed={changed} current_token={mask_token(getattr(doc,'activation_token',None))}"
        )
        doc.save(ignore_permissions=True)
        return payload

    except (LMFWCRequestError, LMFWCContractError) as e:
        LOG.error(f"{frappe.get_traceback()}\nAPI error: {e}")
        _apply_grace_on_failure(doc, reason=str(e))
        doc.save(ignore_permissions=True)
        frappe.throw("Operation failed. See Error Log for details.")

    except Exception as e:
        LOG.exception(f"validate_license: unexpected error: {e}")
        _apply_grace_on_failure(doc, reason=f"Unexpected error: {e}")
        doc.save(ignore_permissions=True)
        frappe.throw(str(e))

# -----------------------------
# Internal helpers
# -----------------------------
def _is_expired_error(msg: str) -> bool:
    return "expired" in (msg or "").lower()

def _mark_expired(doc: Document, reason: str) -> None:
    doc.status = STATUS_EXPIRED
    doc.reason = reason or "License expired"
    doc.grace_until = now_datetime()

def _set_if_exists(doc: Document, fieldname: str, value: Any) -> None:
    try:
        if doc.meta.get_field(fieldname):
            doc.set(fieldname, value)
    except Exception:
        pass

def _write_last_raw(doc: Document, resp: Dict[str, Any]) -> None:
    try:
        _set_if_exists(doc, "last_response_raw", json.dumps(resp, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        pass

def _extract_data(resp: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(resp, dict) and "data" in resp and isinstance(resp["data"], (dict, list)):
        return resp["data"]
    return resp

# İç aktivasyon yürütücüsü: reactivate_license için, LMFWCContractError'ı üst seviyeye iletir
# ki retry/policy uygulanabilsin. activate_license ile aynı yan etkileri üretir.
def _activate_via_client(doc: Document, lk: str, token: Optional[str], client) -> Dict[str, Any]:
    resp = client.activate(lk, token=token)
    LOG.info(f"activate_license: response={compact_json(resp)}")
    _write_last_raw(doc, resp)
    payload = _extract_data(resp)
    _apply_activation_update(doc, payload)
    changed = _maybe_update_token_from_payload(doc, resp)
    LOG.info(
        f"activate_license: token_changed={changed} current_token={mask_token(getattr(doc,'activation_token',None))}"
    )
    doc.save(ignore_permissions=True)
    return payload

def _preflight_refresh_token(doc: Document, lk: str) -> None:
    LOG.info(f"preflight_refresh_token: validating lk={lk!r}")
    client = get_client()
    try:
        v = client.validate(lk)
        LOG.info(f"preflight_refresh_token: validate_response={compact_json(v)}")
        _write_last_raw(doc, v)
        before = (getattr(doc, "activation_token", "") or "").strip()
        changed = _maybe_update_token_from_payload(doc, v)
        after = (getattr(doc, "activation_token", "") or "").strip()
        LOG.info(
            f"preflight_refresh_token: token_changed={changed} before={mask_token(before)} after={mask_token(after)}"
        )
        if changed:
            doc.reason = "Token rotated from validate"
    except Exception as e:
        LOG.error(f"preflight_refresh_token: failed with {e}")
        # Intentionally silent for callers
        pass

def _maybe_update_token_from_payload(doc: Document, payload: Dict[str, Any]) -> bool:
    latest = _extract_latest_token(payload)
    LOG.info(
        f"maybe_update_token: latest_from_payload={mask_token(latest)} current={mask_token(getattr(doc,'activation_token',None))}"
    )
    if not latest:
        return False
    current = (getattr(doc, "activation_token", "") or "").strip()
    if latest != current:
        _set_if_exists(doc, "activation_token", latest)
        return True
    return False

def _extract_latest_token(payload: Dict[str, Any]) -> Optional[str]:
    data = payload.get("data") if isinstance(payload, dict) else payload
    activation_data = None
    if isinstance(data, dict):
        activation_data = data.get("activationData")

    if isinstance(activation_data, dict):
        tok = activation_data.get("token")
        LOG.info(f"extract_latest_token: single-object token={mask_token(tok)}")
        return str(tok).strip() if tok else None

    if not isinstance(activation_data, list) or not activation_data:
        LOG.info("extract_latest_token: no activationData list present")
        return None

    def parse_ts(s: Any) -> float:
        if not s:
            return 0.0
        try:
            return float(get_datetime(s).timestamp())
        except Exception:
            return 0.0

    def score(item: Dict[str, Any]) -> Tuple[int, float]:
        is_active = 1 if not item.get("deactivated_at") else 0
        ts = parse_ts(item.get("updated_at")) or parse_ts(item.get("created_at"))
        return (is_active, ts)

    candidates = [x for x in activation_data if isinstance(x, dict) and x.get("token")]
    LOG.info(f"extract_latest_token: candidates={len(candidates)}")
    if not candidates:
        return None

    best = max(candidates, key=score)
    tok = best.get("token")
    LOG.info(
        f"extract_latest_token: chosen_token={mask_token(tok)} active={not best.get('deactivated_at')} updated_at={best.get('updated_at')} created_at={best.get('created_at')}"
    )
    return str(tok).strip() if tok else None

def _apply_activation_update(doc: Document, data: Dict[str, Any]) -> None:
    _apply_expiry(doc, data)
    doc.status = STATUS_ACTIVE
    doc.reason = "Activated"
    doc.last_validated = now_datetime()
    _clear_grace(doc)
    LOG.info(
        f"apply_activation_update: status={doc.status} expires_at={getattr(doc,'expires_at',None)} last_validated={doc.last_validated}"
    )

def _apply_deactivation_update(doc: Document, data: Dict[str, Any]) -> None:
    _apply_expiry(doc, data)
    doc.status = STATUS_DEACTIVATED
    doc.reason = "Deactivated"
    LOG.info(f"apply_deactivation_update: status={doc.status} expires_at={getattr(doc,'expires_at',None)}")

def _apply_validation_update(doc: Document, data: Dict[str, Any]) -> None:
    _apply_expiry(doc, data)

    # 1) expires_at geçmişse EXPIRED'a çek ve burada dur
    try:
        ex = getattr(doc, "expires_at", None)
        if ex and now_datetime() > get_datetime(ex):
            doc.status = STATUS_EXPIRED
            doc.reason = doc.reason or "License expired"
            if not getattr(doc, "grace_until", None):
                doc.grace_until = now_datetime()
            doc.last_validated = now_datetime()
            LOG.info("apply_validation_update: expires_at in past → set EXPIRED (keep grace)")
            return
    except Exception:
        pass

    # 2) Zaten EXPIRED ise validate ile yeşile dönmesin
    if getattr(doc, "status", None) == STATUS_EXPIRED:
        doc.reason = doc.reason or "Expired (kept on validate)"
        doc.last_validated = now_datetime()
        LOG.info("apply_validation_update: keeping EXPIRED state during validate")
        return

    # 3) Normal akış: aktif aktivasyon var mı?
    def has_active_activation(d: Dict[str, Any]) -> bool:
        act = d.get("activationData")
        if isinstance(act, dict):
            return not act.get("deactivated_at")
        if isinstance(act, list):
            return any(isinstance(x, dict) and not x.get("deactivated_at") for x in act)
        return False

    active = has_active_activation(data) or int(data.get("timesActivated") or 0) > 0

    if active:
        doc.status = STATUS_VALIDATED
        doc.reason = "Validated"
    else:
        doc.status = STATUS_DEACTIVATED
        doc.reason = "Validated (no active activation)"

    doc.last_validated = now_datetime()
    _clear_grace(doc)
    LOG.info(
        f"apply_validation_update: status={doc.status} active={active} "
        f"expires_at={getattr(doc,'expires_at',None)} last_validated={doc.last_validated}"
    )



def _apply_expiry(doc: Document, data: Dict[str, Any]) -> None:
    expires_at = data.get("expiresAt")
    if expires_at:
        try:
            doc.expires_at = get_datetime(expires_at)
        except Exception:
            pass

def _clear_grace(doc: Document) -> None:
    doc.grace_until = None
    if doc.status in (STATUS_GRACE_SOFT, STATUS_LOCK_HARD):
        doc.status = STATUS_VALIDATED
        doc.reason = "Grace cleared after success"

def _apply_grace_on_failure(doc: Document, *, reason: str) -> None:
    now = now_datetime()
    last_ok = getattr(doc, "last_validated", None)

    SOFT_HOURS = 24
    HARD_HOURS = 48

    doc.reason = f"Grace policy engaged: {reason}"

    if not last_ok:
        doc.status = STATUS_GRACE_SOFT
        doc.grace_until = now
        LOG.warning("apply_grace_on_failure: no last_validated → GRACE_SOFT")
        return

    try:
        delta_hours = (now - get_datetime(last_ok)).total_seconds() / 3600.0
    except Exception:
        delta_hours = HARD_HOURS + 1

    if delta_hours <= SOFT_HOURS:
        doc.status = STATUS_GRACE_SOFT
    elif delta_hours >= HARD_HOURS:
        doc.status = STATUS_LOCK_HARD
    else:
        doc.status = STATUS_GRACE_SOFT

    doc.grace_until = now
    LOG.warning(
        f"apply_grace_on_failure: status={doc.status} delta_h={delta_hours:.2f} grace_until={doc.grace_until}"
    )

def get_status_banner() -> str:
    doc = frappe.get_single("License Settings")
    status = getattr(doc, "status", None) or STATUS_UNCONFIGURED
    msg = getattr(doc, "reason", None) or ""
    remain = getattr(doc, "remaining", None)
    remain_display = remain if remain is not None else "?"
    cls = {
        STATUS_VALIDATED: "indicator green",
        STATUS_ACTIVE: "indicator blue",
        STATUS_GRACE_SOFT: "indicator orange",
        STATUS_LOCK_HARD: "indicator red",
        STATUS_DEACTIVATED: "indicator gray",
    }.get(status, "indicator gray")
    return (
        f'<div class="{cls}"><b>Status:</b> {status} &nbsp; <b>Remaining:</b> {remain_display} '
        f"&nbsp; <span>{frappe.utils.escape_html(msg or '')}</span></div>"
    )

# --------------------------------------------------------------------
# Scheduled job: auto-validate license every 12 hours
# --------------------------------------------------------------------

def scheduled_auto_validate() -> None:
    LOG.info("scheduled_auto_validate: start")
    try:
        doc = frappe.get_single("License Settings")
        if not getattr(doc, "license_key", None):
            LOG.warning("scheduled_auto_validate: no license_key set; skipping")
            return
        result = validate_license(doc.license_key)
        LOG.info(f"scheduled_auto_validate: OK resp={compact_json(result)}")
    except Exception as e:
        LOG.exception(f"scheduled_auto_validate: failed: {e}")
