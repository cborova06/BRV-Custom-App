from __future__ import annotations
import json
import frappe
from frappe import local

# Sunucu tarafı gatekeeper: lisans durumuna göre erişimi sınırla / logout
BLOCK_STATUSES = {"REVOKED", "LOCK_HARD"}

SOFT_LOCK_STATUSES = {"DEACTIVATED", "GRACE_SOFT"}  # write-restricted

def _fetch_status() -> tuple[str | None, str | None, str | None]:
    """License Settings'ten status, grace_until, reason getir (yoksa None)."""
    try:
        doc = frappe.get_single("License Settings")
        return (doc.status or None, getattr(doc, "grace_until", None), getattr(doc, "reason", None))
    except Exception:
        return (None, None, None)

def _is_grace_over(grace_until: str | None) -> bool:
    if not grace_until:
        return False
    try:
        return frappe.utils.now_datetime() > frappe.utils.get_datetime(grace_until)
    except Exception:
        return False

def _is_allowlisted(path: str) -> bool:
    from .hooks import license_allowlist_paths  # runtime import
    for p in license_allowlist_paths:
        if path.startswith(p):
            return True
    return False

def _is_license_settings_write_intent() -> bool:
    """Bu istek doğrudan License Settings üzerinde yazma/işlem mi?"""
    try:
        fd = getattr(frappe, "form_dict", {}) or {}
        raw = fd.get("doc") or fd.get("docs")
        if raw:
            try:
                data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
                if isinstance(data, dict) and data.get("doctype") == "License Settings":
                    return True
                if isinstance(data, list) and any(isinstance(d, dict) and d.get("doctype") == "License Settings" for d in data):
                    return True
            except Exception:
                pass
        if (fd.get("dt") == "License Settings") or (fd.get("doctype") == "License Settings"):
            return True
    except Exception:
        pass
    return False

def _is_license_settings_access() -> bool:
    """License Settings sayfasına veya API'lerine erişim mi?"""
    path = frappe.request.path if getattr(frappe, "request", None) else ""
    if path and any(license_path in path for license_path in [
        "/app/license-settings",
        "/api/method/frappe.desk.form.load.getdoc",
        "/api/method/frappe.desk.form.save.savedocs",
        "/api/method/run_doc_method"
    ]):
        if _is_license_settings_write_intent():
            return True
        fd = getattr(frappe, "form_dict", {}) or {}
        if fd.get("doctype") == "License Settings" or fd.get("dt") == "License Settings":
            return True
    return False

def _has_system_manager_role() -> bool:
    try:
        if frappe.session.user == "Administrator":
            return True
        user_roles = frappe.get_roles(frappe.session.user)
        return "System Manager" in user_roles
    except Exception:
        return False

def enforce_request():
    """Her istek başında çağrılır (hooks.auth_hooks ile)."""
    method = (frappe.request.method or "").upper() if getattr(frappe, "request", None) else ""
    if method == "OPTIONS":
        return

    path = frappe.request.path if getattr(frappe, "request", None) else ""

    # 0) Statik dosyalar / allowlist
    if _is_allowlisted(path):
        return

    # 1) License Settings'e erişim (sayfa + API) HER ZAMAN serbest
    if path and (path.startswith("/app/license-settings") or path.startswith("/app/License%20Settings")):
        return
    if _is_license_settings_access() or _is_license_settings_write_intent():
        return

    # 2) Lisans durumunu çek
    status, grace_until, reason = _fetch_status()

    # 2.a) Kayıt yoksa serbest (kurulum aşaması)
    if not status:
        return

    status = (status or "").upper()

    # 3) Sert engel durumları
    if status in BLOCK_STATUSES:
        frappe.throw("Lisans kısıtlı (REVOKED/LOCK_HARD). Lütfen yöneticinizle görüşün.", frappe.PermissionError)

    # 4) EXPIRED: 24 saatlik tolerans penceresi boyunca serbest, sonrası engel (logout yapmadan)
    if status == "EXPIRED":
        if _is_grace_over(grace_until):
            frappe.throw("Lisans süresi doldu ve tolerans süresi bitti. Erişim kısıtlandı.", frappe.PermissionError)
        return

    # 5) Soft-lock durumları: yazma yasak, okuma serbest
    if status in SOFT_LOCK_STATUSES:
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            frappe.throw("Lisans soft-lock. Yazma işlemlerine izin verilmiyor.", frappe.PermissionError)
        return

    # Validated/Active → serbest

# ---- Boot Session Hook ----

def boot_session(bootinfo):
    """Session boot sırasında istemciye lisans özetini ekler + toolbar link override eder."""
    try:
        doc = frappe.get_single("License Settings")
        status = (doc.status or "").upper()
        payload = {
            "status": status,
            "grace_until": getattr(doc, "grace_until", None),
            "reason": getattr(doc, "reason", None),
            "last_validated": getattr(doc, "last_validated", None),
        }
    except Exception:
        payload = {"status": None, "grace_until": None, "reason": None, "last_validated": None}

    try:
        if isinstance(bootinfo, dict):
            bootinfo["brv_license"] = payload
        else:
            setattr(bootinfo, "brv_license", payload)
    except Exception:
        pass