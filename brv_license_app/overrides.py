from __future__ import annotations
import json
import frappe
from frappe import local

# Sunucu tarafı gatekeeper: lisans durumuna göre erişimi sınırla / logout
BLOCK_STATUSES = {"REVOKED", "LOCK_HARD"}


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
        # 1) savedocs + run_doc_method JSON gövdeleri
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
        # 2) run_doc_method parametreleri (dt/dn)
        if (fd.get("dt") == "License Settings") or (fd.get("doctype") == "License Settings"):
            return True
    except Exception:
        pass
    return False


def _is_license_settings_access() -> bool:
    """License Settings sayfasına veya API'lerine erişim mi?"""
    path = frappe.request.path if getattr(frappe, "request", None) else ""
    
    # License Settings sayfasına doğrudan erişim
    if path and any(license_path in path for license_path in [
        "/app/license-settings", 
        "/api/method/frappe.desk.form.load.getdoc",
        "/api/method/frappe.desk.form.save.savedocs",
        "/api/method/run_doc_method"
    ]):
        # Doctype kontrolü yap
        if _is_license_settings_write_intent():
            return True
        
        # Form yükleme isteklerini kontrol et
        fd = getattr(frappe, "form_dict", {}) or {}
        if fd.get("doctype") == "License Settings" or fd.get("dt") == "License Settings":
            return True
            
    return False


def _has_system_manager_role() -> bool:
    """Kullanıcı System Manager rolüne sahip mi?"""
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

    # Statik dosyalar vb. erken çıkış
    if _is_allowlisted(path):
        return

    # System Manager kullanıcıları License Settings'e her zaman erişebilir
    if _has_system_manager_role() and _is_license_settings_access():
        return

    status, grace_until, reason = _fetch_status()

    # Lisans kaydı yoksa veya durum boşsa: serbest bırak (kurulum aşaması)
    if not status:
        return

    status = status.upper()

    # Sert engel durumları
    if status in BLOCK_STATUSES:
        frappe.throw("Lisans kısıtlı (REVOKED/LOCK_HARD). Lütfen yöneticinizle görüşün.", frappe.PermissionError)

    # Süresi geçmiş ve grace bitmişse engelle + logout
    if status == "EXPIRED" and _is_grace_over(grace_until):
        try:
            if getattr(local, "login_manager", None):
                local.login_manager.logout()
        except Exception:
            pass
        frappe.throw("Lisans süresi doldu ve esneklik süresi bitti. Giriş yapamazsınız.", frappe.PermissionError)

    # DEACTIVATED ise genel yazma işlemlerini engelle; ancak License Settings'e istisna tanı
    if status == "DEACTIVATED":
        method = (frappe.request.method or "").upper() if getattr(frappe, "request", None) else ""
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            if _is_license_settings_write_intent():
                # License Settings'i yönetebilmek için bu yazma talebine izin ver
                return
            frappe.throw("Lisans pasif. Yazma işlemlerine izin verilmiyor.", frappe.PermissionError)


# ---- Boot Session Hook ----

def boot_session(bootinfo):
    """Session boot sırasında istemciye lisans özetini ekler."""
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
        payload = {
            "status": None,
            "grace_until": None,
            "reason": None,
            "last_validated": None,
        }

    try:
        # bootinfo objesi attr/dict olabilir; her iki yolu da destekleyelim
        if isinstance(bootinfo, dict):
            bootinfo["brv_license"] = payload
        else:
            setattr(bootinfo, "brv_license", payload)
    except Exception:
        # boot sürecini asla bozma
        pass