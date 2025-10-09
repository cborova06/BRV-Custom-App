from __future__ import annotations
import frappe
from frappe.utils import get_datetime, now_datetime

@frappe.whitelist(allow_guest=True)
def healthz():
    """Lisans sağlık kontrolü (License Settings'ten durum özetini döner)."""
    try:
        doc = frappe.get_single("License Settings")
    except Exception as e:
        frappe.log_error(f"LicenseSettings fetch failed: {e}", "brv_license_app.api.license.healthz")
        return {
            "app": "brv_license_app",
            "ok": False,
            "site": frappe.local.site,
            "error": f"LicenseSettings fetch failed: {e}",
        }

    status = (doc.status or "").upper()
    grace_until = getattr(doc, "grace_until", None)
    reason = getattr(doc, "reason", None)
    last_validated = getattr(doc, "last_validated", None)

    # Grace süresi aktif mi?
    grace_active = False
    if grace_until:
        try:
            grace_active = get_datetime(grace_until) > now_datetime()
        except Exception:
            pass

    # Lisans geçerli mi?
    ok = status in {"ACTIVE", "VALIDATED"} or (status == "EXPIRED" and grace_active)

    return {
        "app": "brv_license_app",
        "site": frappe.local.site,
        "status": status,
        "grace_until": grace_until,
        "reason": reason,
        "last_validated": last_validated,
        "ok": ok,
    }
