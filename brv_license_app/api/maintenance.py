from __future__ import annotations
from typing import Iterable, List, Dict, Any
import frappe


def _ensure_system_manager() -> None:
    """Allow only System Manager or Administrator to run destructive ops."""
    user = frappe.session.user if getattr(frappe, "session", None) else None
    if user in {"Administrator"}:
        return
    roles = set(frappe.get_roles(user)) if user else set()
    if "System Manager" not in roles:
        frappe.throw("Not permitted. System Manager required.", frappe.PermissionError)


def _delete_all(doctype: str, filters: Dict[str, Any]) -> int:
    """Delete all documents of a doctype matching filters; ignore permissions and missing.
    Returns number of deletions attempted.
    """
    names = frappe.get_all(doctype, filters=filters, pluck="name")
    for name in names:
        try:
            frappe.delete_doc(doctype, name, ignore_permissions=True, ignore_missing=True, force=True)
        except Exception:
            # Swallow and continue; we'll still try to delete the ticket later
            frappe.log_error(title=f"Force delete linked {doctype} failed", message=frappe.get_traceback())
    return len(names)


def force_delete_hd_tickets(names: Iterable[str]) -> Dict[str, Any]:
    """
    Force delete HD Tickets and common linked records (Communication, File, Comments, Activity).

    This is a maintenance utility to recover from bulk delete failures due to link constraints.
    Use with caution. Only System Manager can run it.

    Args:
        names: Iterable of ticket names (e.g., ["1", "2"]).

    Returns:
        Dict with per-ticket results and counts of deleted linked records.
    """
    _ensure_system_manager()

    if isinstance(names, (str, bytes)):
        # Support comma-separated input
        names = [n.strip() for n in str(names).split(",") if n.strip()]

    out: Dict[str, Any] = {"results": []}

    for ticket in names:  # type: ignore[assignment]
        res = {"ticket": ticket, "linked_deleted": {}, "status": "ok"}
        try:
            # Linked docs commonly blocking deletion
            res["linked_deleted"]["HD Ticket Comment"] = _delete_all("HD Ticket Comment", {"reference_ticket": ticket})
            res["linked_deleted"]["Communication"] = _delete_all("Communication", {"reference_doctype": "HD Ticket", "reference_name": ticket})
            res["linked_deleted"]["File"] = _delete_all("File", {"attached_to_doctype": "HD Ticket", "attached_to_name": ticket})
            res["linked_deleted"]["Activity Log"] = _delete_all("Activity Log", {"reference_doctype": "HD Ticket", "reference_name": ticket})
            # Version keeps history; safe to remove for cleanup
            res["linked_deleted"]["Version"] = _delete_all("Version", {"ref_doctype": "HD Ticket", "docname": ticket})

            # Finally delete the ticket itself
            try:
                frappe.delete_doc("HD Ticket", ticket, ignore_permissions=True, ignore_missing=True, force=True)
            except Exception:
                res["status"] = "failed"
                res["error"] = frappe.get_traceback()
        except Exception:
            res["status"] = "failed"
            res["error"] = frappe.get_traceback()
        out["results"].append(res)

    return out
