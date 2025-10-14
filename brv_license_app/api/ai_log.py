from __future__ import annotations
from typing import Any, Dict, List
import frappe
from frappe.utils import now_datetime, cint, cstr
import json


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _safe_get_ticket_subject(ticket: str | None) -> str:
    """HD Ticket başlığını güvenli biçimde al (yoksa boş döner)."""
    if not ticket:
        return ""
    try:
        return (frappe.db.get_value("HD Ticket", ticket, "subject") or "").strip()
    except Exception:
        return ""


def _summarize_updates(request: Dict[str, Any] | None, result: Dict[str, Any] | None) -> str:
    """Güncellenen alanları kısa özet olarak üret (subject’e eklenecek)."""
    keys: List[str] = []
    try:
        if isinstance(request, dict):
            keys.extend([k for k in request.keys()])
        if isinstance(result, dict):
            for k in ("changed", "preview"):  # preview artık yazılmıyor ama konu özeti için korunur
                if isinstance(result.get(k), dict):
                    keys.extend(list(result[k].keys()))
    except Exception:
        pass
    keys = sorted(set(keys))
    if not keys:
        return ""
    if len(keys) > 4:
        return f"fields: {', '.join(keys[:4])}…"
    return f"fields: {', '.join(keys)}"


def _compose_subject(*, ticket: str | int, action: str, request: Dict[str, Any] | None, result: Dict[str, Any] | None) -> str:
    """Anlamlı ve tutarlı subject oluşturur. (status/source/preview kaldırıldı)"""
    tnum = cstr(ticket).strip()
    ticket_subject = _safe_get_ticket_subject(tnum)
    parts: List[str] = []

    # İşlem + Ticket No
    parts.append(f"{action} — T#{tnum}")

    # İsteğe bağlı ticket başlığı
    if ticket_subject:
        parts.append(f"— {ticket_subject}")

    # Güncellenen alanlar özeti
    upd = _summarize_updates(request, result)
    if upd:
        parts.append(f"({upd})")

    subject = " ".join([p for p in parts if p]).strip() or f"{action} — {tnum}"
    return subject[:140]


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

def write_model_io(
    ticket: str | int,
    *,
    model: str | None = None,
    action: str = "model_infer",
    request: Dict[str, Any] | None = None,
    response: Dict[str, Any] | None = None,
    error_message: str | None = None,
    subject: str | None = None,
):
    """LLM/AI çağrılarının giriş/çıkışlarını loglamak için sade yardımcı.
    Subject default: "model_infer — <model>".
    """
    subj = (subject or "").strip() or (f"{action} — {model}" if model else action)
    return write(
        ticket=ticket,
        action=action,
        request=request,
        response=response,
        error_message=error_message,
        subject=subj,
    )

def write(
    ticket: str | int,
    action: str = "ai_interaction",
    *,
    request: Dict[str, Any] | None = None,
    response: Dict[str, Any] | None = None,
    error_message: str | None = None,
    subject: str | None = None,
    event_timestamp=None,
    **_ignore,
):
    """
    AI Interaction Log yazımı (json modeline uyumlu):
      DocType alanları: subject, ticket (Int), event_timestamp (Datetime),
                        request (Text), response (Text), error_message (Text)
    Eski parametreler (status/source/preview/direction/meta/user/ip) kaldırıldı.
    """
    try:
        doc = frappe.new_doc("AI Interaction Log")
        doc.ticket = cint(ticket) if str(ticket).isdigit() else ticket  # Int veya name

        # Subject — verilen değeri kullan; yoksa akıllı oluşturucu
        doc.subject = (subject or "").strip() or _compose_subject(
            ticket=doc.ticket, action=action, request=request, result=response
        )

        # Timestamp (always set by server)
        doc.event_timestamp = event_timestamp or now_datetime()

        # JSON'ları metin alanlarına serileştir
        try:
            doc.request = json.dumps(request or {}, ensure_ascii=False, indent=2, sort_keys=True)
        except Exception:
            doc.request = cstr(request or "")
        try:
            doc.response = json.dumps(response or {}, ensure_ascii=False, indent=2, sort_keys=True)
        except Exception:
            doc.response = cstr(response or "")

        if error_message:
            doc.error_message = cstr(error_message)

        doc.insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception as e:
        frappe.log_error(f"ai_log.write: {e}", "HelpdeskAI")