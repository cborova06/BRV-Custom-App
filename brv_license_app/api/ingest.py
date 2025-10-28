# -*- coding: utf-8 -*-
"""
Helpdesk – Integration API (hafif, lisans kontrolü yok).
- GET uç noktaları: takımlar, takım üyeleri, biletler, makaleler, routing context
- POST/PUT uç noktaları: tek bilet alanlarını bağımsız güncelle (summary, sentiment, route, öneriler, metrikler)
- Genel "update_ticket" ile whitelist edilmiş alanlarda toplu/parsiyel güncelleme de mümkün.

NOT: Güvenlik için ileride API Key/Secret eklenecek. Şimdilik açık (allow_guest=True).
"""
from __future__ import annotations

# (1) Tipler ve yardımcılar
from typing import Any, Dict, List, Iterable
import json
import re

import frappe
from frappe.utils import cint, flt, cstr

# --- AI Interaction Log (MERKEZİ) -------------------------------------------
# Merkezi yazıcı – json modeline uyumlu versiyon
# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

def _clean_html(text: str) -> str:
    """HTML/etiket temizleme (metni bozma)."""
    if text is None:
        return ""
    try:
        # Frappe 14/15
        from frappe.utils import strip_html
        return strip_html(text)
    except Exception:
        try:
            from frappe.utils import strip_html_tags
            return strip_html_tags(text)
        except Exception:
            return re.sub(r"<[^>]+>", "", cstr(text))


def _get_doc(doctype: str, name: str):
    doc = frappe.get_doc(doctype, name)
    if not doc:
        frappe.throw(f"{doctype} {name} not found")
    return doc


def _parse_fields_arg(fields: Any) -> Dict[str, Any]:
    """fields parametresi string JSON geldiyse dict'e çevirir."""
    if isinstance(fields, (dict, list)):
        return fields
    if fields is None:
        return {}
    if isinstance(fields, str):
        fields = fields.strip()
        if not fields:
            return {}
        try:
            return json.loads(fields)
        except Exception:
            frappe.throw("Invalid JSON for `fields`")
    return {}


def _pluck(lst: Iterable[Dict[str, Any]], key: str) -> List[Any]:
    return [r.get(key) for r in lst or [] if r.get(key)]


# ---------------------------------------------------------------------------
# GET – KATALOG / LİSTELER
# ---------------------------------------------------------------------------

@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_teams(include_members: int | bool = 0, include_tags: int | bool = 0):
    # Takım listesi, opsiyonel üye detayları
    doctype = "HD Team"
    fields = ["name"]
    if frappe.db.has_column(doctype, "team_name"):
        fields.append("team_name")
    if frappe.db.has_column(doctype, "description"):
        fields.append("description")

    teams = frappe.get_all(doctype, fields=fields, order_by="modified desc")

    if cint(include_members):
        child_dt = "HD Team Member"
        user_field = "user"
        if frappe.db.table_exists(child_dt):
            by_team = frappe.get_all(child_dt, fields=["parent", user_field], limit=10000)
            members_map: Dict[str, List[str]] = {}
            for row in by_team:
                members_map.setdefault(row["parent"], []).append(row[user_field])
            for t in teams:
                t["members"] = members_map.get(t["name"], [])
        else:
            for t in teams:
                t["members"] = []

    # include_tags: şu an kullanılmıyor
    return {"ok": True, "teams": teams}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_team_members(team: str) -> Dict[str, Any]:
    """Tek takımın üyeleri."""
    members = frappe.get_all(
        "HD Team Member",
        fields=["user"],
        filters={"parent": team, "parenttype": "HD Team"},
        order_by="idx asc",
    )
    return {"ok": True, "team": team, "members": _pluck(members, "user")}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_tickets_by_team(
    team: str,
    status: str | None = None,
    limit: int = 50,
    start: int = 0,
) -> Dict[str, Any]:
    """Takıma atanmış HD Ticket'lar."""
    filters: Dict[str, Any] = {"agent_group": team}
    if status:
        filters["status"] = status

    tickets = frappe.get_all(
        "HD Ticket",
        fields=[
            "name",
            "subject",
            "status",
            "priority",
            "agent_group",
            "customer",
            "opening_date",
            "opening_time",
            "modified",
        ],
        filters=filters,
        limit_start=start,
        limit_page_length=limit,
        order_by="modified desc",
    )
    return {"ok": True, "team": team, "tickets": tickets}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_tickets_by_user(
    user: str,
    status: str | None = None,
    limit: int = 50,
    start: int = 0,
) -> Dict[str, Any]:
    """
    Kullanıcıya atanmış biletler.
    Frappe'de atamalar ToDo üstünden tutulur.
    """
    assigned = frappe.get_all(
        "ToDo",
        fields=["reference_name"],
        filters={
            "reference_type": "HD Ticket",
            "allocated_to": user,
            "status": ["!=", "Closed"],
        },
        limit_page_length=1000,
    )
    ticket_names = _pluck(assigned, "reference_name")
    if not ticket_names:
        return {"ok": True, "user": user, "tickets": []}

    filters: Dict[str, Any] = {"name": ["in", ticket_names]}
    if status:
        filters["status"] = status

    tickets = frappe.get_all(
        "HD Ticket",
        fields=[
            "name",
            "subject",
            "status",
            "priority",
            "agent_group",
            "customer",
            "opening_date",
            "opening_time",
            "modified",
        ],
        filters=filters,
        limit_start=start,
        limit_page_length=limit,
        order_by="modified desc",
    )
    return {"ok": True, "user": user, "tickets": tickets}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_articles(q: str | None = None, limit: int = 50, start: int = 0) -> Dict[str, Any]:
    """
    Bilgi bankası makaleleri (HD Article). Alan adları değişebileceği için
    asgari set döndürülür (name, title, content benzeri).
    """
    candidate_fields = [
        "name", "title", "subject", "article_title", "content", "body", "description", "modified"
    ]
    meta = frappe.get_meta("HD Article")
    fields = [f for f in candidate_fields if meta.has_field(f) or f in ("name", "modified")]

    filters: Dict[str, Any] = {}
    if q:
        like_field = "title" if meta.has_field("title") else ("subject" if meta.has_field("subject") else None)
        if like_field:
            filters[like_field] = ["like", f"%{q}%"]

    res = frappe.get_all(
        "HD Article",
        fields=fields,
        filters=filters,
        limit_start=start,
        limit_page_length=limit,
        order_by="modified desc",
    )
    return {"ok": True, "articles": res}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_ticket(ticket: str, fields: str | None = None) -> Dict[str, Any]:
    """Tek bilet detayları (alan listesi opsiyonel). Shadow mode alanları kaldırıldı."""
    default_fields = [
        "name",
        "subject",
        "status",
        "priority",
        "agent_group",
        "customer",
        "description",
        "ai_summary",
        "ai_reply_suggestion",
        "last_sentiment",
        "sentiment_trend",
        "effort_score",
        "effort_band",
        "route_rationale",
        "cluster_hash",
        "modified",
    ]
    if fields:
        try:
            req = json.loads(fields)
            if isinstance(req, list) and req:
                default_fields = req
        except Exception:
            pass

    doc = frappe.get_value("HD Ticket", ticket, default_fields, as_dict=True)
    if not doc:
        frappe.throw("HD Ticket not found")
    return {"ok": True, "ticket": doc}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_routing_context():
    ctx: Dict[str, Any] = {}
    ctx["teams"] = get_teams(include_members=1, include_tags=1)
    return {"ok": True, "context": ctx}


# ---------------------------------------------------------------------------
# POST / PUT – TEK BİLET ALANI GÜNCELLEME (bağımsız ve esnek)
# ---------------------------------------------------------------------------

TEXT_FIELDS = {
    "ai_summary",
    "ai_reply_suggestion",
    "route_rationale",
    "sentiment_trend",
}
FLOAT_FIELDS = {
    "route_confidence",
    "effort_score",
    "problem_confidence",
}
SELECT_FIELDS: Dict[str, set[str]] = {
    "last_sentiment": {"Positive", "Negative", "Nautral"},  # Note: typo in DB schema
    "effort_band": {"Low", "Medium", "High"},
}

# --- Normalization helpers for SELECT fields --------------------------------

_SELECT_SYNONYMS: Dict[str, Dict[str, str]] = {
    # key: fieldname, value: map of lowercase input -> canonical value
    "last_sentiment": {
        "pos": "Positive", "positive": "Positive", "+": "Positive",
        "neu": "Nautral",  "neutral": "Nautral",  "0": "Nautral",  # Maps to DB value "Nautral" (typo)
        "neg": "Negative", "negative": "Negative", "-": "Negative",
        # Turkish synonyms
        "pozitif": "Positive", "olumlu": "Positive",
        "nötr": "Nautral", "notr": "Nautral", "tarafsız": "Nautral", "tarafsiz": "Nautral",
        "negatif": "Negative", "olumsuz": "Negative",
    },
    "effort_band": {
        "l": "Low", "low": "Low", "lo": "Low",
        "m": "Medium", "med": "Medium", "medium": "Medium",
        "h": "High", "hi": "High", "high": "High",
        # Turkish synonyms
        "düşük": "Low", "dusuk": "Low", "az": "Low",
        "orta": "Medium",
        "yüksek": "High", "yuksek": "High", "çok": "High", "cok": "High",
    },
}

def _normalize_select(field: str, value: Any) -> str:
    """Case-insensitive, synonym-aware normalizer; returns canonical or original string."""
    s = cstr(value).strip()
    if not s:
        return s
    # exact match first (handles already-canonical values)
    if s in SELECT_FIELDS.get(field, set()):
        return s
    lower = s.lower()
    if field in _SELECT_SYNONYMS and lower in _SELECT_SYNONYMS[field]:
        return _SELECT_SYNONYMS[field][lower]
    # title-case fallback if matches canonical set
    t = s.capitalize()
    if t in SELECT_FIELDS.get(field, set()):
        return t
    return s


# Shadow mode alanı tamamen kaldırıldı
DATA_FIELDS = {
    "cluster_hash",
}

LINK_FIELDS: Dict[str, str] = {
    "agent_group": "HD Team",
    "customer": "Customer",
}

ALLOWED_FIELDS = TEXT_FIELDS | FLOAT_FIELDS | set(SELECT_FIELDS) | set(LINK_FIELDS) | DATA_FIELDS


# (A) TEXT birleştirme yardımcı fonksiyonu (test edilebilir, yan etkisiz)

def _append_text(base: str, new: str, do_append: bool) -> str:
    base = cstr(base or "")
    new = cstr(new or "")
    if do_append and base:
        return base + "\n" + new
    return new


def _apply_ticket_updates(
    ticket: str,
    updates: Dict[str, Any],
    append: bool = False,
    clean_html: bool = True,
) -> Dict[str, Any]:
    if not updates:
        return {"ok": False, "error": "No fields to update"}

    doc = _get_doc("HD Ticket", ticket)
    changed: Dict[str, Any] = {}

    for k, v in updates.items():
        if k not in ALLOWED_FIELDS:
            continue
        if k in TEXT_FIELDS:
            val = cstr(v)
            if clean_html:
                val = _clean_html(val)
            base = cstr(getattr(doc, k) or "")
            val = _append_text(base, val, append)
            setattr(doc, k, val)
            changed[k] = val
        elif k in FLOAT_FIELDS:
            val = flt(v)
            setattr(doc, k, val)
            changed[k] = val
        elif k in SELECT_FIELDS:
            allowed = SELECT_FIELDS[k]
            val = _normalize_select(k, v)
            if val and val not in allowed:
                frappe.throw(f"Invalid value for {k}. Allowed: {sorted(allowed)}")
            setattr(doc, k, val)
            changed[k] = val
        elif k in LINK_FIELDS:
            doctype = LINK_FIELDS[k]
            if v:
                if not frappe.db.exists(doctype, v):
                    frappe.throw(f"Linked doc not found: {doctype} {v}")
                setattr(doc, k, v)
                changed[k] = v
            else:
                setattr(doc, k, None)
                changed[k] = None
        elif k in DATA_FIELDS:
            val = cstr(v)
            setattr(doc, k, val)
            changed[k] = val

    if not changed:
        return {"ok": False, "error": "No allowed fields were provided"}

    doc.save(ignore_permissions=True)
    frappe.db.commit()

    return {"ok": True, "ticket": ticket, "changed": changed}


# ---- Kolay uç noktalar -----------------------------------------------------

@frappe.whitelist(allow_guest=True, methods=["POST", "PUT"])
def ingest_summary(
    ticket: str,
    summary: str,
    append: int | bool = 0,
    clean_html: int | bool = 1,
) -> Dict[str, Any]:
    return _apply_ticket_updates(
        ticket,
        {"ai_summary": summary},
        append=cint(append) == 1,
        clean_html=cint(clean_html) == 1,
    )

# --- Problem Ticket UPSERT --------------------------------------------------
PROBLEM_TEXT_FIELDS = {
    "subject", "impact", "root_cause", "workaround", "fix_plan", "resolution_summary"
}
PROBLEM_SELECT_FIELDS: Dict[str, set[str]] = {
    "status": {"Open", "Investigating", "Identified", "Monitoring", "Resolved", "Closed"},
    "severity": {"Low", "Medium", "High", "Critical"},
}
PROBLEM_LINK_FIELDS: Dict[str, str] = {
    "owner_team": "HD Team",
    "problem_manager": "User",
}
PROBLEM_DATETIME_FIELDS = {"reported_on", "first_seen_on", "mitigated_on", "resolved_on"}
PROBLEM_INT_FIELDS = {"reopened_count"}


def _find_problem_by_subject(subject: str) -> str | None:
    if not subject:
        return None
    return frappe.db.get_value("Problem Ticket", {"subject": subject}, "name")


def _changed(old, new) -> bool:
    o = (cstr(old) if old is not None else None)
    n = (cstr(new) if new is not None else None)
    return o != n


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_problem_ticket(name: str, fields: str | None = None):
    default_fields = [
        "name", "subject", "status", "severity",
        "owner_team", "problem_manager",
        "impact", "root_cause", "workaround", "fix_plan", "resolution_summary",
        "reported_on", "first_seen_on", "mitigated_on", "resolved_on",
        "reopened_count", "modified",
    ]
    if fields:
        try:
            req = json.loads(fields)
            if isinstance(req, list) and req:
                default_fields = req
        except Exception:
            pass

    doc = frappe.get_value("Problem Ticket", name, default_fields, as_dict=True)
    if not doc:
        frappe.throw("Problem Ticket not found")
    return {"ok": True, "problem": doc}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def list_problem_tickets(
    status: str | None = None,
    severity: str | None = None,
    owner_team: str | None = None,
    problem_manager: str | None = None,
    q: str | None = None,
    limit: int = 50,
    start: int = 0,
):
    filters: Dict[str, Any] = {}
    if status:          filters["status"] = status
    if severity:        filters["severity"] = severity
    if owner_team:      filters["owner_team"] = owner_team
    if problem_manager: filters["problem_manager"] = problem_manager
    if q:               filters["subject"] = ["like", f"%{q}%"]

    fields = [
        "name", "subject", "status", "severity",
        "owner_team", "problem_manager",
        "first_seen_on", "mitigated_on", "resolved_on",
        "reopened_count", "modified",
    ]
    rows = frappe.get_all(
        "Problem Ticket",
        fields=fields,
        filters=filters,
        limit_start=start,
        limit_page_length=limit,
        order_by="modified desc",
    )
    return {"ok": True, "problems": rows}


@frappe.whitelist(allow_guest=True, methods=["POST", "PUT"])
def upsert_problem_ticket(
    name: str | None = None,
    fields: str | dict | None = None,
    lookup_by: str | None = None,
    preview: int | bool = 0,  # no-op; geriye dönük uyumluluk için tutuldu
    normalize_html: int | bool = 1,
    strict: int | bool = 1,
):
    data = _parse_fields_arg(fields)
    if not name and not data.get("subject"):
        frappe.throw("`subject` is required to create a Problem Ticket")

    if cint(strict):
        allowed = (
            PROBLEM_TEXT_FIELDS
            | set(PROBLEM_SELECT_FIELDS)
            | set(PROBLEM_LINK_FIELDS)
            | PROBLEM_DATETIME_FIELDS
            | PROBLEM_INT_FIELDS
        )
        extras = set(data.keys()) - allowed
        if extras:
            frappe.throw(f"Unknown fields: {sorted(extras)}")

    created = False

    if not name and lookup_by == "subject" and data.get("subject"):
        name = _find_problem_by_subject(cstr(data["subject"]).strip())

    if name:
        if not frappe.db.exists("Problem Ticket", name):
            frappe.throw(f"Problem Ticket not found: {name}")
        doc = frappe.get_doc("Problem Ticket", name)
    else:
        doc = frappe.new_doc("Problem Ticket")
        created = True

    changed: Dict[str, Any] = {}

    for k in PROBLEM_TEXT_FIELDS:
        if k in data:
            val = cstr(data.get(k))
            if k != "subject" and cint(normalize_html):
                val = _clean_html(val)
            if created or _changed(getattr(doc, k, None), val):
                setattr(doc, k, val)
                changed[k] = val

    for k, allowed in PROBLEM_SELECT_FIELDS.items():
        if k in data:
            v = cstr(data.get(k))
            if v and v not in allowed:
                frappe.throw(f"Invalid value for {k}. Allowed: {sorted(allowed)}")
            if created or _changed(getattr(doc, k, None), v):
                setattr(doc, k, v)
                changed[k] = v

    for k, dt in PROBLEM_LINK_FIELDS.items():
        if k in data:
            v = data.get(k)
            if v:
                if not frappe.db.exists(dt, v):
                    frappe.throw(f"Linked doc not found: {dt} {v}")
                if created or _changed(getattr(doc, k, None), v):
                    setattr(doc, k, v)
                    changed[k] = v
            else:
                if created or _changed(getattr(doc, k, None), None):
                    setattr(doc, k, None)
                    changed[k] = None

    for k in PROBLEM_DATETIME_FIELDS:
        if k in data:
            val = data.get(k)
            if created or _changed(getattr(doc, k, None), val):
                setattr(doc, k, val)
                changed[k] = val

    for k in PROBLEM_INT_FIELDS:
        if k in data:
            val = cint(data.get(k) or 0)
            if created or _changed(getattr(doc, k, None), val):
                setattr(doc, k, val)
                changed[k] = val

    no_change = (not created) and (len(changed) == 0)
    subject_for_log = cstr(data.get("subject") or getattr(doc, "subject", "")).strip()

    if created:
        doc.insert(ignore_permissions=True)
    elif changed:
        doc.save(ignore_permissions=True)
    frappe.db.commit()

    subject_for_log = cstr(getattr(doc, "subject", "") or data.get("subject") or "").strip()

    return {"ok": True, "name": doc.name, "created": created, "changed": changed, "no_change": no_change}


@frappe.whitelist(allow_guest=True, methods=["POST", "PUT"])
def set_reply_suggestion(ticket: str, text: str, append: int | bool = 0, clean_html: int | bool = 1):
    return _apply_ticket_updates(
        ticket,
        {"ai_reply_suggestion": text},
        append=cint(append) == 1,
        clean_html=cint(clean_html) == 1,
    )


@frappe.whitelist(allow_guest=True, methods=["POST", "PUT"])
def set_sentiment(
    ticket: str,
    last_sentiment: str | None = None,
    sentiment_trend: str | None = None,
    effort_score: float | None = None,
    effort_band: str | None = None,
):
    updates: Dict[str, Any] = {}
    if last_sentiment is not None:
        updates["last_sentiment"] = last_sentiment
    if sentiment_trend is not None:
        updates["sentiment_trend"] = sentiment_trend
    if effort_score is not None:
        updates["effort_score"] = effort_score
    if effort_band is not None:
        updates["effort_band"] = effort_band
    return _apply_ticket_updates(ticket, updates)


@frappe.whitelist(allow_guest=True, methods=["POST", "PUT"])
def set_metrics(
    ticket: str,
    effort_score: float | None = None,
    cluster_hash: str | None = None,
):
    updates: Dict[str, Any] = {}

    if effort_score is not None:
        updates["effort_score"] = effort_score
    if cluster_hash is not None:
        updates["cluster_hash"] = cluster_hash
    return _apply_ticket_updates(ticket, updates)


# Shadow mode bayrak uç noktası ve durum uç noktası KALDIRILDI.

# --- KB Update Requests ------------------------------------------------------
_KB_DT = "Knowledge Base Update Request"


def _kb_meta():
    try:
        return frappe.get_meta(_KB_DT)
    except Exception:
        frappe.throw(f"Meta not found for {_KB_DT}")


def _kb_select_options(fieldname: str) -> set[str]:
    meta = _kb_meta()
    f = meta.get_field(fieldname)
    if not f:
        return set()
    opts = cstr(getattr(f, "options", "")).strip()
    return set([o.strip() for o in opts.split("\n") if o.strip()])

_KB_ALLOWED_FIELDS_BASE = {
    "subject", "priority", "target_doctype", "target_name", "target_path",
    "tags", "current_summary", "proposed_changes", "references", "attachment", "breaking_change"
}


def _kb_allowed_fields() -> set[str]:
    meta = _kb_meta()
    return {f for f in _KB_ALLOWED_FIELDS_BASE if meta.has_field(f)}


def _kb_user() -> str:
    try:
        u = frappe.session.user or "Guest"
    except Exception:
        u = "Guest"
    return u


def _kb_resolve_attachment(val: str | None) -> str | None:
    if not val:
        return None
    s = cstr(val).strip()
    if not s:
        return None
    try:
        if frappe.db.exists("File", s):
            url = frappe.db.get_value("File", s, "file_url")
            return url or s
        row = frappe.db.get_value("File", {"file_name": s}, ["file_url"], as_dict=True)
        if row and row.get("file_url"):
            return row["file_url"]
    except Exception:
        pass
    return s


def _kb_default_series() -> str:
    try:
        meta = _kb_meta()
        f = meta.get_field("naming_series")
        default = cstr(getattr(f, "default", "")).strip() if f else ""
        return default or "KBUR-.YYYY.-.#####"
    except Exception:
        return "KBUR-.YYYY.-.#####"


def _kb_validate_options(change_type: str | None, priority: str | None):
    if change_type:
        allowed_ct = _kb_select_options("change_type")
        if allowed_ct and change_type not in allowed_ct:
            frappe.throw(f"Invalid `change_type`. Allowed: {sorted(allowed_ct)}")
    if priority:
        allowed_pr = _kb_select_options("priority")
        if allowed_pr and priority not in allowed_pr:
            frappe.throw(f"Invalid `priority`. Allowed: {sorted(allowed_pr)}")


def _kb_collect_payload(fields: str | dict | None) -> Dict[str, Any]:
    """İstemcinin gönderdiği gövdeden payload topla."""
    data = _parse_fields_arg(fields)
    if data:
        return data

    req_json: Dict[str, Any] = {}
    try:
        req_json = frappe.request.get_json() or {}
    except Exception:
        try:
            req_json = frappe.request.json or {}
        except Exception:
            req_json = {}

    if isinstance(req_json, dict):
        if isinstance(req_json.get("fields"), dict):
            return req_json.get("fields")  # type: ignore
        allowed = _kb_allowed_fields()
        flat = {k: req_json.get(k) for k in allowed if k in req_json}
        if flat:
            return flat

    try:
        fd = dict(frappe.form_dict)
        if "fields" in fd:
            try:
                return json.loads(fd.get("fields") or "{}")
            except Exception:
                return {}
        else:
            allowed = _kb_allowed_fields()
            flat = {k: fd.get(k) for k in allowed if k in fd}
            if flat:
                return flat
    except Exception:
        pass

    return {}


def _kb_clean_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    allowed = _kb_allowed_fields()
    out: Dict[str, Any] = {}
    for k in (data or {}):
        if k not in allowed:
            continue
        v = data.get(k)
        if k in {"current_summary", "proposed_changes", "references"}:
            out[k] = _clean_html(cstr(v))
        elif k == "breaking_change":
            out[k] = 1 if cint(v) else 0
        else:
            out[k] = cstr(v) if v is not None else None
    if "attachment" in allowed:
        out["attachment"] = _kb_resolve_attachment(out.get("attachment"))
    return out


def _kb_create_request(
    change_type: str,
    fields: str | dict | None = None,
) -> Dict[str, Any]:
    # Sade akış – preview/strict parametreleri yok
    payload_raw = _kb_collect_payload(fields)
    payload = _kb_clean_payload(payload_raw)

    subject = cstr(payload.get("subject") or "").strip()
    if not subject:
        frappe.throw("`subject` is required")

    _kb_validate_options(change_type, payload.get("priority"))

    created_doc = {
        "doctype": _KB_DT,
        "naming_series": _kb_default_series(),
        "subject": subject,
        "status": "Open",
        "change_type": change_type,
        "priority": payload.get("priority") or None,
        "requester": _kb_user(),
        "target_doctype": payload.get("target_doctype"),
        "target_name": payload.get("target_name"),
        "target_path": payload.get("target_path"),
        "tags": payload.get("tags"),
        "current_summary": payload.get("current_summary"),
        "proposed_changes": payload.get("proposed_changes"),
        "references": payload.get("references"),
        "attachment": payload.get("attachment"),
        "breaking_change": payload.get("breaking_change", 0),
    }

    doc = frappe.get_doc(created_doc)
    doc.insert(ignore_permissions=True)
    frappe.db.commit()

    return {"ok": True, "name": doc.name, "change_type": change_type}


@frappe.whitelist(allow_guest=True, methods=["POST"])
def request_kb_new_article(fields: str | dict | None = None):
    return _kb_create_request("New Article", fields=fields)


@frappe.whitelist(allow_guest=True, methods=["POST"])
def request_kb_fix(fields: str | dict | None = None):
    return _kb_create_request("Fix", fields=fields)


@frappe.whitelist(allow_guest=True, methods=["POST"])
def request_kb_update(fields: str | dict | None = None):
    return _kb_create_request("Update", fields=fields)


@frappe.whitelist(allow_guest=True, methods=["POST"])
def report_kb_wrong_document(fields: str | dict | None = None):
    return _kb_create_request("Deprecate", fields=fields)


# ---- Genel/Esnek uç nokta --------------------------------------------------

@frappe.whitelist(allow_guest=True, methods=["POST"]) 
def log_ai_interaction(
    ticket: str | int,
    request: str | dict | None = None,
    response: str | dict | None = None,
):
    """Gerçek AI etkileşimini loglar. Sadece 3 parametre alır: ticket, request, response."""
    def _ensure_dict(v):
        if v is None:
            return {}
        if isinstance(v, (dict, list)):
            return v
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return {}
            try:
                return json.loads(v)
            except Exception:
                return {"raw": v}
        return {"raw": cstr(v)}

    req = _ensure_dict(request)
    resp = _ensure_dict(response)

    # Import locally to avoid coupling ingest to logging except for this endpoint
    from brv_license_app.api.ai_log import write as ai_log_write
    ai_log_write(ticket=ticket, request=req, response=resp)
    return {"ok": True}

# ---- Genel/Esnek uç nokta --------------------------------------------------

@frappe.whitelist(allow_guest=True, methods=["POST", "PUT"])
def update_ticket(
    ticket: str,
    fields: str | dict | None = None,
    append: int | bool = 0,
    clean_html: int | bool = 1,
    ignore_shadow: int | bool = 0,  # no-op: geriye dönük uyumluluk için tutuldu
):
    updates = _parse_fields_arg(fields)
    return _apply_ticket_updates(
        ticket,
        updates,
        append=cint(append) == 1,
        clean_html=cint(clean_html) == 1,
    )


# --- Basit yerel testler (framework bağımsız) -------------------------------

def _run_sanity_tests():
    # TEXT birleştirme
    assert _append_text("", "B", True) == "B"
    assert _append_text("A", "B", True) == "A\nB"
    assert _append_text("A", "B", False) == "B"
    assert _append_text("A", "", True) == "A\n"

    # options split davranışı
    opts = "Open\nApproved\nRejected"
    parsed = set([o.strip() for o in opts.split("\n") if o.strip()])
    assert parsed == {"Open", "Approved", "Rejected"}


if __name__ == "__main__":
    _run_sanity_tests()