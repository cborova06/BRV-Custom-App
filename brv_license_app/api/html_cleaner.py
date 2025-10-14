from __future__ import annotations
import re, frappe

# TR (1–2): HTML etiketlerini silmek için basit ve güvenli regex
_TAG_RE = re.compile(r"(?is)</?[^<>]+?>")

def _clean(obj):
    # TR (5–15): JSON'u aynen dolaş; string ise tag'leri sil, diğer tiplere dokunma
    if isinstance(obj, str):
        return _TAG_RE.sub("", obj)                  # TR: Sadece <...> etiketlerini kaldır
    if isinstance(obj, list):
        return [_clean(x) for x in obj]              # TR: Liste elemanlarını temizle
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}# TR: Sözlük değerlerini temizle
    return obj                                       # TR: Sayılar, null vs. aynen dön

@frappe.whitelist(allow_guest=False)
def strip_tags_json():
    """
    Body'deki JSON'u alır, tüm string değerlerden HTML etiketlerini kaldırır
    ve yapıyı değiştirmeden geri döner. Sadece <...> etiketleri silinir.
    """
    raw = getattr(frappe.request, "data", None)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "ignore")
    if raw and raw.strip():
        data = frappe.parse_json(raw)
    else:
        # Body boşsa query/form'dan 'data' paramını dene (opsiyonel)
        data_param = frappe.form_dict.get("data")
        data = frappe.parse_json(data_param) if data_param else {}

    return _clean(data)
