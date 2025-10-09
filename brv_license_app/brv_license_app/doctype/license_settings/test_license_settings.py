# Copyright (c) 2025, BRV Software
# See license.txt

from __future__ import annotations

import json
import contextlib
from datetime import timedelta
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import now_datetime, add_to_date

# Test ettiğimiz modül
MOD = "brv_license_app.brv_license_app.doctype.license_settings.license_settings"

# ---------------------------------------------------------------------------
# Dummy LMFWC Client
# ---------------------------------------------------------------------------

class DummyClient:
    _server = {
        "license_key": None,
        "token": None,
        "activated": False,
        "activation_limit": 3,
        "activation_count": 0,
        "expires_at": add_to_date(now_datetime(), days=14),
        "revoked": False,
    }

    def __init__(self, *args, **kwargs):
        pass

    def activate(self, license_key: str, device: dict | None = None) -> dict:
        s = self._server
        s["license_key"] = license_key
        s["activated"] = True
        s["activation_count"] = 1
        s["token"] = "TOK1"
        return self._norm()

    def reactivate(self, license_key: str, token: str, device: dict | None = None) -> dict:
        s = self._server
        assert s["token"] == token, "invalid token"
        s["token"] = "TOK2"
        s["activated"] = True
        return self._norm()

    def validate(self, license_key: str, token: str | None = None) -> dict:
        s = self._server
        if token and token != s["token"]:
            from brv_license_app.license_client import LMFWCError  # type: ignore
            raise LMFWCError("invalid token")
        return self._norm()

    def deactivate(self, license_key: str, token: str | None = None) -> dict:
        s = self._server
        s["activated"] = False
        s["activation_count"] = 0
        s["token"] = None
        return self._norm()

    def normalize(self, resp: dict) -> dict:
        resp = dict(resp)
        resp["raw"] = {"dummy": True}
        return resp

    def _norm(self) -> dict:
        s = self._server
        status = "ACTIVE" if s["activated"] else "DEACTIVATED"
        remaining = int(s["activation_limit"]) - int(s["activation_count"])
        return {
            "status": status,
            "expires_at": s["expires_at"],
            "activation_limit": s["activation_limit"],
            "activation_count": s["activation_count"],
            "remaining": remaining,
            "token": s["token"],
            "reason": None,
        }


class DummyClientTokenMismatch(DummyClient):
    def validate(self, license_key: str, token: str | None = None) -> dict:
        if token:
            from brv_license_app.license_client import LMFWCError  # type: ignore
            raise LMFWCError("invalid token")
        return super().validate(license_key, token=None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def patched_client(klass):
    with patch(f"{MOD}.LicenseClient", new=klass):
        yield

def setup_clean_single():
    """License Settings single'ı temiz başlangıca getir (mandatory bypass ile)."""
    doc = frappe.get_single("License Settings")
    for f, v in {
        "license_key": None,
        "activation_token": None,
        "status": "UNCONFIGURED",
        "activation_limit": None,
        "activation_count": None,
        "remaining": None,
        "expires_at": None,
        "grace_until": None,
        "reason": None,
        "last_validated": None,
        "token_version": 0,
        "token_last_rotated": None,
        "token_history": [],
        "validation_interval_hours": 12,
        "grace_days": 7,
        "offline_tolerance_hours": 72,
        "installation_id": None,
    }.items():
        doc.set(f, v)
    # ---- kritik satırlar: mandatory/validate bypass ----
    doc.flags.ignore_mandatory = True
    doc.flags.ignore_validate = True
    doc.save(ignore_permissions=True)
    frappe.db.commit()
    return doc

def set_conf():
    frappe.conf.update({
        "lmfwc_base_url": "https://dummy.local",
        "lmfwc_ck": "ck",
        "lmfwc_cs": "cs",
        "lmfwc_allow_insecure_http": 1,
        "lmfwc_timeout_seconds": 2,
    })


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestLicenseSettings(FrappeTestCase):

    def setUp(self):
        setup_clean_single()
        set_conf()

    def test_activate_sets_fields_and_token(self):
        from brv_license_app.brv_license_app.doctype.license_settings import license_settings as ls
        with patched_client(DummyClient):
            doc = frappe.get_single("License Settings")
            doc.license_key = "LIC-123"
            doc.save(ignore_permissions=True)

            res = json.loads(ls.activate_license())
            self.assertTrue(res["ok"])

            doc = frappe.get_single("License Settings")
            self.assertEqual(doc.status, "VALIDATED")
            self.assertIsNotNone(doc.expires_at)
            self.assertEqual(doc.activation_token, "TOK1")
            self.assertEqual(doc.token_version, 1)

    def test_reactivate_rotates_token_and_history(self):
        from brv_license_app.brv_license_app.doctype.license_settings import license_settings as ls
        with patched_client(DummyClient):
            doc = frappe.get_single("License Settings")
            doc.license_key = "LIC-123"
            doc.save(ignore_permissions=True)
            json.loads(ls.activate_license())

            res = json.loads(ls.reactivate_license())
            self.assertTrue(res["ok"])

            doc = frappe.get_single("License Settings")
            self.assertEqual(doc.activation_token, "TOK2")
            self.assertEqual(doc.token_version, 2)
            self.assertTrue(len(doc.token_history) >= 1)
            row = doc.token_history[0]
            self.assertTrue(row.token_hash_sha256)
            # 'TOK1' için last4 => 'TOK1'
            self.assertEqual(row.token_suffix_last_4, "TOK1")

    def test_validate_tokened_then_fallback(self):
        """Token mismatch olduğunda tokensız validate fallback çalışmalı."""
        from brv_license_app.brv_license_app.doctype.license_settings import license_settings as ls

        with patched_client(DummyClient):
            doc = frappe.get_single("License Settings")
            doc.license_key = "LIC-123"
            doc.save(ignore_permissions=True)
            json.loads(ls.activate_license())

        with patched_client(DummyClientTokenMismatch):
            res = json.loads(ls.validate_license())
            self.assertTrue(res["ok"])
            doc = frappe.get_single("License Settings")
            self.assertIn(doc.status, ("ACTIVE", "VALIDATED"))

    def test_deactivate_single_archives_and_clears_token(self):
        from brv_license_app.brv_license_app.doctype.license_settings import license_settings as ls
        with patched_client(DummyClient):
            doc = frappe.get_single("License Settings")
            doc.license_key = "LIC-123"
            doc.save(ignore_permissions=True)
            json.loads(ls.activate_license())
            self.assertEqual(frappe.get_single("License Settings").activation_token, "TOK1")

            res = json.loads(ls.deactivate_license(mode="single"))
            self.assertTrue(res["ok"])

            doc = frappe.get_single("License Settings")
            self.assertEqual(doc.status, "DEACTIVATED")
            self.assertIsNone(doc.activation_token)
            self.assertTrue(len(doc.token_history) >= 1)

    def test_deactivate_bulk_also_archives_and_sets_deactivated(self):
        from brv_license_app.brv_license_app.doctype.license_settings import license_settings as ls
        with patched_client(DummyClient):
            doc = frappe.get_single("License Settings")
            doc.license_key = "LIC-123"
            doc.save(ignore_permissions=True)
            json.loads(ls.activate_license())

            res = json.loads(ls.deactivate_license(mode="bulk"))
            self.assertTrue(res["ok"])

            doc = frappe.get_single("License Settings")
            self.assertEqual(doc.status, "DEACTIVATED")
            self.assertIsNone(doc.activation_token)

    def test_healthz_ok_and_expired_grace(self):
        from brv_license_app.brv_license_app.doctype.license_settings import license_settings as ls
        with patched_client(DummyClient):
            doc = frappe.get_single("License Settings")
            doc.license_key = "LIC-123"
            doc.save(ignore_permissions=True)
            json.loads(ls.activate_license())

            h = json.loads(ls.healthz())
            self.assertTrue(h["ok"])
            self.assertIn(h["status"], ("ACTIVE", "VALIDATED"))

            doc = frappe.get_single("License Settings")
            doc.expires_at = add_to_date(now_datetime(), days=-1)
            doc.grace_days = 7
            doc.grace_until = add_to_date(now_datetime(), days=6)
            doc.status = "EXPIRED"
            doc.save(ignore_permissions=True)

            h2 = json.loads(ls.healthz())
            self.assertTrue(h2["ok"])

    def test_scheduler_skip_and_run(self):
        from brv_license_app.brv_license_app.doctype.license_settings import license_settings as ls
        with patched_client(DummyClient):
            doc = frappe.get_single("License Settings")
            doc.license_key = "LIC-123"
            doc.validation_interval_hours = 24
            doc.save(ignore_permissions=True)
            json.loads(ls.activate_license())

            before = frappe.get_single("License Settings").last_validated
            ls.scheduled_auto_validate()
            after = frappe.get_single("License Settings").last_validated
            self.assertEqual(before, after)

            doc = frappe.get_single("License Settings")
            doc.last_validated = add_to_date(now_datetime(), hours=-25)
            doc.save(ignore_permissions=True)
            ls.scheduled_auto_validate()
            self.assertTrue(frappe.get_single("License Settings").last_validated > doc.last_validated)
