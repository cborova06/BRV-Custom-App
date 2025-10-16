from __future__ import annotations

import json
import types
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import frappe
from frappe.tests.utils import FrappeTestCase

# Target module under test
from brv_license_app.brv_license_app.doctype.license_settings import license_settings as ls
from brv_license_app.license_client import LMFWCContractError, LMFWCRequestError


# ------------------------
# Test Utilities
# ------------------------
class _StubMeta:
    def get_field(self, name):
        # Pretend all fields exist so _set_if_exists always works
        return True


class _StubDoc:
    def __init__(self):
        # Minimal field surface the controller touches
        self.license_key = None
        self.activation_token = None
        self.status = None
        self.reason = None
        self.last_validated = None
        self.expires_at = None
        self.grace_until = None
        self.remaining = None
        self.last_response_raw = None
        self.last_error_raw = None
        self.meta = _StubMeta()
        self._saves = 0

    def set(self, key, value):
        setattr(self, key, value)

    def save(self, ignore_permissions=False):
        # record that save() was invoked; emulate Frappe's contract
        self._saves += 1


def _ts(s: str) -> datetime:
    # Helper to make naive datetimes (Frappe runtime treats them as naive in tests)
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


# Fixed clock to make assertions deterministic
NOW = _ts("2025-10-16 10:00:00")


class TestLicenseSettings(FrappeTestCase):
    def setUp(self):
        super().setUp()
        # Patch now_datetime globally for deterministic tests
        self.now_patcher = patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.now_datetime", return_value=NOW)
        self.now_patcher.start()

        # Silence frappe.log_error during tests
        self.log_patcher = patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.frappe.log_error")
        self.log_patcher.start()

        # Keep a stub doc handy
        self.doc = _StubDoc()

        # get_single always returns our stub doc unless a test overrides
        self.get_single_patcher = patch(
            "brv_license_app.brv_license_app.doctype.license_settings.license_settings.frappe.get_single",
            return_value=self.doc,
        )
        self.get_single_patcher.start()

    def tearDown(self):
        self.now_patcher.stop()
        self.log_patcher.stop()
        self.get_single_patcher.stop()
        super().tearDown()

    # ------------------------
    # activate_license
    # ------------------------
    def test_activate_license_happy_path_sets_active_and_updates_token(self):
        self.doc.license_key = "LIC-123"

        # fake client.activate -> returns canonical payload
        payload = {
            "success": True,
            "data": {
                "expiresAt": "2025-12-31 00:00:00",
                "activationData": {"token": "tok-NEW-ACTIVE", "deactivated_at": None},
                "timesActivated": 1,
            },
        }

        client = MagicMock()
        client.activate.return_value = payload
        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            out = ls.activate_license()

        # Returned payload should be data level
        self.assertEqual(out, payload["data"])

        # Doc side effects
        self.assertEqual(self.doc.status, ls.STATUS_ACTIVE)
        self.assertEqual(self.doc.reason, "Activated")
        self.assertIsNotNone(self.doc.last_validated)
        self.assertIsNone(self.doc.grace_until)
        self.assertEqual(self.doc.activation_token, "tok-NEW-ACTIVE")
        self.assertEqual(self.doc.expires_at, _ts("2025-12-31 00:00:00"))
        self.assertGreaterEqual(self.doc._saves, 1)

    def test_activate_license_expired_error_marks_doc_and_throws(self):
        self.doc.license_key = "LIC-EXPIRED"

        # Simulate server error payload with expired code and a UTC timestamp in message
        err_payload = {
            "success": False,
            "data": {
                "errors": {"lmfwc_rest_license_expired": ["expired."]},
                "error_data": {"lmfwc_rest_license_expired": {"status": 410}},
            },
        }
        msg = "License expired on 2025-10-10 00:00:00 (UTC)"
        exc = LMFWCContractError(msg)
        # Attach payload attribute like the client does
        setattr(exc, "payload", err_payload)

        client = MagicMock()
        client.activate.side_effect = exc

        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            with self.assertRaises(frappe.ValidationError):
                ls.activate_license()

        # Doc should be stamped as EXPIRED and saved
        self.assertEqual(self.doc.status, ls.STATUS_EXPIRED)
        self.assertIsNotNone(self.doc.grace_until)
        self.assertEqual(self.doc.expires_at, _ts("2025-10-10 00:00:00"))
        self.assertIn("expired", (self.doc.reason or "").lower())
        self.assertGreaterEqual(self.doc._saves, 1)

    # ------------------------
    # validate_license
    # ------------------------
    def test_validate_license_short_circuits_when_already_expired(self):
        self.doc.license_key = "LIC-X"
        self.doc.status = ls.STATUS_EXPIRED
        self.doc.reason = "Expired prior"

        # If get_client.validate gets called, we fail
        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client") as get_client:
            result = ls.validate_license()
            get_client.assert_not_called()

        self.assertEqual(result["status"], ls.STATUS_EXPIRED)
        self.assertEqual(result["reason"], "Expired prior")
        self.assertIsNotNone(self.doc.last_validated)
        self.assertGreaterEqual(self.doc._saves, 1)

    def test_validate_license_sets_validated_when_active_activation(self):
        self.doc.license_key = "LIC-OK"

        payload = {
            "success": True,
            "data": {
                "expiresAt": "2025-12-31 00:00:00",
                "activationData": [{
                    "token": "tok-123",
                    "deactivated_at": None,
                    "updated_at": "2025-10-15 12:00:00",
                }],
                "timesActivated": 2,
            },
        }

        client = MagicMock()
        client.validate.return_value = payload

        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            out = ls.validate_license()

        self.assertEqual(out, payload["data"])
        self.assertEqual(self.doc.status, ls.STATUS_VALIDATED)
        self.assertEqual(self.doc.reason, "Validated")
        self.assertEqual(self.doc.expires_at, _ts("2025-12-31 00:00:00"))
        self.assertIsNone(self.doc.grace_until)
        self.assertIsNotNone(self.doc.last_validated)

    def test_validate_license_marks_expired_if_expires_at_in_past(self):
        self.doc.license_key = "LIC-WILL-EXPIRE"

        payload = {
            "success": True,
            "data": {
                # Past expiry guarantees EXPIRED path in _apply_validation_update
                "expiresAt": "2025-01-01 00:00:00",
                "activationData": [],
                "timesActivated": 0,
            },
        }

        client = MagicMock()
        client.validate.return_value = payload

        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            _ = ls.validate_license()

        self.assertEqual(self.doc.status, ls.STATUS_EXPIRED)
        self.assertIsNotNone(self.doc.grace_until)
        self.assertEqual(self.doc.expires_at, _ts("2025-01-01 00:00:00"))

    # ------------------------
    # reactivate_license
    # ------------------------
    def test_reactivate_license_prefers_token_from_preflight_then_activates(self):
        self.doc.license_key = "LIC-REACT"
        # Preflight validate returns a newer token
        preflight_payload = {
            "success": True,
            "data": {
                "activationData": [{
                    "token": "tok-from-preflight",
                    "deactivated_at": None,
                    "updated_at": "2025-10-16 09:00:00",
                }],
            },
        }
        activate_payload = {
            "success": True,
            "data": {
                "expiresAt": "2026-01-01 00:00:00",
                "activationData": {"token": "tok-from-preflight", "deactivated_at": None},
            },
        }
        client = MagicMock()
        client.validate.return_value = preflight_payload
        client.activate.return_value = activate_payload

        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            out = ls.reactivate_license()

        self.assertEqual(out, activate_payload["data"])
        self.assertEqual(self.doc.activation_token, "tok-from-preflight")
        self.assertEqual(self.doc.status, ls.STATUS_ACTIVE)
        self.assertEqual(self.doc.expires_at, _ts("2026-01-01 00:00:00"))

    # ------------------------
    # deactivate_license
    # ------------------------
    def test_deactivate_license_without_token_preflights_and_hard_locks(self):
        self.doc.license_key = "LIC-DEC"

        # Preflight validate provides token used for deactivation
        preflight_validate = {
            "success": True,
            "data": {
                "activationData": {"token": "tok-pre", "deactivated_at": None}
            },
        }
        # Deactivate response
        deactivate_resp = {
            "success": True,
            "data": {"ok": True},
        }
        # Post-validate after deactivate (best-effort) — keep it simple
        post_validate = {
            "success": True,
            "data": {
                "activationData": [],
                "timesActivated": 0,
            },
        }

        client = MagicMock()
        client.validate.side_effect = [preflight_validate, post_validate]
        client.deactivate.return_value = deactivate_resp

        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            out = ls.deactivate_license()

        self.assertEqual(out, deactivate_resp["data"])
        self.assertEqual(self.doc.status, ls.STATUS_LOCK_HARD)
        self.assertEqual(self.doc.reason, "License deactivated")
        self.assertIsNotNone(self.doc.grace_until)
        self.assertIn("last_response_raw", self.doc.__dict__)
        self.assertFalse(self.doc.activation_token)

    # ------------------------
    # get_status_banner
    # ------------------------
    def test_get_status_banner_renders_expected_html(self):
        self.doc.status = ls.STATUS_VALIDATED
        self.doc.reason = "All good <script>alert('x')</script>"
        self.doc.remaining = 3

        html = ls.get_status_banner()
        self.assertIn("indicator green", html)
        self.assertIn("Status:", html)
        self.assertIn("Remaining:", html)
        # Ensure content got escaped
        self.assertNotIn("<script>", html)

    # ------------------------
    # scheduled_auto_validate
    # ------------------------
    def test_scheduled_auto_validate_no_license_key_is_noop(self):
        self.doc.license_key = None
        # Should not raise
        ls.scheduled_auto_validate()

    def test_scheduled_auto_validate_calls_validate_when_key_present(self):
        self.doc.license_key = "LIC-SCHED"

        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.validate_license") as validate:
            validate.return_value = {"ok": True}
            # Should not raise
            ls.scheduled_auto_validate()
            validate.assert_called_once_with("LIC-SCHED")


if __name__ == "__main__":
    unittest.main()
