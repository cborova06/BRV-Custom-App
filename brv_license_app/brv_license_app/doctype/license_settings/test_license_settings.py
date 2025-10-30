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


    # ------------------------
    # Helper function tests
    # ------------------------
    def test_parse_expiry_from_msg_success(self):
        msg = "License expired on 2025-10-15 12:30:45 (UTC)"
        result = ls._parse_expiry_from_msg(msg)
        self.assertIsNotNone(result)
        self.assertEqual(result, _ts("2025-10-15 12:30:45"))

    def test_parse_expiry_from_msg_no_match(self):
        msg = "Some other error message"
        result = ls._parse_expiry_from_msg(msg)
        self.assertIsNone(result)

    def test_parse_expiry_from_msg_invalid_date(self):
        msg = "expired on INVALID-DATE (UTC)"
        result = ls._parse_expiry_from_msg(msg)
        self.assertIsNone(result)

    def test_is_expired_error(self):
        self.assertTrue(ls._is_expired_error("License expired on..."))
        self.assertTrue(ls._is_expired_error("EXPIRED"))
        self.assertFalse(ls._is_expired_error("Some other error"))
        self.assertFalse(ls._is_expired_error(None))

    def test_mark_expired(self):
        doc = _StubDoc()
        ls._mark_expired(doc, "Test expiration")
        self.assertEqual(doc.status, ls.STATUS_EXPIRED)
        self.assertEqual(doc.reason, "Test expiration")
        self.assertEqual(doc.grace_until, NOW)

    def test_set_if_exists(self):
        doc = _StubDoc()
        ls._set_if_exists(doc, "status", "TEST")
        self.assertEqual(doc.status, "TEST")

    def test_write_last_raw(self):
        doc = _StubDoc()
        resp = {"success": True, "data": {"foo": "bar"}}
        ls._write_last_raw(doc, resp)
        self.assertIsNotNone(doc.last_response_raw)
        parsed = json.loads(doc.last_response_raw)
        self.assertEqual(parsed["success"], True)

    def test_extract_data_with_data_key(self):
        resp = {"success": True, "data": {"foo": "bar"}}
        result = ls._extract_data(resp)
        self.assertEqual(result, {"foo": "bar"})

    def test_extract_data_without_data_key(self):
        resp = {"foo": "bar"}
        result = ls._extract_data(resp)
        self.assertEqual(result, {"foo": "bar"})

    # ------------------------
    # Token extraction tests
    # ------------------------
    def test_extract_latest_token_from_single_object(self):
        payload = {
            "data": {
                "activationData": {"token": "tok-single", "deactivated_at": None}
            }
        }
        result = ls._extract_latest_token(payload)
        self.assertEqual(result, "tok-single")

    def test_extract_latest_token_from_list(self):
        payload = {
            "data": {
                "activationData": [
                    {
                        "token": "tok-old",
                        "deactivated_at": None,
                        "created_at": "2025-10-14 10:00:00",
                        "updated_at": "2025-10-14 10:00:00",
                    },
                    {
                        "token": "tok-newest",
                        "deactivated_at": None,
                        "created_at": "2025-10-16 09:00:00",
                        "updated_at": "2025-10-16 09:00:00",
                    },
                ]
            }
        }
        result = ls._extract_latest_token(payload)
        self.assertEqual(result, "tok-newest")

    def test_extract_latest_token_prefers_active(self):
        payload = {
            "data": {
                "activationData": [
                    {
                        "token": "tok-deactivated",
                        "deactivated_at": "2025-10-15 00:00:00",
                        "created_at": "2025-10-16 10:00:00",
                        "updated_at": "2025-10-16 10:00:00",
                    },
                    {
                        "token": "tok-active",
                        "deactivated_at": None,
                        "created_at": "2025-10-14 10:00:00",
                        "updated_at": "2025-10-14 10:00:00",
                    },
                ]
            }
        }
        result = ls._extract_latest_token(payload)
        self.assertEqual(result, "tok-active")

    def test_extract_latest_token_no_data(self):
        payload = {"data": {}}
        result = ls._extract_latest_token(payload)
        self.assertIsNone(result)

    def test_extract_latest_token_empty_list(self):
        payload = {"data": {"activationData": []}}
        result = ls._extract_latest_token(payload)
        self.assertIsNone(result)

    # ------------------------
    # Grace period tests
    # ------------------------
    def test_apply_grace_on_failure_no_last_validated(self):
        doc = _StubDoc()
        doc.last_validated = None
        ls._apply_grace_on_failure(doc, reason="Network error")
        self.assertEqual(doc.status, ls.STATUS_GRACE_SOFT)
        self.assertEqual(doc.grace_until, NOW)
        self.assertIn("Grace policy", doc.reason)

    def test_apply_grace_on_failure_within_soft_window(self):
        doc = _StubDoc()
        # 12 hours ago (within 24h soft window)
        doc.last_validated = NOW - timedelta(hours=12)
        ls._apply_grace_on_failure(doc, reason="API failure")
        self.assertEqual(doc.status, ls.STATUS_GRACE_SOFT)
        self.assertEqual(doc.grace_until, NOW)

    def test_apply_grace_on_failure_within_hard_window(self):
        doc = _StubDoc()
        # 36 hours ago (between 24h soft and 48h hard)
        doc.last_validated = NOW - timedelta(hours=36)
        ls._apply_grace_on_failure(doc, reason="Validation failed")
        # 36 saat sonra hala GRACE_SOFT'ta olmalı (48 saat hard limit)
        self.assertEqual(doc.status, ls.STATUS_GRACE_SOFT)
        self.assertEqual(doc.grace_until, NOW)

    def test_apply_grace_on_failure_past_hard_window(self):
        doc = _StubDoc()
        # 50 hours ago (48 saat hard window'dan sonra)
        doc.last_validated = NOW - timedelta(hours=50)
        ls._apply_grace_on_failure(doc, reason="Long outage")
        # 48 saat geçtiği için artık LOCK_HARD olmalı
        self.assertEqual(doc.status, ls.STATUS_LOCK_HARD)
        self.assertEqual(doc.grace_until, NOW)

    def test_apply_grace_on_failure_at_24h_boundary(self):
        doc = _StubDoc()
        # Tam 24 saat önce (soft window sınırında)
        doc.last_validated = NOW - timedelta(hours=24)
        ls._apply_grace_on_failure(doc, reason="Network issue")
        # 24 saatte tam sınırda, hala GRACE_SOFT
        self.assertEqual(doc.status, ls.STATUS_GRACE_SOFT)
        self.assertEqual(doc.grace_until, NOW)

    def test_apply_grace_on_failure_at_48h_boundary(self):
        doc = _StubDoc()
        # Tam 48 saat önce (hard window sınırında)
        doc.last_validated = NOW - timedelta(hours=48)
        ls._apply_grace_on_failure(doc, reason="Extended outage")
        # 48 saatte >= kontrolü olduğu için LOCK_HARD olmalı
        self.assertEqual(doc.status, ls.STATUS_LOCK_HARD)
        self.assertEqual(doc.grace_until, NOW)

    def test_apply_grace_on_failure_just_before_48h(self):
        doc = _StubDoc()
        # 47.5 saat önce (48 saatten hemen önce)
        doc.last_validated = NOW - timedelta(hours=47, minutes=30)
        ls._apply_grace_on_failure(doc, reason="Almost expired")
        # Henüz 48 saat geçmediği için hala GRACE_SOFT
        self.assertEqual(doc.status, ls.STATUS_GRACE_SOFT)
        self.assertEqual(doc.grace_until, NOW)

    def test_clear_grace(self):
        doc = _StubDoc()
        doc.grace_until = NOW
        doc.status = ls.STATUS_GRACE_SOFT
        ls._clear_grace(doc)
        self.assertIsNone(doc.grace_until)
        self.assertEqual(doc.status, ls.STATUS_VALIDATED)
        self.assertEqual(doc.reason, "Grace cleared after success")

    def test_clear_grace_with_lock_hard(self):
        doc = _StubDoc()
        doc.grace_until = NOW
        doc.status = ls.STATUS_LOCK_HARD
        ls._clear_grace(doc)
        self.assertIsNone(doc.grace_until)
        self.assertEqual(doc.status, ls.STATUS_VALIDATED)

    # ------------------------
    # Apply update tests
    # ------------------------
    def test_apply_activation_update(self):
        doc = _StubDoc()
        data = {"expiresAt": "2025-12-31 00:00:00"}
        ls._apply_activation_update(doc, data)
        self.assertEqual(doc.status, ls.STATUS_ACTIVE)
        self.assertEqual(doc.reason, "Activated")
        self.assertIsNotNone(doc.last_validated)
        self.assertIsNone(doc.grace_until)
        self.assertEqual(doc.expires_at, _ts("2025-12-31 00:00:00"))

    def test_apply_deactivation_update(self):
        doc = _StubDoc()
        data = {"expiresAt": "2025-12-31 00:00:00"}
        ls._apply_deactivation_update(doc, data)
        self.assertEqual(doc.status, ls.STATUS_DEACTIVATED)
        self.assertEqual(doc.reason, "Deactivated")
        self.assertEqual(doc.expires_at, _ts("2025-12-31 00:00:00"))

    def test_apply_validation_update_with_active_activation(self):
        doc = _StubDoc()
        data = {
            "expiresAt": "2025-12-31 00:00:00",
            "activationData": [{"deactivated_at": None}],
            "timesActivated": 1,
        }
        ls._apply_validation_update(doc, data)
        self.assertEqual(doc.status, ls.STATUS_VALIDATED)
        self.assertEqual(doc.reason, "Validated")
        self.assertIsNone(doc.grace_until)

    def test_apply_validation_update_no_active_activation(self):
        doc = _StubDoc()
        data = {
            "expiresAt": "2025-12-31 00:00:00",
            "activationData": [],
            "timesActivated": 0,
        }
        ls._apply_validation_update(doc, data)
        self.assertEqual(doc.status, ls.STATUS_DEACTIVATED)
        self.assertEqual(doc.reason, "Validated (no active activation)")

    def test_apply_validation_update_keeps_expired_status(self):
        doc = _StubDoc()
        doc.status = ls.STATUS_EXPIRED
        doc.reason = "Previously expired"
        data = {
            "expiresAt": "2025-12-31 00:00:00",
            "activationData": [{"deactivated_at": None}],
            "timesActivated": 1,
        }
        ls._apply_validation_update(doc, data)
        self.assertEqual(doc.status, ls.STATUS_EXPIRED)
        # Reason should be preserved or updated with expired context
        self.assertIn("expired", doc.reason.lower())

    def test_apply_validation_update_marks_expired_if_date_passed(self):
        doc = _StubDoc()
        # Expiry date in the past
        data = {
            "expiresAt": "2025-01-01 00:00:00",
            "activationData": [{"deactivated_at": None}],
            "timesActivated": 1,
        }
        ls._apply_validation_update(doc, data)
        self.assertEqual(doc.status, ls.STATUS_EXPIRED)
        self.assertEqual(doc.grace_until, NOW)

    # ------------------------
    # Error handling tests
    # ------------------------
    def test_activate_license_missing_license_key(self):
        self.doc.license_key = None
        with self.assertRaises(frappe.ValidationError):
            ls.activate_license()

    def test_activate_license_request_error(self):
        self.doc.license_key = "LIC-FAIL"
        client = MagicMock()
        client.activate.side_effect = LMFWCRequestError("Network error", status=500)
        
        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            with self.assertRaises(frappe.ValidationError):
                ls.activate_license()

    def test_validate_license_missing_license_key(self):
        self.doc.license_key = None
        with self.assertRaises(frappe.ValidationError):
            ls.validate_license()

    def test_deactivate_license_missing_token(self):
        self.doc.license_key = "LIC-X"
        self.doc.activation_token = None
        with self.assertRaises(frappe.ValidationError):
            ls.deactivate_license()

    def test_reactivate_license_missing_license_key(self):
        self.doc.license_key = None
        with self.assertRaises(frappe.ValidationError):
            ls.reactivate_license()

    # ------------------------
    # Preflight refresh tests
    # ------------------------
    def test_preflight_refresh_token_updates_token(self):
        self.doc.license_key = "LIC-PRE"
        self.doc.activation_token = "old-token"
        
        payload = {
            "success": True,
            "data": {
                "activationData": {"token": "new-token", "deactivated_at": None}
            },
        }
        
        client = MagicMock()
        client.validate.return_value = payload
        
        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            ls._preflight_refresh_token(self.doc, "LIC-PRE")
        
        self.assertEqual(self.doc.activation_token, "new-token")

    def test_preflight_refresh_token_handles_errors_silently(self):
        self.doc.license_key = "LIC-FAIL"
        
        client = MagicMock()
        client.validate.side_effect = Exception("Network failure")
        
        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            # Should not raise
            ls._preflight_refresh_token(self.doc, "LIC-FAIL")

    # ------------------------
    # Reactivate retry logic tests
    # ------------------------
    def test_reactivate_license_retry_on_activation_limit(self):
        self.doc.license_key = "LIC-LIMIT"
        self.doc.activation_token = "old-token"
        
        preflight1 = {
            "success": True,
            "data": {"activationData": {"token": "token1", "deactivated_at": None}},
        }
        preflight2 = {
            "success": True,
            "data": {"activationData": {"token": "token2-fresh", "deactivated_at": None}},
        }
        activate_success = {
            "success": True,
            "data": {"expiresAt": "2026-01-01 00:00:00"},
        }
        
        client = MagicMock()
        # Two validate calls: initial preflight + retry preflight
        client.validate.side_effect = [preflight1, preflight2]
        # First activate fails with limit error, second succeeds with new token
        client.activate.side_effect = [
            LMFWCContractError("maximum activation limit reached"),
            activate_success,
        ]
        
        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            result = ls.reactivate_license()
        
        self.assertEqual(result, activate_success["data"])
        # Should have called activate twice (first failed, second succeeded)
        self.assertEqual(client.activate.call_count, 2)
        # Should have called validate twice (initial + retry preflight)
        self.assertEqual(client.validate.call_count, 2)

    def test_reactivate_license_expired_on_first_attempt(self):
        self.doc.license_key = "LIC-EXP"
        
        preflight = {
            "success": True,
            "data": {"activationData": {"token": "tok-pre", "deactivated_at": None}},
        }
        
        expired_error = LMFWCContractError("License expired on 2025-10-01 00:00:00 (UTC)")
        
        client = MagicMock()
        client.validate.return_value = preflight
        client.activate.side_effect = expired_error
        
        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            with self.assertRaises(frappe.ValidationError):
                ls.reactivate_license()
        
        # Should be marked expired
        self.assertEqual(self.doc.status, ls.STATUS_EXPIRED)

    # ------------------------
    # New grace period tests (48h window)
    # ------------------------
    def test_validate_license_network_error_applies_grace_within_48h(self):
        """Network hatası olduğunda 48 saat içinde grace period uygulanmalı"""
        self.doc.license_key = "LIC-NET"
        self.doc.last_validated = NOW - timedelta(hours=30)
        
        client = MagicMock()
        client.validate.side_effect = LMFWCRequestError("Connection timeout", status=0)
        
        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            with self.assertRaises(frappe.ValidationError):
                ls.validate_license()
        
        # 30 saat sonra hala grace period içinde
        self.assertIn(self.doc.status, [ls.STATUS_GRACE_SOFT])
        self.assertIsNotNone(self.doc.grace_until)

    def test_validate_license_multiple_failures_over_48h(self):
        """48 saatten fazla süren hatalar sonunda hard lock olmalı"""
        self.doc.license_key = "LIC-LONG-FAIL"
        self.doc.last_validated = NOW - timedelta(hours=49)
        
        client = MagicMock()
        client.validate.side_effect = LMFWCRequestError("Server unavailable", status=503)
        
        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            with self.assertRaises(frappe.ValidationError):
                ls.validate_license()
        
        # 49 saat sonra hard lock olmalı
        self.assertEqual(self.doc.status, ls.STATUS_LOCK_HARD)
        self.assertIsNotNone(self.doc.grace_until)

    def test_scheduled_validate_grace_period_success_clears_grace(self):
        """Grace period'daki bir sistemde başarılı validation grace'i temizlemeli"""
        self.doc.license_key = "LIC-RECOVER"
        self.doc.status = ls.STATUS_GRACE_SOFT
        self.doc.grace_until = NOW - timedelta(hours=1)
        self.doc.last_validated = NOW - timedelta(hours=20)
        
        payload = {
            "success": True,
            "data": {
                "expiresAt": "2025-12-31 00:00:00",
                "activationData": [{"token": "tok-ok", "deactivated_at": None}],
                "timesActivated": 1,
            },
        }
        
        client = MagicMock()
        client.validate.return_value = payload
        
        with patch("brv_license_app.brv_license_app.doctype.license_settings.license_settings.get_client", return_value=client):
            result = ls.validate_license()
        
        # Grace temizlenmeli, sistem VALIDATED'a dönmeli
        self.assertEqual(self.doc.status, ls.STATUS_VALIDATED)
        self.assertIsNone(self.doc.grace_until)
        self.assertIsNotNone(self.doc.last_validated)


if __name__ == "__main__":
    unittest.main()
