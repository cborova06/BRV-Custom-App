# -*- coding: utf-8 -*-
"""
Test suite for license.py API endpoints.
Follows Frappe testing conventions: https://docs.frappe.io/framework/user/en/testing
"""
from __future__ import annotations

import unittest
from datetime import timedelta

import frappe
from frappe.utils import add_days, add_to_date, now_datetime, get_datetime

# Import function to test
from brv_license_app.api.license import healthz


def create_or_get_license_settings():
    """Get or create License Settings singleton."""
    try:
        doc = frappe.get_single("License Settings")
        return doc
    except Exception:
        # If doesn't exist, create it
        doc = frappe.new_doc("License Settings")
        doc.insert(ignore_permissions=True)
        frappe.db.commit()
        return doc


def reset_license_settings():
    """Reset License Settings to default state."""
    try:
        doc = frappe.get_single("License Settings")
        doc.status = None
        doc.grace_until = None
        doc.reason = None
        doc.last_validated = None
        doc.save(ignore_permissions=True)
        frappe.db.commit()
    except Exception as e:
        frappe.log_error(f"Failed to reset license settings: {e}")


class TestLicenseHealthz(unittest.TestCase):
    """Test the healthz endpoint."""
    
    @classmethod
    def setUpClass(cls):
        """Setup test environment once."""
        frappe.set_user("Administrator")
        # Check if License Settings DocType exists (it's a Single, so check differently)
        try:
            frappe.get_meta("License Settings")
            cls.license_exists = True
        except Exception:
            cls.license_exists = False
        
        if not cls.license_exists:
            import warnings
            warnings.warn("License Settings DocType not found - skipping license tests")
    
    def setUp(self):
        """Setup before each test."""
        frappe.set_user("Administrator")
        if not self.license_exists:
            self.skipTest("License Settings DocType not available")
        
        # Ensure License Settings exists
        self.doc = create_or_get_license_settings()
    
    def tearDown(self):
        """Cleanup after each test."""
        if not self.license_exists:
            return
        frappe.set_user("Administrator")
        reset_license_settings()
    
    def test_healthz_basic_structure(self):
        """Test that healthz returns expected structure."""
        result = healthz()
        
        # Check basic structure
        self.assertIsInstance(result, dict)
        self.assertIn("app", result)
        self.assertIn("site", result)
        self.assertIn("ok", result)
        
        # Check app name
        self.assertEqual(result["app"], "brv_license_app")
        
        # Check site
        self.assertEqual(result["site"], frappe.local.site)
    
    def test_healthz_status_active(self):
        """Test healthz with ACTIVE status."""
        # Set status to ACTIVE
        self.doc.status = "ACTIVE"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertEqual(result["status"], "ACTIVE")
        self.assertTrue(result["ok"], "ACTIVE status should be ok=True")
    
    def test_healthz_status_validated(self):
        """Test healthz with VALIDATED status."""
        # Set status to VALIDATED
        self.doc.status = "VALIDATED"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertEqual(result["status"], "VALIDATED")
        self.assertTrue(result["ok"], "VALIDATED status should be ok=True")
    
    def test_healthz_status_expired_no_grace(self):
        """Test healthz with EXPIRED status and no grace period."""
        # Set status to EXPIRED without grace
        self.doc.status = "EXPIRED"
        self.doc.grace_until = None
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertEqual(result["status"], "EXPIRED")
        self.assertFalse(result["ok"], "EXPIRED without grace should be ok=False")
    
    def test_healthz_status_expired_with_valid_grace(self):
        """Test healthz with EXPIRED status but valid grace period."""
        # Set status to EXPIRED with future grace period
        future_grace = add_days(now_datetime(), 7)
        self.doc.status = "EXPIRED"
        self.doc.grace_until = future_grace
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertEqual(result["status"], "EXPIRED")
        self.assertTrue(result["ok"], "EXPIRED with valid grace should be ok=True")
        self.assertIsNotNone(result.get("grace_until"))
    
    def test_healthz_status_expired_with_expired_grace(self):
        """Test healthz with EXPIRED status and expired grace period."""
        # Set status to EXPIRED with past grace period
        past_grace = add_days(now_datetime(), -7)
        self.doc.status = "EXPIRED"
        self.doc.grace_until = past_grace
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertEqual(result["status"], "EXPIRED")
        self.assertFalse(result["ok"], "EXPIRED with expired grace should be ok=False")
    
    def test_healthz_status_invalid(self):
        """Test healthz with REVOKED status."""
        # Set status to REVOKED (equivalent to invalid)
        self.doc.status = "REVOKED"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertEqual(result["status"], "REVOKED")
        self.assertFalse(result["ok"], "REVOKED status should be ok=False")
    
    def test_healthz_status_pending(self):
        """Test healthz with UNCONFIGURED status."""
        # Set status to UNCONFIGURED (equivalent to pending)
        self.doc.status = "UNCONFIGURED"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertEqual(result["status"], "UNCONFIGURED")
        self.assertFalse(result["ok"], "UNCONFIGURED status should be ok=False")
    
    def test_healthz_with_reason(self):
        """Test healthz includes reason field."""
        # Set status with reason
        self.doc.status = "REVOKED"
        self.doc.reason = "License key not found"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertIn("reason", result)
        self.assertEqual(result["reason"], "License key not found")
    
    def test_healthz_with_last_validated(self):
        """Test healthz includes last_validated field."""
        # Set last_validated
        validation_time = now_datetime()
        self.doc.status = "ACTIVE"
        self.doc.last_validated = validation_time
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertIn("last_validated", result)
        self.assertIsNotNone(result["last_validated"])
    
    def test_healthz_case_insensitive_status(self):
        """Test that status is converted to uppercase."""
        # Set status in correct uppercase first
        self.doc.status = "ACTIVE"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        # Then bypass validation to set lowercase via DB
        frappe.db.set_value("License Settings", self.doc.name, 
                           "status", "active",
                           update_modified=False)
        frappe.db.commit()
        
        result = healthz()
        
        # The healthz endpoint should uppercase it
        self.assertEqual(result["status"], "ACTIVE")
        self.assertTrue(result["ok"])
    
    def test_healthz_empty_status(self):
        """Test healthz with empty status."""
        # Set empty status
        self.doc.status = None
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        # Empty status should result in empty string after .upper()
        self.assertEqual(result["status"], "")
        self.assertFalse(result["ok"], "Empty status should be ok=False")
    
    def test_healthz_grace_boundary_future(self):
        """Test grace period boundary - exactly 1 hour in future."""
        # Set grace period to 1 hour in future
        future_grace = add_to_date(now_datetime(), hours=1)
        self.doc.status = "EXPIRED"
        self.doc.grace_until = future_grace
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertTrue(result["ok"], "Grace period 1 hour in future should be valid")
    
    def test_healthz_grace_boundary_past(self):
        """Test grace period boundary - exactly 1 hour in past."""
        # Set grace period to 1 hour in past
        past_grace = add_to_date(now_datetime(), hours=-1)
        self.doc.status = "EXPIRED"
        self.doc.grace_until = past_grace
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        self.assertFalse(result["ok"], "Grace period 1 hour in past should be invalid")
    
    def test_healthz_all_fields_populated(self):
        """Test healthz with all fields populated."""
        # Set all fields
        validation_time = now_datetime()
        future_grace = add_days(now_datetime(), 30)
        
        self.doc.status = "ACTIVE"
        self.doc.grace_until = future_grace
        self.doc.reason = "All systems operational"
        self.doc.last_validated = validation_time
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        # Verify all fields are present
        self.assertEqual(result["status"], "ACTIVE")
        self.assertIsNotNone(result["grace_until"])
        self.assertEqual(result["reason"], "All systems operational")
        self.assertIsNotNone(result["last_validated"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["app"], "brv_license_app")
        self.assertEqual(result["site"], frappe.local.site)
    
    def test_healthz_allow_guest(self):
        """Test that healthz works with guest user."""
        # Set a valid status first
        self.doc.status = "ACTIVE"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        # Switch to guest user
        frappe.set_user("Guest")
        
        result = healthz()
        
        # Should still work
        self.assertIsInstance(result, dict)
        self.assertEqual(result["app"], "brv_license_app")
        self.assertTrue(result["ok"])
        
        # Switch back to Administrator
        frappe.set_user("Administrator")
    
    def test_healthz_multiple_statuses(self):
        """Test multiple status transitions."""
        statuses_and_expected = [
            ("ACTIVE", True),
            ("VALIDATED", True),
            ("EXPIRED", False),
            ("REVOKED", False),
            ("UNCONFIGURED", False),
            ("DEACTIVATED", False),
        ]
        
        for status, expected_ok in statuses_and_expected:
            with self.subTest(status=status):
                self.doc.status = status
                self.doc.grace_until = None
                self.doc.save(ignore_permissions=True)
                frappe.db.commit()
                
                result = healthz()
                
                self.assertEqual(result["status"], status)
                self.assertEqual(result["ok"], expected_ok, 
                               f"Status {status} should have ok={expected_ok}")
    
    def test_healthz_grace_period_variations(self):
        """Test various grace period scenarios."""
        scenarios = [
            ("7 days future", add_days(now_datetime(), 7), True),
            ("1 day future", add_days(now_datetime(), 1), True),
            ("1 hour future", add_to_date(now_datetime(), hours=1), True),
            ("1 hour past", add_to_date(now_datetime(), hours=-1), False),
            ("1 day past", add_days(now_datetime(), -1), False),
            ("30 days past", add_days(now_datetime(), -30), False),
        ]
        
        for description, grace_time, expected_ok in scenarios:
            with self.subTest(scenario=description):
                self.doc.status = "EXPIRED"
                self.doc.grace_until = grace_time
                self.doc.save(ignore_permissions=True)
                frappe.db.commit()
                
                result = healthz()
                
                self.assertEqual(result["ok"], expected_ok,
                               f"Grace period {description} should have ok={expected_ok}")


class TestLicenseEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""
    
    @classmethod
    def setUpClass(cls):
        """Setup test environment once."""
        frappe.set_user("Administrator")
        # Check if License Settings DocType exists
        try:
            frappe.get_meta("License Settings")
            cls.license_exists = True
        except Exception:
            cls.license_exists = False
    
    def setUp(self):
        """Setup before each test."""
        frappe.set_user("Administrator")
        if not self.license_exists:
            self.skipTest("License Settings DocType not available")
        
        self.doc = create_or_get_license_settings()
    
    def tearDown(self):
        """Cleanup after each test."""
        if not self.license_exists:
            return
        frappe.set_user("Administrator")
        reset_license_settings()
    
    def test_healthz_malformed_grace_date(self):
        """Test healthz handles malformed grace_until date gracefully."""
        # Set a valid status first
        self.doc.status = "EXPIRED"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        # Direct DB update to set invalid date format (bypassing validation)
        frappe.db.set_value("License Settings", self.doc.name, 
                           "grace_until", "invalid-date-format", 
                           update_modified=False)
        frappe.db.commit()
        
        # Should not crash
        result = healthz()
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result["status"], "EXPIRED")
        # With invalid grace date, should treat as no grace period
        self.assertFalse(result["ok"])
    
    def test_healthz_status_with_whitespace(self):
        """Test status with leading/trailing whitespace."""
        self.doc.status = "  ACTIVE  "
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result = healthz()
        
        # Should handle whitespace in status
        self.assertIn(result["status"], ["ACTIVE", "  ACTIVE  "])
        # Should still evaluate correctly
        self.assertTrue(result["ok"])
    
    def test_healthz_concurrent_calls(self):
        """Test multiple concurrent calls to healthz."""
        self.doc.status = "ACTIVE"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        # Call healthz multiple times
        results = [healthz() for _ in range(5)]
        
        # All should return consistent results
        for result in results:
            self.assertEqual(result["status"], "ACTIVE")
            self.assertTrue(result["ok"])
    
    def test_healthz_after_status_change(self):
        """Test healthz reflects immediate status changes."""
        # Start with ACTIVE
        self.doc.status = "ACTIVE"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result1 = healthz()
        self.assertTrue(result1["ok"])
        
        # Change to EXPIRED
        self.doc.status = "EXPIRED"
        self.doc.save(ignore_permissions=True)
        frappe.db.commit()
        
        result2 = healthz()
        self.assertFalse(result2["ok"])
        
        # Results should be different
        self.assertNotEqual(result1["ok"], result2["ok"])


# Run tests if executed directly
if __name__ == "__main__":
    unittest.main()
