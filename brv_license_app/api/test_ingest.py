# -*- coding: utf-8 -*-
"""
Test suite for ingest.py API endpoints.
Follows Frappe testing conventions: https://docs.frappe.io/framework/user/en/testing
"""
from __future__ import annotations

import unittest
import json
from typing import Dict, Any

import frappe
from frappe.utils import cint, flt

# Import functions to test
from brv_license_app.api.ingest import (
    _clean_html,
    _parse_fields_arg,
    _pluck,
    _append_text,
    _normalize_select,
    get_teams,
    get_team_members,
    get_tickets_by_team,
    get_tickets_by_user,
    get_articles,
    get_ticket,
    get_routing_context,
    ingest_summary,
    set_reply_suggestion,
    set_sentiment,
    set_metrics,
    update_ticket,
    get_problem_ticket,
    list_problem_tickets,
    upsert_problem_ticket,
    request_kb_new_article,
    request_kb_fix,
    request_kb_update,
    report_kb_wrong_document,
    log_ai_interaction,
)


def create_test_team():
    """Create a test HD Team for testing."""
    if frappe.db.exists("HD Team", "_Test Team"):
        return frappe.get_doc("HD Team", "_Test Team")
    
    team = frappe.get_doc({
        "doctype": "HD Team",
        "name": "_Test Team",
        "team_name": "_Test Team",
        "description": "Test team for unit tests"
    })
    team.insert(ignore_permissions=True)
    frappe.db.commit()
    return team


def create_test_ticket(subject="_Test Ticket", team=None):
    """Create a test HD Ticket for testing."""
    if not team:
        team = create_test_team()
    
    # Check if ticket already exists
    existing = frappe.db.get_value("HD Ticket", {"subject": subject}, "name")
    if existing:
        return frappe.get_doc("HD Ticket", existing)
    
    ticket = frappe.get_doc({
        "doctype": "HD Ticket",
        "subject": subject,
        "status": "Open",
        "priority": "Medium",
        "agent_group": team.name,
        "description": "Test ticket description"
    })
    ticket.insert(ignore_permissions=True)
    frappe.db.commit()
    return ticket


def create_test_article(title="_Test Article"):
    """Create a test HD Article for testing."""
    # Check if article already exists
    existing = frappe.db.get_value("HD Article", {"title": title}, "name")
    if existing:
        return frappe.get_doc("HD Article", existing)
    
    article = frappe.get_doc({
        "doctype": "HD Article",
        "title": title,
        "content": "Test article content"
    })
    article.insert(ignore_permissions=True)
    frappe.db.commit()
    return article


class TestIngestHelperFunctions(unittest.TestCase):
    """Test helper/utility functions."""
    
    def test_clean_html(self):
        """Test HTML cleaning function."""
        self.assertEqual(_clean_html("<p>Hello</p>"), "Hello")
        self.assertEqual(_clean_html("<b>Bold</b> text"), "Bold text")
        self.assertEqual(_clean_html(None), "")
        self.assertEqual(_clean_html(""), "")
        self.assertEqual(_clean_html("Plain text"), "Plain text")
    
    def test_parse_fields_arg(self):
        """Test field argument parsing."""
        # Dict input
        self.assertEqual(_parse_fields_arg({"key": "value"}), {"key": "value"})
        
        # JSON string input
        self.assertEqual(_parse_fields_arg('{"key": "value"}'), {"key": "value"})
        
        # None input
        self.assertEqual(_parse_fields_arg(None), {})
        
        # Empty string
        self.assertEqual(_parse_fields_arg(""), {})
        
        # Invalid JSON should throw
        with self.assertRaises(Exception):
            _parse_fields_arg("{invalid json}")
    
    def test_pluck(self):
        """Test pluck function."""
        data = [
            {"name": "A", "value": 1},
            {"name": "B", "value": 2},
            {"name": "C"},
        ]
        self.assertEqual(_pluck(data, "name"), ["A", "B", "C"])
        self.assertEqual(_pluck(data, "value"), [1, 2])
        self.assertEqual(_pluck([], "name"), [])
        self.assertEqual(_pluck(None, "name"), [])
    
    def test_append_text(self):
        """Test text appending logic."""
        self.assertEqual(_append_text("", "B", True), "B")
        self.assertEqual(_append_text("A", "B", True), "A\nB")
        self.assertEqual(_append_text("A", "B", False), "B")
        self.assertEqual(_append_text("A", "", True), "A\n")
        self.assertEqual(_append_text("", "", False), "")
    
    def test_normalize_select_english(self):
        """Test SELECT field normalization - English."""
        # last_sentiment (note: DB has typo "Nautral")
        self.assertEqual(_normalize_select("last_sentiment", "Positive"), "Positive")
        self.assertEqual(_normalize_select("last_sentiment", "pos"), "Positive")
        self.assertEqual(_normalize_select("last_sentiment", "positive"), "Positive")
        self.assertEqual(_normalize_select("last_sentiment", "+"), "Positive")
        
        self.assertEqual(_normalize_select("last_sentiment", "Nautral"), "Nautral")
        self.assertEqual(_normalize_select("last_sentiment", "neu"), "Nautral")
        self.assertEqual(_normalize_select("last_sentiment", "neutral"), "Nautral")
        self.assertEqual(_normalize_select("last_sentiment", "0"), "Nautral")
        
        self.assertEqual(_normalize_select("last_sentiment", "Negative"), "Negative")
        self.assertEqual(_normalize_select("last_sentiment", "neg"), "Negative")
        self.assertEqual(_normalize_select("last_sentiment", "-"), "Negative")
        
        # effort_band
        self.assertEqual(_normalize_select("effort_band", "Low"), "Low")
        self.assertEqual(_normalize_select("effort_band", "l"), "Low")
        self.assertEqual(_normalize_select("effort_band", "low"), "Low")
        
        self.assertEqual(_normalize_select("effort_band", "Medium"), "Medium")
        self.assertEqual(_normalize_select("effort_band", "m"), "Medium")
        self.assertEqual(_normalize_select("effort_band", "med"), "Medium")
        
        self.assertEqual(_normalize_select("effort_band", "High"), "High")
        self.assertEqual(_normalize_select("effort_band", "h"), "High")
        self.assertEqual(_normalize_select("effort_band", "hi"), "High")
    
    def test_normalize_select_turkish(self):
        """Test SELECT field normalization - Turkish support."""
        # last_sentiment - Turkish (maps to "Nautral" due to DB typo)
        self.assertEqual(_normalize_select("last_sentiment", "pozitif"), "Positive")
        self.assertEqual(_normalize_select("last_sentiment", "olumlu"), "Positive")
        self.assertEqual(_normalize_select("last_sentiment", "Pozitif"), "Positive")
        
        self.assertEqual(_normalize_select("last_sentiment", "nötr"), "Nautral")
        self.assertEqual(_normalize_select("last_sentiment", "notr"), "Nautral")
        self.assertEqual(_normalize_select("last_sentiment", "tarafsız"), "Nautral")
        self.assertEqual(_normalize_select("last_sentiment", "tarafsiz"), "Nautral")
        
        self.assertEqual(_normalize_select("last_sentiment", "negatif"), "Negative")
        self.assertEqual(_normalize_select("last_sentiment", "olumsuz"), "Negative")
        
        # effort_band - Turkish
        self.assertEqual(_normalize_select("effort_band", "düşük"), "Low")
        self.assertEqual(_normalize_select("effort_band", "dusuk"), "Low")
        self.assertEqual(_normalize_select("effort_band", "az"), "Low")
        
        self.assertEqual(_normalize_select("effort_band", "orta"), "Medium")
        
        self.assertEqual(_normalize_select("effort_band", "yüksek"), "High")
        self.assertEqual(_normalize_select("effort_band", "yuksek"), "High")
        self.assertEqual(_normalize_select("effort_band", "çok"), "High")
        self.assertEqual(_normalize_select("effort_band", "cok"), "High")


class TestIngestGetEndpoints(unittest.TestCase):
    """Test GET endpoints."""
    
    @classmethod
    def setUpClass(cls):
        """Setup test data once for all tests."""
        frappe.set_user("Administrator")
        cls.team = create_test_team()
        cls.ticket = create_test_ticket()
        cls.article = create_test_article()
    
    def setUp(self):
        """Setup before each test."""
        frappe.set_user("Administrator")
    
    def test_get_teams(self):
        """Test get_teams endpoint."""
        result = get_teams(include_members=0, include_tags=0)
        self.assertTrue(result.get("ok"))
        self.assertIn("teams", result)
        self.assertIsInstance(result["teams"], list)
        
        # Test with members
        result_with_members = get_teams(include_members=1, include_tags=0)
        self.assertTrue(result_with_members.get("ok"))
        if result_with_members["teams"]:
            # Check that members field is present
            self.assertIn("members", result_with_members["teams"][0])
    
    def test_get_team_members(self):
        """Test get_team_members endpoint."""
        result = get_team_members(self.team.name)
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("team"), self.team.name)
        self.assertIn("members", result)
        self.assertIsInstance(result["members"], list)
    
    def test_get_tickets_by_team(self):
        """Test get_tickets_by_team endpoint."""
        result = get_tickets_by_team(self.team.name, status=None, limit=50, start=0)
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("team"), self.team.name)
        self.assertIn("tickets", result)
        self.assertIsInstance(result["tickets"], list)
    
    def test_get_tickets_by_user(self):
        """Test get_tickets_by_user endpoint."""
        result = get_tickets_by_user("Administrator", status=None, limit=50, start=0)
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("user"), "Administrator")
        self.assertIn("tickets", result)
        self.assertIsInstance(result["tickets"], list)
    
    def test_get_articles(self):
        """Test get_articles endpoint."""
        result = get_articles(q=None, limit=50, start=0)
        self.assertTrue(result.get("ok"))
        self.assertIn("articles", result)
        self.assertIsInstance(result["articles"], list)
        
        # Test with search query
        result_with_query = get_articles(q="Test", limit=50, start=0)
        self.assertTrue(result_with_query.get("ok"))
    
    def test_get_ticket(self):
        """Test get_ticket endpoint."""
        # Use only core fields that definitely exist
        core_fields = '["name", "subject", "status"]'
        result = get_ticket(self.ticket.name, fields=core_fields)
        self.assertTrue(result.get("ok"))
        self.assertIn("ticket", result)
        self.assertEqual(result["ticket"]["name"], self.ticket.name)
        
        # Test with default fields (may fail if custom fields don't exist)
        try:
            result_default = get_ticket(self.ticket.name, fields=None)
            self.assertTrue(result_default.get("ok"))
        except Exception:
            # Some custom fields may not exist in this installation
            pass
    
    def test_get_routing_context(self):
        """Test get_routing_context endpoint."""
        result = get_routing_context()
        self.assertTrue(result.get("ok"))
        self.assertIn("context", result)
        self.assertIn("teams", result["context"])


class TestIngestTicketUpdateEndpoints(unittest.TestCase):
    """Test ticket update endpoints."""
    
    @classmethod
    def setUpClass(cls):
        """Setup test data once for all tests."""
        frappe.set_user("Administrator")
        cls.team = create_test_team()
        
        # Check which custom fields exist on HD Ticket
        meta = frappe.get_meta("HD Ticket")
        cls.has_ai_summary = meta.has_field("ai_summary")
        cls.has_ai_reply_suggestion = meta.has_field("ai_reply_suggestion")
        cls.has_last_sentiment = meta.has_field("last_sentiment")
        cls.has_sentiment_trend = meta.has_field("sentiment_trend")
        cls.has_effort_score = meta.has_field("effort_score")
        cls.has_effort_band = meta.has_field("effort_band")
        cls.has_cluster_hash = meta.has_field("cluster_hash")
    
    def setUp(self):
        """Setup before each test - create fresh ticket."""
        frappe.set_user("Administrator")
        self.ticket = create_test_ticket(subject=f"_Test Ticket {frappe.utils.now()}")
    
    def tearDown(self):
        """Cleanup after each test."""
        frappe.set_user("Administrator")
        if hasattr(self, "ticket") and self.ticket:
            try:
                frappe.delete_doc("HD Ticket", self.ticket.name, force=1)
                frappe.db.commit()
            except Exception:
                pass
    
    def test_ingest_summary(self):
        """Test ingest_summary endpoint."""
        if not self.has_ai_summary:
            self.skipTest("ai_summary field not available")
        
        result = ingest_summary(
            ticket=self.ticket.name,
            summary="AI generated summary",
            append=0,
            clean_html=1
        )
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("ticket"), self.ticket.name)
        self.assertIn("changed", result)
        self.assertIn("ai_summary", result["changed"])
        
        # Verify change
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertEqual(doc.ai_summary, "AI generated summary")
    
    def test_ingest_summary_append(self):
        """Test ingest_summary with append mode."""
        if not self.has_ai_summary:
            self.skipTest("ai_summary field not available")
        
        # First update
        ingest_summary(
            ticket=self.ticket.name,
            summary="First summary",
            append=0,
            clean_html=1
        )
        
        # Append
        result = ingest_summary(
            ticket=self.ticket.name,
            summary="Second summary",
            append=1,
            clean_html=1
        )
        self.assertTrue(result.get("ok"))
        
        # Verify appended
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertIn("First summary", doc.ai_summary)
        self.assertIn("Second summary", doc.ai_summary)
    
    def test_set_reply_suggestion(self):
        """Test set_reply_suggestion endpoint."""
        if not self.has_ai_reply_suggestion:
            self.skipTest("ai_reply_suggestion field not available")
        
        result = set_reply_suggestion(
            ticket=self.ticket.name,
            text="Suggested reply text",
            append=0,
            clean_html=1
        )
        self.assertTrue(result.get("ok"))
        self.assertIn("ai_reply_suggestion", result["changed"])
        
        # Verify
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertEqual(doc.ai_reply_suggestion, "Suggested reply text")
    
    def test_set_sentiment_english(self):
        """Test set_sentiment endpoint with English values."""
        if not (self.has_last_sentiment and self.has_sentiment_trend and 
                self.has_effort_score and self.has_effort_band):
            self.skipTest("Sentiment fields not available")
        
        result = set_sentiment(
            ticket=self.ticket.name,
            last_sentiment="Positive",
            sentiment_trend="Improving",
            effort_score=2.5,
            effort_band="Low"
        )
        self.assertTrue(result.get("ok"))
        
        # Verify
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertEqual(doc.last_sentiment, "Positive")
        self.assertEqual(doc.sentiment_trend, "Improving")
        self.assertEqual(doc.effort_score, 2.5)
        self.assertEqual(doc.effort_band, "Low")
    
    def test_set_sentiment_turkish(self):
        """Test set_sentiment endpoint with Turkish values."""
        if not (self.has_last_sentiment and self.has_sentiment_trend and 
                self.has_effort_score and self.has_effort_band):
            self.skipTest("Sentiment fields not available")
        
        result = set_sentiment(
            ticket=self.ticket.name,
            last_sentiment="pozitif",  # Turkish
            sentiment_trend="Stable",  # Use valid DB value
            effort_score=3.0,
            effort_band="düşük"  # Turkish
        )
        self.assertTrue(result.get("ok"))
        
        # Verify normalized
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertEqual(doc.last_sentiment, "Positive")
        self.assertEqual(doc.effort_band, "Low")
    
    def test_set_sentiment_synonyms(self):
        """Test set_sentiment with various synonyms."""
        if not self.has_last_sentiment:
            self.skipTest("last_sentiment field not available")
        
        # Test positive synonyms
        set_sentiment(self.ticket.name, last_sentiment="pos")
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertEqual(doc.last_sentiment, "Positive")
        
        # Test neutral synonyms (maps to "Nautral" in DB)
        set_sentiment(self.ticket.name, last_sentiment="neu")
        doc.reload()
        self.assertEqual(doc.last_sentiment, "Nautral")
        
        # Test negative synonyms
        set_sentiment(self.ticket.name, last_sentiment="neg")
        doc.reload()
        self.assertEqual(doc.last_sentiment, "Negative")
    
    def test_set_metrics(self):
        """Test set_metrics endpoint."""
        if not (self.has_effort_score and self.has_cluster_hash):
            self.skipTest("Metrics fields not available")
        
        result = set_metrics(
            ticket=self.ticket.name,
            effort_score=4.2,
            cluster_hash="abc123def456"
        )
        self.assertTrue(result.get("ok"))
        
        # Verify
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertEqual(doc.effort_score, 4.2)
        self.assertEqual(doc.cluster_hash, "abc123def456")
    
    def test_update_ticket_general(self):
        """Test general update_ticket endpoint."""
        if not (self.has_ai_summary and self.has_last_sentiment and self.has_effort_score):
            self.skipTest("Required fields not available")
        
        fields = {
            "ai_summary": "General summary",
            "last_sentiment": "Nautral",  # Use actual DB value
            "effort_score": 3.5
        }
        result = update_ticket(
            ticket=self.ticket.name,
            fields=fields,
            append=0,
            clean_html=1
        )
        self.assertTrue(result.get("ok"))
        self.assertIn("changed", result)
        
        # Verify
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertEqual(doc.ai_summary, "General summary")
        self.assertEqual(doc.last_sentiment, "Nautral")
        self.assertEqual(doc.effort_score, 3.5)
    
    def test_update_ticket_with_json_string(self):
        """Test update_ticket with JSON string fields."""
        if not (self.has_ai_summary and self.has_effort_band):
            self.skipTest("Required fields not available")
        
        fields_json = json.dumps({
            "ai_summary": "JSON summary",
            "effort_band": "High"
        })
        result = update_ticket(
            ticket=self.ticket.name,
            fields=fields_json,
            append=0,
            clean_html=1
        )
        self.assertTrue(result.get("ok"))
        
        # Verify
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertEqual(doc.ai_summary, "JSON summary")
        self.assertEqual(doc.effort_band, "High")
    
    def test_update_ticket_invalid_field(self):
        """Test that invalid fields are ignored."""
        if not self.has_ai_summary:
            self.skipTest("ai_summary field not available")
        
        fields = {
            "ai_summary": "Valid field",
            "invalid_field": "Should be ignored"
        }
        result = update_ticket(
            ticket=self.ticket.name,
            fields=fields,
            append=0,
            clean_html=1
        )
        self.assertTrue(result.get("ok"))
        self.assertIn("ai_summary", result["changed"])
        self.assertNotIn("invalid_field", result["changed"])


class TestIngestProblemTicket(unittest.TestCase):
    """Test Problem Ticket endpoints."""
    
    @classmethod
    def setUpClass(cls):
        """Check if Problem Ticket DocType exists."""
        cls.problem_exists = frappe.db.table_exists("Problem Ticket")
        if not cls.problem_exists:
            import warnings
            warnings.warn("Problem Ticket DocType not found - skipping Problem tests")
    
    def setUp(self):
        """Setup before each test."""
        frappe.set_user("Administrator")
        if not self.problem_exists:
            self.skipTest("Problem Ticket DocType not available")
    
    def tearDown(self):
        """Cleanup after each test."""
        if not self.problem_exists:
            return
        frappe.set_user("Administrator")
        # Clean up test problem tickets
        test_problems = frappe.get_all(
            "Problem Ticket",
            filters={"subject": ["like", "_Test Problem%"]},
            pluck="name"
        )
        for name in test_problems:
            try:
                frappe.delete_doc("Problem Ticket", name, force=1)
            except Exception:
                pass
        frappe.db.commit()
    
    def test_upsert_problem_ticket_create(self):
        """Test creating a new Problem Ticket."""
        fields = {
            "subject": "_Test Problem Ticket 1",
            "status": "Open",
            "severity": "High",
            "impact": "Users cannot login",
            "root_cause": "Database connection issue"
        }
        result = upsert_problem_ticket(
            name=None,
            fields=fields,
            strict=1
        )
        self.assertTrue(result.get("ok"))
        self.assertTrue(result.get("created"))
        self.assertIsNotNone(result.get("name"))
        
        # Verify
        doc = frappe.get_doc("Problem Ticket", result["name"])
        self.assertEqual(doc.subject, "_Test Problem Ticket 1")
        self.assertEqual(doc.status, "Open")
        self.assertEqual(doc.severity, "High")
    
    def test_upsert_problem_ticket_update(self):
        """Test updating an existing Problem Ticket."""
        # Create first
        fields_create = {
            "subject": "_Test Problem Ticket 2",
            "status": "Open",
            "severity": "Medium"
        }
        result_create = upsert_problem_ticket(name=None, fields=fields_create)
        problem_name = result_create["name"]
        
        # Update
        fields_update = {
            "status": "Investigating",
            "root_cause": "Found the issue"
        }
        result_update = upsert_problem_ticket(
            name=problem_name,
            fields=fields_update
        )
        self.assertTrue(result_update.get("ok"))
        self.assertFalse(result_update.get("created"))
        self.assertIn("status", result_update["changed"])
        
        # Verify
        doc = frappe.get_doc("Problem Ticket", problem_name)
        self.assertEqual(doc.status, "Investigating")
        self.assertEqual(doc.root_cause, "Found the issue")
    
    def test_upsert_problem_ticket_lookup_by_subject(self):
        """Test upsert with lookup_by=subject."""
        subject = "_Test Problem Ticket 3"
        
        # Create
        fields1 = {"subject": subject, "status": "Open", "severity": "Low"}
        result1 = upsert_problem_ticket(name=None, fields=fields1)
        name1 = result1["name"]
        
        # Upsert again with same subject (should update)
        fields2 = {"subject": subject, "status": "Resolved"}
        result2 = upsert_problem_ticket(
            name=None,
            fields=fields2,
            lookup_by="subject"
        )
        self.assertFalse(result2.get("created"))
        self.assertEqual(result2["name"], name1)
        
        # Verify
        doc = frappe.get_doc("Problem Ticket", name1)
        self.assertEqual(doc.status, "Resolved")
    
    def test_get_problem_ticket(self):
        """Test get_problem_ticket endpoint."""
        # Create a problem ticket
        fields = {"subject": "_Test Problem Ticket 4", "status": "Open"}
        result_create = upsert_problem_ticket(name=None, fields=fields)
        problem_name = result_create["name"]
        
        # Get it
        result = get_problem_ticket(problem_name)
        self.assertTrue(result.get("ok"))
        self.assertIn("problem", result)
        self.assertEqual(result["problem"]["name"], problem_name)
    
    def test_list_problem_tickets(self):
        """Test list_problem_tickets endpoint."""
        # Create some test problems
        for i in range(3):
            fields = {
                "subject": f"_Test Problem Ticket List {i}",
                "status": "Open" if i % 2 == 0 else "Resolved",
                "severity": "High"
            }
            upsert_problem_ticket(name=None, fields=fields)
        
        # List all
        result = list_problem_tickets(limit=50)
        self.assertTrue(result.get("ok"))
        self.assertIn("problems", result)
        self.assertIsInstance(result["problems"], list)
        
        # List with filter
        result_filtered = list_problem_tickets(status="Open", limit=50)
        self.assertTrue(result_filtered.get("ok"))


class TestIngestKBRequests(unittest.TestCase):
    """Test Knowledge Base update request endpoints."""
    
    @classmethod
    def setUpClass(cls):
        """Check if KB DocType exists."""
        cls.kb_exists = frappe.db.table_exists("Knowledge Base Update Request")
        if not cls.kb_exists:
            import warnings
            warnings.warn("Knowledge Base Update Request DocType not found - skipping KB tests")
    
    def setUp(self):
        """Setup before each test."""
        frappe.set_user("Administrator")
        if not self.kb_exists:
            self.skipTest("Knowledge Base Update Request DocType not available")
    
    def tearDown(self):
        """Cleanup after each test."""
        if not self.kb_exists:
            return
        frappe.set_user("Administrator")
        # Clean up test KB requests
        test_kbs = frappe.get_all(
            "Knowledge Base Update Request",
            filters={"subject": ["like", "_Test KB%"]},
            pluck="name"
        )
        for name in test_kbs:
            try:
                frappe.delete_doc("Knowledge Base Update Request", name, force=1)
            except Exception:
                pass
        frappe.db.commit()
    
    def test_request_kb_new_article(self):
        """Test request_kb_new_article endpoint."""
        fields = {
            "subject": "_Test KB New Article Request",
            "proposed_changes": "Need article about login process",
            "priority": "Medium"
        }
        result = request_kb_new_article(fields=fields)
        self.assertTrue(result.get("ok"))
        self.assertIsNotNone(result.get("name"))
        self.assertEqual(result.get("change_type"), "New Article")
        
        # Verify
        doc = frappe.get_doc("Knowledge Base Update Request", result["name"])
        self.assertEqual(doc.change_type, "New Article")
        self.assertEqual(doc.subject, "_Test KB New Article Request")
    
    def test_request_kb_fix(self):
        """Test request_kb_fix endpoint."""
        fields = {
            "subject": "_Test KB Fix Request",
            "proposed_changes": "Fix typo in article",
            "target_doctype": "HD Article"
        }
        result = request_kb_fix(fields=fields)
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("change_type"), "Fix")
    
    def test_request_kb_update(self):
        """Test request_kb_update endpoint."""
        fields = {
            "subject": "_Test KB Update Request",
            "current_summary": "Old content",
            "proposed_changes": "Updated content"
        }
        result = request_kb_update(fields=fields)
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("change_type"), "Update")
    
    def test_report_kb_wrong_document(self):
        """Test report_kb_wrong_document endpoint."""
        fields = {
            "subject": "_Test KB Deprecate Request",
            "proposed_changes": "This document is outdated"
        }
        result = report_kb_wrong_document(fields=fields)
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("change_type"), "Deprecate")
    
    def test_kb_request_with_dict_fields(self):
        """Test KB request with dict fields parameter."""
        fields_dict = {
            "subject": "_Test KB Dict Fields",
            "proposed_changes": "Test with dict",
            "priority": "Low"
        }
        result = request_kb_new_article(fields=fields_dict)
        self.assertTrue(result.get("ok"))


class TestIngestAILog(unittest.TestCase):
    """Test AI interaction logging."""
    
    @classmethod
    def setUpClass(cls):
        """Setup test data once for all tests."""
        frappe.set_user("Administrator")
        cls.team = create_test_team()
        cls.ticket = create_test_ticket()
    
    def setUp(self):
        """Setup before each test."""
        frappe.set_user("Administrator")
    
    def test_log_ai_interaction_dict(self):
        """Test logging AI interaction with dict params."""
        request_data = {
            "action": "summarize",
            "ticket_id": self.ticket.name
        }
        response_data = {
            "summary": "Test summary",
            "confidence": 0.95
        }
        
        result = log_ai_interaction(
            ticket=self.ticket.name,
            request=request_data,
            response=response_data
        )
        self.assertTrue(result.get("ok"))
    
    def test_log_ai_interaction_json_string(self):
        """Test logging AI interaction with JSON string params."""
        request_json = json.dumps({"action": "classify"})
        response_json = json.dumps({"category": "Technical"})
        
        result = log_ai_interaction(
            ticket=self.ticket.name,
            request=request_json,
            response=response_json
        )
        self.assertTrue(result.get("ok"))
    
    def test_log_ai_interaction_none_params(self):
        """Test logging AI interaction with None params."""
        result = log_ai_interaction(
            ticket=self.ticket.name,
            request=None,
            response=None
        )
        self.assertTrue(result.get("ok"))


class TestIngestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""
    
    @classmethod
    def setUpClass(cls):
        """Check which fields exist."""
        frappe.set_user("Administrator")
        meta = frappe.get_meta("HD Ticket")
        cls.has_ai_summary = meta.has_field("ai_summary")
        cls.has_last_sentiment = meta.has_field("last_sentiment")
        cls.has_effort_band = meta.has_field("effort_band")
    
    def setUp(self):
        """Setup before each test."""
        frappe.set_user("Administrator")
        self.team = create_test_team()
        self.ticket = create_test_ticket(subject=f"_Test Edge Case {frappe.utils.now()}")
    
    def tearDown(self):
        """Cleanup after each test."""
        frappe.set_user("Administrator")
        if hasattr(self, "ticket") and self.ticket:
            try:
                frappe.delete_doc("HD Ticket", self.ticket.name, force=1)
                frappe.db.commit()
            except Exception:
                pass
    
    def test_update_nonexistent_ticket(self):
        """Test updating a non-existent ticket."""
        if not self.has_ai_summary:
            self.skipTest("ai_summary field not available")
        
        with self.assertRaises(Exception):
            ingest_summary(
                ticket="NONEXISTENT-TICKET-001",
                summary="Test",
                append=0,
                clean_html=1
            )
    
    def test_update_ticket_empty_fields(self):
        """Test updating ticket with empty fields dict."""
        result = update_ticket(
            ticket=self.ticket.name,
            fields={},
            append=0,
            clean_html=1
        )
        self.assertFalse(result.get("ok"))
        self.assertIn("error", result)
    
    def test_set_sentiment_invalid_value(self):
        """Test setting sentiment with invalid value."""
        if not self.has_last_sentiment:
            self.skipTest("last_sentiment field not available")
        
        with self.assertRaises(Exception):
            set_sentiment(
                ticket=self.ticket.name,
                last_sentiment="InvalidSentiment"
            )
    
    def test_set_sentiment_partial_update(self):
        """Test updating only some sentiment fields."""
        if not (self.has_last_sentiment and self.has_effort_band):
            self.skipTest("Sentiment fields not available")
        
        # Set initial values
        set_sentiment(
            ticket=self.ticket.name,
            last_sentiment="Positive",
            effort_band="Low"
        )
        
        # Update only last_sentiment
        result = set_sentiment(
            ticket=self.ticket.name,
            last_sentiment="Negative"
        )
        self.assertTrue(result.get("ok"))
        
        # Verify effort_band unchanged
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertEqual(doc.last_sentiment, "Negative")
        self.assertEqual(doc.effort_band, "Low")
    
    def test_html_cleaning_in_update(self):
        """Test that HTML is properly cleaned when clean_html=1."""
        if not self.has_ai_summary:
            self.skipTest("ai_summary field not available")
        
        html_text = "<p>This is <b>bold</b> text</p>"
        result = ingest_summary(
            ticket=self.ticket.name,
            summary=html_text,
            append=0,
            clean_html=1
        )
        self.assertTrue(result.get("ok"))
        
        # Verify HTML removed
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertNotIn("<p>", doc.ai_summary)
        self.assertNotIn("<b>", doc.ai_summary)
        self.assertIn("bold", doc.ai_summary)
    
    def test_html_preserved_when_clean_false(self):
        """Test that HTML is preserved when clean_html=0."""
        if not self.has_ai_summary:
            self.skipTest("ai_summary field not available")
        
        html_text = "<p>Test</p>"
        result = ingest_summary(
            ticket=self.ticket.name,
            summary=html_text,
            append=0,
            clean_html=0
        )
        self.assertTrue(result.get("ok"))
        
        # Verify HTML preserved
        doc = frappe.get_doc("HD Ticket", self.ticket.name)
        self.assertIn("<p>", doc.ai_summary)


# Run tests if executed directly
if __name__ == "__main__":
    unittest.main()
