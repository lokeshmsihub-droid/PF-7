import json
import os
import pytest
from datetime import datetime, timedelta
from app.domain.checks.models import CheckDefinition, CheckResultType

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CHECKS_JSON_PATH = os.path.join(BASE_DIR, "app", "domain", "checks", "library.json")

# 1. Core Rule Engine Emulator
def evaluate_check(check: CheckDefinition, context: dict) -> CheckResultType:
    # Check applicability
    change = context.get("change")
    if change and change.get("environment") != "PRODUCTION":
        return CheckResultType.NOT_APPLICABLE

    # Check for insufficient data: if a required entity is completely missing
    for req_data in check.required_data:
        # Ignore repositories or commit list check if they are optional in sub-validation
        if req_data not in context:
            return CheckResultType.INSUFFICIENT_DATA

    logic = check.evaluation_logic

    # Process Rules
    for rule in logic.rules:
        subject = context.get(rule.subject)
        if not subject:
            # If subject is missing but check requires it
            if rule.operator == "NOT_EXISTS":
                continue
            return CheckResultType.INSUFFICIENT_DATA

        # Extract field value
        val = subject.get(rule.field)

        # Apply operators
        if rule.operator == "EQUALS":
            if val != rule.value:
                return CheckResultType.FAIL
        elif rule.operator == "NOT_EQUALS":
            if val == rule.value:
                return CheckResultType.FAIL
        elif rule.operator == "EXISTS":
            if val is None:
                return CheckResultType.FAIL
        elif rule.operator == "NOT_EXISTS":
            if val is not None:
                return CheckResultType.FAIL
        elif rule.operator == "NOT_EMPTY":
            if not val:
                return CheckResultType.FAIL
        elif rule.operator == "IN":
            if val not in rule.value:
                return CheckResultType.FAIL

    # Process Relationships
    for rel in logic.relationships:
        sub = context.get(rel.subject)
        rel_sub = context.get(rel.related_subject)

        # Handle EXISTS condition on relationship
        if rel.operator == "EXISTS":
            if not rel_sub:
                return CheckResultType.FAIL
            continue

        if not sub or not rel_sub:
            return CheckResultType.INSUFFICIENT_DATA

        source_val = sub.get(rel.source_field)
        target_val = rel_sub.get(rel.target_field)

        if source_val is None or target_val is None:
            return CheckResultType.INSUFFICIENT_DATA

        # Apply operators
        if rel.operator == "BEFORE":
            if not (source_val < target_val):
                return CheckResultType.FAIL
        elif rel.operator == "AFTER":
            if not (source_val > target_val):
                return CheckResultType.FAIL
        elif rel.operator == "MATCH_FIELD":
            if source_val != target_val:
                return CheckResultType.FAIL
        elif rel.operator == "NOT_MATCH_FIELD":
            if source_val == target_val:
                return CheckResultType.FAIL

    return CheckResultType.PASS


# 2. Pytest cases loading library
@pytest.fixture(scope="module")
def checks_library():
    with open(CHECKS_JSON_PATH, "r") as f:
        data = json.load(f)
    return {item["check_id"]: CheckDefinition(**item) for item in data}


# 3. Individual check validations
def test_cm_001_semantics(checks_library):
    check = checks_library["CM-001"]

    # PASS: approved and authorized before implemented
    ctx_pass = {
        "change": {"implemented_at": datetime(2026, 8, 22, 12, 0, 0), "environment": "PRODUCTION"},
        "authorization": {"status": "APPROVED", "authorized_at": datetime(2026, 8, 22, 11, 0, 0)}
    }
    assert evaluate_check(check, ctx_pass) == CheckResultType.PASS

    # FAIL: status rejected or unauthorized
    ctx_fail_status = {
        "change": {"implemented_at": datetime(2026, 8, 22, 12, 0, 0), "environment": "PRODUCTION"},
        "authorization": {"status": "PENDING", "authorized_at": datetime(2026, 8, 22, 11, 0, 0)}
    }
    assert evaluate_check(check, ctx_fail_status) == CheckResultType.FAIL

    # FAIL: authorized AFTER implemented
    ctx_fail_time = {
        "change": {"implemented_at": datetime(2026, 8, 22, 10, 0, 0), "environment": "PRODUCTION"},
        "authorization": {"status": "APPROVED", "authorized_at": datetime(2026, 8, 22, 11, 0, 0)}
    }
    assert evaluate_check(check, ctx_fail_time) == CheckResultType.FAIL

    # INSUFFICIENT_DATA: missing authorization entity
    ctx_insufficient = {
        "change": {"implemented_at": datetime(2026, 8, 22, 12, 0, 0), "environment": "PRODUCTION"}
    }
    assert evaluate_check(check, ctx_insufficient) == CheckResultType.INSUFFICIENT_DATA

    # NOT_APPLICABLE: non-production change
    ctx_na = {
        "change": {"implemented_at": datetime(2026, 8, 22, 12, 0, 0), "environment": "DEVELOPMENT"},
        "authorization": {"status": "APPROVED", "authorized_at": datetime(2026, 8, 22, 11, 0, 0)}
    }
    assert evaluate_check(check, ctx_na) == CheckResultType.NOT_APPLICABLE


def test_cm_002_semantics(checks_library):
    check = checks_library["CM-006"]

    # PASS
    ctx_pass = {
        "change": {"title": "Auth Fix", "description": "some details", "change_type": "NORMAL", "risk_level": "HIGH", "environment": "PRODUCTION"}
    }
    assert evaluate_check(check, ctx_pass) == CheckResultType.PASS

    # FAIL: missing description
    ctx_fail = {
        "change": {"title": "Auth Fix", "description": "", "change_type": "NORMAL", "risk_level": "HIGH", "environment": "PRODUCTION"}
    }
    assert evaluate_check(check, ctx_fail) == CheckResultType.FAIL


def test_cm_005_semantics(checks_library):
    check = checks_library["CM-002"]

    # PASS: tests passed before deployed
    ctx_pass = {
        "change": {"environment": "PRODUCTION"},
        "test": {"status": "PASS", "completed_at": datetime(2026, 8, 22, 11, 0, 0)},
        "deployment": {"deployed_at": datetime(2026, 8, 22, 12, 0, 0)}
    }
    assert evaluate_check(check, ctx_pass) == CheckResultType.PASS

    # FAIL: test failed
    ctx_fail_status = {
        "change": {"environment": "PRODUCTION"},
        "test": {"status": "FAIL", "completed_at": datetime(2026, 8, 22, 11, 0, 0)},
        "deployment": {"deployed_at": datetime(2026, 8, 22, 12, 0, 0)}
    }
    assert evaluate_check(check, ctx_fail_status) == CheckResultType.FAIL

    # FAIL: tests passed AFTER deployment
    ctx_fail_time = {
        "change": {"environment": "PRODUCTION"},
        "test": {"status": "PASS", "completed_at": datetime(2026, 8, 22, 13, 0, 0)},
        "deployment": {"deployed_at": datetime(2026, 8, 22, 12, 0, 0)}
    }
    assert evaluate_check(check, ctx_fail_time) == CheckResultType.FAIL


def test_cm_006_semantics(checks_library):
    check = checks_library["CM-003"]

    # PASS
    ctx_pass = {
        "change": {"environment": "PRODUCTION"},
        "approval": {"decision": "APPROVED", "approved_at": datetime(2026, 8, 22, 11, 0, 0)},
        "deployment": {"deployed_at": datetime(2026, 8, 22, 12, 0, 0)}
    }
    assert evaluate_check(check, ctx_pass) == CheckResultType.PASS

    # FAIL
    ctx_fail = {
        "change": {"environment": "PRODUCTION"},
        "approval": {"decision": "REJECTED", "approved_at": datetime(2026, 8, 22, 11, 0, 0)},
        "deployment": {"deployed_at": datetime(2026, 8, 22, 12, 0, 0)}
    }
    assert evaluate_check(check, ctx_fail) == CheckResultType.FAIL


def test_cm_007_semantics(checks_library):
    check = checks_library["CM-004"]

    # PASS: different requester, approver, and deployer
    ctx_pass = {
        "change": {"requester_id": "usr-dev", "environment": "PRODUCTION"},
        "approval": {"approver_id": "usr-manager"},
        "deployment": {"deployed_by": "usr-ops"}
    }
    assert evaluate_check(check, ctx_pass) == CheckResultType.PASS

    # FAIL: developer is approver
    ctx_fail_approver = {
        "change": {"requester_id": "usr-dev", "environment": "PRODUCTION"},
        "approval": {"approver_id": "usr-dev"},
        "deployment": {"deployed_by": "usr-ops"}
    }
    assert evaluate_check(check, ctx_fail_approver) == CheckResultType.FAIL

    # FAIL: developer is deployer
    ctx_fail_deployer = {
        "change": {"requester_id": "usr-dev", "environment": "PRODUCTION"},
        "approval": {"approver_id": "usr-manager"},
        "deployment": {"deployed_by": "usr-dev"}
    }
    assert evaluate_check(check, ctx_fail_deployer) == CheckResultType.FAIL


def test_cm_010_semantics(checks_library):
    check = checks_library["CM-008"]

    # PASS
    ctx_pass = {
        "change": {"change_type": "EMERGENCY", "environment": "PRODUCTION"},
        "authorization": {"justification": "Fix production outage"}
    }
    assert evaluate_check(check, ctx_pass) == CheckResultType.PASS

    # FAIL: no justification
    ctx_fail = {
        "change": {"change_type": "EMERGENCY", "environment": "PRODUCTION"},
        "authorization": {"justification": ""}
    }
    assert evaluate_check(check, ctx_fail) == CheckResultType.FAIL


def test_cm_011_semantics(checks_library):
    check = checks_library["CM-013"]

    # PASS
    ctx_pass = {
        "change": {"change_type": "EMERGENCY", "environment": "PRODUCTION"},
        "post_change_review": {"change_id": "chg-1"}
    }
    assert evaluate_check(check, ctx_pass) == CheckResultType.PASS

    # FAIL: post change review missing
    ctx_fail = {
        "change": {"change_type": "EMERGENCY", "environment": "PRODUCTION"},
        "post_change_review": None
    }
    assert evaluate_check(check, ctx_fail) == CheckResultType.FAIL


def test_cm_014_semantics(checks_library):
    check = checks_library["CM-015"]

    # PASS: deployment is missing change_id (detecting bypass)
    ctx_pass = {
        "change": {"environment": "PRODUCTION"},
        "deployment": {"change_id": None}
    }
    assert evaluate_check(check, ctx_pass) == CheckResultType.PASS

    # FAIL: deployment is associated with a change
    ctx_fail = {
        "change": {"environment": "PRODUCTION"},
        "deployment": {"change_id": "chg-123"}
    }
    assert evaluate_check(check, ctx_fail) == CheckResultType.FAIL
