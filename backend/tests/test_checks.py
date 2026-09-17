import json
import os
import pytest
from app.domain.controls.models import ControlDefinition
from app.domain.checks.models import CheckDefinition

# Utility to get paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTROLS_JSON_PATH = os.path.join(BASE_DIR, "app", "domain", "controls", "library.json")
CHECKS_JSON_PATH = os.path.join(BASE_DIR, "app", "domain", "checks", "library.json")

def test_load_and_validate_control_library():
    assert os.path.exists(CONTROLS_JSON_PATH), f"Control library JSON not found at {CONTROLS_JSON_PATH}"
    
    with open(CONTROLS_JSON_PATH, "r") as f:
        controls_data = json.load(f)
        
    assert isinstance(controls_data, list)
    assert len(controls_data) == 11
    
    controls_map = {}
    for item in controls_data:
        # Parse through Pydantic
        control = ControlDefinition(**item)
        assert control.control_id.startswith("CM-CONTROL-")
        assert control.framework == "SOC 2"
        assert control.criterion == "CC8.1"
        assert len(control.evidence_requirements) > 0
        assert control.evidence_requirements[0].evidence_type is not None
        controls_map[control.control_id] = control

    # Make sure we have the specific controls we expect
    for i in range(1, 12):
        cid = f"CM-CONTROL-{i:02d}"
        assert cid in controls_map, f"Missing control ID: {cid}"


def test_load_and_validate_check_library():
    assert os.path.exists(CHECKS_JSON_PATH), f"Check library JSON not found at {CHECKS_JSON_PATH}"
    
    with open(CHECKS_JSON_PATH, "r") as f:
        checks_data = json.load(f)
        
    assert isinstance(checks_data, list)
    assert len(checks_data) == 15
    
    checks_map = {}
    for item in checks_data:
        # Parse through Pydantic
        check = CheckDefinition(**item)
        assert check.check_id.startswith("CM-")
        assert len(check.required_data) > 0
        assert check.evaluation_logic is not None
        # Ensure rules or relationships are populated
        assert len(check.evaluation_logic.rules) > 0 or len(check.evaluation_logic.relationships) > 0
        checks_map[check.check_id] = check

    # Verify we have CM-001 to CM-015
    for i in range(1, 16):
        chk_id = f"CM-{i:03d}"
        assert chk_id in checks_map, f"Missing check ID: {chk_id}"


def test_check_to_control_mappings():
    with open(CONTROLS_JSON_PATH, "r") as f:
        controls = {item["control_id"]: item for item in json.load(f)}
        
    with open(CHECKS_JSON_PATH, "r") as f:
        checks = json.load(f)
        
    # Verify every check maps to a control that actually exists in the library
    for chk in checks:
        control_id = chk["control_id"]
        assert control_id in controls, f"Check {chk['check_id']} refers to non-existent control: {control_id}"


def test_check_required_data_mapping():
    with open(CHECKS_JSON_PATH, "r") as f:
        checks = json.load(f)
        
    # The set of recognized vendor-neutral data models
    valid_data_models = {
        "change", "authorization", "approval", "test", "test_result", 
        "deployment", "repository", "application", "environment", "evidence", 
        "post_change_review", "commit_id", "commit"
    }
    
    for chk in checks:
        for data_item in chk["required_data"]:
            assert data_item in valid_data_models, (
                f"Check {chk['check_id']} requires unrecognized data model '{data_item}'"
            )
