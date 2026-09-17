import uuid
import json
import os
from datetime import datetime, UTC
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.orm import (
    ChangeORM, CheckResultORM, ORMCheckResultType, EvidenceMetadataORM,
    ComplianceCheckORM, EnvironmentORM, ORMEnvType
)
from app.domain.canonical.models import DataAvailability
from app.normalization.canonical_adapter import CanonicalMapper
from app.services.evidence_association_service import EvidenceAssociationService
from app.services.evidence_validation_service import EvidenceValidationService

def get_field_value(obj, path: str) -> Any:
    """Helper to dynamically resolve nested dot-notation paths on Pydantic models or dictionaries."""
    parts = path.split(".")
    current = obj
    for part in parts:
        if current is None:
            return None
        if hasattr(current, part):
            current = getattr(current, part)
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current

def translate_legacy_logic(evaluation_logic: dict) -> dict:
    """Translates legacy rules and relationships structure to dynamic dot-notation conditions."""
    rules = evaluation_logic.get("rules", [])
    relationships = evaluation_logic.get("relationships", [])
    new_rules = []
    
    for r in rules:
        subj = r.get("subject", "")
        prefix = "testing" if subj == "test" else subj
        if subj in ["change", "basic_info"]:
            prefix = "basic_info"
            
        field = r.get("field", "")
        fld_name = field
        if field == "status" and prefix == "testing":
            fld_name = "test_status"
            
        op = r.get("operator", "").lower()
        val = r.get("value")
        new_rules.append({
            "field": f"{prefix}.{fld_name}",
            "operator": op,
            "value": val
        })
        
    for rel in relationships:
        subj = rel.get("subject", "")
        prefix = "testing" if subj == "test" else subj
        if subj in ["change", "basic_info"]:
            prefix = "basic_info"
            
        rel_subj = rel.get("related_subject", "")
        rel_prefix = "deployment" if rel_subj == "deployment" else rel_subj
        if rel_subj in ["change", "basic_info"]:
            rel_prefix = "basic_info"
            
        op = rel.get("operator", "").lower()
        
        src_fld = rel.get("source_field", "")
        if src_fld == "completed_at" and prefix == "testing":
            src_fld = "tested_at"
        elif src_fld == "authorized_at" and prefix == "authorization":
            src_fld = "authorized_at"
        elif src_fld == "approved_at" and prefix == "approval":
            src_fld = "approved_at"
            
        tgt_fld = rel.get("target_field", "")
        if tgt_fld == "deployed_at" and rel_prefix == "deployment":
            tgt_fld = "deployed_at"
        elif tgt_fld == "implemented_at" and rel_prefix == "basic_info":
            tgt_fld = "implemented_at"
            
        new_rules.append({
            "field": f"{prefix}.{src_fld}",
            "operator": op,
            "field_reference": f"{rel_prefix}.{tgt_fld}"
        })
        
    return {"all": new_rules}

def translate_legacy_required(required_data: list) -> list:
    """Translates legacy required data model names to dynamic canonical field paths."""
    fields = []
    for r in required_data:
        if r == "test":
            fields.extend(["testing.test_status", "testing.tested_at"])
        elif r == "deployment":
            fields.extend(["deployment.deployed_at"])
        elif r == "approval":
            fields.extend(["approval.approved", "approval.approved_at"])
        elif r == "authorization":
            fields.extend(["authorization.authorized", "authorization.authorized_at"])
    return fields

class EvaluationService:
    """Dynamically executes dynamic compliance check catalog rules against the Canonical Change Data Contract."""

    def __init__(self, db: Session):
        self.db = db

    def evaluate_change(self, tenant_id: str, change_id: str, check_id: str, event_id: Optional[str] = None) -> CheckResultORM:
        # Harvest and validate all active evidence for this change request
        association_service = EvidenceAssociationService(self.db)
        validation_service = EvidenceValidationService(self.db)
        
        harvested = association_service.harvest_change_evidence(tenant_id, change_id, event_id=event_id)
        for ev in harvested:
            validation_service.validate_evidence(ev)

        # 1. Fetch Change ORM context from the database
        change = self.db.query(ChangeORM).filter_by(change_id=change_id, tenant_id=tenant_id).first()
        if not change:
            raise ValueError(f"Change request {change_id} not found under tenant")

        # 2. Map to CanonicalChange representation
        canonical_change = CanonicalMapper.to_canonical_change(self.db, change)

        # 3. Load check definition from database (falling back to library.json)
        check_orm = self.db.query(ComplianceCheckORM).filter_by(check_id=check_id).first()
        
        check_def = None
        if check_orm:
            # Handle PRODUCTION environment applicability check
            if check_orm.applicability == "PRODUCTION":
                env = self.db.query(EnvironmentORM).filter_by(environment_id=change.environment_id).first()
                if env and env.type != ORMEnvType.PRODUCTION:
                    return self._persist_result(
                        tenant_id=tenant_id,
                        check_id=check_id,
                        change_id=change_id,
                        result=ORMCheckResultType.NOT_APPLICABLE,
                        rule_version=check_orm.version,
                        inputs={"environment": change.environment_id},
                        details={
                            "message": f"Check skipped: environment type is {env.type} (not PRODUCTION).",
                            "reason": f"Check skipped: environment type is {env.type} (not PRODUCTION).",
                            "missing_fields": []
                        }
                    )
            
            logic_data = check_orm.evaluation_logic
            req_fields = []
            if isinstance(logic_data, dict) and ("rules" in logic_data or "relationships" in logic_data):
                logic_data = translate_legacy_logic(logic_data)
                req_fields = translate_legacy_required(check_orm.required_data)
            else:
                req_fields = check_orm.required_data or []
                
            lib_def = self._load_check_definition(check_id)
            app_rule = lib_def.get("applicability") if lib_def else None
            
            check_def = {
                "check_id": check_orm.check_id,
                "framework": "SOC2",
                "criterion": "CC8.1",
                "name": check_orm.name,
                "description": check_orm.description,
                "category": check_orm.category,
                "severity": check_orm.severity,
                "required_fields": req_fields,
                "logic": logic_data,
                "applicability": app_rule,
                "success_result": "PASS",
                "failure_result": "FAIL",
                "missing_data_result": "FAIL" if check_orm.check_id == "CM-015" or (check_orm.check_id == "CM-005" and check_orm.category == "traceability") else "INSUFFICIENT_DATA",
                "evidence_requirements": check_orm.evidence_requirements or [],
                "version": check_orm.version
            }
        else:
            check_def = self._load_check_definition(check_id)

        if not check_def:
            raise ValueError(f"Compliance check definition for {check_id} not found")

        # 4. Check applicability rules
        applicability = check_def.get("applicability")
        if applicability:
            app_field = applicability.get("field")
            app_op = applicability.get("operator")
            app_val = applicability.get("value")
            app_result = applicability.get("result", "NOT_APPLICABLE")

            val = get_field_value(canonical_change, app_field)
            if app_op == "equals" and val == app_val:
                return self._persist_result(
                    tenant_id=tenant_id,
                    check_id=check_id,
                    change_id=change_id,
                    result=ORMCheckResultType.NOT_APPLICABLE,
                    rule_version=check_def.get("version", "1.0.0"),
                    inputs={app_field: str(val)},
                    details={
                        "message": f"Check skipped: applicability rule ({app_field} equals {app_val}) satisfied.",
                        "reason": f"Check skipped: applicability rule ({app_field} equals {app_val}) satisfied.",
                        "missing_fields": []
                    }
                )
            elif app_op == "not_equals" and val != app_val:
                return self._persist_result(
                    tenant_id=tenant_id,
                    check_id=check_id,
                    change_id=change_id,
                    result=ORMCheckResultType.NOT_APPLICABLE,
                    rule_version=check_def.get("version", "1.0.0"),
                    inputs={app_field: str(val)},
                    details={
                        "message": f"Check skipped: applicability rule ({app_field} not_equals {app_val}) satisfied.",
                        "reason": f"Check skipped: applicability rule ({app_field} not_equals {app_val}) satisfied.",
                        "missing_fields": []
                    }
                )

        # Check evidence requirements dynamically from the check definition
        evidence_reqs = check_def.get("evidence_requirements", [])
        for req in evidence_reqs:
            req_type = req.get("evidence_type")
            req_source = req.get("required_source")
            
            matching_evs = [
                ev for ev in harvested
                if ev.evidence_type == req_type
                and (
                    req_source in ["system", "any", "all", None] 
                    or ev.source == req_source 
                    or (req_source in ["jira", "github"] and ev.source in ["jira", "github", "system"])
                )
            ]
            
            valid_evs = [
                ev for ev in matching_evs
                if ev.status in ["VALIDATED", "ASSOCIATED"]
                and ev.freshness_status == "CURRENT"
                and ev.integrity_status != "INTEGRITY_FAILURE"
            ]
            
            if not valid_evs:
                missing_result_type = check_def.get("missing_data_result", "INSUFFICIENT_DATA")
                orm_result = (
                    ORMCheckResultType.FAIL 
                    if missing_result_type == "FAIL" 
                    else ORMCheckResultType.INSUFFICIENT_DATA
                )
                
                reason = f"Required evidence of type '{req_type}' from source '{req_source}' is missing or invalid."
                result_orm = self._persist_result(
                    tenant_id=tenant_id,
                    check_id=check_id,
                    change_id=change_id,
                    result=orm_result,
                    rule_version=check_def.get("version", "1.0.0"),
                    inputs={"missing_evidence_type": req_type},
                    details={
                        "message": reason,
                        "reason": reason,
                        "expected": f"Valid, current evidence of type '{req_type}' from source '{req_source}'",
                        "actual": "None found or evidence is invalid/stale/tampered.",
                        "missing_fields": [f"evidence:{req_type}"]
                    }
                )
                db_evs = self.db.query(EvidenceMetadataORM).filter_by(change_id=change_id, tenant_id=tenant_id).all()
                for ev in harvested + db_evs:
                    if ev not in result_orm.evidences:
                        result_orm.evidences.append(ev)
                self.db.commit()
                return result_orm

        # 5. Check required fields availability
        required_fields = check_def.get("required_fields", [])
        missing_fields = []
        for field_path in required_fields:
            val = get_field_value(canonical_change, field_path)
            if (
                val is None or 
                val == DataAvailability.UNKNOWN or 
                val == DataAvailability.UNAVAILABLE or 
                str(val).upper() in ["UNKNOWN", "UNAVAILABLE"]
            ):
                missing_fields.append(field_path)

        if missing_fields:
            missing_result_type = check_def.get("missing_data_result", "INSUFFICIENT_DATA")
            orm_result = (
                ORMCheckResultType.FAIL 
                if missing_result_type == "FAIL" 
                else ORMCheckResultType.INSUFFICIENT_DATA
            )

            return self._persist_result(
                tenant_id=tenant_id,
                check_id=check_id,
                change_id=change_id,
                result=orm_result,
                rule_version=check_def.get("version", "1.0.0"),
                inputs={"missing_fields": missing_fields},
                details={
                    "message": f"Required fields {missing_fields} are unavailable.",
                    "reason": f"Required fields {missing_fields} are unavailable.",
                    "missing_fields": missing_fields
                }
            )

        # 6. Evaluate rules logic
        logic = check_def.get("logic", {})
        rules = logic.get("all", [])
        is_or = False
        if "any" in logic:
            rules = logic.get("any", [])
            is_or = True

        rule_results = []
        evaluation_inputs = {}
        reason_parts = []

        for rule in rules:
            field_path = rule.get("field")
            op = rule.get("operator")
            expected = rule.get("value")
            ref_path = rule.get("field_reference")

            val = get_field_value(canonical_change, field_path)
            evaluation_inputs[field_path] = str(val)

            ref_val = None
            if ref_path:
                ref_val = get_field_value(canonical_change, ref_path)
                evaluation_inputs[ref_path] = str(ref_val)

            rule_ok = False
            if op == "equals":
                rule_ok = (val == expected)
            elif op == "not_equals":
                rule_ok = (val != expected)
            elif op == "exists":
                rule_ok = (
                    val is not None and 
                    val != "" and 
                    str(val).upper() not in ["UNKNOWN", "UNAVAILABLE"]
                )
            elif op == "not_exists":
                rule_ok = (
                    val is None or 
                    val == "" or 
                    str(val).upper() in ["UNKNOWN", "UNAVAILABLE"]
                )
            elif op == "not_equal_field":
                rule_ok = (val != ref_val)
            elif op in ["before", "before_or_equal", "after", "after_or_equal"]:
                # Date comparisons
                dt_val = self._parse_datetime(val)
                dt_ref = self._parse_datetime(ref_val if ref_path else expected)

                if dt_val and dt_ref:
                    if op == "before":
                        rule_ok = (dt_val < dt_ref)
                    elif op == "before_or_equal":
                        rule_ok = (dt_val <= dt_ref)
                    elif op == "after":
                        rule_ok = (dt_val > dt_ref)
                    elif op == "after_or_equal":
                        rule_ok = (dt_val >= dt_ref)
                else:
                    rule_ok = False

            rule_results.append(rule_ok)
            if rule_ok:
                reason_parts.append(f"Rule Passed: {field_path} {op} {ref_path or expected}")
            else:
                reason_parts.append(
                    f"Rule Failed: {field_path} {op} {ref_path or expected} "
                    f"(evaluated values: {val} vs {ref_val or expected})"
                )

        success = any(rule_results) if is_or else all(rule_results)
        result_str = check_def.get("success_result", "PASS") if success else check_def.get("failure_result", "FAIL")
        orm_result = ORMCheckResultType.PASS if result_str == "PASS" else ORMCheckResultType.FAIL

        reason = "; ".join(reason_parts)

        result_orm = self._persist_result(
            tenant_id=tenant_id,
            check_id=check_id,
            change_id=change_id,
            result=orm_result,
            rule_version=check_def.get("version", "1.0.0"),
            inputs=evaluation_inputs,
            details={
                "message": reason or ("All policy rule assertions passed." if orm_result == ORMCheckResultType.PASS else "Rule assertion failed."),
                "reason": reason,
                "expected": f"Satisfy compliance policy requirements for '{check_def.get('name', check_id)}'.",
                "actual": "All required policy criteria and attributes verified compliant." if orm_result == ORMCheckResultType.PASS else reason,
                "missing_fields": []
            }
        )

        # 7. Attach and persist evidence references
        db_evs = self.db.query(EvidenceMetadataORM).filter_by(change_id=change_id, tenant_id=tenant_id).all()
        for ev in harvested + db_evs:
            if ev not in result_orm.evidences:
                result_orm.evidences.append(ev)
        self.db.commit()

        return result_orm

    def _load_check_definition(self, check_id: str) -> Optional[dict]:
        """Loads and filters a check definition from the dynamic JSON catalog."""
        try:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            path = os.path.join(base_dir, "domain", "checks", "library.json")
            if not os.path.exists(path):
                return None
            with open(path, "r") as f:
                checks = json.load(f)
                for item in checks:
                    if item.get("check_id") == check_id:
                        return item
        except Exception:
            pass
        return None

    def _parse_datetime(self, val: Any) -> Optional[datetime]:
        """Helper to convert date objects or strings safely into naive UTC datetimes."""
        if isinstance(val, datetime):
            return val.replace(tzinfo=None)
        if isinstance(val, str):
            try:
                clean_str = val.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_str)
                if dt.tzinfo:
                    return dt.astimezone(UTC).replace(tzinfo=None)
                return dt
            except ValueError:
                pass
        return None

    def _persist_result(
        self, tenant_id: str, check_id: str, change_id: str, result: ORMCheckResultType,
        rule_version: str, inputs: dict, details: dict
    ) -> CheckResultORM:
        """Saves a CheckResultORM log record to PostgreSQL."""
        res_id = str(uuid.uuid4())
        res = CheckResultORM(
            result_id=res_id,
            tenant_id=tenant_id,
            check_id=check_id,
            change_id=change_id,
            result=result,
            rule_version=rule_version,
            evaluation_inputs=inputs,
            details=details,
            evaluated_at=datetime.now(UTC)
        )
        self.db.add(res)
        self.db.commit()
        return res
