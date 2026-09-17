from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, model_validator

class CheckResultType(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"

class EvidenceRequirement(BaseModel):
    evidence_type: str
    required_source: str
    required_fields: List[str] = Field(default_factory=list)
    retention_days: int = 365
    validation_method: str = "HASH"

class RuleCondition(BaseModel):
    """Legacy condition evaluator."""
    subject: str
    field: str
    operator: str
    value: Optional[Any] = None

class RuleRelationship(BaseModel):
    """Legacy relationship evaluator."""
    subject: str
    related_subject: str
    operator: str
    source_field: str
    target_field: str

class EvaluationLogic(BaseModel):
    """Legacy evaluation logic wrapper."""
    rules: List[RuleCondition] = Field(default_factory=list)
    relationships: List[RuleRelationship] = Field(default_factory=list)

class CheckDefinition(BaseModel):
    """Domain model representing dynamic compliance checks with legacy attributes for compatibility."""
    __test__ = False
    check_id: str
    framework: str = "SOC 2"
    criterion: str = "CC8.1"
    name: str
    description: str
    category: str
    severity: str
    required_fields: List[str] = Field(default_factory=list)
    applicability: Optional[Any] = None
    logic: Dict[str, Any] = Field(default_factory=dict)
    success_result: str = "PASS"
    failure_result: str = "FAIL"
    missing_data_result: str = "INSUFFICIENT_DATA"
    evidence_requirements: List[EvidenceRequirement] = Field(default_factory=list)
    version: str = "1.0.0"

    # Legacy attributes for backward compatibility
    control_id: str = ""
    lifecycle_stage: str = "Testing"
    required_data: List[str] = Field(default_factory=list)
    evaluation_logic: Optional[EvaluationLogic] = None
    remediation_guidance: Optional[str] = None
    result_types: List[CheckResultType] = Field(
        default=[CheckResultType.PASS, CheckResultType.FAIL, CheckResultType.INSUFFICIENT_DATA, CheckResultType.NOT_APPLICABLE, CheckResultType.ERROR]
    )
    status: str = "ACTIVE"
    effective_from: datetime = Field(default_factory=datetime.utcnow)
    effective_until: Optional[datetime] = None

    class Config:
        populate_by_name = True

    @model_validator(mode="after")
    def populate_legacy_fields(self) -> "CheckDefinition":
        # Parse control_id
        if not self.control_id:
            try:
                num = int(self.check_id.split("-")[1])
                self.control_id = f"CM-CONTROL-{num:02d}"
                if num > 11:
                    self.control_id = "CM-CONTROL-01"
            except Exception:
                self.control_id = "CM-CONTROL-01"

        # Map required_fields to required_data models
        if not self.required_data and self.required_fields:
            legacy = set()
            for f in self.required_fields:
                parts = f.split(".")
                prefix = parts[0]
                if prefix == "testing":
                    legacy.add("test")
                elif prefix in ["identity", "basic_info", "request", "rollback", "emergency"]:
                    legacy.add("change")
                elif prefix == "approval":
                    legacy.add("approval")
                elif prefix == "authorization":
                    legacy.add("authorization")
                elif prefix == "deployment":
                    legacy.add("deployment")
                elif prefix == "evidence_ids":
                    legacy.add("evidence")
                else:
                    legacy.add(prefix)
            self.required_data = list(legacy)

        # Map logic to evaluation_logic
        if (not self.evaluation_logic or (not self.evaluation_logic.rules and not self.evaluation_logic.relationships)) and self.logic:
            rules_list = []
            rel_list = []
            rules = self.logic.get("all", []) or self.logic.get("any", [])
            for r in rules:
                field_path = r.get("field", "")
                parts = field_path.split(".")
                subj = parts[0] if len(parts) > 1 else "change"
                if subj == "testing":
                    subj = "test"
                elif subj in ["basic_info", "development", "request", "rollback", "emergency", "identity"]:
                    subj = "change"
                fld = parts[1] if len(parts) > 1 else field_path
                rules_list.append(RuleCondition(
                    subject=subj,
                    field=fld,
                    operator=r.get("operator", "EQUALS").upper(),
                    value=r.get("value")
                ))
            
            # Map relationships if any field_reference is before/after
            for r in rules:
                if "field_reference" in r:
                    ref_parts = r["field_reference"].split(".")
                    ref_subj = ref_parts[0] if len(ref_parts) > 1 else "change"
                    if ref_subj == "testing":
                        ref_subj = "test"
                    ref_fld = ref_parts[1] if len(ref_parts) > 1 else r["field_reference"]
                    
                    field_parts = r["field"].split(".")
                    f_subj = field_parts[0] if len(field_parts) > 1 else "change"
                    if f_subj == "testing":
                        f_subj = "test"
                    f_fld = field_parts[1] if len(field_parts) > 1 else r["field"]

                    rel_list.append(RuleRelationship(
                        subject=f_subj,
                        related_subject=ref_subj,
                        operator=r["operator"].upper(),
                        source_field=f_fld,
                        target_field=ref_fld
                    ))

            self.evaluation_logic = EvaluationLogic(rules=rules_list, relationships=rel_list)

        return self

class CheckResult(BaseModel):
    """Domain model representing a unified compliance check evaluation result output."""
    result_id: str
    tenant_id: str
    check_id: str
    change_id: str
    status: CheckResultType
    evaluated_at: datetime
    evaluation_version: str
    reason: str
    evidence_ids: List[str] = Field(default_factory=list)
    missing_fields: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Legacy attributes for backward compatibility
    result: Optional[CheckResultType] = None
    rule_version: str = "1.0.0"
    evaluation_inputs: Dict[str, Any] = Field(default_factory=dict)
    details: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True

    @model_validator(mode="before")
    @classmethod
    def map_from_orm(cls, data: Any) -> Any:
        """Enforces Pydantic V2 translation parsing when mapping SQLAlchemy ORM tables to the schema."""
        if not isinstance(data, dict):
            status_val = data.result.name if hasattr(data.result, "name") else str(data.result)
            details_dict = data.details if isinstance(data.details, dict) else {}
            ev_ids = [ev.evidence_id for ev in data.evidences] if hasattr(data, "evidences") and data.evidences else []
            return {
                "result_id": data.result_id,
                "tenant_id": data.tenant_id,
                "check_id": data.check_id,
                "change_id": data.change_id,
                "status": status_val,
                "result": status_val,
                "evaluated_at": data.evaluated_at,
                "evaluation_version": data.rule_version,
                "rule_version": data.rule_version,
                "reason": details_dict.get("reason") or details_dict.get("message") or "Evaluated compliance logic.",
                "evidence_ids": ev_ids,
                "missing_fields": details_dict.get("missing_fields") or [],
                "metadata": details_dict.get("metadata") or {},
                "evaluation_inputs": data.evaluation_inputs or {},
                "details": details_dict
            }
        return data

    @model_validator(mode="after")
    def populate_legacy_result(self) -> "CheckResult":
        if not self.result:
            self.result = self.status
        if not self.rule_version:
            self.rule_version = self.evaluation_version
        if not self.details:
            self.details = {"reason": self.reason, "message": self.reason, "missing_fields": self.missing_fields, "metadata": self.metadata}
        return self
