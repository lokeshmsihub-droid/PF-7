from typing import List, Optional
from pydantic import BaseModel, Field

class OfficialRequirement(BaseModel):
    """Official framework text and context."""
    id: str = Field(..., description="Official ID from framework criteria, e.g. CC8.1")
    text: str = Field(..., description="Official description of the criterion")
    trust_service_category: str = Field("Common Criteria / Operations", description="Trust Services Criteria category")

class PlatformInterpretation(BaseModel):
    """Internal platform interpretation of how to meet the official criterion."""
    objective: str = Field(..., description="Interpretation objective for the organization")
    operational_expectations: List[str] = Field(default_factory=list, description="Concrete operational practices expected")
    evidence_expectations: List[str] = Field(default_factory=list, description="Concrete evidence expected to satisfy the criterion")
    applicability: str = Field("All environments and components handling production infrastructure/code", description="Scope of applicability")

class FrameworkDefinition(BaseModel):
    """Domain model representing a compliance framework (e.g. SOC 2)."""
    framework_id: str = Field(..., description="Unique ID, e.g., SOC2, ISO27001")
    name: str = Field(..., description="Framework name")
    description: Optional[str] = Field(None, description="Detailed description")
    version: str = Field("2017", description="Framework release/version identifier")
    authority: str = Field("AICPA", description="Governing/authoritative body")
    status: str = Field("ACTIVE", description="Framework status: ACTIVE, DEPRECATED")

class FrameworkCriterion(BaseModel):
    """Full representation of a framework criterion like CC8.1."""
    framework_id: str = Field(..., description="Associated framework ID")
    criterion_id: str = Field("CC8.1", description="Criterion ID")
    official_requirement: OfficialRequirement
    interpretation: PlatformInterpretation
    related_control_ids: List[str] = Field(default_factory=list, description="IDs of related internal controls")
    related_check_ids: List[str] = Field(default_factory=list, description="IDs of related automation checks")
