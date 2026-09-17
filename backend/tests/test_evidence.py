import pytest
import os
from app.services.evidence_service import EvidenceService
from app.models.orm import ChangeORM, UserORM, ORMChangeType

def test_evidence_storage_local(db_session):
    tenant_id = "tenant-abc"
    change_id = "chg-evidence-test"
    
    # 1. Seed user and change
    user = UserORM(
        internal_user_id="usr-eva",
        tenant_id=tenant_id,
        name="Eva",
        email="eva@acme.com",
        role="Dev",
        status="ACTIVE"
    )
    # Pre-populate baseline environment and application
    from app.services.normalization_service import NormalizationService
    NormalizationService(db_session)._ensure_baseline_entities(tenant_id)
    
    change = ChangeORM(
        change_id=change_id,
        tenant_id=tenant_id,
        external_id="4001",
        source="github",
        title="CM-005 Evidence test",
        description="",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-eva",
        owner_id="usr-eva",
        environment_id="env-prod",
        application_id="app-default",
        status="OPEN"
    )
    db_session.add(user)
    db_session.commit()
    db_session.add(change)
    db_session.commit()

    # 2. Store evidence
    service = EvidenceService(db_session)
    content = b'{"status": "PASSED", "tests_run": 45}'
    meta = service.store_evidence(
        tenant_id=tenant_id,
        change_id=change_id,
        file_name="pipeline_run.json",
        content=content,
        content_type="application/json"
    )

    # 3. Assertions
    assert meta.evidence_id is not None
    assert meta.source_record_id == "pipeline_run.json"
    assert meta.evidence_type == "application/json"
    assert meta.hash is not None
    assert meta.storage_reference.startswith("file://")

    # Verify physical file existence
    clean_path = meta.storage_reference.replace("file://", "")
    assert os.path.exists(clean_path)
    with open(clean_path, "rb") as f:
        assert f.read() == content

    # Cleanup test file
    if os.path.exists(clean_path):
        os.remove(clean_path)
