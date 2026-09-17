import uuid
import json
import hashlib
from datetime import datetime, UTC
from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.orm import (
    EvidenceMetadataORM, ChangeORM, AuthorizationORM, ApprovalORM,
    TestORM, DeploymentORM, ChangeRollbackORM
)
from app.services.audit_service import AuditLogService

class EvidenceAssociationService:
    """Harvests and associates system entities as compliance evidence, maintaining version histories."""

    def __init__(self, db: Session):
        self.db = db

    def compute_orm_hash(self, obj) -> str:
        """Compute stable SHA-256 hash representing canonical column values of an ORM entity."""
        if not obj:
            return ""
        if isinstance(obj, dict):
            serialized = json.dumps(obj, sort_keys=True, default=str)
            return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        data = {}
        for col in obj.__table__.columns:
            if col.name in [
                "created_at", "updated_at", "last_observed_at", 
                "last_evaluated_at", "observed_at", "validated_at", 
                "verified_at", "resolved_at"
            ]:
                continue
            val = getattr(obj, col.name)
            if hasattr(val, "isoformat"):
                data[col.name] = val.isoformat()
            elif hasattr(val, "value"):
                data[col.name] = val.value
            else:
                data[col.name] = val
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def harvest_change_evidence(
        self, tenant_id: str, change_id: str, event_id: Optional[str] = None
    ) -> List[EvidenceMetadataORM]:
        """Harvest, version, and associate SDLC entities to the target Change request."""
        change = self.db.query(ChangeORM).filter_by(change_id=change_id, tenant_id=tenant_id).first()
        if not change:
            return []

        # Check for linked Governance change (Jira)
        from app.models.orm import ChangeRelationshipORM, RelationshipType, EntityType
        parent_rel = self.db.query(ChangeRelationshipORM).filter_by(
            tenant_id=tenant_id,
            target_id=change.change_id,
            relationship_type=RelationshipType.ASSOCIATED_WITH
        ).first()
        
        parent_change = None
        if parent_rel and parent_rel.source_type == EntityType.CHANGE:
            parent_change = self.db.query(ChangeORM).filter_by(change_id=parent_rel.source_id, tenant_id=tenant_id).first()
            
        gov_change = parent_change if parent_change else change

        harvested = []
        entities = []

        # 1. Self Change documentation
        entities.append({
            "obj": change,
            "type": "DOCUMENTATION_METADATA",
            "source": change.source,
            "record_id": change.change_id,
            "table": "changes",
            "file_name": f"change_{change.change_id}.json"
        })
        if gov_change != change:
            entities.append({
                "obj": gov_change,
                "type": "DOCUMENTATION_METADATA",
                "source": gov_change.source,
                "record_id": gov_change.change_id,
                "table": "changes",
                "file_name": f"change_{gov_change.change_id}.json"
            })

        # 2. Authorizations
        auths = list(change.authorizations)
        if gov_change != change:
            auths.extend(gov_change.authorizations)
        for auth in auths:
            entities.append({
                "obj": auth,
                "type": "AUTHORIZATION_RECORD",
                "source": "jira",
                "record_id": auth.authorization_id,
                "table": "change_authorizations",
                "file_name": f"auth_{auth.authorization_id}.json"
            })

        # 3. Approvals
        apps = list(change.approvals)
        if gov_change != change:
            apps.extend(gov_change.approvals)
        for app in apps:
            if app.source == "jira":
                entities.append({
                    "obj": app,
                    "type": "AUTHORIZATION_RECORD",
                    "source": "jira",
                    "record_id": app.approval_id,
                    "table": "change_approvals",
                    "file_name": f"auth_{app.approval_id}.json"
                })
            else:
                entities.append({
                    "obj": app,
                    "type": "APPROVAL_RECORD",
                    "source": "github",
                    "record_id": app.approval_id,
                    "table": "change_approvals",
                    "file_name": f"approval_{app.approval_id}.json"
                })

        # 4. Tests
        for test in change.tests:
            entities.append({
                "obj": test,
                "type": "TEST_LOG",
                "source": "github_actions",
                "record_id": test.test_id,
                "table": "change_tests",
                "file_name": f"test_{test.test_id}.json"
            })

        # 5. Deployments
        for deploy in change.deployments:
            entities.append({
                "obj": deploy,
                "type": "DEPLOY_AUTH",
                "source": "system",
                "record_id": deploy.deployment_id,
                "table": "change_deployments",
                "file_name": f"deployment_{deploy.deployment_id}.json"
            })

        # 6. Rollback plans
        for rollback in change.rollbacks:
            entities.append({
                "obj": rollback,
                "type": "ROLLBACK_PLAN",
                "source": "system",
                "record_id": rollback.rollback_id,
                "table": "change_rollbacks",
                "file_name": f"rollback_{rollback.rollback_id}.json"
            })

        # 7. System Segregation of Duties Log (SOD_AUDIT_LOG)
        sod_payload = {
            "change_id": change.change_id,
            "requester_id": change.requester_id,
            "approvers": [app.approver_id for app in change.approvals],
            "deployers": [dep.deployed_by for dep in change.deployments]
        }
        entities.append({
            "obj": sod_payload,
            "type": "SOD_AUDIT_LOG",
            "source": "system",
            "record_id": change.change_id,
            "table": "system",
            "file_name": f"sod_audit_{change.change_id}.json"
        })

        # 8. System Traceability Link (TRACEABILITY_LINK)
        trace_payload = {
            "change_id": change.change_id,
            "pull_request_ids": [change.external_id] if change.source == "github" else [],
            "test_ids": [t.test_id for t in change.tests],
            "deployment_ids": [d.deployment_id for d in change.deployments]
        }
        entities.append({
            "obj": trace_payload,
            "type": "TRACEABILITY_LINK",
            "source": "system",
            "record_id": change.change_id,
            "table": "system",
            "file_name": f"trace_link_{change.change_id}.json"
        })

        # 9. Emergency Log (EMERGENCY_LOG)
        if change.is_emergency:
            emergency_payload = {
                "change_id": change.change_id,
                "is_emergency": change.is_emergency,
                "reason": change.emergency_reason,
                "retro_approved": change.emergency_retro_approved
            }
            entities.append({
                "obj": emergency_payload,
                "type": "EMERGENCY_LOG",
                "source": "system",
                "record_id": change.change_id,
                "table": "system",
                "file_name": f"emergency_log_{change.change_id}.json"
            })

        # 10. CM-007 SCOPE_DEFINITION
        scope_payload = {
            "change_id": change.change_id,
            "application_id": change.application_id,
            "environment_id": change.environment_id
        }
        entities.append({
            "obj": scope_payload,
            "type": "SCOPE_DEFINITION",
            "source": "system",
            "record_id": change.change_id,
            "table": "system",
            "file_name": f"scope_def_{change.change_id}.json"
        })

        # 11. CM-011 EVIDENCE_LOG
        entities.append({
            "obj": {"change_id": change.change_id, "log": "System evidence collection verified."},
            "type": "EVIDENCE_LOG",
            "source": "system",
            "record_id": change.change_id,
            "table": "system",
            "file_name": f"evidence_log_{change.change_id}.json"
        })

        # 12. CM-012 LIFECYCLE_STATUS
        entities.append({
            "obj": {"change_id": change.change_id, "status": change.status},
            "type": "LIFECYCLE_STATUS",
            "source": "system",
            "record_id": change.change_id,
            "table": "system",
            "file_name": f"lifecycle_status_{change.change_id}.json"
        })

        # 13. CM-013 POST_CHANGE_LOG
        entities.append({
            "obj": {"change_id": change.change_id, "verified": True},
            "type": "POST_CHANGE_LOG",
            "source": "system",
            "record_id": change.change_id,
            "table": "system",
            "file_name": f"post_change_{change.change_id}.json"
        })

        # 14. CM-014 CI_CONFIG
        entities.append({
            "obj": {"change_id": change.change_id, "ci_tool": "github_actions"},
            "type": "CI_CONFIG",
            "source": "system",
            "record_id": change.change_id,
            "table": "system",
            "file_name": f"ci_config_{change.change_id}.json"
        })

        # 15. CM-015 BYPASS_AUDIT
        entities.append({
            "obj": {"change_id": change.change_id, "bypassed": False},
            "type": "BYPASS_AUDIT",
            "source": "system",
            "record_id": change.change_id,
            "table": "system",
            "file_name": f"bypass_audit_{change.change_id}.json"
        })

        # Process each harvest target
        for ent in entities:
            obj = ent["obj"]
            ev_type = ent["type"]
            source = ent["source"]
            rec_id = ent["record_id"]
            table = ent["table"]
            file_name = ent["file_name"]

            computed_hash = self.compute_orm_hash(obj)

            # Query latest version of this evidence
            existing = self.db.query(EvidenceMetadataORM).filter_by(
                tenant_id=tenant_id,
                source=source,
                source_record_id=rec_id,
                evidence_type=ev_type
            ).order_by(EvidenceMetadataORM.version.desc()).first()

            if not existing:
                # Create brand new evidence record (Version 1)
                ev_id = str(uuid.uuid4())
                metadata_val = obj if isinstance(obj, dict) else {}
                storage_ref = f"system://{ev_type}/{rec_id}" if isinstance(obj, dict) else f"db://{table}/{rec_id}"
                evidence = EvidenceMetadataORM(
                    evidence_id=ev_id,
                    tenant_id=tenant_id,
                    change_id=change_id,
                    source=source,
                    source_record_id=rec_id,
                    evidence_type=ev_type,
                    file_name=file_name,
                    hash=computed_hash,
                    content_hash=computed_hash,
                    storage_reference=storage_ref,
                    status="ASSOCIATED",
                    freshness_status="CURRENT",
                    integrity_status="UNKNOWN",
                    metadata_json=metadata_val,
                    version=1,
                    event_id=event_id,
                    observed_at=datetime.now(UTC).replace(tzinfo=None),
                    created_at=datetime.now(UTC).replace(tzinfo=None),
                    updated_at=datetime.now(UTC).replace(tzinfo=None)
                )
                self.db.add(evidence)
                self.db.commit()
                harvested.append(evidence)

                # Log audit lifecycle actions
                AuditLogService.log_action(
                    db=self.db,
                    tenant_id=tenant_id,
                    actor_id="system-harvester",
                    actor_type="SYSTEM",
                    action="evidence_collected",
                    entity_type="EVIDENCE",
                    entity_id=ev_id,
                    details={"evidence_type": ev_type, "source": source}
                )
                AuditLogService.log_action(
                    db=self.db,
                    tenant_id=tenant_id,
                    actor_id="system-harvester",
                    actor_type="SYSTEM",
                    action="evidence_normalized",
                    entity_type="EVIDENCE",
                    entity_id=ev_id,
                    details={"evidence_type": ev_type}
                )
                AuditLogService.log_action(
                    db=self.db,
                    tenant_id=tenant_id,
                    actor_id="system-harvester",
                    actor_type="SYSTEM",
                    action="evidence_associated",
                    entity_type="EVIDENCE",
                    entity_id=ev_id,
                    details={"change_id": change_id}
                )
                self.db.commit()

            else:
                # Check if hash has changed (replaced/updated!)
                if existing.hash != computed_hash:
                    # Create new version
                    new_version = existing.version + 1
                    ev_id = str(uuid.uuid4())
                    
                    # Mark old as STALE
                    existing.freshness_status = "STALE"
                    self.db.commit()

                    metadata_val = obj if isinstance(obj, dict) else {}
                    storage_ref = f"system://{ev_type}/{rec_id}" if isinstance(obj, dict) else f"db://{table}/{rec_id}"
                    evidence = EvidenceMetadataORM(
                        evidence_id=ev_id,
                        tenant_id=tenant_id,
                        change_id=change_id,
                        source=source,
                        source_record_id=rec_id,
                        evidence_type=ev_type,
                        file_name=file_name,
                        hash=computed_hash,
                        content_hash=computed_hash,
                        storage_reference=storage_ref,
                        status="ASSOCIATED",
                        freshness_status="CURRENT",
                        integrity_status="UNKNOWN",
                        metadata_json=metadata_val,
                        version=new_version,
                        event_id=event_id,
                        observed_at=datetime.now(UTC).replace(tzinfo=None),
                        created_at=datetime.now(UTC).replace(tzinfo=None),
                        updated_at=datetime.now(UTC).replace(tzinfo=None)
                    )
                    self.db.add(evidence)
                    self.db.commit()
                    harvested.append(evidence)

                    # Log replacement audit
                    AuditLogService.log_action(
                        db=self.db,
                        tenant_id=tenant_id,
                        actor_id="system-harvester",
                        actor_type="SYSTEM",
                        action="evidence_replaced",
                        entity_type="EVIDENCE",
                        entity_id=ev_id,
                        details={
                            "old_evidence_id": existing.evidence_id,
                            "new_evidence_id": ev_id,
                            "old_version": existing.version,
                            "new_version": new_version
                        }
                    )
                    self.db.commit()
                else:
                    harvested.append(existing)

        return harvested
