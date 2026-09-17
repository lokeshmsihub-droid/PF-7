from typing import List, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.orm import (
    ChangeORM, IdentityLinkORM, ORMChangeType, ChangeRelationshipORM,
    EntityType, RelationshipType
)
from app.domain.canonical.models import (
    CanonicalChange, CanonicalChangeIdentity, CanonicalChangeBasicInfo,
    CanonicalChangeRequest, CanonicalChangeAuthorization, CanonicalChangeDevelopment,
    CanonicalChangeTesting, CanonicalChangeApproval, CanonicalChangeDeployment,
    CanonicalChangeRollback, CanonicalChangeEmergency, DataAvailability
)

class CanonicalMapper:
    """Traverses PostgreSQL relational tables and maps database ORM records to the unified Canonical Change model."""
    
    @staticmethod
    def to_canonical_change(db: Session, change: ChangeORM) -> CanonicalChange:
        tenant_id = change.tenant_id
        
        # 0. Check for linked Governance change (Jira)
        parent_rel = db.query(ChangeRelationshipORM).filter_by(
            tenant_id=tenant_id,
            target_id=change.change_id,
            relationship_type=RelationshipType.ASSOCIATED_WITH
        ).first()
        
        parent_change = None
        if parent_rel and parent_rel.source_type == EntityType.CHANGE:
            parent_change = db.query(ChangeORM).filter_by(change_id=parent_rel.source_id, tenant_id=tenant_id).first()
            
        gov_change = parent_change if parent_change else change
        
        # 1. Map basic info (Prefer governance metadata)
        basic_info = CanonicalChangeBasicInfo(
            title=gov_change.title,
            description=gov_change.description if gov_change.description else DataAvailability.UNAVAILABLE,
            change_type=gov_change.change_type.value,
            status=gov_change.status,
            risk_level=gov_change.risk_level,
            environment=change.environment_id # Technical env is usually more accurate
        )
        
        # 2. Map request info (Prefer governance metadata)
        request = CanonicalChangeRequest(
            requester_id=gov_change.requester_id,
            owner_id=gov_change.owner_id,
            created_at=gov_change.created_at,
            requested_at=gov_change.planned_start if gov_change.planned_start else DataAvailability.UNKNOWN
        )
        
        # 3. Map Authorization (From ITSM/Governance change)
        if gov_change.approvals and gov_change.source == "jira":
            auth_val = gov_change.approvals[0]
            auth = CanonicalChangeAuthorization(
                required=True,
                authorized=(auth_val.decision == "APPROVED"),
                authorized_by=auth_val.approver_id,
                authorized_at=auth_val.approved_at,
                reference=auth_val.approval_id
            )
        elif change.authorizations:
            auth_val = change.authorizations[0]
            auth = CanonicalChangeAuthorization(
                required=True,
                authorized=(auth_val.status == "APPROVED"),
                authorized_by=auth_val.authorized_by,
                authorized_at=auth_val.authorized_at,
                reference=auth_val.justification if auth_val.justification else DataAvailability.UNAVAILABLE
            )
        else:
            auth = CanonicalChangeAuthorization(
                required=(change.change_type == ORMChangeType.NORMAL),
                authorized=DataAvailability.UNKNOWN,
                authorized_by=DataAvailability.UNKNOWN,
                authorized_at=DataAvailability.UNKNOWN,
                reference=DataAvailability.UNKNOWN
            )
            
        # 4. Map Development
        pr_id = change.external_id if change.source == "github" else None
        dev = CanonicalChangeDevelopment(
            repository=change.source if change.source else DataAvailability.UNKNOWN,
            branch=DataAvailability.UNKNOWN,
            pull_request_id=pr_id if pr_id else DataAvailability.UNAVAILABLE,
            commit_id=DataAvailability.UNKNOWN,
            changed_components=DataAvailability.UNKNOWN
        )
        
        # Sort tests and deployments by completed_at/started_at or deployed_at descending to get the latest
        sorted_tests = sorted(
            change.tests,
            key=lambda t: t.completed_at or t.started_at or datetime.min,
            reverse=True
        ) if change.tests else []

        sorted_deploys = sorted(
            change.deployments,
            key=lambda d: d.deployed_at or datetime.min,
            reverse=True
        ) if change.deployments else []

        if sorted_tests:
            dev.commit_id = sorted_tests[0].commit_id
        elif sorted_deploys:
            dev.commit_id = sorted_deploys[0].commit_id
            
        # 5. Map Testing
        if sorted_tests:
            test_val = sorted_tests[0]
            testing = CanonicalChangeTesting(
                required=True,
                test_id=test_val.test_id,
                test_type=test_val.test_type,
                test_status=test_val.status.value,
                tested_at=test_val.completed_at if test_val.completed_at else test_val.started_at,
                evidence_reference=test_val.evidence_reference if test_val.evidence_reference else DataAvailability.UNAVAILABLE,
                evidence_ref=test_val.evidence_reference if test_val.evidence_reference else DataAvailability.UNAVAILABLE
            )
        else:
            testing = CanonicalChangeTesting(
                required=(change.change_type == ORMChangeType.NORMAL),
                test_id=DataAvailability.UNAVAILABLE,
                test_type=DataAvailability.UNAVAILABLE,
                test_status=DataAvailability.UNAVAILABLE,
                tested_at=DataAvailability.UNAVAILABLE,
                evidence_reference=DataAvailability.UNAVAILABLE,
                evidence_ref=DataAvailability.UNAVAILABLE
            )
            
        # 6. Map Approval
        if change.approvals:
            app_val = change.approvals[0]
            approval = CanonicalChangeApproval(
                required=True,
                approved=(app_val.decision == "APPROVED"),
                approver_id=app_val.approver_id,
                approved_at=app_val.approved_at,
                reference=app_val.role
            )
        else:
            approval = CanonicalChangeApproval(
                required=(change.change_type == ORMChangeType.NORMAL),
                approved=DataAvailability.UNKNOWN,
                approver_id=DataAvailability.UNKNOWN,
                approved_at=DataAvailability.UNKNOWN,
                reference=DataAvailability.UNKNOWN
            )
            
        # 7. Map Deployment
        if sorted_deploys:
            dep_val = sorted_deploys[0]
            deployment = CanonicalChangeDeployment(
                deployment_id=dep_val.deployment_id,
                environment=dep_val.environment_id,
                deployed_by=dep_val.deployed_by,
                deployed_at=dep_val.deployed_at,
                deployment_status=dep_val.status,
                status=dep_val.status,
                version=dep_val.version
            )
        else:
            deployment = CanonicalChangeDeployment(
                deployment_id=DataAvailability.UNAVAILABLE,
                environment=DataAvailability.UNAVAILABLE,
                deployed_by=DataAvailability.UNAVAILABLE,
                deployed_at=DataAvailability.UNAVAILABLE,
                deployment_status=DataAvailability.UNAVAILABLE,
                status=DataAvailability.UNAVAILABLE,
                version=DataAvailability.UNAVAILABLE
            )
            
        # 8. Map Rollback
        if change.rollbacks:
            roll_val = change.rollbacks[0]
            rollback = CanonicalChangeRollback(
                rollback_plan=roll_val.rollback_plan,
                rollback_tested=roll_val.rollback_tested,
                rollback_reference=roll_val.rollback_reference
            )
        else:
            rollback = CanonicalChangeRollback(
                rollback_plan=DataAvailability.UNKNOWN,
                rollback_tested=DataAvailability.UNKNOWN,
                rollback_reference=DataAvailability.UNKNOWN
            )
            
        # 9. Map Emergency (Prefer governance metadata)
        emergency = CanonicalChangeEmergency(
            is_emergency=gov_change.is_emergency,
            reason=gov_change.emergency_reason if gov_change.emergency_reason else DataAvailability.UNAVAILABLE,
            emergency_approved_by=gov_change.emergency_approved_by if gov_change.emergency_approved_by else DataAvailability.UNAVAILABLE,
            retro_approval=gov_change.emergency_retro_approved if gov_change.emergency_retro_approved is not None else DataAvailability.UNAVAILABLE
        )
        
        # 10. Map Evidence IDs
        ev_ids = [ev.evidence_id for ev in change.evidence] if change.evidence else []
        
        identity = CanonicalChangeIdentity(
            change_id=change.change_id,
            tenant_id=change.tenant_id,
            source=change.source,
            external_id=change.external_id
        )
        
        return CanonicalChange(
            identity=identity,
            basic_info=basic_info,
            request=request,
            authorization=auth,
            development=dev,
            testing=testing,
            approval=approval,
            deployment=deployment,
            rollback=rollback,
            emergency=emergency,
            evidence_ids=ev_ids
        )
