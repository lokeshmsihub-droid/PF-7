from datetime import datetime, timezone, UTC
from typing import Dict, Any, Optional, List
from app.models.orm import (
    ChangeORM, ApprovalORM, AuthorizationORM, IdentityLinkORM, ORMChangeType
)

def parse_iso_datetime(dt_str: Optional[Any]) -> Optional[datetime]:
    """Helper to parse ISO-8601 string from Jira to naive UTC datetime object."""
    if not dt_str:
        return None
    if isinstance(dt_str, datetime):
        if dt_str.tzinfo:
            return dt_str.astimezone(timezone.utc).replace(tzinfo=None)
        return dt_str
    if isinstance(dt_str, dict):
        dt_str = dt_str.get("iso8601") or dt_str.get("value")
    if not isinstance(dt_str, str):
        return None
    try:
        clean_str = dt_str.replace("+0000", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None

def _extract_field_value(fields: Dict[str, Any], field_key: Optional[str]) -> Any:
    """Safely extract nested dictionary or string value from a Jira field."""
    if not field_key or field_key not in fields:
        return None
    val = fields[field_key]
    if isinstance(val, dict):
        return val.get("value") or val.get("name") or val.get("displayName") or val
    if isinstance(val, list) and val:
        first = val[0]
        if isinstance(first, dict):
            return first.get("value") or first.get("name")
        return first
    return val

class JiraNormalizer:
    """Transforms raw Jira JSON payloads to Common Change Data Model (CCDM) database models."""

    @staticmethod
    def normalize_issue(
        payload: Dict[str, Any],
        tenant_id: str,
        custom_field_map: Optional[Dict[str, str]] = None
    ) -> ChangeORM:
        """Map Jira issue payload to normalized ChangeORM model."""
        fields = payload.get("fields", {})
        cf_map = custom_field_map or {}
        
        issue_key = payload.get("key") or payload.get("id", "CHG-UNKNOWN")
        title = fields.get("summary") or "Jira Change Request"
        description = fields.get("description") or ""
        if isinstance(description, dict):
            # Jira Atlassian Document Format (ADF) handling
            description = str(description.get("content", ""))

        # 1. Risk assessment
        risk = "medium"
        risk_key = cf_map.get("risk_field", "customfield_risk")
        risk_val = _extract_field_value(fields, risk_key)
        if not risk_val and "priority" in fields:
            p_val = _extract_field_value(fields, "priority")
            if p_val:
                risk_val = p_val
        if risk_val:
            r_str = str(risk_val).lower()
            if "low" in r_str:
                risk = "low"
            elif "high" in r_str or "critical" in r_str or "highest" in r_str:
                risk = "high"
            elif "medium" in r_str:
                risk = "medium"

        # 2. Change Type & Emergency status
        change_type = ORMChangeType.STANDARD
        emergency_key = cf_map.get("emergency_field", "customfield_is_emergency")
        em_val = _extract_field_value(fields, emergency_key)
        
        type_key = cf_map.get("change_type_field", "customfield_change_type")
        type_val = _extract_field_value(fields, type_key)
        
        is_emergency = False
        if em_val and str(em_val).lower() in ["yes", "true", "emergency", "1"]:
            is_emergency = True
            change_type = ORMChangeType.EMERGENCY
        elif type_val and "emergency" in str(type_val).lower():
            is_emergency = True
            change_type = ORMChangeType.EMERGENCY
        elif "emergency" in title.lower():
            is_emergency = True
            change_type = ORMChangeType.EMERGENCY

        # 3. Status resolution
        status_field = fields.get("status", {})
        status_name = status_field.get("name") if isinstance(status_field, dict) else str(status_field or "OPEN")
        source_status = status_name
        status_lower = status_name.lower()
        
        status = status_name
        if status_lower in ["done", "closed", "resolved", "implemented", "completed"]:
            status = "CLOSED"
        elif status_lower in ["canceled", "cancelled", "rejected"]:
            status = "CANCELLED"
        elif not status:
            status = "OPEN"

        change_id = f"chg-jira-{issue_key}"

        # 4. Dates
        created_at = parse_iso_datetime(fields.get("created")) or datetime.now(UTC).replace(tzinfo=None)
        updated_at = parse_iso_datetime(fields.get("updated")) or created_at
        
        start_key = cf_map.get("planned_start_field", "customfield_planned_start")
        end_key = cf_map.get("planned_end_field", "customfield_planned_end")
        planned_start = parse_iso_datetime(_extract_field_value(fields, start_key)) or created_at
        planned_end = parse_iso_datetime(_extract_field_value(fields, end_key)) or updated_at

        # 5. Creator / Assignee
        creator = fields.get("creator") or fields.get("reporter") or {}
        creator_login = creator.get("emailAddress") or creator.get("displayName") or creator.get("accountId") or "unknown"
        
        assignee = fields.get("assignee") or {}
        assignee_login = assignee.get("emailAddress") or assignee.get("displayName") or assignee.get("accountId") or creator_login

        # 6. Target Environment
        environment_id = "env-prod"
        env_key = cf_map.get("environment_field", "customfield_environment")
        env_val = _extract_field_value(fields, env_key)
        if env_val:
            e_str = str(env_val).lower()
            if "staging" in e_str or "stage" in e_str:
                environment_id = "env-staging"
            elif "dev" in e_str or "development" in e_str:
                environment_id = "env-dev"
            elif "qa" in e_str:
                environment_id = "env-qa"

        # Application / Project scope
        application_id = "app-default"


        return ChangeORM(
            change_id=change_id,
            tenant_id=tenant_id,
            external_id=issue_key,
            source="jira",
            title=title,
            description=description,
            change_type=change_type,
            requester_id=f"usr-{creator_login}",
            owner_id=f"usr-{assignee_login}",
            risk_level=risk,
            environment_id=environment_id,
            application_id=application_id,
            status=status,
            planned_start=planned_start,
            planned_end=planned_end,
            implemented_at=updated_at,
            completed_at=updated_at if status == "CLOSED" else None,
            created_at=created_at,
            updated_at=updated_at
        )

    @staticmethod
    def extract_approvals(payload: Dict[str, Any], tenant_id: str) -> List[ApprovalORM]:
        """Extract approvals from Jira Issue JSM approval records or changelog status transitions."""
        approvals = []
        issue_key = payload.get("key") or payload.get("id", "CHG-UNKNOWN")
        change_id = f"chg-jira-{issue_key}"
        seen_approvers = set()

        # 1. Jira Service Management (JSM) Approvals
        jsm_approvals = payload.get("jsm_approvals", [])
        for jsm in jsm_approvals:
            appr_id = jsm.get("id") or f"jsm-{len(approvals)}"
            decision_raw = (jsm.get("finalDecision") or "approved").upper()
            decision = "APPROVED" if decision_raw in ["APPROVED", "COMPLETED"] else ("REJECTED" if decision_raw in ["REJECTED", "DECLINED"] else "PENDING")
            created_at = parse_iso_datetime(jsm.get("createdDate")) or datetime.now(UTC).replace(tzinfo=None)

            for item in jsm.get("approvers", []):
                approver_info = item.get("approver", {})
                login = approver_info.get("emailAddress") or approver_info.get("displayName") or approver_info.get("accountId") or "jsm-approver"
                if login not in seen_approvers:
                    seen_approvers.add(login)
                    approvals.append(ApprovalORM(
                        approval_id=f"appr-jira-{issue_key}-{appr_id}",
                        tenant_id=tenant_id,
                        change_id=change_id,
                        approver_id=f"usr-{login}",
                        role="cab_approver",
                        decision=decision,
                        approved_at=created_at,
                        source="jira"
                    ))

        # 2. Jira Changelog Status Transitions (e.g. Under Review -> Approved / CAB Approved)
        changelog = payload.get("changelog", {}).get("histories", [])
        for history in changelog:
            author = history.get("author", {})
            author_login = author.get("emailAddress") or author.get("displayName") or author.get("accountId") or "approver"
            created = parse_iso_datetime(history.get("created")) or datetime.now(UTC).replace(tzinfo=None)
            h_id = history.get("id") or str(len(approvals) + 1)

            for item in history.get("items", []):
                if item.get("field") == "status":
                    to_string = item.get("toString", "").lower()
                    from_string = item.get("fromString", "").lower()

                    if to_string in ["approved", "done", "authorized", "cab approved", "scheduled"]:
                        if author_login not in seen_approvers:
                            seen_approvers.add(author_login)
                            approvals.append(ApprovalORM(
                                approval_id=f"appr-jira-{issue_key}-{h_id}",
                                tenant_id=tenant_id,
                                change_id=change_id,
                                approver_id=f"usr-{author_login}",
                                role="cab_approver" if ("cab" in to_string or "cab" in from_string) else "manager",
                                decision="APPROVED",
                                approved_at=created,
                                source="jira"
                            ))
                    elif to_string in ["rejected", "cancelled", "revoked"]:
                        approvals.append(ApprovalORM(
                            approval_id=f"appr-jira-{issue_key}-{h_id}-revoked",
                            tenant_id=tenant_id,
                            change_id=change_id,
                            approver_id=f"usr-{author_login}",
                            role="manager",
                            decision="REJECTED",
                            approved_at=created,
                            source="jira"
                        ))

        return approvals

    @staticmethod
    def extract_authorizations(payload: Dict[str, Any], tenant_id: str) -> List[AuthorizationORM]:
        """Extract explicit change authorization entities."""
        auths = []
        issue_key = payload.get("key") or payload.get("id", "CHG-UNKNOWN")
        change_id = f"chg-jira-{issue_key}"
        fields = payload.get("fields", {})

        creator = fields.get("creator") or fields.get("reporter") or {}
        creator_login = creator.get("emailAddress") or creator.get("displayName") or creator.get("accountId") or "unknown"
        created_at = parse_iso_datetime(fields.get("created")) or datetime.now(UTC).replace(tzinfo=None)

        auths.append(AuthorizationORM(
            authorization_id=f"auth-jira-{issue_key}-req",
            tenant_id=tenant_id,
            change_id=change_id,
            authorized_by=f"usr-{creator_login}",
            status="APPROVED",
            authorized_at=created_at,
            justification="Jira Change Request Submission",
            source="jira"
        ))
        return auths

    @staticmethod
    def extract_identities(payload: Dict[str, Any], tenant_id: str) -> List[IdentityLinkORM]:
        """Extract user identities from creator, reporter, assignee, and changelog authors."""
        identities = []
        fields = payload.get("fields", {})
        seen_handles = set()

        users_to_check = [
            fields.get("creator"),
            fields.get("reporter"),
            fields.get("assignee")
        ]

        # Add changelog authors
        for h in payload.get("changelog", {}).get("histories", []):
            if h.get("author"):
                users_to_check.append(h.get("author"))

        for u in users_to_check:
            if not u or not isinstance(u, dict):
                continue
            email = u.get("emailAddress")
            display_name = u.get("displayName")
            account_id = u.get("accountId") or u.get("name")

            identifier = email or account_id or display_name
            if identifier and identifier not in seen_handles:
                seen_handles.add(identifier)
                identities.append(IdentityLinkORM(
                    tenant_id=tenant_id,
                    internal_user_id=f"usr-{identifier}",
                    source="jira",
                    external_user_id=account_id or identifier,
                    external_username=identifier,
                    external_reference=email,
                    status="ACTIVE"
                ))

        return identities
