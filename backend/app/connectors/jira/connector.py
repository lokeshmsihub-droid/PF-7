import os
import time
import httpx
import base64
from datetime import datetime, UTC
from typing import List, Dict, Any, Optional
from app.connectors.contract import (
    BaseConnector, ConnectionConfig, ConnectionStatus, SyncRequest,
    SyncResult, CollectedRecord, ConnectorType, AuthType, ConnectorError
)
from app.core.security import decrypt_token, encrypt_token
from app.core.config import settings

def resolve_jira_token(credentials: dict) -> str:
    """Resolve API token or OAuth access token from credentials payload or secure environment references."""
    # 1. Direct access token (from OAuth 2.0)
    access_token = credentials.get("access_token")
    if access_token:
        return decrypt_token(access_token) or access_token
        
    # 2. Encrypted access token key
    enc_access_token = credentials.get("access_token_encrypted")
    if enc_access_token:
        dec = decrypt_token(enc_access_token)
        if dec:
            return dec

    # 3. Token reference from env
    token_ref = credentials.get("token_reference")
    if token_ref:
        return os.environ.get(token_ref, "")
        
    # 4. Standard token / PAT
    raw_tok = credentials.get("token", "")
    dec = decrypt_token(raw_tok)
    return dec or raw_tok

class JiraConnector(BaseConnector):
    """Connector for collecting change management records from Jira Cloud via OAuth 2.0 or API Token."""

    ATLASSIAN_AUTH_URL = "https://auth.atlassian.com/authorize"
    ATLASSIAN_TOKEN_URL = "https://auth.atlassian.com/oauth/token"
    ATLASSIAN_ACCESSIBLE_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"

    def __init__(self, config: ConnectionConfig):
        super().__init__(config)
        self.token = resolve_jira_token(self.config.credentials)
        self.refresh_token = self.config.credentials.get("refresh_token") or decrypt_token(self.config.credentials.get("refresh_token_encrypted"))
        self.token_expires_at = self.config.credentials.get("token_expires_at", 0)
        self.cloud_id = self.config.credentials.get("cloud_id") or self.config.credentials.get("site_cloud_id")
        self.email = self.config.credentials.get("email", os.environ.get("JIRA_USER_EMAIL", ""))
        self.auth_type = self.config.auth_type
        
        # Cloud ID API route takes precedence for OAuth 2.0 (3LO)
        if self.cloud_id:
            self.base_url = f"https://api.atlassian.com/ex/jira/{self.cloud_id}/rest/api/3"
        elif self.config.endpoint_url:
            self.base_url = self.config.endpoint_url
        else:
            self.base_url = "https://acme.atlassian.net/rest/api/3"

        self._client: Optional[httpx.Client] = None
        self.mock_mode = (
            self.config.credentials.get("mock") is True 
            or os.environ.get("JIRA_MOCK") == "true"
            or (not self.token and not self.mock_mode_allowed())
        )

    def mock_mode_allowed(self) -> bool:
        """Check if connector can run in real mode."""
        return bool(self.token or (self.refresh_token and settings.JIRA_CLIENT_ID))

    @staticmethod
    def get_accessible_resources(access_token: str) -> List[Dict[str, Any]]:
        """
        Discover accessible Jira sites for a granted OAuth 2.0 3LO access token.
        Calls https://api.atlassian.com/oauth/token/accessible-resources.
        """
        if not access_token or access_token == "mock_token":
            return [
                {
                    "id": "cloud-site-mock-uuid-1",
                    "name": "acme-engineering",
                    "url": "https://acme-engineering.atlassian.net",
                    "scopes": ["read:jira-work", "read:jira-user", "read:servicedesk-request", "offline_access"],
                    "avatarUrl": "https://avatar-management--avatars.us-west-2.prod.public.atl-paas.net/default-avatar.png"
                },
                {
                    "id": "cloud-site-mock-uuid-2",
                    "name": "acme-operations",
                    "url": "https://acme-operations.atlassian.net",
                    "scopes": ["read:jira-work", "read:jira-user"],
                    "avatarUrl": "https://avatar-management--avatars.us-west-2.prod.public.atl-paas.net/default-avatar.png"
                }
            ]

        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            with httpx.Client(timeout=10.0) as client:
                res = client.get(JiraConnector.ATLASSIAN_ACCESSIBLE_RESOURCES_URL, headers=headers)
                if res.status_code == 200:
                    return res.json()
                return []
        except Exception:
            return []

    def refresh_access_token(self) -> str:
        """
        Exchange refresh token for a fresh access token with Atlassian OAuth endpoint.
        Handles invalid_grant and revoked authorization.
        """
        if self.mock_mode:
            self.token = "mock_refreshed_access_token"
            self.token_expires_at = int(time.time()) + 3600
            return self.token

        client_id = settings.JIRA_CLIENT_ID or os.environ.get("JIRA_CLIENT_ID")
        client_secret = settings.JIRA_CLIENT_SECRET or os.environ.get("JIRA_CLIENT_SECRET")
        
        if not client_id or not client_secret:
            raise ConnectorError("Jira OAuth client credentials are not configured", self.config.connector_id)

        if not self.refresh_token:
            raise ConnectorError("No refresh token available for Jira connection. REAUTH_REQUIRED", self.config.connector_id)

        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.post(
                    self.ATLASSIAN_TOKEN_URL,
                    json={
                        "grant_type": "refresh_token",
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "refresh_token": self.refresh_token
                    },
                    headers={"Content-Type": "application/json"}
                )

                if res.status_code == 200:
                    data = res.json()
                    new_access_token = data.get("access_token")
                    new_refresh_token = data.get("refresh_token") or self.refresh_token
                    expires_in = data.get("expires_in", 3600)

                    self.token = new_access_token
                    self.refresh_token = new_refresh_token
                    self.token_expires_at = int(time.time()) + int(expires_in)

                    # Update internal config credentials
                    self.config.credentials["access_token_encrypted"] = encrypt_token(new_access_token)
                    self.config.credentials["refresh_token_encrypted"] = encrypt_token(new_refresh_token)
                    self.config.credentials["token_expires_at"] = self.token_expires_at

                    # Persist rotated tokens to DB
                    try:
                        from app.db.postgres import SessionLocal
                        from app.models.orm import ConnectorAccountORM
                        db_s = SessionLocal()
                        acc = db_s.query(ConnectorAccountORM).filter_by(account_id=self.config.connector_id).first()
                        if acc:
                            new_cfg = dict(acc.config or {})
                            new_cfg["access_token_encrypted"] = encrypt_token(new_access_token)
                            new_cfg["refresh_token_encrypted"] = encrypt_token(new_refresh_token)
                            new_cfg["token_expires_at"] = self.token_expires_at
                            acc.config = new_cfg
                            db_s.commit()
                        db_s.close()
                    except Exception as persist_err:
                        print(f"Error persisting refreshed Jira token: {persist_err}")

                    # Re-create client with new auth header
                    if self._client:
                        self.disconnect()
                        self.connect()

                    return new_access_token
                elif res.status_code in [400, 401]:
                    err_payload = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
                    err_msg = err_payload.get("error_description") or err_payload.get("error") or res.text
                    raise ConnectorError(f"REAUTH_REQUIRED: Jira token refresh failed: {err_msg}", self.config.connector_id)
                else:
                    raise ConnectorError(f"Unexpected token refresh status {res.status_code}: {res.text}", self.config.connector_id)
        except Exception as e:
            if "REAUTH_REQUIRED" in str(e):
                raise
            raise ConnectorError(f"Failed to refresh Jira token: {str(e)}", self.config.connector_id)

    def _ensure_valid_token(self):
        """Check token expiration and refresh automatically if near expiry."""
        if self.mock_mode:
            return

        if self.refresh_token and self.token_expires_at:
            # Refresh if token expires in less than 30 seconds
            if time.time() >= (self.token_expires_at - 30):
                try:
                    self.refresh_access_token()
                except Exception as e:
                    # If we still have an access token, try using it before aborting
                    if not self.token:
                        raise

    def connect(self) -> bool:
        """Establish connection or configure HTTPX client with OAuth Bearer or Basic PAT."""
        self._ensure_valid_token()

        if not self._client:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            # OAuth 2.0 3LO Bearer Token takes precedence
            if self.token and (self.cloud_id or not self.email):
                headers["Authorization"] = f"Bearer {self.token}"
            elif self.token and self.email:
                auth_str = f"{self.email}:{self.token}"
                b64_auth = base64.b64encode(auth_str.encode()).decode()
                headers["Authorization"] = f"Basic {b64_auth}"
                
            self._client = httpx.Client(base_url=self.base_url, headers=headers, timeout=15.0)
        return True

    def disconnect(self) -> bool:
        """Close connection client."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        return True

    def test_connection(self) -> ConnectionStatus:
        """Verify API reachability and authentication validity."""
        if self.mock_mode:
            return ConnectionStatus(
                status="CONNECTED",
                checked_at=datetime.now(UTC),
                error_message=None
            )

        try:
            self.connect()
            # In Jira Cloud OAuth 2.0, verify access with /myself or /project
            response = self._client.get("/myself")
            
            if response.status_code == 200:
                user_info = response.json()
                return ConnectionStatus(
                    status="CONNECTED",
                    checked_at=datetime.now(UTC),
                    error_message=None
                )
            elif response.status_code in [401, 403]:
                # Attempt one token refresh if token expired
                if self.refresh_token:
                    try:
                        self.refresh_access_token()
                        retry_res = self._client.get("/myself")
                        if retry_res.status_code == 200:
                            return ConnectionStatus(
                                status="CONNECTED",
                                checked_at=datetime.now(UTC),
                                error_message=None
                            )
                    except Exception:
                        pass
                return ConnectionStatus(
                    status="REAUTH_REQUIRED",
                    checked_at=datetime.now(UTC),
                    error_message=f"Jira authorization expired or invalid (HTTP {response.status_code})"
                )
            else:
                return ConnectionStatus(
                    status="ERROR",
                    checked_at=datetime.now(UTC),
                    error_message=f"Jira returned HTTP status {response.status_code}: {response.text}"
                )
        except Exception as e:
            return ConnectionStatus(
                status="ERROR",
                checked_at=datetime.now(UTC),
                error_message=str(e)
            )

    def discover(self) -> List[Dict[str, Any]]:
        """Discover accessible Jira projects for this installation."""
        if self.mock_mode:
            return [
                {
                    "id": "10000",
                    "key": "CHG",
                    "name": "Change Management",
                    "projectTypeKey": "service_desk"
                }
            ]
        return self.discover_projects()

    def discover_projects(self) -> List[Dict[str, Any]]:
        """Discover Jira projects."""
        if self.mock_mode:
            return [
                {
                    "id": "10000",
                    "key": "CHG",
                    "name": "Change Management & Operations",
                    "projectTypeKey": "service_desk",
                    "lead": "Alice Project Lead"
                },
                {
                    "id": "10001",
                    "key": "OPS",
                    "name": "Infrastructure & Core Services",
                    "projectTypeKey": "software",
                    "lead": "Bob Operations Lead"
                }
            ]

        self.connect()
        try:
            response = self._client.get("/project")
            if response.status_code == 200:
                return response.json()
            return []
        except Exception:
            return []

    def discover_issue_types(self, project_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """Discover issue types available in Jira."""
        if self.mock_mode:
            return [
                {"id": "10010", "name": "Change", "description": "Standard Change Request", "subtask": False},
                {"id": "10011", "name": "Emergency Change", "description": "Emergency Outage Patch", "subtask": False},
                {"id": "10012", "name": "Service Request", "description": "IT Service Request", "subtask": False},
                {"id": "10013", "name": "Bug", "description": "Software Bug Defect", "subtask": False}
            ]

        self.connect()
        try:
            response = self._client.get("/issuetype")
            if response.status_code == 200:
                return response.json()
            return []
        except Exception:
            return []

    def discover_fields(self) -> List[Dict[str, Any]]:
        """Discover custom and system fields for custom field mapping."""
        if self.mock_mode:
            return [
                {"id": "customfield_risk", "name": "Risk Level", "custom": True, "schema": {"type": "option"}},
                {"id": "customfield_environment", "name": "Environment Target", "custom": True, "schema": {"type": "option"}},
                {"id": "customfield_is_emergency", "name": "Emergency Change Flag", "custom": True, "schema": {"type": "option"}},
                {"id": "customfield_rollback_plan", "name": "Rollback Procedure", "custom": True, "schema": {"type": "string"}},
                {"id": "customfield_planned_start", "name": "Planned Start Date", "custom": True, "schema": {"type": "datetime"}},
                {"id": "customfield_planned_end", "name": "Planned End Date", "custom": True, "schema": {"type": "datetime"}},
                {"id": "customfield_business_impact", "name": "Business Impact Assessment", "custom": True, "schema": {"type": "string"}}
            ]

        self.connect()
        try:
            response = self._client.get("/field")
            if response.status_code == 200:
                return response.json()
            return []
        except Exception:
            return []

    def collect(self, sync_request: SyncRequest) -> List[CollectedRecord]:
        """Collect Jira Change Request issues, changelogs, and approvals with pagination."""
        params = sync_request.parameters or {}
        jql = params.get("jql") or self.config.credentials.get("jql")
        if not jql or "CHG" in jql:
            # Dynamically discover user's real projects in their workspace
            try:
                projs = self.discover_projects()
                proj_keys = [p["key"] for p in projs if "key" in p]
                if proj_keys:
                    proj_list_str = ", ".join(f'"{k}"' for k in proj_keys)
                    jql = f"project in ({proj_list_str}) ORDER BY created DESC"
                else:
                    jql = "ORDER BY created DESC"
            except Exception:
                jql = "ORDER BY created DESC"

        if self.mock_mode:
            return self._generate_mock_collection(jql)

        self.connect()
        records: List[CollectedRecord] = []
        start_at = 0
        max_results = 50
        total_fetched = 0
        max_limit = params.get("max_limit", 200)

        # Configured custom fields
        custom_fields = self.config.credentials.get("custom_fields", {})
        extra_fields = list(custom_fields.values()) if isinstance(custom_fields, dict) else []

        fields_to_request = [
            "summary", "description", "status", "creator", "assignee", "reporter",
            "created", "updated", "priority", "labels", "components", "issuelinks"
        ] + extra_fields

        next_page_token = None
        while total_fetched < max_limit:
            self._ensure_valid_token()
            try:
                # 1. Try modern Jira Cloud Search JQL API (/search/jql)
                search_payload = {
                    "jql": jql,
                    "maxResults": max_results
                }
                if next_page_token:
                    search_payload["nextPageToken"] = next_page_token

                response = self._client.post("/search/jql", json=search_payload)
                
                # If /search/jql returned 404/410, try classic /search
                if response.status_code in [404, 410]:
                    response = self._client.post(
                        "/search",
                        json={
                            "jql": jql,
                            "startAt": start_at,
                            "maxResults": max_results,
                            "fields": fields_to_request,
                            "expand": ["changelog"]
                        }
                    )

                if response.status_code == 429:
                    # Rate limiting: respect Retry-After
                    retry_after = int(response.headers.get("Retry-After", "2"))
                    time.sleep(min(retry_after, 10))
                    continue

                if response.status_code == 200:
                    data = response.json()
                    issues = data.get("issues", [])
                    if not issues:
                        break

                    for issue in issues:
                        issue_id = issue.get("id") or issue.get("key")
                        # If issue payload is lightweight (e.g. only {'id': ...}), fetch full details
                        if not issue.get("fields") and issue_id:
                            try:
                                d_res = self._client.get(f"/issue/{issue_id}?expand=changelog,renderedFields")
                                if d_res.status_code == 200:
                                    issue = d_res.json()
                            except Exception:
                                pass

                        # Also check Jira Service Management approvals if available
                        jsm_approvals = self._fetch_jsm_approvals(issue.get("id") or issue.get("key"))
                        if jsm_approvals:
                            issue["jsm_approvals"] = jsm_approvals

                        record_key = issue.get("key") or str(issue_id)
                        records.append(CollectedRecord(
                            record_id=record_key,
                            connector_type=ConnectorType.JIRA,
                            entity_type="jira_issue",
                            payload=issue,
                            collected_at=datetime.now(UTC).replace(tzinfo=None)
                        ))

                    total_fetched += len(issues)
                    start_at += len(issues)
                    next_page_token = data.get("nextPageToken")
                    total_available = data.get("total", total_fetched)
                    if data.get("isLast", True) or not next_page_token or start_at >= total_available:
                        break
                elif response.status_code in [401, 403]:
                    raise ConnectorError(f"REAUTH_REQUIRED: Jira returned {response.status_code}", self.config.connector_id)
                else:
                    break
            except Exception as e:
                if "REAUTH_REQUIRED" in str(e):
                    raise
                raise ConnectorError(f"Failed to collect Jira data: {str(e)}", self.config.connector_id)

        return records

    def _fetch_jsm_approvals(self, issue_id_or_key: str) -> List[Dict[str, Any]]:
        """Fetch formal approvals from Jira Service Management API if enabled."""
        if not self._client or self.mock_mode:
            return []
        try:
            # JSM Approval API
            jsm_url = f"/rest/servicedeskapi/request/{issue_id_or_key}/approval"
            res = self._client.get(jsm_url)
            if res.status_code == 200:
                return res.json().get("values", [])
        except Exception:
            pass
        return []

    def sync(self, sync_request: SyncRequest) -> SyncResult:
        """High-level orchestration of sync."""
        start_time = datetime.now(UTC)
        try:
            records = self.collect(sync_request)
            
            # Use shared collection service to push to MongoDB
            from app.services.collection_service import CollectionService
            from app.db.mongodb import MongoDBClient
            
            mongo = MongoDBClient()
            collector = CollectionService(mongo.db)
            
            count = collector.store_collected_records(
                tenant_id=getattr(self.config, 'tenant_id', 'default-tenant'),
                sync_run_id=sync_request.sync_run_id,
                records=records
            )
            
            return SyncResult(
                sync_run_id=sync_request.sync_run_id,
                status="SUCCESS",
                records_synced=count,
                started_at=start_time,
                completed_at=datetime.now(UTC)
            )
        except Exception as e:
            return SyncResult(
                sync_run_id=sync_request.sync_run_id,
                status="FAILED",
                records_synced=0,
                started_at=start_time,
                completed_at=datetime.now(UTC),
                error=str(e)
            )

    def get_status(self) -> ConnectionStatus:
        return self.test_connection()

    def _generate_mock_collection(self, jql: str) -> List[CollectedRecord]:
        """Generate reliable, comprehensive mock Jira payloads for testing all SDLC controls."""
        now = datetime.now(UTC).replace(tzinfo=None)
        records = []
        
        # Mock Issue 1: Standard Compliant Change (correlates to GitHub PR 101)
        issue_1 = {
            "key": "CHG-101",
            "id": "10001",
            "fields": {
                "summary": "STANDARD: CM-005 Auth Token Refactoring",
                "description": "Fixes auth token generation issues. PR #101. Linked to GitHub commit 3ca3281c.",
                "creator": {"emailAddress": "alice@acme.com", "displayName": "Alice Developer"},
                "assignee": {"emailAddress": "bob@acme.com", "displayName": "Bob Reviewer"},
                "reporter": {"emailAddress": "alice@acme.com", "displayName": "Alice Developer"},
                "status": {"name": "Done", "statusCategory": {"key": "done"}},
                "priority": {"name": "Medium"},
                "created": "2026-08-24T00:00:00.000+0000",
                "updated": "2026-08-24T08:00:00.000+0000",
                "customfield_risk": {"value": "Low"},
                "customfield_environment": {"value": "Production"},
                "customfield_planned_start": "2026-08-24T03:00:00.000+0000",
                "customfield_planned_end": "2026-08-24T05:00:00.000+0000",
                "customfield_rollback_plan": "Automated blue/green rollback to previous stable deployment container.",
                "customfield_is_emergency": {"value": "No"},
                "customfield_business_impact": "Zero downtime expected. Standard token refresh logic."
            },
            "changelog": {
                "histories": [
                    {
                        "id": "chlog-101-1",
                        "created": "2026-08-24T02:00:00.000+0000",
                        "author": {"emailAddress": "bob@acme.com", "displayName": "Bob Reviewer"},
                        "items": [
                            {"field": "status", "fromString": "In Review", "toString": "Approved"}
                        ]
                    },
                    {
                        "id": "chlog-101-2",
                        "created": "2026-08-24T04:00:00.000+0000",
                        "author": {"emailAddress": "alice@acme.com", "displayName": "Alice Developer"},
                        "items": [
                            {"field": "status", "fromString": "Approved", "toString": "Done"}
                        ]
                    }
                ]
            },
            "jsm_approvals": [
                {
                    "id": "jsm-appr-101",
                    "approvers": [{"approver": {"displayName": "Bob Reviewer", "emailAddress": "bob@acme.com"}}],
                    "finalDecision": "approved",
                    "createdDate": {"iso8601": "2026-08-24T02:00:00.000+0000"}
                }
            ]
        }
        
        records.append(CollectedRecord(
            record_id="CHG-101",
            connector_type=ConnectorType.JIRA,
            entity_type="jira_issue",
            payload=issue_1,
            collected_at=now
        ))

        # Mock Issue 2: Emergency Change (correlates to PR 104)
        issue_2 = {
            "key": "CHG-104",
            "id": "10004",
            "fields": {
                "summary": "EMERGENCY: Fix production database connection pool starvation",
                "description": "Critical outage fix applied to resolve database timeouts. Hotfix PR #104.",
                "creator": {"emailAddress": "alice@acme.com", "displayName": "Alice Developer"},
                "assignee": {"emailAddress": "manager@acme.com", "displayName": "Engineering Manager"},
                "reporter": {"emailAddress": "alice@acme.com", "displayName": "Alice Developer"},
                "status": {"name": "Done", "statusCategory": {"key": "done"}},
                "priority": {"name": "Highest"},
                "created": "2026-08-24T09:00:00.000+0000",
                "updated": "2026-08-24T10:00:00.000+0000",
                "customfield_risk": {"value": "High"},
                "customfield_environment": {"value": "Production"},
                "customfield_rollback_plan": "Restore database snapshot and revert configuration flags.",
                "customfield_is_emergency": {"value": "Yes"},
                "customfield_emergency_reason": "Sev-1 production outage due to pool starvation.",
                "customfield_retro_approved": {"value": "Yes"},
                "customfield_business_impact": "Resolved customer-facing 500 errors across payment gateway."
            },
            "changelog": {
                "histories": [
                    {
                        "id": "chlog-104-1",
                        "created": "2026-08-24T10:30:00.000+0000",
                        "author": {"emailAddress": "manager@acme.com", "displayName": "Engineering Manager"},
                        "items": [
                            {"field": "status", "fromString": "In Progress", "toString": "Approved"}
                        ]
                    }
                ]
            }
        }

        records.append(CollectedRecord(
            record_id="CHG-104",
            connector_type=ConnectorType.JIRA,
            entity_type="jira_issue",
            payload=issue_2,
            collected_at=now
        ))

        if "105" in str(jql) or "all" in str(jql).lower():
            # Mock Issue 3: CAB Approved Scheduled Change
            issue_3 = {
                "key": "CHG-105",
                "id": "10005",
                "fields": {
                    "summary": "CAB REVIEW: Microservice Gateway Migration",
                    "description": "Migration to new ingress controller. PR #105.",
                    "creator": {"emailAddress": "devops@acme.com", "displayName": "DevOps Engineer"},
                    "assignee": {"emailAddress": "cab-chair@acme.com", "displayName": "CAB Chair"},
                    "reporter": {"emailAddress": "devops@acme.com", "displayName": "DevOps Engineer"},
                    "status": {"name": "CAB Approved", "statusCategory": {"key": "indeterminate"}},
                    "priority": {"name": "High"},
                    "created": "2026-08-25T01:00:00.000+0000",
                    "updated": "2026-08-25T04:00:00.000+0000",
                    "customfield_risk": {"value": "High"},
                    "customfield_environment": {"value": "Production"},
                    "customfield_planned_start": "2026-08-25T05:00:00.000+0000",
                    "customfield_planned_end": "2026-08-25T07:00:00.000+0000",
                    "customfield_rollback_plan": "Traffic routing DNS switchback.",
                    "customfield_is_emergency": {"value": "No"}
                },
                "changelog": {
                    "histories": [
                        {
                            "id": "chlog-105-1",
                            "created": "2026-08-25T03:30:00.000+0000",
                            "author": {"emailAddress": "cab-chair@acme.com", "displayName": "CAB Chair"},
                            "items": [
                                {"field": "status", "fromString": "Under Review", "toString": "CAB Approved"}
                            ]
                        }
                    ]
                }
            }

            records.append(CollectedRecord(
                record_id="CHG-105",
                connector_type=ConnectorType.JIRA,
                entity_type="jira_issue",
                payload=issue_3,
                collected_at=now
            ))

        return records
