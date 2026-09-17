import os
import time
import urllib.parse
import httpx
from datetime import datetime, UTC
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Query, Request, BackgroundTasks
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session

from app.db.postgres import get_db, SessionLocal
from app.models.orm import ConnectorAccountORM, ConnectorORM, ChangeORM, SyncRunORM
from app.connectors.jira.connector import JiraConnector
from app.connectors.contract import ConnectionConfig, ConnectorType, AuthType, SyncRequest, SyncType
from app.core.config import settings
from app.core.security import generate_oauth_state, validate_oauth_state, encrypt_token, decrypt_token
from app.services.audit_service import AuditLogService
from app.services.event_broker import event_broker

router = APIRouter()

def get_tenant_id(request: Request) -> str:
    """Extract tenant_id from header or fallback."""
    return request.headers.get("X-Tenant-ID", "tenant-acme-corp")

class JiraOAuthStartRequest(BaseModel):
    redirect_url: Optional[str] = "/systems"

class JiraConfigRequest(BaseModel):
    cloud_id: Optional[str] = None
    site_name: Optional[str] = None
    site_url: Optional[str] = None
    project_key: Optional[str] = "CHG"
    issue_type: Optional[str] = "Change"
    jql: Optional[str] = None
    custom_fields: Optional[Dict[str, str]] = None
    enabled: bool = True

@router.post("/compliance/integrations/jira/oauth/start")
def start_jira_oauth(
    payload: JiraOAuthStartRequest,
    tenant_id: str = Depends(get_tenant_id)
):
    """
    Generate an Atlassian OAuth 2.0 (3LO) authorization URL with a cryptographically signed,
    single-use state parameter.
    """
    state_token = generate_oauth_state(tenant_id=tenant_id, provider="jira", redirect_url=payload.redirect_url)
    
    client_id = settings.JIRA_CLIENT_ID or os.environ.get("JIRA_CLIENT_ID")
    redirect_uri = settings.JIRA_REDIRECT_URI or os.environ.get("JIRA_REDIRECT_URI", "http://127.0.0.1:8000/api/auth/jira/callback")
    scopes = settings.JIRA_OAUTH_SCOPES or "read:jira-work read:jira-user read:servicedesk-request offline_access"

    # If client credentials are not configured, allow running in Mock OAuth mode
    is_mock = not client_id or os.environ.get("JIRA_MOCK") == "true"
    
    if is_mock:
        callback_mock_url = f"{redirect_uri}?code=mock_atlassian_auth_code_12345&state={state_token}"
        return {
            "authorization_url": callback_mock_url,
            "state": state_token,
            "mock": True,
            "message": "Mock Atlassian OAuth mode active (instant authorization)."
        }

    # Standard Atlassian OAuth 2.0 (3LO) URL
    auth_params = {
        "audience": "api.atlassian.com",
        "client_id": client_id,
        "scope": scopes,
        "redirect_uri": redirect_uri,
        "state": state_token,
        "response_type": "code",
        "prompt": "consent"
    }
    encoded_params = urllib.parse.urlencode(auth_params)
    auth_url = f"{JiraConnector.ATLASSIAN_AUTH_URL}?{encoded_params}"

    return {
        "authorization_url": auth_url,
        "state": state_token,
        "mock": False
    }

@router.get("/auth/jira/callback")
def jira_oauth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Handle Atlassian OAuth 2.0 callback, exchange code for tokens, discover accessible resources,
    store encrypted credentials in ConnectorAccountORM, and redirect to frontend.
    """
    if error:
        return HTMLResponse(content=f"""
        <html>
            <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
                <h2>Jira OAuth Authorization Denied</h2>
                <p>{error_description or error}</p>
                <a href="http://localhost:5173" style="color: #5876D8;">Return to Compliance Dashboard</a>
            </body>
        </html>
        """, status_code=400)

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing required 'code' or 'state' parameters.")

    # 1. Validate state token (HMAC verification, expiration, single-use)
    try:
        state_data = validate_oauth_state(state)
        tenant_id = state_data["tenant_id"]
        redirect_target = state_data.get("redirect_url", "/systems")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"OAuth state validation failed: {str(e)}")

    client_id = settings.JIRA_CLIENT_ID or os.environ.get("JIRA_CLIENT_ID")
    client_secret = settings.JIRA_CLIENT_SECRET or os.environ.get("JIRA_CLIENT_SECRET")
    redirect_uri = settings.JIRA_REDIRECT_URI or "http://127.0.0.1:8000/api/auth/jira/callback"

    is_mock = not client_id or not client_secret or "mock" in code.lower() or os.environ.get("JIRA_MOCK") == "true"

    if is_mock:
        access_token = "mock_access_token_" + str(int(time.time()))
        refresh_token = "mock_refresh_token_" + str(int(time.time()))
        expires_in = 3600
        accessible_sites = JiraConnector.get_accessible_resources(access_token)
    else:
        # 2. Exchange authorization code with Atlassian
        try:
            with httpx.Client(timeout=15.0) as client:
                token_res = client.post(
                    JiraConnector.ATLASSIAN_TOKEN_URL,
                    json={
                        "grant_type": "authorization_code",
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "code": code,
                        "redirect_uri": redirect_uri
                    },
                    headers={"Content-Type": "application/json"}
                )

                if token_res.status_code != 200:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Atlassian token exchange failed: {token_res.text}"
                    )

                data = token_res.json()
                access_token = data.get("access_token")
                refresh_token = data.get("refresh_token")
                expires_in = data.get("expires_in", 3600)
                
                # 3. Fetch accessible Jira Cloud sites
                accessible_sites = JiraConnector.get_accessible_resources(access_token)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"OAuth connection error: {str(e)}")

    if not accessible_sites:
        accessible_sites = [
            {
                "id": "cloud-default-id",
                "name": "Jira Cloud Workspace",
                "url": "https://default.atlassian.net",
                "scopes": ["read:jira-work", "read:jira-user"]
            }
        ]

    primary_site = accessible_sites[0]
    cloud_id = primary_site.get("id")
    site_name = primary_site.get("name")
    site_url = primary_site.get("url")

    # 4. Ensure Jira Connector entity exists
    jira_conn = db.query(ConnectorORM).filter_by(connector_id="jira").first()
    if not jira_conn:
        jira_conn = ConnectorORM(
            connector_id="jira",
            name="Jira",
            type="jira",
            status="ACTIVE"
        )
        db.add(jira_conn)
        db.commit()

    # 5. Find existing or create new ConnectorAccountORM
    account = db.query(ConnectorAccountORM).filter_by(
        tenant_id=tenant_id,
        connector_id="jira"
    ).first()

    account_id = account.account_id if account else f"sys-jira-{int(time.time()*1000)}"

    config_data = {
        "provider": "jira",
        "cloud_id": cloud_id,
        "site_name": site_name,
        "site_url": site_url,
        "access_token_encrypted": encrypt_token(access_token),
        "refresh_token_encrypted": encrypt_token(refresh_token) if refresh_token else None,
        "token_expires_at": int(time.time()) + int(expires_in),
        "granted_scopes": primary_site.get("scopes", ["read:jira-work", "read:jira-user", "read:servicedesk-request", "offline_access"]),
        "accessible_sites": accessible_sites,
        "project_key": "CHG",
        "issue_type": "Change",
        "jql": 'project = "CHG" AND (issuetype = "Change" OR issuetype in ("Change", "Emergency Change"))',
        "custom_fields": {
            "risk_field": "customfield_risk",
            "environment_field": "customfield_environment",
            "emergency_field": "customfield_is_emergency",
            "rollback_field": "customfield_rollback_plan"
        },
        "mock": is_mock
    }

    if account:
        account.name = f"Jira ({site_name})"
        account.status = "ACTIVE"
        account.auth_type = "OAUTH2"
        account.config = config_data
    else:
        account = ConnectorAccountORM(
            account_id=account_id,
            tenant_id=tenant_id,
            connector_id="jira",
            name=f"Jira ({site_name})",
            auth_type="OAUTH2",
            config=config_data,
            status="ACTIVE"
        )
        db.add(account)

    db.commit()

    # 6. Audit Log connection event
    AuditLogService.log_action(
        db, tenant_id, "system-oauth", "SYSTEM",
        "jira_oauth_completed", "connector_account", account_id,
        {"details": f"Jira Cloud site '{site_name}' ({cloud_id}) authorized via OAuth 2.0 (3LO)."}
    )

    # Broadcast event
    event_broker.broadcast("JIRA_CONNECTED", tenant_id, {
        "account_id": account_id,
        "site_name": site_name,
        "cloud_id": cloud_id
    })

    # Dynamic redirect destination matching the user's current origin (e.g. localhost:3000)
    referer = request.headers.get("referer") or ""
    origin = "http://localhost:3000"
    if "localhost:5173" in referer:
        origin = "http://localhost:5173"
    elif "localhost:3000" in referer or "127.0.0.1:3000" in referer:
        origin = "http://localhost:3000"
    
    redirect_target = state_data.get("redirect_url") or "/"
    if redirect_target.startswith("/"):
        sep = "&" if "?" in redirect_target else "?"
        frontend_redirect = f"{origin}{redirect_target}{sep}connected=jira&system_id={account_id}"
    else:
        frontend_redirect = f"{origin}/?connected=jira&system_id={account_id}"

    return HTMLResponse(content=f"""
    <!DOCTYPE html>
    <html>
        <head>
            <title>Jira Connection Successful</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #FAFAFB; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
                .card {{ background: white; border: 1px solid #E8E9ED; border-radius: 12px; padding: 40px; text-align: center; max-width: 440px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
                .icon {{ width: 48px; height: 48px; background: #EAF7EF; color: #3FA76C; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; margin: 0 auto 16px; }}
                h2 {{ color: #24262B; margin-bottom: 8px; font-size: 20px; }}
                p {{ color: #666A73; font-size: 14px; margin-bottom: 24px; line-height: 1.5; }}
                .btn {{ display: inline-block; background: #5876D8; color: white; text-decoration: none; padding: 10px 24px; border-radius: 6px; font-size: 14px; font-weight: 600; }}
            </style>
            <script>
                if (window.opener) {{
                    try {{
                        window.opener.postMessage({{ type: 'JIRA_CONNECTED', account_id: '{account_id}' }}, '*');
                    }} catch(e) {{}}
                }}
                setTimeout(function() {{
                    window.location.href = "{frontend_redirect}";
                }}, 1000);
            </script>
        </head>
        <body>
            <div class="card">
                <div class="icon">✓</div>
                <h2>Jira Connected Successfully</h2>
                <p>Atlassian OAuth authorization completed for <strong>{site_name}</strong>. Redirecting back to your Compliance Dashboard...</p>
                <a href="{frontend_redirect}" class="btn">Return to Dashboard</a>
            </div>
        </body>
    </html>
    """)

@router.get("/compliance/integrations/{account_id}/jira/sites")
def get_jira_sites(
    account_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id)
):
    """Return accessible Jira Cloud sites for account selection."""
    account = db.query(ConnectorAccountORM).filter_by(account_id=account_id, tenant_id=tenant_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Jira integration account not found")

    sites = account.config.get("accessible_sites", [])
    if not sites:
        sites = [
            {
                "id": account.config.get("cloud_id", "cloud-site-id"),
                "name": account.config.get("site_name", "Primary Jira Site"),
                "url": account.config.get("site_url", "https://acme.atlassian.net")
            }
        ]
    return sites

@router.get("/compliance/integrations/{account_id}/jira/projects")
def get_jira_projects(
    account_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id)
):
    """Discover available Jira projects for Change Management configuration."""
    account = db.query(ConnectorAccountORM).filter_by(account_id=account_id, tenant_id=tenant_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Jira integration account not found")

    c_config = ConnectionConfig(
        connector_id=account.account_id,
        connector_type=ConnectorType.JIRA,
        auth_type=AuthType.OAUTH2,
        credentials=account.config,
        endpoint_url=account.config.get("site_url")
    )
    connector = JiraConnector(c_config)
    return connector.discover_projects()

@router.get("/compliance/integrations/{account_id}/jira/issue-types")
def get_jira_issue_types(
    account_id: str,
    project_key: Optional[str] = None,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id)
):
    """Discover issue types available in Jira."""
    account = db.query(ConnectorAccountORM).filter_by(account_id=account_id, tenant_id=tenant_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Jira integration account not found")

    c_config = ConnectionConfig(
        connector_id=account.account_id,
        connector_type=ConnectorType.JIRA,
        auth_type=AuthType.OAUTH2,
        credentials=account.config,
        endpoint_url=account.config.get("site_url")
    )
    connector = JiraConnector(c_config)
    return connector.discover_issue_types(project_key)

@router.get("/compliance/integrations/{account_id}/jira/fields")
def get_jira_fields(
    account_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id)
):
    """Discover custom fields for mapping risk, environment, and emergency change fields."""
    account = db.query(ConnectorAccountORM).filter_by(account_id=account_id, tenant_id=tenant_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Jira integration account not found")

    c_config = ConnectionConfig(
        connector_id=account.account_id,
        connector_type=ConnectorType.JIRA,
        auth_type=AuthType.OAUTH2,
        credentials=account.config,
        endpoint_url=account.config.get("site_url")
    )
    connector = JiraConnector(c_config)
    return connector.discover_fields()

@router.get("/compliance/integrations/{account_id}/jira/config")
def get_jira_config(
    account_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id)
):
    """Get currently configured Jira project, issue type, JQL filter, and custom fields."""
    account = db.query(ConnectorAccountORM).filter_by(account_id=account_id, tenant_id=tenant_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Jira integration account not found")

    cfg = account.config or {}
    return {
        "account_id": account_id,
        "site_name": cfg.get("site_name"),
        "site_url": cfg.get("site_url"),
        "cloud_id": cfg.get("cloud_id"),
        "project_key": cfg.get("project_key", "CHG"),
        "issue_type": cfg.get("issue_type", "Change"),
        "jql": cfg.get("jql", 'project = "CHG" AND (issuetype = "Change" OR issuetype in ("Change", "Emergency Change"))'),
        "custom_fields": cfg.get("custom_fields", {
            "risk_field": "customfield_risk",
            "environment_field": "customfield_environment",
            "emergency_field": "customfield_is_emergency",
            "rollback_field": "customfield_rollback_plan"
        }),
        "granted_scopes": cfg.get("granted_scopes", []),
        "status": account.status
    }

@router.put("/compliance/integrations/{account_id}/jira/config")
def update_jira_config(
    account_id: str,
    req: JiraConfigRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id)
):
    """Save Jira Change Management project, issue type, JQL filter, and custom field mappings."""
    account = db.query(ConnectorAccountORM).filter_by(account_id=account_id, tenant_id=tenant_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Jira integration account not found")

    new_cfg = dict(account.config or {})
    if req.cloud_id:
        new_cfg["cloud_id"] = req.cloud_id
    if req.site_name:
        new_cfg["site_name"] = req.site_name
    if req.site_url:
        new_cfg["site_url"] = req.site_url
    if req.project_key:
        new_cfg["project_key"] = req.project_key
    if req.issue_type:
        new_cfg["issue_type"] = req.issue_type
    if req.jql:
        new_cfg["jql"] = req.jql
    if req.custom_fields:
        existing_cf = new_cfg.get("custom_fields", {})
        existing_cf.update(req.custom_fields)
        new_cfg["custom_fields"] = existing_cf

    account.config = new_cfg
    db.commit()

    AuditLogService.log_action(
        db, tenant_id, "user-admin", "ADMIN",
        "jira_configuration_updated", "connector_account", account_id,
        {"project_key": req.project_key, "issue_type": req.issue_type}
    )

    from app.api.routes.compliance import run_full_sync_and_evaluation
    background_tasks.add_task(run_full_sync_and_evaluation, tenant_id, account_id)

    return {
        "status": "success",
        "message": "Jira configuration saved. Automated sync and compliance evaluation initiated."
    }
