import os
import logging
from typing import Dict, Any, List, Optional
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

class JiraNotConfiguredError(RuntimeError):
    """Raised when Jira operations are attempted without required credentials."""
    pass

class JiraIntegrationError(RuntimeError):
    """Raised when Jira API calls fail or return error status."""
    pass

class JiraService:
    """
    Production-grade Jira Cloud REST API service abstraction.
    Supports secure authentication, issue creation, status transitions, and issue synchronization.
    Never logs or exposes credentials.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        email: Optional[str] = None,
        api_token: Optional[str] = None,
        default_project_key: Optional[str] = None
    ):
        self.base_url = (base_url or settings.JIRA_URL or "").rstrip("/")
        self.email = email or settings.JIRA_EMAIL or ""
        self.api_token = api_token or settings.JIRA_API_TOKEN or ""
        self.default_project_key = default_project_key or settings.JIRA_PROJECT_KEY or "SEC"

    def is_configured(self) -> bool:
        """Returns True if all required Jira Cloud credentials are configured."""
        return bool(self.base_url and self.email and self.api_token)

    def _get_auth(self) -> httpx.BasicAuth:
        if not self.is_configured():
            raise JiraNotConfiguredError(
                "Jira integration is not configured. JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN are required."
            )
        return httpx.BasicAuth(username=self.email, password=self.api_token)

    def create_issue(
        self,
        project_key: Optional[str] = None,
        summary: str = "",
        description: str = "",
        issue_type: str = "Bug",
        priority: str = "Medium",
        labels: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Creates a new issue in Jira Cloud via REST API v2.
        Returns dictionary containing issue key, ID, and browse URL.
        """
        if not self.is_configured():
            raise JiraNotConfiguredError(
                "Cannot create Jira issue: Jira credentials are not configured in environment."
            )

        proj = project_key or self.default_project_key
        payload = {
            "fields": {
                "project": {"key": proj},
                "summary": summary,
                "description": description,
                "issuetype": {"name": issue_type},
                "labels": labels or ["security-finding", "compliance"]
            }
        }

        # Map standard severity to Jira priority if appropriate
        if priority:
            payload["fields"]["priority"] = {"name": priority}

        url = f"{self.base_url}/rest/api/2/issue"
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(url, auth=self._get_auth(), json=payload)
                if resp.status_code not in (200, 201):
                    logger.error(f"Jira API error ({resp.status_code}): {resp.text}")
                    raise JiraIntegrationError(f"Jira API returned {resp.status_code}: {resp.text}")
                
                data = resp.json()
                issue_key = data.get("key")
                issue_id = data.get("id")
                browse_url = f"{self.base_url}/browse/{issue_key}"
                return {
                    "key": issue_key,
                    "id": issue_id,
                    "url": browse_url
                }
        except httpx.RequestError as req_err:
            logger.error(f"Failed to connect to Jira Cloud: {req_err}")
            raise JiraIntegrationError(f"Connection to Jira failed: {str(req_err)}")

    def get_issue(self, issue_key: str) -> Dict[str, Any]:
        """Fetches issue details from Jira Cloud."""
        if not self.is_configured():
            raise JiraNotConfiguredError("Jira is not configured.")

        url = f"{self.base_url}/rest/api/2/issue/{issue_key}"
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(url, auth=self._get_auth())
                if resp.status_code != 200:
                    raise JiraIntegrationError(f"Failed to get issue {issue_key}: {resp.status_code}")
                return resp.json()
        except httpx.RequestError as exc:
            raise JiraIntegrationError(f"Jira request error: {str(exc)}")

    def update_issue(self, issue_key: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        """Updates fields of an existing Jira issue."""
        if not self.is_configured():
            raise JiraNotConfiguredError("Jira is not configured.")

        url = f"{self.base_url}/rest/api/2/issue/{issue_key}"
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.put(url, auth=self._get_auth(), json={"fields": fields})
                if resp.status_code not in (200, 204):
                    raise JiraIntegrationError(f"Failed to update issue {issue_key}: {resp.text}")
                return {"key": issue_key, "updated": True}
        except httpx.RequestError as exc:
            raise JiraIntegrationError(f"Jira request error: {str(exc)}")

    def transition_issue(self, issue_key: str, transition_name_or_id: str) -> Dict[str, Any]:
        """Transitions an issue workflow state (e.g. 'Done', 'In Progress', or ID)."""
        if not self.is_configured():
            raise JiraNotConfiguredError("Jira is not configured.")

        transitions_url = f"{self.base_url}/rest/api/2/issue/{issue_key}/transitions"
        try:
            with httpx.Client(timeout=10.0) as client:
                # Get available transitions
                t_resp = client.get(transitions_url, auth=self._get_auth())
                if t_resp.status_code != 200:
                    raise JiraIntegrationError(f"Could not retrieve transitions for {issue_key}")
                
                avail = t_resp.json().get("transitions", [])
                target_id = None
                for t in avail:
                    if t.get("id") == transition_name_or_id or t.get("name", "").lower() == transition_name_or_id.lower():
                        target_id = t.get("id")
                        break
                
                if not target_id:
                    target_id = transition_name_or_id  # Fallback to direct ID

                trans_resp = client.post(
                    transitions_url,
                    auth=self._get_auth(),
                    json={"transition": {"id": target_id}}
                )
                if trans_resp.status_code not in (200, 204):
                    raise JiraIntegrationError(f"Failed to transition issue: {trans_resp.text}")
                return {"key": issue_key, "transition_id": target_id, "status": "TRANSITIONED"}
        except httpx.RequestError as exc:
            raise JiraIntegrationError(f"Jira transition error: {str(exc)}")

    def add_comment(self, issue_key: str, comment_text: str) -> Dict[str, Any]:
        """Adds a comment to an existing Jira issue."""
        if not self.is_configured():
            raise JiraNotConfiguredError("Jira is not configured.")

        url = f"{self.base_url}/rest/api/2/issue/{issue_key}/comment"
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(url, auth=self._get_auth(), json={"body": comment_text})
                if resp.status_code not in (200, 201):
                    raise JiraIntegrationError(f"Failed to add comment: {resp.text}")
                return resp.json()
        except httpx.RequestError as exc:
            raise JiraIntegrationError(f"Jira comment error: {str(exc)}")
