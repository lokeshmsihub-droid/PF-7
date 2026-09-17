import os
import time
import hmac
import hashlib
import base64
import json
import secrets
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet

# Master encryption key derivation
def _get_fernet_key() -> bytes:
    raw_secret = os.environ.get("ENCRYPTION_KEY", "compliance-secret-key-32-chars-long!")
    digest = hashlib.sha256(raw_secret.encode()).digest()
    return base64.urlsafe_b64encode(digest)

_FERNET = Fernet(_get_fernet_key())

# In-memory single-use state store
_USED_STATES = set()
_ACTIVE_STATES: Dict[str, Dict[str, Any]] = {}

def encrypt_token(raw_token: Optional[str]) -> Optional[str]:
    """Encrypt a sensitive token string at rest."""
    if not raw_token:
        return None
    try:
        return _FERNET.encrypt(raw_token.encode()).decode()
    except Exception:
        return raw_token

def decrypt_token(encrypted_token: Optional[str]) -> Optional[str]:
    """Decrypt a sensitive token string for backend API use."""
    if not encrypted_token:
        return None
    try:
        return _FERNET.decrypt(encrypted_token.encode()).decode()
    except Exception:
        return encrypted_token

def generate_oauth_state(tenant_id: str, provider: str = "jira", redirect_url: Optional[str] = None) -> str:
    """
    Generate a cryptographically secure, signed, single-use state parameter.
    Valid for 15 minutes (900 seconds).
    """
    nonce = secrets.token_urlsafe(24)
    expires_at = int(time.time()) + 900
    state_data = {
        "tenant_id": tenant_id,
        "provider": provider,
        "nonce": nonce,
        "expires_at": expires_at,
        "redirect_url": redirect_url or "/systems"
    }
    serialized = json.dumps(state_data, sort_keys=True)
    b64_payload = base64.urlsafe_b64encode(serialized.encode()).decode()
    
    # HMAC-SHA256 signature
    secret_key = os.environ.get("OAUTH_STATE_SECRET", "oauth-state-signing-secret-key")
    signature = hmac.new(secret_key.encode(), b64_payload.encode(), hashlib.sha256).hexdigest()
    
    state_token = f"{b64_payload}.{signature}"
    _ACTIVE_STATES[state_token] = state_data
    return state_token

def validate_oauth_state(state_token: str, expected_tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Validate HMAC signature, expiration, tenant isolation, and single-use invariant.
    Raises ValueError if state is invalid, expired, already used, or tampered.
    """
    if not state_token:
        raise ValueError("Missing OAuth state parameter")
        
    if state_token in _USED_STATES:
        raise ValueError("OAuth state token has already been consumed (replay attack prevention)")

    parts = state_token.split(".")
    if len(parts) != 2:
        raise ValueError("Malformed OAuth state format")
        
    b64_payload, signature = parts
    secret_key = os.environ.get("OAUTH_STATE_SECRET", "oauth-state-signing-secret-key")
    expected_sig = hmac.new(secret_key.encode(), b64_payload.encode(), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError("Invalid OAuth state signature (tampering detected)")
        
    try:
        raw_json = base64.urlsafe_b64decode(b64_payload.encode()).decode()
        data = json.loads(raw_json)
    except Exception:
        raise ValueError("Corrupted OAuth state payload")
        
    if time.time() > data.get("expires_at", 0):
        raise ValueError("OAuth state token has expired")
        
    if expected_tenant_id and data.get("tenant_id") != expected_tenant_id:
        raise ValueError(f"OAuth state tenant mismatch: {data.get('tenant_id')} != {expected_tenant_id}")

    # Mark as used (single-use)
    _USED_STATES.add(state_token)
    _ACTIVE_STATES.pop(state_token, None)
    
    return data
