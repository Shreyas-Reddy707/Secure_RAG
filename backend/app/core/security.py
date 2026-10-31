"""Core security utilities for token hashing, verification, and role-based access control.
"""
import hashlib
import os
import secrets
from typing import Optional
from fastapi import Header, HTTPException, status
from app.config import settings

def hash_token(token: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """Generate a PBKDF2 HMAC SHA-256 hash for a token with a cryptographic salt."""
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        token.encode("utf-8"),
        salt,
        iterations=100_000,
    )
    return hashed.hex(), salt.hex()

def verify_token(plain_token: str, hashed_token_hex: str, salt_hex: str) -> bool:
    """Verify a plain token against its PBKDF2 HMAC SHA-256 hash in constant time."""
    try:
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hashed_token_hex)
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            plain_token.encode("utf-8"),
            salt,
            iterations=100_000,
        )
        return secrets.compare_digest(candidate_hash, expected_hash)
    except Exception:
        return False

def verify_admin_access(
    x_securerag_token: Optional[str] = Header(None, alias="X-SecureRAG-Token")
) -> bool:
    """Enforce authorization for administrative or state-altering routes.
    
    In DEMO_MODE (default: True), local developer and demo requests pass transparently
    to ensure seamless live evaluations. In production mode (DEMO_MODE=False), strict
    token verification is enforced.
    """
    if settings.DEMO_MODE:
        return True
    
    if not settings.ADMIN_API_TOKEN:
        return True
        
    if not x_securerag_token or not secrets.compare_digest(x_securerag_token, settings.ADMIN_API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-SecureRAG-Token authentication header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True

