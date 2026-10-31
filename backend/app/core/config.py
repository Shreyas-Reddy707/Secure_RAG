"""Core configuration module for SecureRAG.

Loads environment variables strictly server-side and exposes system settings.
"""
from app.config import settings, Settings

__all__ = ["settings", "Settings"]

