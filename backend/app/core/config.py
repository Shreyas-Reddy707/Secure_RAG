"""Core configuration module for SecureRAG.

Loads environment variables strictly server-side and exposes system settings.
"""
import os
from app.config import settings, Settings

# Ensure default active models are up-to-date
if not os.environ.get("GEMINI_MODEL") or settings.GEMINI_MODEL in ("gemini-2.5-flash", "gemini-2.0-flash"):
    settings.GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")

if not os.environ.get("GROQ_MODEL") or settings.GROQ_MODEL in ("llama-3.3-70b-versatile",):
    settings.GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

__all__ = ["settings", "Settings"]

