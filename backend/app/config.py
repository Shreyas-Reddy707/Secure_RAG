from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, List
from pathlib import Path

# Resolve .env paths relative to this file's location
_this_dir = Path(__file__).resolve().parent          # backend/app/
_backend_dir = _this_dir.parent                       # backend/
_project_root = _backend_dir.parent                   # project root

# Prefer backend/.env, then project root .env
_env_files = []
if (_project_root / ".env").is_file():
    _env_files.append(str(_project_root / ".env"))
if (_backend_dir / ".env").is_file():
    _env_files.append(str(_backend_dir / ".env"))
# Fallback: if running inside Docker where CWD is /app, try /app/.env
if not _env_files:
    _env_files = [".env"]

class Settings(BaseSettings):
    APP_NAME: str = "SecureRAG Defense Engine"
    DEBUG: bool = False
    DEMO_MODE: bool = True
    
    # Qdrant Vector Store Config
    QDRANT_HOST: str = "qdrant"
    QDRANT_PORT: int = 6333
    QDRANT_COLLECTION: str = "securerag_hybrid_kb"
    QDRANT_API_KEY: Optional[str] = None
    
    # CORS & Security
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000"
    ADMIN_API_TOKEN: Optional[str] = None
    
    # LLM Provider Config
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    DEFAULT_LLM_PROVIDER: str = "gemini"  # "gemini" | "groq" | "deterministic"
    
    # Retrieval & Security Thresholds
    DEFAULT_TOP_K: int = 6
    INPUT_BLOCK_THRESHOLD: float = 0.75
    CHUNK_TRUST_THRESHOLD: float = 0.60

    @property
    def cors_origins(self) -> List[str]:
        if not self.ALLOWED_ORIGINS:
            return ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000"]
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    model_config = SettingsConfigDict(
        env_file=_env_files if _env_files else ".env",
        extra="ignore",
    )

settings = Settings()
