from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, List

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

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
