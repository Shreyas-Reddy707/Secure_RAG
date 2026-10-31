import json
import re
from typing import Type, TypeVar, Optional
from pydantic import BaseModel
from google import genai
from google.genai import types
from groq import Groq
from app.config import settings

T = TypeVar("T", bound=BaseModel)

class LLMClient:
    def __init__(self):
        self.gemini_client = genai.Client(api_key=settings.GEMINI_API_KEY) if settings.GEMINI_API_KEY else None
        self.groq_client = Groq(api_key=settings.GROQ_API_KEY) if settings.GROQ_API_KEY else None

    def generate_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_schema: Type[T],
        provider: Optional[str] = None,
    ) -> Optional[T]:
        active_provider = provider or settings.DEFAULT_LLM_PROVIDER

        # 1. Try Gemini Structured Output
        if active_provider == "gemini" and self.gemini_client:
            try:
                resp = self.gemini_client.models.generate_content(
                    model=settings.GEMINI_MODEL,
                    contents=user_prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        temperature=0.0,
                        response_mime_type="application/json",
                        response_schema=response_schema,
                    ),
                )
                return response_schema.model_validate_json(resp.text)
            except Exception as e:
                print(f"[LLMClient] Gemini error, attempting fallback: {e}")

        # 2. Try Groq JSON Mode Fallback
        if self.groq_client and active_provider in ("gemini", "groq"):
            try:
                schema_json = json.dumps(response_schema.model_json_schema(), indent=2)
                completion = self.groq_client.chat.completions.create(
                    model=settings.GROQ_MODEL,
                    temperature=0.0,
                    response_format={"type": "json_object"},
                    messages=[
                        {
                            "role": "system",
                            "content": f"{system_prompt}\n\nYou MUST output valid JSON strictly adhering to this JSON schema:\n{schema_json}",
                        },
                        {"role": "user", "content": user_prompt},
                    ],
                )
                return response_schema.model_validate_json(completion.choices[0].message.content)
            except Exception as e:
                print(f"[LLMClient] Groq fallback error: {e}")

        return None

    def generate_text(
        self,
        system_prompt: str,
        user_prompt: str,
        provider: Optional[str] = None,
    ) -> Optional[str]:
        active_provider = provider or settings.DEFAULT_LLM_PROVIDER

        if active_provider == "gemini" and self.gemini_client:
            try:
                resp = self.gemini_client.models.generate_content(
                    model=settings.GEMINI_MODEL,
                    contents=user_prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        temperature=0.1,
                    ),
                )
                return resp.text
            except Exception as e:
                print(f"[LLMClient] Gemini text error: {e}")

        if self.groq_client and active_provider in ("gemini", "groq"):
            try:
                completion = self.groq_client.chat.completions.create(
                    model=settings.GROQ_MODEL,
                    temperature=0.1,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                )
                return completion.choices[0].message.content
            except Exception as e:
                print(f"[LLMClient] Groq text error: {e}")

        return None

llm_client = LLMClient()

