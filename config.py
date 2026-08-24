"""Central settings loaded from environment variables.

Every module that needs Razorpay or Ollama config imports from here
rather than reading os.environ directly, so there is one place that
knows how config is sourced.
"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    razorpay_key_id: str | None = os.getenv("RAZORPAY_KEY_ID")
    razorpay_key_secret: str | None = os.getenv("RAZORPAY_KEY_SECRET")
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:7b-instruct")


settings = Settings()
