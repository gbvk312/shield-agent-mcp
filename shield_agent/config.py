import os
from dotenv import load_dotenv


class Config:
    _loaded = False

    def __init__(self) -> None:
        if not Config._loaded:
            load_dotenv()
            Config._loaded = True

    @property
    def GEMINI_API_KEY(self) -> str | None:
        return os.getenv("GEMINI_API_KEY")

    @property
    def OLLAMA_HOST(self) -> str:
        return os.getenv("OLLAMA_HOST", "http://localhost:11434")

    @property
    def OLLAMA_MODEL(self) -> str:
        return os.getenv("OLLAMA_MODEL", "gemma2")

    @staticmethod
    def get_exclude_dirs() -> list[str]:
        # Future: Load from shield-agent.yaml
        return [".git", "__pycache__", "venv", "node_modules", ".venv"]

config = Config()
