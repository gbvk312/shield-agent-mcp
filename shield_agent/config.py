import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma2")
    
    @staticmethod
    def get_exclude_dirs():
        # Future: Load from shield-agent.yaml
        return [".git", "__pycache__", "venv", "node_modules", ".venv"]

config = Config()
