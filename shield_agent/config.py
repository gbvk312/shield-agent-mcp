import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


class Config:
    _loaded = False
    _yaml_config: dict[str, Any] = {}

    def __init__(self) -> None:
        if not Config._loaded:
            load_dotenv()
            self._load_yaml()
            Config._loaded = True

    @classmethod
    def _load_yaml(cls) -> None:
        yaml_path = Path("shield-agent.yaml")
        if yaml_path.exists():
            try:
                with open(yaml_path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data:
                        cls._yaml_config = data
            except Exception as e:
                import logging

                logging.getLogger("shield_agent.config").warning(f"Failed to load shield-agent.yaml: {e}")

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
        default_excludes = [".git", "__pycache__", "venv", ".venv", "node_modules", "scratch"]
        yaml_excludes = Config._yaml_config.get("exclude_dirs", [])
        return list(set(default_excludes + yaml_excludes))

    @staticmethod
    def get_custom_rules() -> list[dict[str, str]]:
        rules = Config._yaml_config.get("custom_rules", [])
        return rules if isinstance(rules, list) else []


config = Config()
