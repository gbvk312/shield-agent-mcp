import re
import os
import logging
from pathlib import Path
from typing import List, Optional, Dict
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("shield_agent.scanner")

class Issue(BaseModel):
    file_path: str
    line_number: int
    rule_name: str
    severity: str
    content: str
    description: str

class LocalScanner:
    """
    LocalSentinel: Privacy-first scanner for PII and Secrets.
    Uses high-speed regex patterns and optional local LLM verification.
    """
    
    # Common Patterns (Secrets & PII)
    PATTERNS: Dict[str, str] = {
        "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Generic API Key": r"(?i)(?:key|api|token|secret|password|auth)(?:[\s|'|\"]*)[:|=](?:[\s|'|\"]*)([a-z0-9\-_]{16,})",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Azure Secret": r"[a-z0-9]{3,45}~[a-z0-9._\-]{2,256}",
        "Stripe Secret Key": r"sk_(?:test|live)_[0-9a-zA-Z]{24,}",
        "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
        "Private Key": r"-----BEGIN (?:RSA|OPENSSH|PRIVATE) KEY-----",
        "IPv4 Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    }

    def __init__(self, root_path: str):
        self.root_path = Path(root_path)

    def scan_file(self, file_path: Path) -> List[Issue]:
        issues = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    for name, pattern in self.PATTERNS.items():
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            # Basic heuristic to avoid false positives for Generic API Key
                            if name == "Generic API Key" and self._is_likely_false_positive(match.group(1)):
                                continue
                                
                            issues.append(Issue(
                                file_path=str(file_path.relative_to(self.root_path)),
                                line_number=line_num,
                                rule_name=name,
                                severity="HIGH" if "Key" in name else "MEDIUM",
                                content=match.group(0).strip(),
                                description=f"Potential {name} detected."
                            ))
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
        return issues

    def _is_likely_false_positive(self, value: str) -> bool:
        """Heuristics to filter out non-secrets."""
        # Too many repetitive characters
        if len(set(value)) < 4:
            return True
        # Common placeholder names
        placeholders = {"YOUR_API_KEY", "example_token", "SECRET_KEY_HERE"}
        if value in placeholders:
            return True
        return False

    def verify_with_ollama(self, issue: Issue) -> bool:
        """
        Uses a local LLM (Ollama) to verify if a detection is a real secret.
        """
        import requests
        ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        try:
            prompt = f"Identify if the following string is likely a real sensitive API key or secret password. Respond with only 'YES' or 'NO'.\nString: {issue.content}"
            response = requests.post(
                f"{ollama_host}/api/generate",
                json={
                    "model": "gemma2",
                    "prompt": prompt,
                    "stream": False
                },
                timeout=5
            )
            if response.status_code == 200:
                result = response.json().get("response", "").strip().upper()
                return "YES" in result
        except Exception as e:
            logger.warning(f"Ollama verification failed: {e}. Falling back to detection.")
            return True
        return True

    def scan_directory(self, exclude_dirs: Optional[List[str]] = None, use_ollama: bool = False) -> List[Issue]:
        all_issues = []
        exclude = set(exclude_dirs or [".git", "__pycache__", "venv", "node_modules"])
        
        for p in self.root_path.rglob("*"):
            if p.is_file() and not any(part in exclude for part in p.parts):
                issues = self.scan_file(p)
                if use_ollama:
                    issues = [i for i in issues if self.verify_with_ollama(i)]
                all_issues.extend(issues)
        
        return all_issues
