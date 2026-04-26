import re
import os
import math
import logging
from pathlib import Path
from typing import List, Optional, Dict
from pydantic import BaseModel
from concurrent.futures import ThreadPoolExecutor
import pathspec

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
    Uses high-speed regex patterns, Shannon entropy analysis,
    and optional local LLM verification.
    """

    # Binary file extensions to skip during scanning
    BINARY_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".bin",
        ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".pyc", ".pyo", ".class", ".o",
    }

    
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
        "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
        "Phone Number": r"\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b",
        # Modern cloud provider patterns
        "OpenAI API Key": r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
        "Slack Bot Token": r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}",
        "Slack Webhook URL": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}",
        "Google Cloud Service Account": r"\"type\":\s*\"service_account\"",
        "Twilio API Key": r"SK[0-9a-fA-F]{32}",
        "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
        "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "JSON Web Token": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    }

    # Entropy threshold for detecting high-randomness strings (likely secrets)
    ENTROPY_THRESHOLD = 4.5
    ENTROPY_MIN_LENGTH = 20

    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.gitignore = self._load_gitignore()

    def _load_gitignore(self) -> Optional[pathspec.PathSpec]:
        gitignore_path = self.root_path / ".gitignore"
        if gitignore_path.exists():
            with open(gitignore_path, "r") as f:
                return pathspec.PathSpec.from_lines("gitwildmatch", f)
        return None

    def _is_ignored(self, file_path: Path) -> bool:
        if self.gitignore:
            relative_path = str(file_path.relative_to(self.root_path))
            return self.gitignore.match_file(relative_path)
        return False

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _detect_high_entropy_strings(self, line: str) -> List[str]:
        """Extract tokens from assignment-like patterns and check their entropy."""
        hits = []
        # Match quoted strings in assignments: key = "value" or key: "value"
        for match in re.finditer(r"""(?:=|:)\s*['"]([a-zA-Z0-9+/=_\-]{20,})['"]""", line):
            token = match.group(1)
            if len(token) >= self.ENTROPY_MIN_LENGTH and self._shannon_entropy(token) >= self.ENTROPY_THRESHOLD:
                # Skip known false positive patterns
                if not self._is_likely_false_positive(token):
                    hits.append(token)
        return hits

    def scan_file(self, file_path: Path) -> List[Issue]:
        issues = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    # Regex-based pattern matching
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
                                severity="HIGH" if any(k in name for k in ["Key", "Secret", "Token", "Private"]) else "MEDIUM",
                                content=match.group(0).strip(),
                                description=f"Potential {name} detected."
                            ))

                    # Entropy-based detection for strings not caught by regex
                    for token in self._detect_high_entropy_strings(line):
                        issues.append(Issue(
                            file_path=str(file_path.relative_to(self.root_path)),
                            line_number=line_num,
                            rule_name="High Entropy String",
                            severity="MEDIUM",
                            content=token[:60] + "..." if len(token) > 60 else token,
                            description="High-entropy string detected — possible embedded secret or key."
                        ))
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
        return issues

    def _is_likely_false_positive(self, value: str) -> bool:
        """Heuristics to filter out non-secrets."""
        if not value:
            return True
        # Too many repetitive characters
        if len(set(value)) < 4:
            return True
        # Common placeholder names and patterns
        placeholders = {
            "YOUR_API_KEY", "example_token", "SECRET_KEY_HERE",
            "your_google_gemini_api_key_here", "your_gemini_api_key_here",
            "your_api_key_here",
        }
        if value.lower() in {p.lower() for p in placeholders}:
            return True
        # Catch generic placeholder patterns
        lower = value.lower()
        if lower.startswith("your_") or lower.endswith("_here"):
            return True
        return False

    def verify_with_ollama(self, issue: Issue) -> bool:
        """
        Uses a local LLM (Ollama) to verify if a detection is a real secret.
        """
        import requests
        ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        ollama_model = os.getenv("OLLAMA_MODEL", "gemma2")
        try:
            prompt = f"Identify if the following string is likely a real sensitive API key or secret password. Respond with only 'YES' or 'NO'.\nString: {issue.content}"
            response = requests.post(
                f"{ollama_host}/api/generate",
                json={
                    "model": ollama_model,
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

    def scan_directory(self, exclude_dirs: Optional[List[str]] = None, use_ollama: bool = False, max_workers: int = 4) -> List[Issue]:
        all_issues = []
        static_exclude = set(exclude_dirs or [".git", "__pycache__", "venv", ".venv", "node_modules", "scratch"])
        
        files_to_scan = []
        for p in self.root_path.rglob("*"):
            if p.is_file():
                # Skip binary files
                if p.suffix.lower() in self.BINARY_EXTENSIONS:
                    continue
                # Check static excludes and .gitignore
                if any(part in static_exclude for part in p.parts):
                    continue
                if self._is_ignored(p):
                    continue
                files_to_scan.append(p)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(self.scan_file, files_to_scan)
            for file_issues in results:
                if use_ollama:
                    file_issues = [i for i in file_issues if self.verify_with_ollama(i)]
                all_issues.extend(file_issues)
        
        return all_issues
