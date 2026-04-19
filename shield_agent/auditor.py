import os
from typing import Optional
from pathlib import Path
from google import genai
from .scanner import Issue


class CloudAuditor:
    """
    CloudAuditor: Deep Intelligence Layer using Gemini.
    Analyzes code for logic flaws, architectural issues, and complex vulnerabilities.
    """

    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)
        self.model_id = "gemini-2.0-flash"

    def audit_file(self, file_path: Path, content: str) -> str:
        """Performs a deep audit of a single file."""
        prompt = f"""
        You are an expert security researcher and software architect.
        Analyze the following code from file '{file_path}' for:
        1. Security vulnerabilities (e.g., SQL injection, XSS, insecure logic).
        2. Architectural patterns that could lead to technical debt.
        3. Compliance with professional coding standards.

        Provide a concise, bulleted report with actionable recommendations.
        If no critical issues are found, state 'Analysis complete: No critical flaws detected.'

        Code Content:
        ---
        {content}
        ---
        """
        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt,
            )
            return response.text
        except Exception as e:
            return f"Error during cloud audit: {str(e)}"

    def audit_diff(self, diff_text: str) -> str:
        """Analyzes a git diff for potential impact."""
        prompt = f"""
        Analyze the following code change (diff) for potential security regressions or quality drops.
        Identify if any newly added code introduces risks.

        Diff Content:
        ---
        {diff_text}
        ---
        """
        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt,
            )
            return response.text
        except Exception as e:
            return f"Error during diff audit: {str(e)}"
