from pathlib import Path
from google import genai
from google.genai import types


class CloudAuditor:
    """
    CloudAuditor: Deep Intelligence Layer using Gemini.
    Analyzes code for logic flaws, architectural issues, and complex vulnerabilities.
    """

    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)
        self.model_id = "gemini-2.0-flash"
        self.system_instruction = """
You are an expert security researcher and software architect.
Analyze the provided code for:
1. Security vulnerabilities (e.g., SQL injection, XSS, insecure logic).
2. Architectural patterns that could lead to technical debt.
3. Compliance with professional coding standards.

Provide a concise, bulleted report with actionable recommendations.
If no critical issues are found, state 'Analysis complete: No critical flaws detected.'
"""

    def audit_file(self, file_path: Path, content: str) -> str:
        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=f"File: {file_path}\n---\n{content}\n---",
                config=types.GenerateContentConfig(
                    system_instruction=self.system_instruction,
                )
            )
            return response.text or "No response generated."
        except Exception as e:
            return f"Error during cloud audit: {str(e)}"

    def audit_diff(self, diff_text: str) -> str:
        """Analyzes a git diff for potential impact."""
        extra_instruction = "Focus heavily on security regressions or newly introduced architectural flaws in this diff."
        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=f"Diff Content:\n---\n{diff_text}\n---",
                config=types.GenerateContentConfig(
                    system_instruction=self.system_instruction + "\n\n" + extra_instruction,
                )
            )
            return response.text or "No response generated."
        except Exception as e:
            return f"Error during diff audit: {str(e)}"
