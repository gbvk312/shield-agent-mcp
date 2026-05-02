from pathlib import Path
from google import genai
from google.genai import types


class CloudAuditor:
    """
    CloudAuditor: Deep Intelligence Layer using Gemini.
    Analyzes code for logic flaws, architectural issues, and complex vulnerabilities.
    """

    FALLBACK_MODELS = ["gemini-2.0-flash", "gemini-flash-latest", "gemini-pro-latest"]

    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)
        self.system_instruction = """
You are an expert security researcher and software architect.
Analyze the provided code for:
1. Security vulnerabilities (e.g., SQL injection, XSS, insecure logic).
2. Architectural patterns that could lead to technical debt.
3. Compliance with professional coding standards.

Provide a concise, bulleted report with actionable recommendations.
If no critical issues are found, state 'Analysis complete: No critical flaws detected.'
"""

    def _call_with_fallback(
        self, contents: str, extra_instruction: str = "", error_prefix: str = "audit"
    ) -> str:
        """Shared model-fallback logic for all Gemini-powered analysis."""
        system = self.system_instruction
        if extra_instruction:
            system += "\n\n" + extra_instruction

        for model in self.FALLBACK_MODELS:
            try:
                response = self.client.models.generate_content(
                    model=model,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        system_instruction=system,
                    )
                )
                return response.text or "No response generated."
            except Exception as e:
                if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                    continue
                return f"Error during {error_prefix}: {str(e)}"

        return f"❌ Error: All available models for {error_prefix} are currently rate-limited."

    def audit_file(self, file_path: Path, content: str) -> str:
        return self._call_with_fallback(
            contents=f"File: {file_path}\n---\n{content}\n---",
            error_prefix="cloud audit",
        )

    def audit_diff(self, diff_text: str) -> str:
        """Analyzes a git diff for potential impact."""
        return self._call_with_fallback(
            contents=f"Diff Content:\n---\n{diff_text}\n---",
            extra_instruction="Focus heavily on security regressions or newly introduced architectural flaws in this diff.",
            error_prefix="diff audit",
        )
