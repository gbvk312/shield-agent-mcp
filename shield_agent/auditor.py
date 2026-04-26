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
        # Fallback pool for the tool itself - using high-level aliases
        models = ["gemini-2.0-flash", "gemini-flash-latest", "gemini-pro-latest"]
        
        for model in models:
            try:
                response = self.client.models.generate_content(
                    model=model,
                    contents=f"File: {file_path}\n---\n{content}\n---",
                    config=types.GenerateContentConfig(
                        system_instruction=self.system_instruction,
                    )
                )
                return response.text or "No response generated."
            except Exception as e:
                if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                    continue
                return f"Error during cloud audit: {str(e)}"
        
        return "❌ Error: All available models for deep audit are currently rate-limited."

    def audit_diff(self, diff_text: str) -> str:
        """Analyzes a git diff for potential impact."""
        extra_instruction = "Focus heavily on security regressions or newly introduced architectural flaws in this diff."
        models = ["gemini-2.0-flash", "gemini-flash-latest", "gemini-pro-latest"]
        
        for model in models:
            try:
                response = self.client.models.generate_content(
                    model=model,
                    contents=f"Diff Content:\n---\n{diff_text}\n---",
                    config=types.GenerateContentConfig(
                        system_instruction=self.system_instruction + "\n\n" + extra_instruction,
                    )
                )
                return response.text or "No response generated."
            except Exception as e:
                if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                    continue
                return f"Error during diff audit: {str(e)}"
                
        return "❌ Error: All available models for diff audit are currently rate-limited."
