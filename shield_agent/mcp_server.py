import os
from typing import Optional
from pathlib import Path
from .scanner import LocalScanner
from .auditor import CloudAuditor

try:
    from mcp.server.fastmcp import FastMCP
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

# Initialize the MCP Server (if library available)
if HAS_MCP:
    mcp = FastMCP("ShieldAgent")

    @mcp.tool()
    def scan_for_secrets(directory: str = ".") -> str:
        """Scans the specified directory for sensitive data leaks (PII, Secrets)."""
        scanner = LocalScanner(directory)
        issues = scanner.scan_directory()
        if not issues:
            return "✅ No security issues found."
        
        report = "🚨 Detected Security Issues:\n"
        for issue in issues:
            report += f"- {issue.file_path}:{issue.line_number} [{issue.rule_name}] ({issue.severity})\n"
        return report

    @mcp.tool()
    def audit_codebase(file_path: str) -> str:
        """Performs a deep Gemini-powered security audit on a specific file."""
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return "❌ Error: GEMINI_API_KEY not configured."
        
        auditor = CloudAuditor(api_key)
        path = Path(file_path)
        if not path.exists():
            return f"❌ Error: File {file_path} not found."
            
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return auditor.audit_file(path, content)

else:
    def main():
        print("MCP Server functionality requires the 'mcp' library and Python 3.10+.")
        print("Install it using: pip install 'shield-agent-mcp[mcp]'")

if __name__ == "__main__":
    if HAS_MCP:
        mcp.run()
    else:
        main()
