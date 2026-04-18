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
    async def scan_for_secrets(directory: str = ".", use_ollama: bool = False) -> str:
        """
        Scans specified directory for sensitive data leaks (PII, Secrets).
        
        Args:
            directory: The path to the directory to scan.
            use_ollama: Whether to use local Ollama for verification (requires OLLAMA_HOST).
        """
        import anyio
        
        def run_scan():
            scanner = LocalScanner(directory)
            return scanner.scan_directory(use_ollama=use_ollama)
            
        issues = await anyio.to_thread.run_sync(run_scan)
        
        if not issues:
            return "✅ No security issues found."
        
        report = "🚨 Detected Security Issues:\n"
        for issue in issues:
            report += f"- {issue.file_path}:{issue.line_number} [{issue.rule_name}] ({issue.severity})\n"
        return report

    @mcp.tool()
    async def audit_file(file_path: str) -> str:
        """Performs a deep Gemini-powered security audit on a specific file."""
        import anyio
        
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return "❌ Error: GEMINI_API_KEY not configured."
        
        path = Path(file_path)
        if not path.exists():
            return f"❌ Error: File {file_path} not found."
            
        async def run_audit():
            auditor = CloudAuditor(api_key)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            return auditor.audit_file(path, content)
            
        return await anyio.to_thread.run_sync(run_audit)

else:
    def main():
        print("MCP Server functionality requires the 'mcp' library and Python 3.10+.")
        print("Install it using: pip install 'shield-agent-mcp[mcp]'")

if __name__ == "__main__":
    if HAS_MCP:
        mcp.run()
    else:
        main()
