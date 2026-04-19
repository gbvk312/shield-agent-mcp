import os
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
    async def list_directory(directory: str = ".") -> str:
        """
        Lists files and directories in the specified path.
        
        Args:
            directory: The path to the directory to list.
        """
        path = Path(directory)
        if not path.exists():
            return f"❌ Error: Directory {directory} not found."
        
        try:
            items = os.listdir(path)
            if not items:
                return f"📁 Directory {directory} is empty."
            
            output = f"📁 Contents of {directory}:\n"
            for item in sorted(items):
                is_dir = (path / item).is_dir()
                prefix = "📁 " if is_dir else "📄 "
                output += f"{prefix}{item}\n"
            return output
        except Exception as e:
            return f"❌ Error listing directory: {e}"

    @mcp.tool()
    async def read_file(file_path: str) -> str:
        """
        Reads the full content of a specified file.
        
        Args:
            file_path: The path to the file to read.
        """
        path = Path(file_path)
        if not path.exists():
            return f"❌ Error: File {file_path} not found."
        
        try:
            return path.read_text(encoding="utf-8")
        except Exception as e:
            return f"❌ Error reading file: {str(e)}"

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
            
        def run_audit():
            auditor = CloudAuditor(api_key)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            return auditor.audit_file(path, content)
            
        return await anyio.to_thread.run_sync(run_audit)

    @mcp.tool()
    async def safe_write_file(file_path: str, content: str, reason: str) -> str:
        """
        Safely writes or updates a file with a mandatory justification.
        Used by remediation agents to fix security vulnerabilities.
        
        Args:
            file_path: The path to the file to write.
            content: The new content for the file.
            reason: The security justification for this change.
        """
        import anyio
        
        path = Path(file_path)
        
        def do_write():
            # Basic safety: don't write to sensitive system paths (simulated)
            base_name = path.name.lower()
            if base_name in (".env", "id_rsa", ".ssh"):
                 return f"⚠️ Warning: Direct write to {base_name} is restricted. Use specialized tools for secrets."
            
            # Create backup if exists
            if path.exists():
                backup = path.with_suffix(path.suffix + ".bak")
                path.replace(backup)
                backup_msg = f" (Backup created at {backup.name})"
            else:
                backup_msg = ""

            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            
            return f"✅ Successfully wrote {file_path}. Reason: {reason}{backup_msg}"

        return await anyio.to_thread.run_sync(do_write)

    @mcp.tool()
    async def check_network_exposure() -> str:
        """
        Checks for risky network listening ports on the local machine.
        Identifies potential exposure of services.
        """
        import subprocess
        import anyio

        def run_check():
            try:
                # Use lsof for macOS/Linux to find listening ports
                result = subprocess.run(
                    ["lsof", "-i", "-P", "-n"], 
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                lines = result.stdout.splitlines()
                listeners = [l for l in lines if "LISTEN" in l]
                
                if not listeners:
                    return "✅ No open listening ports detected."
                
                report = "🔍 Found the following listening services:\n"
                for listener in listeners:
                    report += f"- {listener}\n"
                return report
            except Exception as e:
                return f"❌ Error checking network: {e}"

        return await anyio.to_thread.run_sync(run_check)

else:
    def main():
        print("MCP Server functionality requires the 'mcp' library and Python 3.10+.")
        print("Install it using: pip install 'shield-agent-mcp[mcp]'")

if __name__ == "__main__":
    if HAS_MCP:
        mcp.run()
    else:
        main()
