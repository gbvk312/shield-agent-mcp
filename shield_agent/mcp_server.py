import logging
import os
import re
import shutil
from pathlib import Path

from .auditor import CloudAuditor
from .scanner import LocalScanner

__all__ = ["HAS_MCP", "MAX_FILE_SIZE"]

logger = logging.getLogger("shield_agent.mcp_server")

# Maximum file size for read/audit operations (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Capture the server root at startup to prevent TOCTOU path traversal.
# Tests should monkeypatch this value when running from a different CWD.
_SERVER_ROOT = Path.cwd().resolve()

try:
    from mcp.server.fastmcp import FastMCP

    HAS_MCP = True
except ImportError:
    HAS_MCP = False


def _validate_path(path: Path, must_exist: bool = True) -> str | None:
    """Validate that a resolved path is within _SERVER_ROOT.

    Returns an error message string if validation fails, or None if the path is safe.
    """
    resolved = path.resolve()
    try:
        resolved.relative_to(_SERVER_ROOT)
    except ValueError:
        return f"❌ Error: Path '{path}' is outside the working directory. Access rejected."
    if must_exist and not resolved.exists():
        return f"❌ Error: Path '{path}' not found."
    return None


def _prompt_firewall(content: str) -> str | None:
    """Basic prompt injection firewall to protect MCP tools."""
    suspicious_patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"you\s+are\s+now",
        r"system\s+prompt",
        r"bypass",
    ]
    content_lower = content.lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, content_lower):
            return f"🚫 Firewall Blocked: Suspicious prompt injection pattern detected ('{pattern}')."
    return None


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

        path = Path(directory).resolve()
        error = _validate_path(path)
        if error:
            return error

        def run_scan() -> str:
            scanner = LocalScanner(str(path))
            issues = scanner.scan_directory(use_ollama=use_ollama)

            if not issues:
                return "✅ No security issues found."

            report = "🚨 Detected Security Issues:\n"
            for issue in issues:
                report += f"- {issue.file_path}:{issue.line_number} [{issue.rule_name}] ({issue.severity})\n"
            return report

        return await anyio.to_thread.run_sync(run_scan)

    @mcp.tool()
    async def list_directory(directory: str = ".") -> str:
        """
        Lists files and directories in the specified path.

        Args:
            directory: The path to the directory to list.
        """
        path = Path(directory).resolve()
        error = _validate_path(path)
        if error:
            return error

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
        path = Path(file_path).resolve()
        error = _validate_path(path)
        if error:
            return error

        try:
            file_size = path.stat().st_size
            if file_size > MAX_FILE_SIZE:
                return f"❌ File too large ({file_size:,} bytes). Max: {MAX_FILE_SIZE:,} bytes."
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

        path = Path(file_path).resolve()
        error = _validate_path(path)
        if error:
            return error

        file_size = path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            return f"❌ File too large ({file_size:,} bytes). Max: {MAX_FILE_SIZE:,} bytes."

        def run_audit() -> str:
            with open(path, encoding="utf-8") as f:
                content = f.read()
                
            fw_error = _prompt_firewall(content)
            if fw_error:
                return fw_error
                
            auditor = CloudAuditor(api_key)
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

        path = Path(file_path).resolve()

        def do_write() -> str:
            fw_error = _prompt_firewall(content)
            if fw_error:
                return fw_error
            fw_error_reason = _prompt_firewall(reason)
            if fw_error_reason:
                return fw_error_reason

            # Path traversal protection: reject paths outside server root
            try:
                path.relative_to(_SERVER_ROOT)
            except ValueError:
                return f"❌ Error: Path '{file_path}' is outside the working directory. Write rejected."

            # Safety: don't write to sensitive files
            base_name = path.name.lower()
            sensitive_names = {".env", "id_rsa", ".ssh", ".env.production", ".env.local"}
            if base_name in sensitive_names or base_name.startswith(".env"):
                return f"⚠️ Warning: Direct write to {base_name} is restricted. Use specialized tools for secrets."

            # Create backup if exists (copy, not move, so original survives a failed write)
            if path.exists():
                backup = path.with_suffix(path.suffix + ".bak")
                shutil.copy2(path, backup)
                backup_msg = f" (Backup created at {backup.name})"
            else:
                backup_msg = ""

            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

            return f"✅ Successfully wrote {file_path}. Reason: {reason}{backup_msg}"

        return await anyio.to_thread.run_sync(do_write)

    @mcp.tool()
    async def restore_backup(file_path: str) -> str:
        """
        Restores a file from its .bak backup.
        Used to rollback a flawed remediation.

        Args:
            file_path: The original path to the file to restore.
        """
        import anyio

        path = Path(file_path).resolve()

        def do_restore() -> str:
            # Path traversal protection
            try:
                path.relative_to(_SERVER_ROOT)
            except ValueError:
                return f"❌ Error: Path '{file_path}' is outside the working directory."

            backup_path = path.with_suffix(path.suffix + ".bak")
            if not backup_path.exists():
                return f"❌ Error: No backup found at {backup_path.name}"

            try:
                shutil.copy2(backup_path, path)
                backup_path.unlink()  # Clean up the backup after restoration
                return f"✅ Successfully restored {file_path} from backup and cleaned up."
            except Exception as e:
                return f"❌ Error restoring backup: {str(e)}"

        return await anyio.to_thread.run_sync(do_restore)

    @mcp.tool()
    async def scan_supply_chain(directory: str = ".") -> str:
        """
        Scans CI/CD pipelines and Dockerfiles for supply chain vulnerabilities.
        Checks for mutable tags in GitHub Actions and permissive scopes.
        """
        import re

        import anyio

        path = Path(directory).resolve()
        error = _validate_path(path)
        if error:
            return error

        def run_scan() -> str:
            issues = []
            
            # Check GitHub Actions
            workflows_dir = path / ".github" / "workflows"
            if workflows_dir.exists() and workflows_dir.is_dir():
                for yaml_file in workflows_dir.glob("*.yml"):
                    content = yaml_file.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()
                    for i, line in enumerate(lines, 1):
                        # Check for mutable tags (e.g., uses: actions/checkout@v3 or @main)
                        match = re.search(r"uses:\s+[^@]+@([a-zA-Z0-9\.\-_]+)", line)
                        if match:
                            tag = match.group(1)
                            if not re.match(r"^[a-fA-F0-9]{40}$", tag):
                                issues.append(
                                    f"  - ⚠️ {yaml_file.name}:{i} Mutable tag used ('{tag}'). "
                                    "Pin to a commit SHA."
                                )
                        
                        # Check for write-all permissions
                        if "write-all" in line.lower() and "permissions:" in content.lower():
                            issues.append(f"  - 🚨 {yaml_file.name}:{i} Overly permissive scope 'write-all' detected.")

            # Check Dockerfiles
            for dockerfile in path.rglob("Dockerfile*"):
                content = dockerfile.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                for i, line in enumerate(lines, 1):
                    if line.strip().upper().startswith("FROM "):
                        if "@sha256:" not in line:
                            issues.append(
                                f"  - ⚠️ {dockerfile.relative_to(path)}:{i} Unpinned base image used "
                                f"('{line.strip()}'). Pin to a @sha256 digest."
                            )

            if not issues:
                return "✅ Supply chain scan clean. No unpinned actions or loose permissions found."
            
            return "🚨 Supply Chain Vulnerabilities Detected:\n" + "\n".join(issues)

        return await anyio.to_thread.run_sync(run_scan)

    @mcp.tool()
    async def check_network_exposure() -> str:
        """
        Checks for risky network listening ports on the local machine.
        Identifies potential exposure of services.
        """
        import subprocess

        import anyio

        def run_check() -> str:
            try:
                import platform

                # Use platform-appropriate command
                if platform.system() == "Windows":
                    cmd = ["netstat", "-an"]
                else:
                    cmd = ["lsof", "-i", "-P", "-n"]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                lines = result.stdout.splitlines()
                listeners = [line for line in lines if "LISTEN" in line]

                if not listeners:
                    return "✅ No open listening ports detected."

                report = "🔍 Found the following listening services:\n"
                for listener in listeners:
                    # Check if port is bound to localhost vs all interfaces
                    if "127.0.0.1" in listener or "[::1]" in listener or "localhost" in listener:
                        report += f"  - [Safe/Local] {listener.strip()}\n"
                    elif "0.0.0.0" in listener or "[::]" in listener or "*:" in listener:
                        report += f"  - [⚠️ Exposed/External] {listener.strip()}\n"
                    else:
                        report += f"  - [?] {listener.strip()}\n"
                return report
            except Exception as e:
                return f"❌ Error checking network: {e}"

        return await anyio.to_thread.run_sync(run_check)

else:

    def main() -> None:
        print("MCP Server functionality requires the 'mcp' library and Python 3.10+.")
        print("Install it using: pip install shield-agent-mcp")


if __name__ == "__main__":
    if HAS_MCP:
        mcp.run()
    else:
        main()
