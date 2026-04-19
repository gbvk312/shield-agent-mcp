import click
import os
import sys
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from .scanner import LocalScanner
from .auditor import CloudAuditor
from .config import config

console = Console()

@click.group()
def main():
    """ShieldAgent-MCP: Hybrid AI Security Sentinel."""
    pass

@main.command()
@click.option("--dir", default=".", help="Directory to scan")
@click.option("--ollama", is_flag=True, help="Use local Ollama for verification")
@click.option("--format", type=click.Choice(["text", "json", "jsonl"]), default="text", help="Output format")
def scan(dir, ollama, format):
    """Run a local security scan for PII and secrets."""
    scanner = LocalScanner(dir)
    
    with console.status("[bold green]Scanning for leaks..."):
        issues = scanner.scan_directory(use_ollama=ollama)
    
    if format == "json":
        click.echo(json.dumps([i.model_dump() for i in issues], indent=2))
        if issues:
            sys.exit(1)
        return
    elif format == "jsonl":
        for issue in issues:
            click.echo(json.dumps(issue.model_dump()))
        if issues:
            sys.exit(1)
        return

    if not issues:
        console.print("[bold green]✅ No issues found! Clean codebase.[/bold green]")
        return

    table = Table(title="Detected Security Issues")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="magenta")
    table.add_column("Rule", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("Content", style="white")

    for issue in issues:
        table.add_row(
            issue.file_path,
            str(issue.line_number),
            issue.rule_name,
            issue.severity,
            issue.content
        )

    console.print(table)
    console.print(f"\n[bold red]Total issues found: {len(issues)}[/bold red]")
    
    # Exit with code 1 so CI/CD and Git hooks can detect failure
    sys.exit(1)

@main.command()
@click.argument("file", type=click.Path(exists=True))
def audit(file):
    """Perform a deep AI audit on a specific file using Gemini."""
    api_key = config.GEMINI_API_KEY
    if not api_key:
        console.print("[bold red]Error: GEMINI_API_KEY not found in environment or .env file.[/bold red]")
        return

    auditor = CloudAuditor(api_key)
    path = Path(file)
    
    with console.status(f"[bold cyan]Performing deep audit on {path.name}..."):
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        report = auditor.audit_file(path, content)

    console.print(Panel(Markdown(report), title=f"Audit Report: {path.name}", border_style="cyan"))

@main.command()
def install_hooks():
    """Install pre_push git hooks."""
    git_dir = Path(".git")
    hooks_dir = Path(".git/hooks")
    
    if not hooks_dir.exists():
        if git_dir.is_file():
            console.print("[bold red]Error: .git is a file (likely a submodule). Hook installation not supported directly.[/bold red]")
        else:
            console.print("[bold red]Error: No .git/hooks directory found. Run this in the repo root.[/bold red]")
        return
        
    pre_push_path = hooks_dir / "pre-push"
    
    # Template for the pre-push hook (more robust)
    hook_content = """#!/bin/bash
# ShieldAgent-MCP Pre-Push Hook
echo "🛡️ ShieldAgent-MCP: Scanning for secrets before push..."

# Only scan files that are about to be pushed (heuristic: diff against remote)
# For simplicity, we scan the whole directory but you could optimize this
if command -v uv >/dev/null 2>&1; then
    uv run shield-agent scan --dir .
elif command -v shield-agent >/dev/null 2>&1; then
    shield-agent scan --dir .
else
    echo "⚠️  shield-agent not found in PATH or via uv. Skipping scan."
    exit 0
fi

if [ $? -ne 0 ]; then
    echo "❌ Push blocked by ShieldAgent-MCP. Fix the security issues listed above before pushing."
    exit 1
fi
echo "✅ Security scan passed. Proceeding with push."
exit 0
"""
    
    with open(pre_push_path, "w") as f:
        f.write(hook_content)
    
    os.chmod(pre_push_path, 0o755)
    console.print("[bold green]🚀 Pre-push hook installed successfully![/bold green]")

@main.command()
def run_mcp():
    """Start the ShieldAgent MCP server for integration with AI assistants."""
    try:
        from .mcp_server import mcp, HAS_MCP
        if not HAS_MCP:
            console.print("[bold red]Error: MCP dependencies not found or incompatible Python version.[/bold red]")
            console.print("Note: MCP requires Python 3.10+ and the 'mcp' package.")
            console.print("Install with: pip install 'shield-agent-mcp[mcp]'")
            return
        
        console.print("[bold green]🛡️ Starting ShieldAgent MCP Server...[/bold green]")
        # FastMCP.run() defaults to stdio if no arguments are passed
        mcp.run()
    except Exception as e:
        console.print(f"[bold red]Error: Failed to start MCP server: {e}[/bold red]")

if __name__ == "__main__":
    main()
