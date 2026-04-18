import click
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from .scanner import LocalScanner
from .auditor import CloudAuditor
from dotenv import load_dotenv

load_dotenv()

console = Console()

@click.group()
def main():
    """ShieldAgent-MCP: Hybrid AI Security Sentinel."""
    pass

@main.command()
@click.option("--dir", default=".", help="Directory to scan")
@click.option("--ollama", is_flag=True, help="Use local Ollama for verification")
def scan(dir, ollama):
    """Run a local security scan for PII and secrets."""
    scanner = LocalScanner(dir)
    
    with console.status("[bold green]Scanning for leaks..."):
        issues = scanner.scan_directory(use_ollama=ollama)
    
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

@main.command()
@click.argument("file", type=click.Path(exists=True))
def audit(file):
    """Perform a deep AI audit on a specific file using Gemini."""
    api_key = os.getenv("GEMINI_API_KEY")
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
    if not git_dir.exists():
        console.print("[bold red]Error: No .git directory found. Run this in the repo root.[/bold red]")
        return
        
    hooks_dir = git_dir / "hooks"
    pre_push_path = hooks_dir / "pre-push"
    
    # Template for the pre-push hook
    hook_content = """#!/bin/bash
# ShieldAgent-MCP Pre-Push Hook
shield-agent scan --dir .
if [ $? -ne 0 ]; then
    echo "❌ Push blocked by ShieldAgent-MCP. Fix security issues first."
    exit 1
fi
"""
    
    with open(pre_push_path, "w") as f:
        f.write(hook_content)
    
    os.chmod(pre_push_path, 0o755)
    console.print("[bold green]🚀 Pre-push hook installed successfully![/bold green]")

if __name__ == "__main__":
    main()
