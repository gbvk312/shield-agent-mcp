import sys
import os
from pathlib import Path

# Add the project directory to sys.path
sys.path.insert(0, str(Path("/Users/gbvk/Downloads/repo/github/shield-agent-mcp").absolute()))

from shield_agent.scanner import LocalScanner

def run_verification():
    root = Path("/Users/gbvk/Downloads/repo/github/shield-agent-mcp/scratch_test")
    root.mkdir(exist_ok=True)
    
    # Create test files
    (root / "secret.txt").write_text("AWS_KEY: AKIA1234567890ABCDEF\nPhone: +1-555-0199-5678")
    (root / "ignored.txt").write_text("This should be ignored ghp_123456789012345678901234567890123456")
    
    # Create .gitignore
    (root / ".gitignore").write_text("ignored.txt")
    
    print(f"Scanning {root}...")
    scanner = LocalScanner(str(root))
    issues = scanner.scan_directory()
    
    print(f"Found {len(issues)} issues.")
    for issue in issues:
        print(f"- {issue.file_path}:{issue.line_number} {issue.rule_name} ({issue.severity})")

    # Cleanup
    import shutil
    # shutil.rmtree(root)

if __name__ == "__main__":
    run_verification()
