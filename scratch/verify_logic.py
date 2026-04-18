import os
import sys

# Add the project root to sys.path to import local package
sys.path.append(os.getcwd())

from shield_agent.scanner import LocalScanner, Issue

def verify():
    print("🚀 Starting Manual Verification...")
    
    # Test file with various secrets
    test_content = """
    AWS_KEY = AKIA1234567890ABCDEF
    EMAIL = test@example.com
    STRIPE = sk_test_51Q123456789012345678901234567890
    GITHUB = ghp_123456789012345678901234567890123456
    """
    
    # Create temp file
    with open("verify_test.txt", "w") as f:
        f.write(test_content)
    
    scanner = LocalScanner(".")
    from pathlib import Path
    issues = scanner.scan_file(Path("verify_test.txt"))
    
    found_rules = [i.rule_name for i in issues]
    print(f"Detected issues: {found_rules}")
    
    expected = ["AWS Access Key", "Email Address", "Stripe Secret Key", "GitHub Personal Access Token"]
    all_passed = True
    for rule in expected:
        if rule not in found_rules:
            print(f"❌ FAILED: Missing {rule}")
            all_passed = False
    
    if all_passed:
        print("✅ PASS: All secret patterns detected correctly!")
    
    # Clean up
    os.remove("verify_test.txt")

if __name__ == "__main__":
    verify()
