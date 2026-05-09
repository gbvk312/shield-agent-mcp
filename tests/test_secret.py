from shield_agent.scanner import LocalScanner


def test_secret_detection(tmp_path):
    # Create a dummy file with a secret
    d = tmp_path / "subdir"
    d.mkdir()
    f = d / "secrets.txt"
    f.write_text("My AWS Key is AKIA1234567890ABCDEF\nAnd my email is test@example.com")

    scanner = LocalScanner(str(tmp_path))
    issues = scanner.scan_file(f)

    # Check if both were detected
    rules = [i.rule_name for i in issues]
    assert "AWS Access Key" in rules
    assert "Email Address" in rules
    assert len(issues) == 2


def test_false_positive_filtering(tmp_path):
    f = tmp_path / "code.py"
    f.write_text("api_key = 'YOUR_API_KEY'")  # Should be filtered out

    scanner = LocalScanner(str(tmp_path))
    issues = scanner.scan_file(f)

    assert len(issues) == 0


def test_directory_scan(tmp_path):
    (tmp_path / "folder").mkdir()
    (tmp_path / "folder" / "file.txt").write_text("ghp_123456789012345678901234567890123456")

    scanner = LocalScanner(str(tmp_path))
    issues = scanner.scan_directory()

    assert len(issues) == 1
    assert issues[0].rule_name == "GitHub Personal Access Token"
