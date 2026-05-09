"""Tests for advanced scanner features: entropy, gitignore, case-sensitivity."""

from unittest.mock import patch

from shield_agent.scanner import LocalScanner

# --- Shannon Entropy Tests ---

class TestShannonEntropy:
    def test_empty_string(self):
        assert LocalScanner._shannon_entropy("") == 0.0

    def test_single_char(self):
        assert LocalScanner._shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        result = LocalScanner._shannon_entropy("ab")
        assert abs(result - 1.0) < 0.01

    def test_high_entropy_random_string(self):
        # A string with many unique chars should have high entropy
        high_entropy = "aB3$xZ9!kL7@mN2&pQ5"
        result = LocalScanner._shannon_entropy(high_entropy)
        assert result > 4.0

    def test_low_entropy_repetitive_string(self):
        low_entropy = "aaabbbcccddd"
        result = LocalScanner._shannon_entropy(low_entropy)
        assert result < 2.5


# --- Entropy-Based Detection Tests ---

class TestHighEntropyDetection:
    def test_detects_high_entropy_in_assignment(self, tmp_path):
        f = tmp_path / "config.py"
        # Generate a high-entropy string (base64-like)
        f.write_text('SECRET = "aB3xZ9kL7mN2pQ5rT8wY1cF4gH6jK0"')

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_file(f)
        entropy_issues = [i for i in issues if i.rule_name == "High Entropy String"]
        assert len(entropy_issues) >= 1

    def test_ignores_low_entropy_assignment(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text('NAME = "aaaaaaaaaaaaaaaaaaaaaa"')

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_file(f)
        entropy_issues = [i for i in issues if i.rule_name == "High Entropy String"]
        assert len(entropy_issues) == 0

    def test_ignores_short_strings(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text('KEY = "aB3xZ9kL7"')  # < 20 chars

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_file(f)
        entropy_issues = [i for i in issues if i.rule_name == "High Entropy String"]
        assert len(entropy_issues) == 0


# --- Gitignore Integration Tests ---

class TestGitignoreIntegration:
    def test_respects_gitignore(self, tmp_path):
        # Create a .gitignore that ignores secret files
        (tmp_path / ".gitignore").write_text("secrets/\n")
        (tmp_path / "secrets").mkdir()
        (tmp_path / "secrets" / "keys.txt").write_text("AKIA1234567890ABCDEF")

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_directory()
        assert len(issues) == 0

    def test_scans_non_ignored_files(self, tmp_path):
        (tmp_path / ".gitignore").write_text("logs/\n")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "config.txt").write_text("AKIA1234567890ABCDEF")

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_directory()
        assert any(i.rule_name == "AWS Access Key" for i in issues)

    def test_no_gitignore_scans_all(self, tmp_path):
        (tmp_path / "file.txt").write_text("AKIA1234567890ABCDEF")

        scanner = LocalScanner(str(tmp_path))
        assert scanner.gitignore is None
        issues = scanner.scan_directory()
        assert len(issues) >= 1


# --- Case-Sensitivity Tests ---

class TestCaseSensitivity:
    def test_aws_key_case_sensitive(self, tmp_path):
        """AWS keys start with uppercase AKIA — lowercase should NOT match."""
        f = tmp_path / "test.txt"
        f.write_text("akia1234567890abcdef")

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_file(f)
        aws_issues = [i for i in issues if i.rule_name == "AWS Access Key"]
        assert len(aws_issues) == 0

    def test_aws_key_uppercase_matches(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("AKIA1234567890ABCDEF")

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_file(f)
        aws_issues = [i for i in issues if i.rule_name == "AWS Access Key"]
        assert len(aws_issues) == 1

    def test_github_pat_case_sensitive(self, tmp_path):
        """GitHub PATs start with lowercase ghp_ — uppercase should NOT match."""
        f = tmp_path / "test.txt"
        f.write_text("GHP_123456789012345678901234567890123456")

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_file(f)
        ghp_issues = [i for i in issues if i.rule_name == "GitHub Personal Access Token"]
        assert len(ghp_issues) == 0

    def test_email_case_insensitive(self, tmp_path):
        """Emails should match regardless of case."""
        f = tmp_path / "test.txt"
        f.write_text("Contact: Admin@Example.COM")

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_file(f)
        email_issues = [i for i in issues if i.rule_name == "Email Address"]
        assert len(email_issues) == 1


# --- False Positive Filtering Tests ---

class TestFalsePositiveFiltering:
    def test_placeholder_filtered(self):
        scanner = LocalScanner(".")
        assert scanner._is_likely_false_positive("YOUR_API_KEY") is True

    def test_placeholder_your_prefix(self):
        scanner = LocalScanner(".")
        assert scanner._is_likely_false_positive("your_custom_key") is True

    def test_placeholder_here_suffix(self):
        scanner = LocalScanner(".")
        assert scanner._is_likely_false_positive("put_secret_here") is True

    def test_repetitive_chars_filtered(self):
        scanner = LocalScanner(".")
        assert scanner._is_likely_false_positive("aaaa") is True

    def test_empty_string_filtered(self):
        scanner = LocalScanner(".")
        assert scanner._is_likely_false_positive("") is True

    def test_real_looking_key_passes(self):
        scanner = LocalScanner(".")
        assert scanner._is_likely_false_positive("aB3xZ9kL7mN2pQ5rT8wY1cF4") is False


# --- Severity Map Tests ---

class TestSeverityMap:
    def test_aws_key_is_high(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("AKIA1234567890ABCDEF")

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_file(f)
        aws_issues = [i for i in issues if i.rule_name == "AWS Access Key"]
        assert aws_issues[0].severity == "HIGH"

    def test_email_is_medium(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("user@example.com")

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_file(f)
        email_issues = [i for i in issues if i.rule_name == "Email Address"]
        assert email_issues[0].severity == "MEDIUM"

    def test_ipv4_is_low(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("server at 192.168.1.100 is down")

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_file(f)
        ip_issues = [i for i in issues if i.rule_name == "IPv4 Address"]
        assert ip_issues[0].severity == "LOW"

    def test_unknown_rule_defaults_medium(self):
        scanner = LocalScanner(".")
        assert scanner._get_severity("Unknown Rule") == "MEDIUM"


# --- Binary File Skipping Tests ---

class TestBinaryFileSkipping:
    def test_skips_binary_extensions(self, tmp_path):
        (tmp_path / "image.png").write_bytes(b"AKIA1234567890ABCDEF")
        (tmp_path / "archive.zip").write_bytes(b"ghp_123456789012345678901234567890123456")

        scanner = LocalScanner(str(tmp_path))
        issues = scanner.scan_directory()
        assert len(issues) == 0


# --- Ollama Verification Tests ---

class TestOllamaVerification:
    def test_verify_with_ollama_yes(self):
        """Should return True when Ollama says YES."""
        from shield_agent.scanner import Issue

        scanner = LocalScanner(".")
        issue = Issue(
            file_path="test.py",
            line_number=1,
            rule_name="AWS Access Key",
            severity="HIGH",
            content="AKIA1234567890ABCDEF",
            description="Potential AWS Access Key detected.",
        )

        mock_response = type("Response", (), {
            "status_code": 200,
            "json": lambda self: {"response": "YES"},
        })()

        with patch("requests.post", return_value=mock_response):
            assert scanner.verify_with_ollama(issue) is True

    def test_verify_with_ollama_no(self):
        """Should return False when Ollama says NO."""
        from shield_agent.scanner import Issue

        scanner = LocalScanner(".")
        issue = Issue(
            file_path="test.py",
            line_number=1,
            rule_name="Email Address",
            severity="MEDIUM",
            content="test@example.com",
            description="Potential Email Address detected.",
        )

        mock_response = type("Response", (), {
            "status_code": 200,
            "json": lambda self: {"response": "NO"},
        })()

        with patch("requests.post", return_value=mock_response):
            assert scanner.verify_with_ollama(issue) is False

    def test_verify_with_ollama_fallback_on_error(self):
        """Should return True (keep issue) when Ollama is unreachable."""
        from shield_agent.scanner import Issue

        scanner = LocalScanner(".")
        issue = Issue(
            file_path="test.py",
            line_number=1,
            rule_name="AWS Access Key",
            severity="HIGH",
            content="AKIA1234567890ABCDEF",
            description="Potential AWS Access Key detected.",
        )

        with patch("requests.post", side_effect=ConnectionError("refused")):
            assert scanner.verify_with_ollama(issue) is True
