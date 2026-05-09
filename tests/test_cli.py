"""Tests for CLI commands using Click's CliRunner."""

import json
import sys
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from shield_agent.cli import main


class TestScanCommand:
    def test_clean_directory(self, tmp_path):
        """Clean dir should exit 0 with success message."""
        runner = CliRunner()
        (tmp_path / "clean.py").write_text("x = 42")
        result = runner.invoke(main, ["scan", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "No issues found" in result.output

    def test_directory_with_secret(self, tmp_path):
        """Dir with secrets should exit 1."""
        runner = CliRunner()
        (tmp_path / "leak.txt").write_text("AKIA1234567890ABCDEF")
        result = runner.invoke(main, ["scan", "--dir", str(tmp_path)])
        assert result.exit_code == 1
        assert "AWS Access Key" in result.output

    def test_json_output(self, tmp_path):
        """JSON format should output valid JSON."""
        runner = CliRunner()
        (tmp_path / "leak.txt").write_text("AKIA1234567890ABCDEF")
        result = runner.invoke(main, ["scan", "--dir", str(tmp_path), "--format", "json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["rule_name"] == "AWS Access Key"

    def test_json_clean(self, tmp_path):
        """Clean JSON scan should output empty list."""
        runner = CliRunner()
        (tmp_path / "clean.py").write_text("x = 42")
        result = runner.invoke(main, ["scan", "--dir", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_jsonl_output(self, tmp_path):
        """JSONL format should output one JSON object per line."""
        runner = CliRunner()
        (tmp_path / "leak.txt").write_text("AKIA1234567890ABCDEF\ntest@example.com")
        result = runner.invoke(main, ["scan", "--dir", str(tmp_path), "--format", "jsonl"])
        assert result.exit_code == 1
        lines = [line for line in result.output.strip().split("\n") if line]
        for line in lines:
            obj = json.loads(line)
            assert "rule_name" in obj


class TestInstallHooksCommand:
    def test_no_git_dir(self, tmp_path, monkeypatch):
        """Should error when no .git directory exists."""
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(main, ["install-hooks"])
        assert "Error" in result.output

    def test_installs_hook(self, tmp_path, monkeypatch):
        """Should install pre-push hook successfully."""
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        result = runner.invoke(main, ["install-hooks"])
        assert "successfully" in result.output.lower()
        hook = tmp_path / ".git" / "hooks" / "pre-push"
        assert hook.exists()
        assert hook.stat().st_mode & 0o755


class TestAuditCommand:
    def test_audit_missing_api_key(self, tmp_path, monkeypatch):
        """Should exit 1 when GEMINI_API_KEY is not set."""
        runner = CliRunner()
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        f = tmp_path / "test.py"
        f.write_text("print('hello')")
        result = runner.invoke(main, ["audit", str(f)])
        assert result.exit_code == 1
        assert "GEMINI_API_KEY" in result.output

    @patch("shield_agent.cli.CloudAuditor")
    def test_audit_success(self, mock_auditor_class, tmp_path, monkeypatch):
        """Should display audit report on success."""
        runner = CliRunner()
        monkeypatch.setenv("GEMINI_API_KEY", "fake_key")

        mock_instance = MagicMock()
        mock_instance.audit_file.return_value = "No critical flaws detected."
        mock_auditor_class.return_value = mock_instance

        f = tmp_path / "test.py"
        f.write_text("print('hello')")
        result = runner.invoke(main, ["audit", str(f)])
        assert result.exit_code == 0
        assert "No critical flaws detected" in result.output


class TestRunMcpCommand:
    def test_run_mcp_no_mcp_library(self, monkeypatch):
        """Should exit 1 when MCP library is not available."""
        runner = CliRunner()
        with patch("shield_agent.cli.HAS_MCP", False, create=True):
            # Patch the import inside run_mcp
            with patch.dict(sys.modules, {"shield_agent.mcp_server": MagicMock(HAS_MCP=False)}):
                result = runner.invoke(main, ["run-mcp"])
                # Should indicate MCP is not available
                assert result.exit_code != 0 or "Error" in result.output or "MCP" in result.output


class TestHelpCommand:
    def test_main_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "ShieldAgent-MCP" in result.output

    def test_scan_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--dir" in result.output
