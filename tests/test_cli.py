"""Tests for CLI commands using Click's CliRunner."""

import pytest
from pathlib import Path
from click.testing import CliRunner
from shield_agent.cli import main


@pytest.fixture
def runner():
    return CliRunner()


class TestScanCommand:
    def test_clean_directory(self, runner, tmp_path):
        """Clean dir should exit 0 with success message."""
        (tmp_path / "clean.py").write_text("x = 42")
        result = runner.invoke(main, ["scan", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "No issues found" in result.output

    def test_directory_with_secret(self, runner, tmp_path):
        """Dir with secrets should exit 1."""
        (tmp_path / "leak.txt").write_text("AKIA1234567890ABCDEF")
        result = runner.invoke(main, ["scan", "--dir", str(tmp_path)])
        assert result.exit_code == 1
        assert "AWS Access Key" in result.output

    def test_json_output(self, runner, tmp_path):
        """JSON format should output valid JSON."""
        import json

        (tmp_path / "leak.txt").write_text("AKIA1234567890ABCDEF")
        result = runner.invoke(main, ["scan", "--dir", str(tmp_path), "--format", "json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["rule_name"] == "AWS Access Key"

    def test_json_clean(self, runner, tmp_path):
        """Clean JSON scan should output empty list."""
        import json

        (tmp_path / "clean.py").write_text("x = 42")
        result = runner.invoke(main, ["scan", "--dir", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    def test_jsonl_output(self, runner, tmp_path):
        """JSONL format should output one JSON object per line."""
        import json

        (tmp_path / "leak.txt").write_text("AKIA1234567890ABCDEF\ntest@example.com")
        result = runner.invoke(main, ["scan", "--dir", str(tmp_path), "--format", "jsonl"])
        assert result.exit_code == 1
        lines = [line for line in result.output.strip().split("\n") if line]
        for line in lines:
            obj = json.loads(line)
            assert "rule_name" in obj


class TestInstallHooksCommand:
    def test_no_git_dir(self, runner, tmp_path, monkeypatch):
        """Should error when no .git directory exists."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(main, ["install-hooks"])
        assert "Error" in result.output

    def test_installs_hook(self, runner, tmp_path, monkeypatch):
        """Should install pre-push hook successfully."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        result = runner.invoke(main, ["install-hooks"])
        assert "successfully" in result.output.lower()
        hook = tmp_path / ".git" / "hooks" / "pre-push"
        assert hook.exists()
        assert hook.stat().st_mode & 0o755


class TestHelpCommand:
    def test_main_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "ShieldAgent-MCP" in result.output

    def test_scan_help(self, runner):
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--dir" in result.output
