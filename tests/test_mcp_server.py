"""Tests for MCP server tool functions."""

import pytest

# Import the tool functions directly (they're regular async functions under the hood)
from shield_agent.mcp_server import HAS_MCP

pytestmark = pytest.mark.skipif(not HAS_MCP, reason="MCP not available")


@pytest.fixture
def project_dir(tmp_path):
    """Create a minimal project structure for testing."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hello world')")
    (tmp_path / "README.md").write_text("# Test Project")
    return tmp_path


@pytest.mark.asyncio
async def test_scan_for_secrets_clean(tmp_path, monkeypatch):
    """Clean directory should return success message."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import scan_for_secrets

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    (tmp_path / "clean.py").write_text("x = 42")
    result = await scan_for_secrets(str(tmp_path))
    assert "No security issues found" in result


@pytest.mark.asyncio
async def test_scan_for_secrets_finds_issues(tmp_path, monkeypatch):
    """Directory with secrets should return findings."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import scan_for_secrets

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    (tmp_path / "leak.txt").write_text("AKIA1234567890ABCDEF")
    result = await scan_for_secrets(str(tmp_path))
    assert "Detected Security Issues" in result
    assert "AWS Access Key" in result


@pytest.mark.asyncio
async def test_scan_for_secrets_blocks_outside_root(tmp_path, monkeypatch):
    """Should reject scanning directories outside server root."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import scan_for_secrets

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    result = await scan_for_secrets("/etc")
    assert "outside" in result.lower()


@pytest.mark.asyncio
async def test_list_directory(project_dir, monkeypatch):
    """Should list directory contents."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import list_directory

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", project_dir.resolve())
    result = await list_directory(str(project_dir))
    assert "src" in result
    assert "README.md" in result


@pytest.mark.asyncio
async def test_list_directory_not_found(tmp_path, monkeypatch):
    """Should return error for non-existent directory."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import list_directory

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    result = await list_directory(str(tmp_path / "nonexistent"))
    assert "Error" in result


@pytest.mark.asyncio
async def test_list_directory_empty(tmp_path, monkeypatch):
    """Should handle empty directory."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import list_directory

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    empty = tmp_path / "empty"
    empty.mkdir()
    result = await list_directory(str(empty))
    assert "empty" in result.lower()


@pytest.mark.asyncio
async def test_list_directory_blocks_outside_root(tmp_path, monkeypatch):
    """Should reject listing directories outside server root."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import list_directory

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    result = await list_directory("/etc")
    assert "outside" in result.lower()


@pytest.mark.asyncio
async def test_read_file(tmp_path, monkeypatch):
    """Should read file contents."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import read_file

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    f = tmp_path / "test.txt"
    f.write_text("hello world")
    result = await read_file(str(f))
    assert result == "hello world"


@pytest.mark.asyncio
async def test_read_file_not_found(tmp_path, monkeypatch):
    """Should return error for missing file."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import read_file

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    result = await read_file(str(tmp_path / "nonexistent.txt"))
    assert "Error" in result


@pytest.mark.asyncio
async def test_read_file_too_large(tmp_path, monkeypatch):
    """Should reject files exceeding size limit."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import MAX_FILE_SIZE, read_file

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    f = tmp_path / "big.txt"
    f.write_text("x" * (MAX_FILE_SIZE + 1))
    result = await read_file(str(f))
    assert "too large" in result.lower()


@pytest.mark.asyncio
async def test_read_file_blocks_outside_root(tmp_path, monkeypatch):
    """Should reject reading files outside server root."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import read_file

    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    result = await read_file("/etc/passwd")
    assert "outside" in result.lower()


@pytest.mark.asyncio
async def test_safe_write_file(tmp_path, monkeypatch):
    """Should write file with justification."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import safe_write_file

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    target = tmp_path / "output.py"
    result = await safe_write_file(str(target), "print('fixed')", "Patched XSS vulnerability")
    assert "Successfully wrote" in result
    assert target.read_text() == "print('fixed')"


@pytest.mark.asyncio
async def test_safe_write_file_creates_backup(tmp_path, monkeypatch):
    """Should create backup when overwriting existing file."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import safe_write_file

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    target = tmp_path / "existing.py"
    target.write_text("original content")

    result = await safe_write_file(str(target), "new content", "Security fix")
    assert "Backup created" in result
    assert (tmp_path / "existing.py.bak").exists()
    assert (tmp_path / "existing.py.bak").read_text() == "original content"


@pytest.mark.asyncio
async def test_safe_write_file_blocks_env(tmp_path, monkeypatch):
    """Should refuse to write to .env files."""
    from shield_agent import mcp_server
    from shield_agent.mcp_server import safe_write_file

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    result = await safe_write_file(str(tmp_path / ".env"), "SECRET=x", "test")
    assert "restricted" in result.lower()


@pytest.mark.asyncio
async def test_safe_write_file_blocks_path_traversal(tmp_path, monkeypatch):
    """Should refuse to write outside working directory."""
    from shield_agent.mcp_server import safe_write_file

    monkeypatch.chdir(tmp_path)
    result = await safe_write_file("/etc/passwd", "hacked", "test")
    assert "outside" in result.lower() or "Error" in result


@pytest.mark.asyncio
async def test_audit_file_no_api_key(tmp_path, monkeypatch):
    """Should return error when GEMINI_API_KEY is not set."""
    from shield_agent.mcp_server import audit_file

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    f = tmp_path / "test.py"
    f.write_text("print('hello')")
    result = await audit_file(str(f))
    assert "GEMINI_API_KEY" in result


@pytest.mark.asyncio
async def test_check_network_exposure():
    """Should return listening services or no-ports message."""
    from unittest.mock import MagicMock, patch

    from shield_agent.mcp_server import check_network_exposure

    mock_result = MagicMock()
    mock_result.stdout = "COMMAND PID USER TYPE\nsshd 123 root IPv4 LISTEN\n"

    with patch("subprocess.run", return_value=mock_result):
        result = await check_network_exposure()
        assert "listening" in result.lower() or "LISTEN" in result


@pytest.mark.asyncio
async def test_check_network_exposure_no_listeners():
    """Should report clean when no listeners found."""
    from unittest.mock import MagicMock, patch

    from shield_agent.mcp_server import check_network_exposure

    mock_result = MagicMock()
    mock_result.stdout = "COMMAND PID USER TYPE\nchrome 456 user IPv4 ESTABLISHED\n"

    with patch("subprocess.run", return_value=mock_result):
        result = await check_network_exposure()
        assert "No open listening ports" in result
