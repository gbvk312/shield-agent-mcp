import pytest
from pathlib import Path
from shield_agent.mcp_server import HAS_MCP

pytestmark = pytest.mark.skipif(not HAS_MCP, reason="MCP not available")

@pytest.fixture
def supply_chain_dir(tmp_path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    
    # Vulnerable workflow
    (wf_dir / "vuln.yml").write_text(
        "name: Vuln\n"
        "on: push\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v3\n"
    )
    
    # Safe workflow
    (wf_dir / "safe.yml").write_text(
        "name: Safe\n"
        "on: push\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@1d356f57ca67451f8e91c7356db6330fb3efcee3\n"
    )

    # Vulnerable Dockerfile
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.9\n"
        "RUN echo hello\n"
    )
    
    return tmp_path

@pytest.mark.asyncio
async def test_scan_supply_chain_vuln(supply_chain_dir, monkeypatch):
    from shield_agent import mcp_server
    from shield_agent.mcp_server import scan_supply_chain
    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", supply_chain_dir.resolve())
    
    result = await scan_supply_chain(str(supply_chain_dir))
    
    assert "Supply Chain Vulnerabilities Detected" in result
    assert "write-all" in result.lower()
    assert "actions/checkout@v3" in result or "Mutable tag" in result
    assert "python:3.9" in result or "Unpinned base image" in result

@pytest.mark.asyncio
async def test_scan_supply_chain_clean(tmp_path, monkeypatch):
    from shield_agent import mcp_server
    from shield_agent.mcp_server import scan_supply_chain
    monkeypatch.setattr(mcp_server, "_SERVER_ROOT", tmp_path.resolve())
    
    # Safe Dockerfile
    (tmp_path / "Dockerfile.safe").write_text(
        "FROM python:3.9@sha256:1d356f57ca67451f8e91c7356db6330fb3efcee3\n"
        "RUN echo hello\n"
    )
    
    result = await scan_supply_chain(str(tmp_path))
    assert "Supply chain scan clean" in result
