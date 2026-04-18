# Developer Guide 👨‍💻

Thank you for contributing to ShieldAgent-MCP! This guide will help you set up your development environment and understand the codebase.

## 1. Development Setup

We recommend using `uv` for dependency management.

```bash
# Clone the repository
git clone https://github.com/gbvk/shield-agent-mcp.git
cd shield-agent-mcp

# Sync dependencies and create venv
uv sync

# Install in editable mode
uv pip install -e .
```

---

## 2. Project Structure

- `shield_agent/`: Core package.
  - `cli.py`: Command-line interface definitions using `click`.
  - `scanner.py`: Local PII/Secret scanning logic (Regex + Pydantic models).
  - `auditor.py`: Gemini-powered architectural auditing logic.
  - `mcp_server.py`: Bridge between core logic and Model Context Protocol.
- `tests/`: Project tests (pytest).
- `docs/`: Documentation and assets.

---

## 3. Running Tests

We use `pytest` for testing.

```bash
uv run pytest
```

---

## 4. Coding Standards

- **Typing**: All new functions should have type hints.
- **Models**: Use Pydantic models (like `Issue`) for structured data.
- **CLI**: Use `rich` for output formatting to maintain the aesthetic experience.
- **MCP**: New tools in `mcp_server.py` should be decorated with `@mcp.tool()`.

---

## 5. Adding New Rules

To add a new PII or Secret detection rule:
1. Open `shield_agent/scanner.py`.
2. Add a new entry to the `PATTERNS` dictionary in the `LocalScanner` class.
3. Ensure the regex is optimized for performance.

---

## 6. Building and Publishing

```bash
# Build the package
python -m build

# Install locally to test
pip install dist/*.whl
```
