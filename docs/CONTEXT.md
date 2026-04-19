# ShieldAgent-MCP Architecture Context

## Overview
ShieldAgent-MCP is a hybrid security and code quality sentinel. It combines fast local regex-based scanning for sensitive data (secrets, PII) and leverages advanced LLMs (specifically Google Gemini 1.5/2.0) for in-depth architectural and vulnerability auditing. The tool exposes its capabilities natively via the Model Context Protocol (MCP) using `FastMCP`.

## Project Structure
- `shield_agent/cli.py`: The entry point for the CLI using `click` and `rich`. Exposes commands for `scan`, `audit`, `run-mcp`, and `install-hooks`.
- `shield_agent/scanner.py`: Local scanning utility (`LocalScanner`). Evaluates files against high-speed regex routines, ignoring `.gitignore` files and a predefined static list (like `node_modules`, `__pycache__`). Has optional `Ollama` support to reduce false positives using a local LLM.
- `shield_agent/auditor.py`: Cloud-based LLM analysis (`CloudAuditor`) relying on the new `google.genai` library and `gemini-2.0-flash` models.
- `shield_agent/mcp_server.py`: Defines the `FastMCP` server, bridging `scan_for_secrets` and `audit_file` to any MCP-compatible clients (e.g., Cursor, Claude Desktop).
- `shield_agent/config.py`: Environment variable loading (loading `GEMINI_API_KEY`).

## Tool Dependencies
- **CLI & UX:** `click`, `rich`
- **MCP Server:** `mcp` (using `FastMCP`)
- **LLM Integrations:** `google-genai` (Cloud Analysis), `requests` (Local Ollama Verification)
- **Scanning Logic:** Built-in regex, `pathspec` (for `.gitignore` matching)

## Key Concepts
- **Heuristic False Positive Checking**: Local secrets scanner uses basic character repetition counts and placeholder strings (e.g., `YOUR_API_KEY`) to reduce noise.
- **Git Hook Integration**: Can bind to `pre-push` to restrict leaks from escaping local environments.

## Future Improvement Considerations
- Extending the Cloud Auditor to utilize `google.genai` System Instructions for stricter compliance output.
- Migrating `Ollama` fallback parsing to structured JSON outputs if precision of local modeling increases.
- Providing finer telemetry or JUnit-style output formats for CI environments.
