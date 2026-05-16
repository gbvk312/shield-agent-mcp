# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-10

### Added

- Initial release of ShieldAgent-MCP.
- Local sentinel scanner with regex-based detection for API keys, PII, secrets, and tokens.
- Cloud auditor powered by Google Gemini 2.0 Flash for deep architectural reviews.
- MCP server with 6 tools: `scan_for_secrets`, `audit_file`, `list_directory`, `read_file`, `safe_write_file`, `check_network_exposure`.
- CLI interface powered by `rich` and `click`.
- Git pre-push hook installation via `shield-agent install-hooks`.
- CI pipeline with lint, type-check, test, and security scan workflows.
- Comprehensive test suite with `pytest` and `pytest-asyncio`.
- Documentation: CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md.
