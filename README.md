# ShieldAgent-MCP 🛡️🤖
### *The Hybrid-AI Security & Quality Sentinel for the MCP Era*

![ShieldAgent-MCP Logo](docs/logo.png)

**ShieldAgent-MCP** is a cutting-edge, production-ready security tool designed for modern developer workflows. It leverages the power of **Hybrid AI**—combining the deep reasoning of **Google Gemini Pro** with the lightning-fast, privacy-safe execution of **Local Gemma models (via Ollama)**.

As an **MCP (Model Context Protocol)** server, ShieldAgent-MCP integrates seamlessly with AI coding assistants like Claude, Cursor, and ChatGPT, giving them the "Superpowers" needed to protect your codebase from the inside out.

---

## 🔥 Why ShieldAgent-MCP?

In 2026, security is no longer just about static analysis; it's about **context**. ShieldAgent-MCP provides:

- **Local Sentinel (Zero-Cloud)**: High-speed PII and secret scanning that never leaves your machine.
- **Cloud Auditor (Deep Intelligence)**: Advanced architectural reviews and logic flaw detection powered by Gemini.
- **MCP Integration**: A standardized way for your AI agents to "ask" for security audits.
- **Git Gating**: Automated pre-push hooks to ensure no secret ever hits the wire.

---

## 🚀 Key Features

### 1. Dual-Layer Scanning
- **Privacy Layer**: Uses local RegEx + Ollama/Gemma to detect sensitive data (API keys, PII, Credentials).
- **Intelligence Layer**: Uses Gemini 1.5 Pro to identify complex vulnerabilities like "Broken Access Control" or "Insecure Architecture" patterns.

### 2. Model Context Protocol (MCP) Ready
Exposes high-level security tools to your AI agent ecosystem:
- `audit_codebase`: Performs a full structural review.
- `scan_for_secrets`: Checks for potential leaks in the current diff.

### 3. Beautiful Terminal Experience
Powered by `rich`, providing clear, actionable, and aesthetic security reports directly in your CLI.

---

## 🛠️ Tech Stack

- **Core**: Python 3.10+
- **Cloud AI**: Google Gemini API
- **Local AI**: Ollama (Gemma 2)
- **Protocol**: MCP (Python SDK)
- **Interface**: Click + Rich

---

## 🏗️ Installation (Coming Soon)

```bash
# Clone the repo
git clone https://github.com/gbvk/shield-agent-mcp.git
cd shield-agent-mcp

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Install Git hooks
shield-agent install-hooks
```

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*Built with ❤️ for the AI-Native Developer.*
