# Configuration Guide 🛠️

ShieldAgent-MCP is designed to be flexible and secure. This guide covers how to set up your environment for both Local and Cloud scanning.

## 1. Environment Variables

The easiest way to configure ShieldAgent-MCP is via a `.env` file in your project root or by exporting variables in your terminal.

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `GEMINI_API_KEY` | Your Google AI Studio API Key | Yes (for `audit`) | None |
| `OLLAMA_HOST` | URL for your local Ollama instance | No (for `scan --ollama`) | `http://localhost:11434` |
| `OLLAMA_MODEL` | Name of the Ollama model to use for verification | No (for `scan --ollama`) | `gemma2` |

### Setting up the Gemini API Key
1. Go to [Google AI Studio](https://aistudio.google.com/).
2. Generate a new API Key for **Gemini 2.0 Flash**.
3. Add it to your `.env` file:
   ```env
   GEMINI_API_KEY=your_key_here
   ```

---

## 2. Local AI Verification (Ollama)

To reduce false positives during local scans (checking if a string that *looks* like a key is actually a key), ShieldAgent-MCP can use a local Ollama instance.

### Prerequisites
1. [Install Ollama](https://ollama.com/).
2. Pull the **Gemma 2** model:
   ```bash
   ollama pull gemma2
   ```

### Usage
Run the scan with the `--ollama` flag:
```bash
shield-agent scan --dir . --ollama
```

---

## 3. MCP Integration

To use ShieldAgent-MCP with AI assistants like Claude Desktop:

### Claude Desktop Setup
Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "shield-agent": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/shield-agent-mcp",
        "run",
        "shield-agent",
        "run-mcp"
      ],
      "env": {
        "GEMINI_API_KEY": "your_key_here"
      }
    }
  }
}
```

---

## 4. Troubleshooting

- **Gemini Errors**: Ensure your API key has "Gemini 2.0 Flash" access. Paid and free tier keys both work, but free tier is subject to rate limits.
- **Ollama Connection**: If Ollama is running on a different port or machine, ensure `OLLAMA_HOST` is set correctly.
- **Python Version**: MCP features require **Python 3.10+**.
