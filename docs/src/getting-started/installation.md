# Installation

## Full Stack

Add Laminae to your `Cargo.toml`:

```toml
[dependencies]
laminae = "0.3"
tokio = { version = "1", features = ["full"] }
```

## With LLM Backends

```toml
# Claude (Anthropic)
laminae = { version = "0.3", features = ["anthropic"] }

# OpenAI / Groq / Together / DeepSeek / local
laminae = { version = "0.3", features = ["openai"] }

# All backends
laminae = { version = "0.3", features = ["all-backends"] }
```

## Individual Layers

Pick only what you need:

```toml
[dependencies]
laminae-psyche = "0.3"       # Cognitive pipeline
laminae-persona = "0.3"      # Voice extraction & enforcement
laminae-cortex = "0.3"       # Learning loop
laminae-shadow = "0.3"       # Red-teaming
laminae-glassbox = "0.3"     # I/O containment
laminae-ironclad = "0.3"     # Process sandbox
laminae-ollama = "0.3"       # Ollama client
laminae-anthropic = "0.3"    # Claude EgoBackend
laminae-openai = "0.3"       # OpenAI-compatible EgoBackend
```

## Requirements

- **Rust 1.70+**
- **Ollama** (for Psyche, Persona, Cortex, and Shadow LLM features)
  ```bash
  # macOS
  brew install ollama && ollama serve

  # Linux
  curl -fsSL https://ollama.com/install.sh | sh && ollama serve
  ```
- **macOS, Linux, or Windows** (for Ironclad's process sandbox)
  - macOS: Full Seatbelt sandbox
  - Linux: Kernel namespaces + rlimits
  - Windows: Job Object resource limits + env scrubbing
