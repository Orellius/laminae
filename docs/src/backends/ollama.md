# Ollama (Local LLM)

The `laminae-ollama` crate is a standalone HTTP client for Ollama. It's used internally by Psyche, Persona, Cortex, and Shadow for local LLM calls, but you can also use it directly.

## Setup

```bash
# Install Ollama
brew install ollama    # macOS
# or: curl -fsSL https://ollama.com/install.sh | sh  # Linux

# Start the server
ollama serve

# Pull a model
ollama pull qwen2.5:7b
```

## Usage

```rust
use laminae::ollama::OllamaClient;

let client = OllamaClient::new(); // defaults to localhost:11434

let response = client.complete(
    "qwen2.5:7b",
    "You are a helpful assistant.",
    "What is Rust?",
    0.3,    // temperature
    1024,   // max tokens
).await?;

println!("{response}");
```

## Custom Host

```rust
let client = OllamaClient::with_host("http://my-ollama-server:11434");
```

## Recommended Models

| Use Case | Model | Size |
|----------|-------|------|
| Psyche Id/Superego | `qwen2.5:7b` | 4.7 GB |
| Shadow LLM Review | `qwen2.5:14b` | 9.0 GB |
| Persona Extraction | `qwen2.5:7b` | 4.7 GB |
| Cortex Analysis | `qwen2.5:7b` | 4.7 GB |
