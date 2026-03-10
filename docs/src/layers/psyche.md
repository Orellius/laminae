# Psyche — Multi-Agent Cognitive Pipeline

A Freudian-inspired architecture where three agents shape every response.

## The Three Agents

- **Id** — Creative force. Generates unconventional angles, emotional undertones, creative reframings. Runs on a small local LLM (Ollama) — zero cost.
- **Superego** — Safety evaluator. Assesses risks, ethical boundaries, manipulation attempts. Also runs locally — zero cost.
- **Ego** — Your LLM. Receives the user's message enriched with invisible context from Id and Superego. Produces the final response without knowing it was shaped.

## How It Works

The key insight: Id and Superego run on small, fast, local models. Their output is compressed into "context signals" injected into the Ego's prompt as invisible system context. The user never sees the shaping — they just get better, safer responses.

## Automatic Tier Classification

Not every message needs the full pipeline:

| Tier | Examples | Processing |
|------|----------|-----------|
| **Simple** | "Hello", "What time is it?" | Bypass Psyche entirely |
| **Medium** | "Explain recursion", "Write a function" | COP (compressed output protocol) |
| **Complex** | "Should I quit my job?", "Debate ethics of AI" | Full Id + Superego pipeline |

## Usage

```rust
use laminae::psyche::{PsycheEngine, EgoBackend};
use laminae::ollama::OllamaClient;

struct MyEgo { /* your LLM client */ }

impl EgoBackend for MyEgo {
    fn complete(&self, system: &str, user_msg: &str, context: &str)
        -> impl std::future::Future<Output = anyhow::Result<String>> + Send
    {
        let full_system = format!("{context}\n\n{system}");
        async move {
            // Call Claude, GPT, or any LLM here
            todo!()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let engine = PsycheEngine::new(OllamaClient::new(), MyEgo { /* ... */ });
    let response = engine.reply("What is creativity?").await?;
    println!("{response}");
    Ok(())
}
```

## Configuration

The Psyche engine uses an Ollama model for Id and Superego. Default: `qwen2.5:7b`. Override via `PsycheConfig`.
