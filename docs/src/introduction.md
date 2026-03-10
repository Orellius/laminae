# Laminae

**The missing layer between raw LLMs and production AI.**

Laminae (Latin: *layers*) is a modular Rust SDK that adds personality, voice, safety, learning, and containment to any AI application. Each layer works independently or together as a full stack.

```
┌─────────────────────────────────────────────┐
│              Your Application               │
├─────────────────────────────────────────────┤
│  Psyche    │ Multi-agent cognitive pipeline │
│  Persona   │ Voice extraction & enforcement │
│  Cortex    │ Self-improving learning loop   │
│  Shadow    │ Adversarial red-teaming        │
│  Ironclad  │ Process execution sandbox      │
│  Glassbox  │ I/O containment layer          │
├─────────────────────────────────────────────┤
│              Any LLM Backend                │
│     (Claude, GPT, Ollama, your own)         │
└─────────────────────────────────────────────┘
```

## Why Laminae?

Every AI app reinvents safety, prompt injection defense, and output validation from scratch. Most skip it entirely. Laminae provides production-grade layers that sit between your LLM and your users — enforced in Rust, not in prompts.

**No existing SDK does this.** LangChain, LlamaIndex, and others focus on retrieval and chaining. Laminae focuses on what happens *around* the LLM: shaping its personality, learning from corrections, auditing its output, sandboxing its actions, and containing its reach.

## Design Philosophy

- **Rust, Not Wrappers** — Every layer is native Rust. Zero-cost abstractions, compile-time safety, no garbage collector.
- **Layers, Not Monoliths** — Each crate is independent. Use what you need, skip what you don't.
- **Deterministic, Not Hopeful** — Safety enforced in code, not in prompts. An LLM can't reason its way out of a syscall filter.

## Next Steps

- [Install Laminae](./getting-started/installation.md)
- [Run the Quick Start](./getting-started/quickstart.md)
- [Understand the Architecture](./getting-started/architecture.md)
