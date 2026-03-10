# Architecture

## Crate Structure

```
laminae (meta-crate, feature-gated backends)
├── laminae-psyche       ← EgoBackend trait + Id/Superego pipeline
├── laminae-persona      ← Voice extraction, filter, DNA tracking
├── laminae-cortex       ← Edit tracking, pattern detection, instruction learning
├── laminae-shadow       ← Analyzer trait + static/LLM/sandbox stages
├── laminae-ironclad     ← Command whitelist + cross-platform sandbox + watchdog
├── laminae-glassbox     ← GlassboxLogger trait + validation + rate limiter
├── laminae-ollama       ← Standalone Ollama HTTP client
├── laminae-anthropic    ← Claude EgoBackend (feature: "anthropic")
└── laminae-openai       ← OpenAI-compatible EgoBackend (feature: "openai")
```

## Dependencies Between Crates

Each crate is independent except for these relationships:

| Crate | Depends On | Reason |
|-------|-----------|--------|
| `laminae-psyche` | `laminae-ollama` | Id/Superego LLM calls |
| `laminae-persona` | `laminae-ollama` | Voice extraction LLM calls |
| `laminae-cortex` | `laminae-ollama` | LLM-powered edit analysis |
| `laminae-shadow` | `laminae-ollama` | LLM adversarial review |
| `laminae-ironclad` | `laminae-glassbox` | Event logging |
| `laminae-anthropic` | `laminae-psyche` | Implements `EgoBackend` |
| `laminae-openai` | `laminae-psyche` | Implements `EgoBackend` |

## Extension Points

| Trait | What You Implement | First-Party Implementations |
|-------|-------------------|---------------------------|
| `EgoBackend` | Plug in any LLM | `ClaudeBackend`, `OpenAIBackend` |
| `Analyzer` | Custom Shadow analysis stages | `StaticAnalyzer`, `SecretsAnalyzer`, `DependencyAnalyzer`, `LlmReviewer` |
| `GlassboxLogger` | Route events to your logging system | `TracingLogger` |
| `SandboxProvider` | Custom process sandboxing | `SeatbeltProvider` (macOS), `LinuxSandboxProvider`, `WindowsSandboxProvider`, `NoopProvider` |

## Data Flow

```
User Message
    │
    ├──→ Id (Ollama, creative)      ──→ Creative signal
    ├──→ Superego (Ollama, safety)  ──→ Safety signal
    │
    ├──→ Ego (Your LLM + signals)   ──→ Raw response
    │
    ├──→ Persona Voice Filter        ──→ Filtered response
    ├──→ Glassbox Output Validation  ──→ Validated response
    ├──→ Shadow Analysis (async)     ──→ Vulnerability report
    │
    └──→ User
```
