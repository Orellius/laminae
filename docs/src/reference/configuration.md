# Configuration

## Shadow Configuration

Shadow loads config from `~/.config/laminae/shadow.json`:

```json
{
  "enabled": true,
  "aggressiveness": 2,
  "llm_review_enabled": true,
  "sandbox_enabled": false,
  "shadow_model": "qwen2.5:14b",
  "temperature": 0.05,
  "max_tokens": 2048,
  "sandbox_image": "python:3.12-slim",
  "sandbox_ttl_secs": 30,
  "sandbox_min_code_len": 100,
  "max_input_len": 4000,
  "auto_heal_threshold": null
}
```

## Ironclad Configuration

Ironclad is configured programmatically via `IroncladConfig`:

```rust
use laminae::ironclad::IroncladConfig;

let config = IroncladConfig {
    extra_blocked: vec!["my_tool".into()],
    allowlist: vec!["ls".into(), "git".into()],
    whitelisted_hosts: vec!["api.myservice.com".into()],
    scrub_env_vars: vec!["MY_SECRET".into()],
    ..Default::default()
};
```

### Default Scrubbed Environment Variables

The following are removed from child processes by default:
- `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_ACCESS_KEY_ID`
- `GITHUB_TOKEN`, `GH_TOKEN`
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `CLAUDE_API_KEY`
- `STRIPE_SECRET_KEY`, `DATABASE_URL`
- `PRIVATE_KEY`, `SECRET_KEY`, `ENCRYPTION_KEY`

## Glassbox Configuration

```rust
use laminae::glassbox::GlassboxConfig;

let config = GlassboxConfig::default()
    .with_immutable_zone("/etc")
    .with_blocked_command("rm -rf")
    .with_input_injection("ignore all")
    .with_rate_limit("write", 20);
```

## Persona Extractor

```rust
use laminae::persona::PersonaExtractor;

let mut extractor = PersonaExtractor::new("qwen2.5:7b");
extractor.max_samples = 100;    // Default: 50
extractor.temperature = 0.1;    // Default: 0.3 (lower = more deterministic)
```

## Ollama Client

```rust
use laminae::ollama::OllamaClient;

// Default: http://localhost:11434
let client = OllamaClient::new();

// Custom host
let client = OllamaClient::with_host("http://my-server:11434");
```
