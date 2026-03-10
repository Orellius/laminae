# Shadow — Adversarial Red-Teaming

Automated security auditor that red-teams every AI response. Runs as an async post-processing pipeline — never blocks the conversation.

## Three Stages

### Stage 1: Static Analysis
Regex pattern scanning for 25+ vulnerability categories:
- SQL injection (string concatenation, format strings)
- Command injection (eval, exec, subprocess)
- Hardcoded secrets (API keys, passwords, private keys, connection strings)
- XSS (innerHTML, dangerouslySetInnerHTML)
- Path traversal (../ in file operations)
- Insecure deserialization (pickle, yaml.load)
- Weak cryptography (MD5, SHA-1)
- Resource abuse (infinite loops)
- Supply chain attacks (pipe-to-shell, insecure package indices)

### Stage 2: LLM Adversarial Review
A local Ollama model with an attacker-mindset prompt reviews the output. Catches logic flaws and attack vectors that regex can't find.

### Stage 3: Sandbox Execution
Runs code blocks in ephemeral Docker/Podman containers with strict security constraints:
- `--network=none` — no network access
- `--memory=128m` — memory limit
- `--cpus=0.5` — CPU limit
- `--read-only` root filesystem
- `--cap-drop=ALL` — drop all Linux capabilities
- TTL timeout — force-kills after configured seconds

Analyzes output for network access attempts, filesystem violations, privilege escalation, and crash signals.

## Usage

```rust
use laminae::shadow::{ShadowEngine, ShadowEvent, create_report_store};

let store = create_report_store();
let engine = ShadowEngine::new(store.clone());

let mut rx = engine.analyze_async(
    "session-1".into(),
    "Here's some code:\n```python\neval(user_input)\n```".into(),
);

while let Some(event) = rx.recv().await {
    match event {
        ShadowEvent::Finding { finding, .. } => {
            eprintln!("[{}] {}: {}", finding.severity, finding.category, finding.title);
        }
        ShadowEvent::Done { report, .. } => {
            println!("Clean: {} | Issues: {}", report.clean, report.findings.len());
        }
        _ => {}
    }
}
```

## Configuration

Shadow is configured via `ShadowConfig` (JSON file at `~/.config/laminae/shadow.json`):

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Master enable/disable |
| `aggressiveness` | `2` | 1=static, 2=static+LLM, 3=all stages |
| `llm_review_enabled` | `true` | Enable LLM adversarial reviewer |
| `sandbox_enabled` | `false` | Enable container sandbox (requires Docker/Podman) |
| `shadow_model` | `qwen2.5:14b` | Ollama model for LLM review |
| `sandbox_image` | `python:3.12-slim` | Docker image for sandbox |
| `sandbox_ttl_secs` | `30` | Max execution time per block |

## Custom Analyzers

Implement the `Analyzer` trait to add custom analysis stages:

```rust
use laminae::shadow::analyzer::{Analyzer, AnalyzerError};

struct MyAnalyzer;

impl Analyzer for MyAnalyzer {
    fn name(&self) -> &'static str { "my-analyzer" }
    async fn is_available(&self) -> bool { true }
    async fn analyze(&self, output: &str, blocks: &[ExtractedBlock])
        -> Result<Vec<VulnFinding>, AnalyzerError>
    {
        // Your analysis logic
        Ok(vec![])
    }
}
```
