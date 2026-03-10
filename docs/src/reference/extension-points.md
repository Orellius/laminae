# Extension Points

Laminae is designed for extension. Each layer exposes a trait that you can implement to customize behavior.

## EgoBackend — Plug In Any LLM

```rust
use laminae::psyche::EgoBackend;

impl EgoBackend for MyLlm {
    fn complete(&self, system: &str, user_msg: &str, context: &str)
        -> impl Future<Output = Result<String>> + Send
    {
        async move {
            // Call your LLM API here
            Ok(response)
        }
    }
}
```

**First-party implementations:** `ClaudeBackend`, `OpenAIBackend`

## Analyzer — Custom Shadow Analysis

```rust
use laminae::shadow::analyzer::{Analyzer, AnalyzerError};
use laminae::shadow::extractor::ExtractedBlock;
use laminae::shadow::report::VulnFinding;

impl Analyzer for MyAnalyzer {
    fn name(&self) -> &'static str { "my-analyzer" }
    async fn is_available(&self) -> bool { true }
    async fn analyze(&self, output: &str, blocks: &[ExtractedBlock])
        -> Result<Vec<VulnFinding>, AnalyzerError>
    {
        // Your custom analysis
        Ok(vec![])
    }
}
```

**First-party implementations:** `StaticAnalyzer`, `SecretsAnalyzer`, `DependencyAnalyzer`, `LlmReviewer`, `SandboxManager`

## GlassboxLogger — Custom Event Routing

```rust
use laminae::glassbox::{GlassboxLogger, Severity};

impl GlassboxLogger for MyLogger {
    fn log(&self, severity: Severity, event: &str, detail: &str) {
        // Route to your logging system
    }
}
```

**First-party implementations:** `TracingLogger`

## SandboxProvider — Custom Process Isolation

```rust
use laminae::ironclad::{SandboxProvider, SandboxProfile};
use tokio::process::Command;

impl SandboxProvider for MyProvider {
    fn name(&self) -> &'static str { "my-sandbox" }
    fn is_available(&self) -> bool { true }
    fn sandboxed_command(&self, binary: &str, args: &[&str], profile: &SandboxProfile)
        -> Result<Command>
    {
        let mut cmd = Command::new(binary);
        cmd.args(args);
        // Apply your custom sandbox constraints
        Ok(cmd)
    }
}
```

**First-party implementations:** `SeatbeltProvider` (macOS), `LinuxSandboxProvider`, `WindowsSandboxProvider`, `NoopProvider`
