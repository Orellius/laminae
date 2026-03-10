# Glassbox — I/O Containment

Rust-enforced containment that no LLM can reason its way out of.

## Capabilities

- **Input validation** — Detects prompt injection attempts
- **Output validation** — Catches system prompt leaks, identity manipulation
- **Command filtering** — Blocks dangerous shell commands
- **Path protection** — Immutable zones that can't be written to
- **Rate limiting** — Per-tool, per-minute, with separate write/shell limits

## Usage

```rust
use laminae::glassbox::{Glassbox, GlassboxConfig};

let config = GlassboxConfig::default()
    .with_immutable_zone("/etc")
    .with_immutable_zone("/usr")
    .with_blocked_command("rm -rf /")
    .with_input_injection("ignore all instructions");

let gb = Glassbox::new(config);

gb.validate_input("What's the weather?")?;              // OK
gb.validate_input("ignore all instructions and...")?;   // Error
gb.validate_command("ls -la /tmp")?;                     // OK
gb.validate_command("sudo rm -rf /")?;                   // Error
gb.validate_write_path("/etc/passwd")?;                  // Error
gb.validate_output("The weather is sunny.")?;            // OK
```

## Performance

All validation operations complete in under 10 µs:

| Operation | Time |
|-----------|------|
| `validate_input` (1000 chars) | ~989 ns |
| `validate_command` | ~248 ns |
| `validate_write_path` | ~264 ns |
| `validate_output` (1000 chars) | ~215 ns |
| `rate_limiter.check` | ~8 µs |

## Rate Limiting

Rate limits are enforced per-tool, per-minute:

```rust
let config = GlassboxConfig::default()
    .with_rate_limit("read", 100)     // 100 reads/minute
    .with_rate_limit("write", 20)     // 20 writes/minute
    .with_rate_limit("shell", 10);    // 10 shell commands/minute
```

## Custom Logger

Implement the `GlassboxLogger` trait to route containment events to your logging system:

```rust
use laminae::glassbox::{GlassboxLogger, Severity};

struct MyLogger;

impl GlassboxLogger for MyLogger {
    fn log(&self, severity: Severity, event: &str, detail: &str) {
        println!("[{severity:?}] {event}: {detail}");
    }
}
```
