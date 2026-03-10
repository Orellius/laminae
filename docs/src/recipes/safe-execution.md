# Recipe: Safe Code Execution

Combine Glassbox (I/O containment) and Ironclad (process sandbox) for safe AI-driven code execution.

## The Problem

AI agents that can execute code need guardrails:
- What commands can they run?
- What files can they access?
- How much CPU/memory can they consume?
- Can they phone home?

## The Solution

```rust
use laminae::glassbox::{Glassbox, GlassboxConfig};
use laminae::ironclad::{
    validate_binary, validate_command_deep,
    sandboxed_command, spawn_watchdog, WatchdogConfig,
};

// Step 1: Configure containment
let gb = Glassbox::new(
    GlassboxConfig::default()
        .with_immutable_zone("/etc")
        .with_immutable_zone("/usr")
        .with_immutable_zone(&home_dir)
        .with_blocked_command("rm -rf")
        .with_blocked_command("sudo"),
);

// Step 2: Validate the command BEFORE execution
let command = "git status";
gb.validate_command(command)?;
validate_command_deep(command)?;

// Step 3: Run inside platform-native sandbox
let mut cmd = sandboxed_command("git", &["status"], "/path/to/project")?;
let child = cmd.spawn()?;

// Step 4: Monitor resource usage
let cancel = spawn_watchdog(
    child.id().unwrap(),
    WatchdogConfig {
        cpu_threshold: 80.0,
        memory_threshold_mb: 2048,
        max_wall_time: Duration::from_secs(300),
        ..Default::default()
    },
    "code-executor".into(),
);

// Step 5: Wait and clean up
let output = child.wait_with_output().await?;
cancel.store(true, Ordering::Relaxed);

// Step 6: Validate output
gb.validate_output(&String::from_utf8_lossy(&output.stdout))?;
```

## What Each Layer Does

| Layer | Protects Against |
|-------|-----------------|
| Glassbox `validate_command` | Dangerous shell patterns (`rm -rf`, `sudo`) |
| Ironclad `validate_command_deep` | Piped attacks, reverse shells, crypto mining |
| Ironclad `sandboxed_command` | Network access, filesystem escape, privilege escalation |
| Ironclad `spawn_watchdog` | CPU/memory abuse, infinite loops |
| Glassbox `validate_output` | System prompt leaks in output |
