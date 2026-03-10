//! No-op sandbox provider for unsupported platforms.
//!
//! Scrubs environment variables and pipes stdio but does not apply any
//! OS-level isolation. A warning is logged on first use.

use anyhow::Result;
use tokio::process::Command;

use super::{apply_common, SandboxProfile, SandboxProvider};

/// Fallback provider that applies no OS-level sandbox.
///
/// Used on platforms where neither Seatbelt nor Linux namespaces are
/// available. The provider still scrubs sensitive environment variables
/// and configures piped stdio, but **does not restrict** filesystem,
/// network, or resource access at the kernel level.
///
/// A warning is emitted via `tracing` whenever a command is created
/// through this provider.
pub struct NoopProvider;

impl SandboxProvider for NoopProvider {
    fn sandboxed_command(
        &self,
        binary: &str,
        args: &[&str],
        profile: &SandboxProfile,
    ) -> Result<Command> {
        tracing::warn!(
            "[IRONCLAD] NoopProvider in use -- no OS-level sandbox applied. \
             Binary '{binary}' will run with env scrubbing only."
        );

        let mut cmd = Command::new(binary);
        for arg in args {
            cmd.arg(arg);
        }

        apply_common(&mut cmd, profile);
        Ok(cmd)
    }

    fn is_available(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}
