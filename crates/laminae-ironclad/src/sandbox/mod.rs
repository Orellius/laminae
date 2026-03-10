//! Platform-abstracted process sandboxing.
//!
//! Provides a [`SandboxProvider`] trait that each platform implements to enforce
//! filesystem, network, and resource constraints on child processes. Use
//! [`default_provider`] to obtain the best available provider for the current OS.

use std::process::Stdio;

use anyhow::Result;
use tokio::process::Command;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod noop;
#[cfg(target_os = "windows")]
mod windows;

pub use noop::NoopProvider;

#[cfg(target_os = "macos")]
pub use macos::SeatbeltProvider;

#[cfg(target_os = "linux")]
pub use linux::LinuxSandboxProvider;

#[cfg(target_os = "windows")]
pub use windows::WindowsSandboxProvider;

/// Describes the network access policy for a sandboxed process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// No network access whatsoever.
    None,
    /// Only localhost / loopback connections are allowed.
    LocalhostOnly,
    /// Outbound connections are restricted to whitelisted hosts and localhost.
    Restricted,
}

/// A platform-agnostic sandbox profile describing the constraints to apply.
#[derive(Debug, Clone)]
pub struct SandboxProfile {
    /// The project directory -- the sandboxed process may write here.
    pub project_dir: String,
    /// Additional paths the process is allowed to write to.
    pub writable_paths: Vec<String>,
    /// Hosts the process is allowed to connect to (in addition to localhost).
    pub whitelisted_hosts: Vec<String>,
    /// Network access policy.
    pub network_policy: NetworkPolicy,
    /// Environment variables to remove before spawning the child.
    pub scrub_env_vars: Vec<String>,
}

impl SandboxProfile {
    /// Build a profile from an [`IroncladConfig`](crate::IroncladConfig) and project directory.
    pub fn from_config(project_dir: &str, config: &crate::IroncladConfig) -> Self {
        Self {
            project_dir: project_dir.to_string(),
            writable_paths: vec![
                "/tmp".to_string(),
                "/private/tmp".to_string(),
                "/var/folders".to_string(),
            ],
            whitelisted_hosts: config.whitelisted_hosts.clone(),
            network_policy: NetworkPolicy::Restricted,
            scrub_env_vars: config.scrub_env_vars.clone(),
        }
    }
}

/// A platform-specific sandbox implementation.
///
/// Each provider wraps a [`Command`] with OS-level isolation primitives.
/// The provider is responsible for configuring filesystem, network, and
/// resource constraints before the child process is exec'd.
pub trait SandboxProvider: Send + Sync {
    /// Wrap `binary` and `args` in a sandboxed [`Command`] according to `profile`.
    fn sandboxed_command(
        &self,
        binary: &str,
        args: &[&str],
        profile: &SandboxProfile,
    ) -> Result<Command>;

    /// Whether this provider's underlying sandbox mechanism is available on the
    /// current system. Returns `false` if prerequisites are missing (e.g. kernel
    /// features, binaries).
    fn is_available(&self) -> bool;

    /// Human-readable name of this provider (e.g. `"seatbelt"`, `"linux-ns"`).
    fn name(&self) -> &'static str;
}

/// Return the best available [`SandboxProvider`] for the current platform.
///
/// * **macOS** -- [`SeatbeltProvider`] (`sandbox-exec` / Seatbelt).
/// * **Linux** -- [`LinuxSandboxProvider`] (namespaces, seccomp, rlimits).
/// * **Other** -- [`NoopProvider`] (env scrubbing only, no OS-level sandbox).
pub fn default_provider() -> Box<dyn SandboxProvider> {
    #[cfg(target_os = "macos")]
    {
        Box::new(SeatbeltProvider)
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxSandboxProvider)
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsSandboxProvider)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Box::new(NoopProvider)
    }
}

/// Apply common post-setup to a command: pipe stdio and scrub env vars.
fn apply_common(cmd: &mut Command, profile: &SandboxProfile) {
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    for var in &profile.scrub_env_vars {
        cmd.env_remove(var);
    }
}
