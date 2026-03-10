//! macOS Seatbelt (`sandbox-exec`) provider.

use anyhow::Result;
use tokio::process::Command;

use super::{apply_common, SandboxProfile, SandboxProvider};

/// Sandbox provider that uses the macOS `sandbox-exec` (Seatbelt) subsystem.
///
/// Generates a Seatbelt profile string that restricts filesystem writes to the
/// project directory and temp paths, limits network egress to localhost and
/// whitelisted hosts, and blocks all inbound connections.
pub struct SeatbeltProvider;

impl SandboxProvider for SeatbeltProvider {
    fn sandboxed_command(
        &self,
        binary: &str,
        args: &[&str],
        profile: &SandboxProfile,
    ) -> Result<Command> {
        let seatbelt = generate_seatbelt_profile(profile);

        let mut cmd = Command::new("sandbox-exec");
        cmd.arg("-p").arg(&seatbelt).arg(binary);
        for arg in args {
            cmd.arg(arg);
        }

        apply_common(&mut cmd, profile);
        Ok(cmd)
    }

    fn is_available(&self) -> bool {
        std::path::Path::new("/usr/bin/sandbox-exec").exists()
    }

    fn name(&self) -> &'static str {
        "seatbelt"
    }
}

/// Generate a macOS Seatbelt profile from a [`SandboxProfile`].
fn generate_seatbelt_profile(profile: &SandboxProfile) -> String {
    let project_dir = &profile.project_dir;

    // Build host-specific network rules from the whitelist.
    // If no hosts are whitelisted, no outbound HTTPS is allowed.
    let host_rules = build_host_network_rules(&profile.whitelisted_hosts);

    // Only allow DNS to system resolvers (port 53 on loopback and common
    // system resolver addresses), not to arbitrary remote hosts.
    let dns_rules = r#";; Allow DNS resolution via system resolvers only
(allow network-outbound (remote ip "127.0.0.1:53"))
(allow network-outbound (remote ip "::1:53"))
(allow network-outbound
    (remote unix-socket (subpath "/var/run"))
)"#;

    format!(
        r#"(version 1)

;; Default: deny everything
(deny default)

;; Allow basic process operations
(allow process-exec)
(allow process-fork)
(allow signal)
(allow sysctl-read)

;; Allow file reads globally (needed for binary execution, libs, etc.)
(allow file-read*)

;; Allow file writes ONLY in project directory and temp
(allow file-write*
    (subpath "{project_dir}")
    (subpath "/tmp")
    (subpath "/private/tmp")
    (subpath "/var/folders")
)

;; Allow home dir dotfiles for tool configs
(allow file-write*
    (subpath (string-append (param "HOME") "/.config"))
    (subpath (string-append (param "HOME") "/.local"))
    (subpath (string-append (param "HOME") "/.cache"))
)

;; NETWORK: Allow ONLY outbound to localhost and unix sockets
(allow network-outbound
    (remote ip "localhost:*")
    (remote unix-socket)
)

{dns_rules}

;; Allow outbound HTTPS only to explicitly whitelisted hosts
{host_rules}

;; BLOCK all inbound network connections (no reverse shells)
(deny network-inbound)

;; Allow IPC (needed for stdio communication)
(allow ipc-posix-shm-read*)
(allow ipc-posix-shm-write*)
(allow mach-lookup)

;; Allow reading system info
(allow system-info)
"#
    )
}

/// Build Seatbelt network-outbound rules for each whitelisted host.
///
/// Seatbelt cannot filter by hostname directly, so we use `remote ip` with
/// the hostname string. The kernel resolves it at profile load time. For
/// IP-literal hosts (localhost, 127.0.0.1) we allow all ports; for named
/// hosts we restrict to port 443 only.
fn build_host_network_rules(hosts: &[String]) -> String {
    let mut rules = String::new();
    for host in hosts {
        // Skip localhost variants since they are already covered above.
        if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            continue;
        }
        // Named hosts get HTTPS (port 443) only.
        rules.push_str(&format!(
            "(allow network-outbound (remote ip \"{host}:443\"))\n"
        ));
    }
    if rules.is_empty() {
        ";; No additional hosts whitelisted for outbound HTTPS".to_string()
    } else {
        rules
    }
}
