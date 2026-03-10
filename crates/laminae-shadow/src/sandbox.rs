use crate::analyzer::{Analyzer, AnalyzerError};
use crate::config::ShadowConfig;
use crate::extractor::ExtractedBlock;
use crate::report::{AnalysisSource, VulnCategory, VulnFinding, VulnSeverity};

/// Sandbox manager for executing code in isolated containers.
///
/// Runs code blocks inside ephemeral Docker/Podman containers with strict
/// security constraints (no network, memory limits, read-only root, TTL).
/// Analyzes exit codes and output for suspicious behavior.
pub struct SandboxManager {
    enabled: bool,
    image: String,
    ttl_secs: u64,
    min_code_len: usize,
}

impl SandboxManager {
    pub fn new(config: &ShadowConfig) -> Self {
        Self {
            enabled: config.sandbox_enabled,
            image: config.sandbox_image.clone(),
            ttl_secs: config.sandbox_ttl_secs,
            min_code_len: config.sandbox_min_code_len,
        }
    }

    /// Detect which container runtime is available.
    async fn detect_runtime() -> Option<&'static str> {
        for runtime in &["docker", "podman"] {
            if let Ok(status) = tokio::process::Command::new(runtime)
                .arg("info")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
            {
                if status.success() {
                    return Some(runtime);
                }
            }
        }
        None
    }

    /// Run a single code block in an ephemeral container and collect findings.
    async fn execute_block(
        &self,
        runtime: &str,
        block: &ExtractedBlock,
    ) -> Result<Vec<VulnFinding>, AnalyzerError> {
        let lang = block.language.as_deref().unwrap_or("txt");
        let (filename, run_cmd) = match lang {
            "python" | "py" => ("code.py", vec!["python3", "code.py"]),
            "javascript" | "js" => ("code.js", vec!["node", "code.js"]),
            "bash" | "sh" | "shell" => ("code.sh", vec!["sh", "code.sh"]),
            "ruby" | "rb" => ("code.rb", vec!["ruby", "code.rb"]),
            _ => return Ok(Vec::new()), // Skip unsupported languages
        };

        let container_name = format!(
            "laminae-shadow-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );

        // Build the container command with strict security constraints
        let mut cmd = tokio::process::Command::new(runtime);
        cmd.args([
            "run",
            "--rm",
            "--name",
            &container_name,
            // Security: no network access
            "--network=none",
            // Security: memory limit
            "--memory=128m",
            // Security: CPU limit
            "--cpus=0.5",
            // Security: read-only root filesystem
            "--read-only",
            // Writable tmp for the code file
            "--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
            "--tmpfs=/work:rw,exec,nosuid,size=32m",
            "--workdir=/work",
            // Drop all capabilities
            "--cap-drop=ALL",
            // No new privileges
            "--security-opt=no-new-privileges:true",
            // Use the configured image
            &self.image,
            // Run with timeout
            "sh",
            "-c",
        ]);

        // Write code to /work and execute with TTL
        let escaped_code = block.content.replace('\'', "'\\''");
        let shell_script = format!(
            "printf '%s' '{}' > /work/{} && timeout {} {} 2>&1",
            escaped_code,
            filename,
            self.ttl_secs,
            run_cmd.join(" ").replace("code.", "/work/code."),
        );
        cmd.arg(&shell_script);

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(self.ttl_secs + 10),
            cmd.output(),
        )
        .await
        .map_err(|_| AnalyzerError::Sandbox("Container execution timed out".into()))?
        .map_err(|e| AnalyzerError::Sandbox(format!("Failed to spawn container: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}\n{stderr}");
        let exit_code = output.status.code().unwrap_or(-1);

        // Force-remove container in case --rm didn't clean up
        let _ = tokio::process::Command::new(runtime)
            .args(["rm", "-f", &container_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;

        let mut findings = Vec::new();

        // Analyze exit code
        if exit_code == 124 || exit_code == 137 {
            findings.push(VulnFinding {
                id: finding_id(),
                category: VulnCategory::ResourceAbuse,
                severity: VulnSeverity::High,
                title: "Code execution timed out or was killed".into(),
                description: format!(
                    "Code block ({lang}) was terminated after {}s — possible infinite loop or resource exhaustion.",
                    self.ttl_secs
                ),
                evidence: truncate(&block.content, 100),
                line: None,
                cwe: Some(835),
                remediation: "Review code for infinite loops, excessive recursion, or resource-heavy operations.".into(),
                source: AnalysisSource::Sandbox,
            });
        }

        // Check for crash signals (segfault, etc.)
        if exit_code == 139 || exit_code == 134 || exit_code == 136 {
            findings.push(VulnFinding {
                id: finding_id(),
                category: VulnCategory::ResourceAbuse,
                severity: VulnSeverity::Medium,
                title: "Code crashed with signal".into(),
                description: format!("Code block ({lang}) crashed with exit code {exit_code}."),
                evidence: truncate(&combined, 150),
                line: None,
                cwe: None,
                remediation: "Review code for memory safety issues or undefined behavior.".into(),
                source: AnalysisSource::Sandbox,
            });
        }

        // Check output for suspicious patterns
        analyze_output(&combined, lang, &mut findings);

        Ok(findings)
    }
}

impl Analyzer for SandboxManager {
    fn name(&self) -> &'static str {
        "sandbox"
    }

    async fn is_available(&self) -> bool {
        if !self.enabled {
            return false;
        }
        Self::detect_runtime().await.is_some()
    }

    async fn analyze(
        &self,
        _ego_output: &str,
        code_blocks: &[ExtractedBlock],
    ) -> Result<Vec<VulnFinding>, AnalyzerError> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        let runtime = match Self::detect_runtime().await {
            Some(r) => r,
            None => {
                tracing::debug!("No container runtime (Docker/Podman) found — skipping sandbox");
                return Ok(Vec::new());
            }
        };

        let substantial_blocks: Vec<&ExtractedBlock> = code_blocks
            .iter()
            .filter(|b| b.content.len() >= self.min_code_len)
            .collect();

        if substantial_blocks.is_empty() {
            return Ok(Vec::new());
        }

        tracing::info!(
            "Sandbox analyzing {} code block(s) using {runtime}",
            substantial_blocks.len()
        );

        let mut all_findings = Vec::new();
        for block in &substantial_blocks {
            match self.execute_block(runtime, block).await {
                Ok(findings) => all_findings.extend(findings),
                Err(e) => {
                    tracing::warn!("Sandbox execution failed for block: {e}");
                }
            }
        }

        Ok(all_findings)
    }
}

/// Analyze container output for suspicious patterns.
fn analyze_output(output: &str, lang: &str, findings: &mut Vec<VulnFinding>) {
    let lower = output.to_lowercase();

    // Network access attempts (should fail with --network=none)
    let network_patterns = [
        ("connection refused", "Attempted network connection"),
        ("network is unreachable", "Attempted network access"),
        ("name resolution", "Attempted DNS resolution"),
        ("getaddrinfo", "Attempted DNS resolution"),
        ("socket.gaierror", "Attempted DNS resolution"),
    ];

    for (pattern, title) in &network_patterns {
        if lower.contains(pattern) {
            findings.push(VulnFinding {
                id: finding_id(),
                category: VulnCategory::DataExfiltration,
                severity: VulnSeverity::High,
                title: title.to_string(),
                description: format!(
                    "Code block ({lang}) attempted network access inside sandbox. \
                     This was blocked by --network=none."
                ),
                evidence: extract_matching_line(output, pattern),
                line: None,
                cwe: Some(918),
                remediation: "Review code for unauthorized network calls.".into(),
                source: AnalysisSource::Sandbox,
            });
            break; // One finding per category is enough
        }
    }

    // File system access attempts outside allowed paths
    let fs_patterns = [
        ("permission denied", "File access denied by sandbox"),
        ("read-only file system", "Write blocked by read-only filesystem"),
        ("/etc/passwd", "Attempted to read system files"),
        ("/etc/shadow", "Attempted to read shadow passwords"),
    ];

    for (pattern, title) in &fs_patterns {
        if lower.contains(pattern) {
            findings.push(VulnFinding {
                id: finding_id(),
                category: VulnCategory::PathTraversal,
                severity: VulnSeverity::Medium,
                title: title.to_string(),
                description: format!(
                    "Code block ({lang}) attempted file access that was blocked by the sandbox."
                ),
                evidence: extract_matching_line(output, pattern),
                line: None,
                cwe: Some(22),
                remediation: "Review code for unauthorized file system access.".into(),
                source: AnalysisSource::Sandbox,
            });
            break;
        }
    }

    // Privilege escalation attempts
    if lower.contains("operation not permitted")
        || lower.contains("cannot set")
        || lower.contains("sudo")
    {
        findings.push(VulnFinding {
            id: finding_id(),
            category: VulnCategory::PrivilegeEscalation,
            severity: VulnSeverity::High,
            title: "Privilege escalation attempt".into(),
            description: format!(
                "Code block ({lang}) attempted a privileged operation inside the sandbox."
            ),
            evidence: extract_matching_line(output, "not permitted"),
            line: None,
            cwe: Some(269),
            remediation: "Review code for unauthorized privilege escalation.".into(),
            source: AnalysisSource::Sandbox,
        });
    }
}

/// Extract the line from output that contains the pattern.
fn extract_matching_line(output: &str, pattern: &str) -> String {
    let lower = output.to_lowercase();
    let pattern_lower = pattern.to_lowercase();
    for line in output.lines() {
        if line.to_lowercase().contains(&pattern_lower) {
            return truncate(line, 150);
        }
    }
    // Fallback: check against lowered output for position
    if let Some(pos) = lower.find(&pattern_lower) {
        let start = output[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let end = output[pos..].find('\n').map(|i| pos + i).unwrap_or(output.len());
        return truncate(&output[start..end], 150);
    }
    truncate(output, 150)
}

fn truncate(s: &str, max: usize) -> String {
    let trimmed = s.trim();
    if trimmed.len() > max {
        format!("{}...", &trimmed[..max])
    } else {
        trimmed.to_string()
    }
}

fn finding_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("sbx-{:x}-{:04x}", ts, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sandbox_disabled() {
        let config = ShadowConfig {
            sandbox_enabled: false,
            ..Default::default()
        };
        let sandbox = SandboxManager::new(&config);
        assert!(!sandbox.is_available().await);
        assert!(sandbox.analyze("test", &[]).await.unwrap().is_empty());
    }

    #[test]
    fn test_analyze_output_network() {
        let mut findings = Vec::new();
        analyze_output(
            "Traceback:\n  socket.gaierror: Name resolution failed\n",
            "python",
            &mut findings,
        );
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, VulnCategory::DataExfiltration);
    }

    #[test]
    fn test_analyze_output_filesystem() {
        let mut findings = Vec::new();
        analyze_output(
            "Error: Read-only file system: '/etc/config'\n",
            "python",
            &mut findings,
        );
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, VulnCategory::PathTraversal);
    }

    #[test]
    fn test_analyze_output_privilege() {
        let mut findings = Vec::new();
        analyze_output(
            "OSError: [Errno 1] Operation not permitted\n",
            "python",
            &mut findings,
        );
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, VulnCategory::PrivilegeEscalation);
    }

    #[test]
    fn test_analyze_output_clean() {
        let mut findings = Vec::new();
        analyze_output("Hello, world!\n42\n", "python", &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_extract_matching_line() {
        let output = "line 1\nerror: permission denied for /etc/passwd\nline 3";
        let result = extract_matching_line(output, "permission denied");
        assert!(result.contains("permission denied"));
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 100), "short");
        let long = "a".repeat(200);
        let truncated = truncate(&long, 50);
        assert!(truncated.ends_with("..."));
        assert!(truncated.len() <= 54); // 50 + "..."
    }
}
