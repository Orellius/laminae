use crate::analyzer::{Analyzer, AnalyzerError};
use crate::config::ShadowConfig;
use crate::extractor::ExtractedBlock;
use crate::report::VulnFinding;

/// Sandbox manager for executing code in isolated containers.
///
/// Stub implementation — full container-based sandboxing is available
/// as a future enhancement. The architecture supports it via the
/// [`Analyzer`] trait.
pub struct SandboxManager {
    enabled: bool,
    _image: String,
    _ttl_secs: u64,
    _min_code_len: usize,
}

impl SandboxManager {
    pub fn new(config: &ShadowConfig) -> Self {
        Self {
            enabled: config.sandbox_enabled,
            _image: config.sandbox_image.clone(),
            _ttl_secs: config.sandbox_ttl_secs,
            _min_code_len: config.sandbox_min_code_len,
        }
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

        match tokio::process::Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
        {
            Ok(status) => status.success(),
            Err(_) => {
                match tokio::process::Command::new("podman")
                    .arg("info")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await
                {
                    Ok(status) => status.success(),
                    Err(_) => false,
                }
            }
        }
    }

    async fn analyze(
        &self,
        _ego_output: &str,
        _code_blocks: &[ExtractedBlock],
    ) -> Result<Vec<VulnFinding>, AnalyzerError> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        tracing::debug!("Sandbox analysis requested but full implementation is pending");
        Ok(Vec::new())
    }
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
}
