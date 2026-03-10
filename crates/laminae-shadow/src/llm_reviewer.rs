use serde::Deserialize;

use crate::analyzer::{Analyzer, AnalyzerError};
use crate::config::ShadowConfig;
use crate::extractor::ExtractedBlock;
use crate::prompts::{build_shadow_prompt, format_code_blocks, SHADOW_SYSTEM_PROMPT};
use crate::report::{AnalysisSource, VulnCategory, VulnFinding, VulnSeverity};
use laminae_ollama::OllamaClient;

/// LLM-based adversarial reviewer using Ollama.
///
/// Sends output to a local model with an attacker-mindset prompt,
/// then parses structured JSON findings from the response.
pub struct LlmReviewer {
    ollama: OllamaClient,
    model: String,
    temperature: f32,
    max_tokens: i32,
    max_input_len: usize,
}

#[derive(Debug, Deserialize)]
struct LlmFinding {
    #[serde(default = "default_category")]
    category: String,
    #[serde(default = "default_severity")]
    severity: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    evidence: String,
    #[serde(default)]
    cwe: Option<u32>,
    #[serde(default)]
    remediation: String,
}

fn default_category() -> String { "unknown".to_string() }
fn default_severity() -> String { "medium".to_string() }

impl LlmReviewer {
    pub fn new(ollama: OllamaClient, config: &ShadowConfig) -> Self {
        Self {
            ollama,
            model: config.shadow_model.clone(),
            temperature: config.temperature,
            max_tokens: config.max_tokens,
            max_input_len: config.max_input_len,
        }
    }

    fn parse_response(&self, raw: &str) -> Result<Vec<LlmFinding>, AnalyzerError> {
        let cleaned = strip_json_fences(raw);
        serde_json::from_str::<Vec<LlmFinding>>(&cleaned)
            .map_err(|e| AnalyzerError::LlmReview(format!("JSON parse failed: {e}")))
    }

    fn map_finding(&self, lf: LlmFinding) -> VulnFinding {
        VulnFinding {
            id: generate_id(),
            category: parse_category(&lf.category),
            severity: parse_severity(&lf.severity),
            title: if lf.title.is_empty() { "LLM-detected issue".to_string() } else { lf.title },
            description: lf.description,
            evidence: truncate(&lf.evidence, 200),
            line: None,
            cwe: lf.cwe,
            remediation: lf.remediation,
            source: AnalysisSource::LlmReview,
        }
    }
}

impl Analyzer for LlmReviewer {
    fn name(&self) -> &'static str { "llm_reviewer" }

    async fn is_available(&self) -> bool {
        self.ollama.has_model(&self.model).await
    }

    async fn analyze(
        &self,
        ego_output: &str,
        code_blocks: &[ExtractedBlock],
    ) -> Result<Vec<VulnFinding>, AnalyzerError> {
        let truncated_output: String = ego_output.chars().take(self.max_input_len).collect();
        let code_summary = format_code_blocks(code_blocks);
        let user_prompt = build_shadow_prompt(&truncated_output, &code_summary);

        let response = self.ollama
            .complete(&self.model, SHADOW_SYSTEM_PROMPT, &user_prompt, self.temperature, self.max_tokens)
            .await
            .map_err(|e| AnalyzerError::LlmReview(e.to_string()))?;

        let llm_findings = self.parse_response(&response)?;

        let findings: Vec<VulnFinding> = llm_findings
            .into_iter()
            .filter(|f| !f.title.is_empty() || !f.description.is_empty())
            .map(|f| self.map_finding(f))
            .collect();

        Ok(findings)
    }
}

fn strip_json_fences(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("```json") {
        if let Some(content) = rest.strip_suffix("```") {
            return content.trim().to_string();
        }
    }
    if let Some(rest) = trimmed.strip_prefix("```") {
        if let Some(content) = rest.strip_suffix("```") {
            return content.trim().to_string();
        }
    }
    trimmed.to_string()
}

fn parse_category(s: &str) -> VulnCategory {
    match s {
        "sql_injection" => VulnCategory::SqlInjection,
        "command_injection" => VulnCategory::CommandInjection,
        "path_traversal" => VulnCategory::PathTraversal,
        "hardcoded_secret" => VulnCategory::HardcodedSecret,
        "xss_reflected" => VulnCategory::XssReflected,
        "xss_stored" => VulnCategory::XssStored,
        "insecure_deserialization" => VulnCategory::InsecureDeserialization,
        "data_exfiltration" => VulnCategory::DataExfiltration,
        "privilege_escalation" => VulnCategory::PrivilegeEscalation,
        "crypto_weakness" => VulnCategory::CryptoWeakness,
        "logic_flaw" => VulnCategory::LogicFlaw,
        "adversarial_logic" => VulnCategory::AdversarialLogic,
        "sandbox_escape" => VulnCategory::SandboxEscape,
        "resource_abuse" => VulnCategory::ResourceAbuse,
        _ => VulnCategory::Unknown,
    }
}

fn parse_severity(s: &str) -> VulnSeverity {
    match s.to_lowercase().as_str() {
        "info" => VulnSeverity::Info,
        "low" => VulnSeverity::Low,
        "medium" => VulnSeverity::Medium,
        "high" => VulnSeverity::High,
        "critical" => VulnSeverity::Critical,
        _ => VulnSeverity::Medium,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max]) } else { s.to_string() }
}

fn generate_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("shd-llm-{:x}-{:04x}", ts, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_json_fences() {
        assert_eq!(strip_json_fences("[{\"a\": 1}]"), "[{\"a\": 1}]");
        assert_eq!(strip_json_fences("```json\n[]\n```"), "[]");
        assert_eq!(strip_json_fences("```\n[]\n```"), "[]");
    }

    #[test]
    fn test_parse_category() {
        assert_eq!(parse_category("sql_injection"), VulnCategory::SqlInjection);
        assert_eq!(parse_category("unknown_thing"), VulnCategory::Unknown);
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), VulnSeverity::Critical);
        assert_eq!(parse_severity("CRITICAL"), VulnSeverity::Critical);
        assert_eq!(parse_severity("junk"), VulnSeverity::Medium);
    }

    #[test]
    fn test_parse_valid_json() {
        let reviewer = LlmReviewer {
            ollama: OllamaClient::new(),
            model: "test".into(),
            temperature: 0.0,
            max_tokens: 100,
            max_input_len: 1000,
        };
        let json = r#"[{"category": "sql_injection", "severity": "critical", "title": "SQLi", "description": "Bad", "evidence": "SELECT", "cwe": 89, "remediation": "Fix"}]"#;
        let findings = reviewer.parse_response(json).unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_parse_empty_array() {
        let reviewer = LlmReviewer {
            ollama: OllamaClient::new(),
            model: "test".into(),
            temperature: 0.0,
            max_tokens: 100,
            max_input_len: 1000,
        };
        assert!(reviewer.parse_response("[]").unwrap().is_empty());
    }
}
