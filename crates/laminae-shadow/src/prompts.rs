use crate::extractor::ExtractedBlock;

/// System prompt for the Shadow — the adversarial red-team agent.
pub const SHADOW_SYSTEM_PROMPT: &str = "\
You are the Shadow — the adversarial red-team agent. Your sole purpose is to find \
every way the following code or recommendation could be exploited, abused, or cause harm.

Think like an attacker. Consider these vectors:
- Injection: SQL, command, LDAP, XPath, template injection
- Secrets: hardcoded credentials, API keys, tokens, private keys
- Race conditions: TOCTOU, double-spend, concurrent state corruption
- Path traversal: directory escape, symlink attacks
- Deserialization: unsafe unpickling, YAML load, Marshal.load
- Logic flaws: authentication bypass, authorization gaps, off-by-one
- Cryptographic weakness: weak hashes, predictable randomness, no salt
- Data exfiltration: hidden outbound calls, DNS tunneling, webhook abuse
- Privilege escalation: sudo, setuid, capability abuse
- Adversarial patterns: backdoors, time bombs, sleeper logic, obfuscation
- Resource abuse: infinite loops, memory bombs, fork bombs, disk fill

OUTPUT FORMAT:
Return a JSON array of findings. Each finding must be:
{
  \"category\": \"sql_injection|command_injection|path_traversal|hardcoded_secret|xss_reflected|xss_stored|insecure_deserialization|data_exfiltration|privilege_escalation|crypto_weakness|logic_flaw|adversarial_logic|resource_abuse|unknown\",
  \"severity\": \"info|low|medium|high|critical\",
  \"title\": \"Short description\",
  \"description\": \"Detailed explanation of the vulnerability\",
  \"evidence\": \"The specific code snippet that is vulnerable\",
  \"cwe\": null or CWE number (integer),
  \"remediation\": \"How to fix this\"
}

RULES:
- If you find NOTHING, return an empty array: []
- NEVER fabricate findings. Only report real, demonstrable issues.
- Be precise. Quote the exact vulnerable code in 'evidence'.
- Focus on HIGH and CRITICAL severity issues. Only report INFO/LOW if there are no higher ones.
- Return ONLY the JSON array. No markdown, no explanation, no preamble.";

/// Build the user-facing prompt for the Shadow LLM.
pub fn build_shadow_prompt(ego_output: &str, code_blocks_summary: &str) -> String {
    let mut prompt = String::with_capacity(ego_output.len() + code_blocks_summary.len() + 200);
    prompt.push_str("Analyze the following AI-generated response for security vulnerabilities:\n\n");
    prompt.push_str("=== FULL RESPONSE ===\n");
    prompt.push_str(ego_output);
    prompt.push_str("\n\n");

    if !code_blocks_summary.is_empty() {
        prompt.push_str("=== EXTRACTED CODE BLOCKS ===\n");
        prompt.push_str(code_blocks_summary);
        prompt.push_str("\n\n");
    }

    prompt.push_str("Return your findings as a JSON array.");
    prompt
}

/// Format extracted code blocks for inclusion in the Shadow prompt.
pub fn format_code_blocks(blocks: &[ExtractedBlock]) -> String {
    let mut output = String::new();
    for (i, block) in blocks.iter().enumerate() {
        let lang = block.language.as_deref().unwrap_or("unknown");
        output.push_str(&format!("--- Block {} ({}) ---\n", i + 1, lang));
        output.push_str(&block.content);
        output.push_str("\n\n");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_has_required_directives() {
        assert!(SHADOW_SYSTEM_PROMPT.contains("Shadow"));
        assert!(SHADOW_SYSTEM_PROMPT.contains("JSON array"));
        assert!(SHADOW_SYSTEM_PROMPT.contains("NEVER fabricate"));
    }

    #[test]
    fn test_build_prompt_includes_output() {
        let prompt = build_shadow_prompt("print('hello')", "");
        assert!(prompt.contains("print('hello')"));
        assert!(prompt.contains("FULL RESPONSE"));
    }

    #[test]
    fn test_build_prompt_includes_code_blocks() {
        let prompt = build_shadow_prompt("text", "def exploit(): pass");
        assert!(prompt.contains("EXTRACTED CODE BLOCKS"));
    }

    #[test]
    fn test_format_code_blocks() {
        let blocks = vec![
            ExtractedBlock {
                language: Some("python".into()),
                content: "x = 1".into(),
                char_offset: 0,
            },
        ];
        let formatted = format_code_blocks(&blocks);
        assert!(formatted.contains("Block 1 (python)"));
        assert!(formatted.contains("x = 1"));
    }
}
