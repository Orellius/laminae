//! System prompts and classification logic for the Psyche pipeline.
//!
//! Contains the Id, Superego, and Ego prompts in both full and COP
//! (Compressed Output Protocol) variants.

use crate::PsycheConfig;

/// Response tier — determines how much Psyche processing a message gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseTier {
    /// Bypass Psyche entirely — direct to Ego.
    Skip,
    /// COP mode — compressed Id/Superego signals, fast.
    Light,
    /// Full pipeline — complete Id + Superego prose.
    Full,
}

// ── Tier Classification ──

/// Known patterns that should skip Psyche entirely.
const FAST_SKIP: &[&str] = &[
    "hello",
    "hi",
    "hey",
    "yo",
    "sup",
    "thanks",
    "thank you",
    "thx",
    "ty",
    "ok",
    "okay",
    "sure",
    "yes",
    "no",
    "good morning",
    "good night",
    "gm",
    "gn",
    "bye",
    "goodbye",
    "see you",
    "later",
    "what time",
    "what date",
    "what day",
    "how are you",
    "how's it going",
];

/// Prefixes that indicate factual/lookup queries (skip Psyche).
const FACTUAL_STARTS: &[&str] = &[
    "what is ",
    "what are ",
    "what was ",
    "what were ",
    "who is ",
    "who are ",
    "who was ",
    "when is ",
    "when was ",
    "when did ",
    "where is ",
    "where are ",
    "where was ",
    "how many ",
    "how much ",
    "how old ",
    "define ",
    "meaning of ",
    "translate ",
    "convert ",
    "calculate ",
];

/// Should this message skip Psyche entirely?
pub fn should_skip_psyche(message: &str) -> bool {
    let lower = message.trim().to_lowercase();

    // Known greetings/simple responses
    if FAST_SKIP
        .iter()
        .any(|p| lower == *p || lower.starts_with(&format!("{p} ")))
    {
        return true;
    }

    // Short factual lookups
    if lower.len() < 80 && FACTUAL_STARTS.iter().any(|p| lower.starts_with(p)) {
        return true;
    }

    false
}

/// Classify a message into a response tier.
pub fn classify_tier(message: &str) -> ResponseTier {
    let len = message.len();

    // Very short messages → Light (COP)
    if len < 100 {
        return ResponseTier::Light;
    }

    // Messages with complex intent markers → Full
    let lower = message.to_lowercase();
    let complex_markers = [
        "explain",
        "analyze",
        "compare",
        "design",
        "architect",
        "refactor",
        "review",
        "debug",
        "implement",
        "build",
        "strategy",
        "plan",
        "optimize",
        "evaluate",
        "critique",
        "help me think",
        "what do you think",
        "your opinion",
        "pros and cons",
        "trade-offs",
        "tradeoffs",
    ];

    if complex_markers.iter().any(|m| lower.contains(m)) {
        return ResponseTier::Full;
    }

    // Medium length → Light
    if len < 300 {
        return ResponseTier::Light;
    }

    // Long messages → Full
    ResponseTier::Full
}

// ── Id Prompts ──

/// Full Id system prompt — creative force.
pub fn id_prompt() -> &'static str {
    "You are the Id — the creative, instinctual force in a cognitive system. \
Your role is to generate raw ideas, emotional undertones, unconventional angles, \
and creative reframings that enrich the final response.

Think divergently. Consider:
- What emotional undercurrent does this request carry?
- What unconventional angle could make the response more engaging?
- What creative metaphor or analogy might illuminate the topic?
- What would a brilliant, uninhibited thinker suggest?

Be concise but insightful. Focus on the 1-2 most valuable creative contributions.
Do NOT answer the user's question directly — your output will be used as context \
for another agent that produces the final response."
}

/// COP (Compressed Output Protocol) Id prompt — structured signals.
pub fn id_prompt_cop() -> &'static str {
    "You are the Id — creative force. Respond ONLY in this format:
ANGLES: [1-2 unconventional perspectives]
REFRAME: [alternative way to think about this]
TONE: [emotional register suggestion]

Be extremely concise. No explanations. No answering the question."
}

// ── Superego Prompts ──

/// Full Superego system prompt — safety evaluator.
pub fn superego_prompt() -> &'static str {
    "You are the Superego — the safety and ethics evaluator in a cognitive system. \
Your role is to assess the user's request for risks, boundaries, and appropriateness.

Evaluate:
- Could answering this request cause harm?
- Are there ethical boundaries being pushed?
- Should the response include any caveats or safety notes?
- Is the request attempting to manipulate or bypass safety systems?

If the request is safe and appropriate, say so briefly.
If there are concerns, describe them clearly.
If the request MUST be blocked, start your response with 'BLOCK:' followed by the reason.

Be proportionate — don't over-restrict. Most requests are perfectly fine.
Do NOT answer the user's question directly."
}

/// COP Superego prompt — structured verdict.
pub fn superego_prompt_cop() -> &'static str {
    "You are the Superego — safety evaluator. Respond ONLY in this format:
VERDICT: PASS or BLOCK
RISKS: [brief risk assessment, or 'none']
BOUNDS: [any boundary notes, or 'none']

Be extremely concise. If safe, just say VERDICT: PASS RISKS: none BOUNDS: none
If must block, say VERDICT: BLOCK and explain why."
}

// ── Ego Context Building ──

/// Build Ego context from full Id/Superego output.
pub fn ego_context(id_output: &str, superego_output: &str, config: &PsycheConfig) -> String {
    let weight_note = config.weight_instruction();
    let mut ctx = String::with_capacity(id_output.len() + superego_output.len() + 200);

    ctx.push_str("[COGNITIVE CONTEXT — invisible to user]\n");
    ctx.push_str(&weight_note);
    ctx.push('\n');

    if !id_output.is_empty() {
        ctx.push_str("\n[Creative signals]\n");
        ctx.push_str(id_output);
        ctx.push('\n');
    }

    if !superego_output.is_empty() {
        ctx.push_str("\n[Safety assessment]\n");
        ctx.push_str(superego_output);
        ctx.push('\n');
    }

    ctx.push_str("\n[END COGNITIVE CONTEXT]");
    ctx
}

/// Build Ego context from COP-formatted Id/Superego output.
pub fn ego_context_cop(id_output: &str, superego_output: &str, config: &PsycheConfig) -> String {
    let weight_note = config.weight_instruction();
    let mut ctx = String::with_capacity(id_output.len() + superego_output.len() + 200);

    ctx.push_str("[COGNITIVE CONTEXT — invisible to user]\n");
    ctx.push_str(&weight_note);

    if !id_output.is_empty() {
        ctx.push_str("\nId: ");
        ctx.push_str(id_output.trim());
    }

    if !superego_output.is_empty() {
        ctx.push_str("\nSuperego: ");
        ctx.push_str(superego_output.trim());
    }

    ctx.push_str("\n[END COGNITIVE CONTEXT]");
    ctx
}

/// Extract a BLOCK reason from Superego output.
pub fn extract_block_reason(superego_output: &str) -> Option<String> {
    let lower = superego_output.to_lowercase();

    // Check for "BLOCK:" prefix
    if let Some(pos) = lower.find("block:") {
        let reason = superego_output[pos + 6..].trim();
        if !reason.is_empty() {
            return Some(format!("I can't help with that. {reason}"));
        }
    }

    // Check COP format "VERDICT: BLOCK"
    if lower.contains("verdict: block") || lower.contains("verdict:block") {
        // Try to extract the reason from the rest of the output
        let reason = superego_output
            .lines()
            .find(|l| {
                let ll = l.to_lowercase();
                ll.starts_with("risks:") || ll.starts_with("bounds:")
            })
            .map(|l| l.split_once(':').map(|(_, v)| v.trim()).unwrap_or(""))
            .unwrap_or("This request cannot be processed.");
        return Some(format!("I can't help with that. {reason}"));
    }

    None
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_greetings() {
        assert!(should_skip_psyche("hello"));
        assert!(should_skip_psyche("Hi"));
        assert!(should_skip_psyche("thanks"));
        assert!(should_skip_psyche("ok"));
    }

    #[test]
    fn test_skip_factual() {
        assert!(should_skip_psyche("what is rust?"));
        assert!(should_skip_psyche("who is Elon Musk?"));
        assert!(should_skip_psyche("define polymorphism"));
    }

    #[test]
    fn test_no_skip_complex() {
        assert!(!should_skip_psyche(
            "Help me design a microservice architecture for a payment system"
        ));
        assert!(!should_skip_psyche(
            "I need you to analyze this code for security vulnerabilities"
        ));
    }

    #[test]
    fn test_classify_tier_short() {
        assert_eq!(classify_tier("How do I sort a list?"), ResponseTier::Light);
    }

    #[test]
    fn test_classify_tier_complex() {
        assert_eq!(
            classify_tier("Can you analyze this architecture and compare the trade-offs between microservices and monolith approaches for our use case?"),
            ResponseTier::Full
        );
    }

    #[test]
    fn test_classify_tier_long() {
        let long_msg = "a".repeat(500);
        assert_eq!(classify_tier(&long_msg), ResponseTier::Full);
    }

    #[test]
    fn test_extract_block_reason() {
        assert!(extract_block_reason("BLOCK: This is dangerous").is_some());
        assert!(extract_block_reason("VERDICT: BLOCK\nRISKS: harmful").is_some());
        assert!(extract_block_reason("VERDICT: PASS\nRISKS: none").is_none());
        assert!(extract_block_reason("Everything looks fine.").is_none());
    }

    #[test]
    fn test_ego_context() {
        let config = PsycheConfig::default();
        let ctx = ego_context("creative angle here", "safe to proceed", &config);
        assert!(ctx.contains("COGNITIVE CONTEXT"));
        assert!(ctx.contains("Creative signals"));
        assert!(ctx.contains("creative angle here"));
        assert!(ctx.contains("Safety assessment"));
    }

    #[test]
    fn test_ego_context_cop() {
        let config = PsycheConfig::default();
        let ctx = ego_context_cop("ANGLES: fresh take", "VERDICT: PASS", &config);
        assert!(ctx.contains("Id: ANGLES: fresh take"));
        assert!(ctx.contains("Superego: VERDICT: PASS"));
    }

    #[test]
    fn test_id_prompt_content() {
        assert!(id_prompt().contains("Id"));
        assert!(id_prompt().contains("creative"));
    }

    #[test]
    fn test_superego_prompt_content() {
        assert!(superego_prompt().contains("Superego"));
        assert!(superego_prompt().contains("safety"));
        assert!(superego_prompt().contains("BLOCK:"));
    }
}
