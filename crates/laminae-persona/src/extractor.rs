//! Voice persona extraction from text samples via local LLM analysis.

use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::HashSet;

use crate::model::*;
use laminae_ollama::OllamaClient;

/// Minimum number of samples required for extraction.
const MIN_SAMPLES: usize = 3;
/// Recommended number of samples for high-quality extraction.
const RECOMMENDED_SAMPLES: usize = 5;
/// Minimum word count for a sample to be considered useful.
const MIN_SAMPLE_WORDS: usize = 10;

/// Extracts a writing persona from text samples using a local LLM.
///
/// Analyzes 20-100 text samples to identify 7 dimensions of writing voice:
/// tone, humor, vocabulary, formality, perspective, emotional style, and
/// narrative preference.
pub struct PersonaExtractor {
    client: OllamaClient,
    model: String,
    /// Max samples to analyze (default: 50).
    pub max_samples: usize,
    /// LLM temperature for extraction (default: 0.3 — deterministic).
    pub temperature: f32,
}

impl PersonaExtractor {
    /// Create a new extractor with the specified Ollama model.
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            client: OllamaClient::new(),
            model: model.into(),
            max_samples: 50,
            temperature: 0.3,
        }
    }

    /// Create with a custom Ollama client (e.g., different host/port).
    pub fn with_client(client: OllamaClient, model: impl Into<String>) -> Self {
        Self {
            client,
            model: model.into(),
            max_samples: 50,
            temperature: 0.3,
        }
    }

    /// Extract a persona from text samples.
    ///
    /// Requires at least 3 samples. Recommends 5+ for high-confidence extraction.
    /// Returns the extracted persona with quality metrics attached.
    pub async fn extract(&self, samples: &[WeightedSample]) -> Result<Persona> {
        if samples.is_empty() {
            anyhow::bail!("Cannot extract persona from zero samples");
        }
        if samples.len() < MIN_SAMPLES {
            anyhow::bail!(
                "Need at least {} samples for extraction (got {}). \
                 Provide {} or more for best results.",
                MIN_SAMPLES,
                samples.len(),
                RECOMMENDED_SAMPLES,
            );
        }

        // Sort by weight (highest first) and cap at max_samples
        let mut sorted: Vec<&WeightedSample> = samples.iter().collect();
        sorted.sort_by(|a, b| {
            b.weight
                .partial_cmp(&a.weight)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.truncate(self.max_samples);

        // Compute quality metrics before extraction
        let quality = compute_extraction_quality(&sorted);

        if quality.confidence < 0.2 {
            tracing::warn!(
                confidence = quality.confidence,
                diversity = quality.diversity_score,
                "Very low extraction confidence — persona may be unreliable"
            );
        } else if !quality.warnings.is_empty() {
            for w in &quality.warnings {
                tracing::info!("Extraction quality: {}", w);
            }
        }

        let samples_text = sorted
            .iter()
            .enumerate()
            .map(|(i, s)| format!("{}. {}", i + 1, s.text))
            .collect::<Vec<_>>()
            .join("\n");

        let system_prompt = EXTRACTION_SYSTEM_PROMPT;
        let user_prompt = format!(
            "Analyze these {} text samples and extract the writing persona.\n\
             Respond with ONLY valid JSON matching the schema.\n\n\
             --- TEXT SAMPLES ---\n{}\n--- END SAMPLES ---",
            sorted.len(),
            samples_text
        );

        let raw = self
            .client
            .complete(
                &self.model,
                system_prompt,
                &user_prompt,
                self.temperature,
                2048,
            )
            .await
            .context("LLM extraction call failed")?;

        let extracted: ExtractedPersona =
            parse_json_response(&raw).context("Failed to parse LLM extraction response")?;

        // Validate examples are actual copies, not fabrications
        let validated_examples = validate_examples(&extracted.example_posts, &sorted);

        let now = Utc::now();
        Ok(Persona {
            meta: PersonaMeta {
                id: format!("persona-{}", now.timestamp()),
                name: "Extracted Persona".to_string(),
                version: 1,
                created_at: now,
                updated_at: now,
                source: PersonaSource::Extracted,
                samples_analyzed: sorted.len(),
                quality: Some(quality),
            },
            identity: PersonaIdentity {
                bio: extracted.bio,
                expertise: extracted.expertise,
                perspective: extracted.perspective,
            },
            voice: PersonaVoice {
                tone_words: extracted.tone_words,
                writing_style: extracted.writing_style,
                humor_style: extracted.humor_style,
                emotional_range: extracted.emotional_range,
                sentence_length: match extracted.sentence_length.to_lowercase().as_str() {
                    "very_short" | "very short" => SentenceLength::VeryShort,
                    "short" => SentenceLength::Short,
                    "long" => SentenceLength::Long,
                    _ => SentenceLength::Medium,
                },
                punctuation_style: extracted.punctuation_style,
                voice_summary: extracted.voice_summary,
                examples: validated_examples,
                voice_dna: Vec::new(),
            },
            rules: PersonaRules::default(),
        })
    }

    /// Incremental extraction: compare new samples against an existing persona.
    ///
    /// Returns the new persona draft and a similarity score (0.0-1.0).
    /// High similarity (>0.8) means the persona hasn't drifted much.
    pub async fn refresh(
        &self,
        samples: &[WeightedSample],
        existing: &Persona,
    ) -> Result<(Persona, f64)> {
        let mut new_persona = self.extract(samples).await?;
        new_persona.meta.source = PersonaSource::Refreshed;

        // Carry forward voice DNA from existing
        new_persona.voice.voice_dna = existing.voice.voice_dna.clone();

        let similarity = compute_similarity(&existing.voice, &new_persona.voice);
        Ok((new_persona, similarity))
    }
}

/// Compute similarity between two voice profiles (0.0-1.0).
fn compute_similarity(a: &PersonaVoice, b: &PersonaVoice) -> f64 {
    // Tone word overlap (Jaccard similarity) — 50% weight
    let a_tones: std::collections::HashSet<_> =
        a.tone_words.iter().map(|w| w.to_lowercase()).collect();
    let b_tones: std::collections::HashSet<_> =
        b.tone_words.iter().map(|w| w.to_lowercase()).collect();
    let tone_jaccard = if a_tones.is_empty() && b_tones.is_empty() {
        1.0
    } else {
        let intersection = a_tones.intersection(&b_tones).count() as f64;
        let union = a_tones.union(&b_tones).count() as f64;
        intersection / union
    };

    // Writing style word overlap — 50% weight
    let a_words: std::collections::HashSet<_> = a
        .writing_style
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect();
    let b_words: std::collections::HashSet<_> = b
        .writing_style
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect();
    let style_overlap = if a_words.is_empty() && b_words.is_empty() {
        1.0
    } else {
        let intersection = a_words.intersection(&b_words).count() as f64;
        let max_len = a_words.len().max(b_words.len()) as f64;
        if max_len == 0.0 {
            1.0
        } else {
            intersection / max_len
        }
    };

    tone_jaccard * 0.5 + style_overlap * 0.5
}

/// Compute quality metrics for a set of samples before extraction.
fn compute_extraction_quality(samples: &[&WeightedSample]) -> ExtractionQuality {
    let mut warnings = Vec::new();

    // Count short samples
    let word_counts: Vec<usize> = samples
        .iter()
        .map(|s| s.text.split_whitespace().count())
        .collect();
    let short_samples = word_counts
        .iter()
        .filter(|&&c| c < MIN_SAMPLE_WORDS)
        .count();
    let avg_sample_length = if word_counts.is_empty() {
        0.0
    } else {
        word_counts.iter().sum::<usize>() as f64 / word_counts.len() as f64
    };

    if short_samples > samples.len() / 2 {
        warnings.push(format!(
            "{} of {} samples are very short (<{} words) — extraction may miss nuance",
            short_samples,
            samples.len(),
            MIN_SAMPLE_WORDS,
        ));
    }

    // Diversity: unique words / total words across all samples (type-token ratio)
    let mut all_words = Vec::new();
    let mut unique_words = HashSet::new();
    for s in samples {
        for word in s.text.split_whitespace() {
            let lower = word.to_lowercase();
            let cleaned: String = lower.chars().filter(|c| c.is_alphanumeric()).collect();
            if cleaned.len() >= 2 {
                all_words.push(cleaned.clone());
                unique_words.insert(cleaned);
            }
        }
    }

    let diversity_score = if all_words.is_empty() {
        0.0
    } else {
        // Normalized type-token ratio (raw TTR drops with corpus size,
        // so we cap to give meaningful 0-1 range)
        let raw_ttr = unique_words.len() as f64 / all_words.len() as f64;
        (raw_ttr * 2.0).min(1.0) // Scale: 0.5 raw TTR → 1.0 score
    };

    if diversity_score < 0.3 {
        warnings.push(
            "Low vocabulary diversity — samples may be too similar to each other".to_string(),
        );
    }

    if samples.len() < RECOMMENDED_SAMPLES {
        warnings.push(format!(
            "Only {} samples provided (recommend {}+ for high confidence)",
            samples.len(),
            RECOMMENDED_SAMPLES,
        ));
    }

    // Overall confidence: weighted combination of factors
    let count_factor = (samples.len() as f64 / RECOMMENDED_SAMPLES as f64).min(1.0);
    let useful_ratio = 1.0 - (short_samples as f64 / samples.len().max(1) as f64);
    let confidence =
        (count_factor * 0.3 + diversity_score * 0.4 + useful_ratio * 0.3).clamp(0.0, 1.0);

    ExtractionQuality {
        confidence,
        diversity_score,
        avg_sample_length,
        short_samples,
        warnings,
    }
}

/// Anti-hallucination: validate that LLM-provided examples are actual copies.
fn validate_examples(claimed: &[String], samples: &[&WeightedSample]) -> Vec<String> {
    let mut validated = Vec::new();

    for example in claimed {
        let is_real = samples.iter().any(|s| {
            // Exact match or fuzzy match (60% substring overlap)
            s.text == *example || fuzzy_match(&s.text, example) > 0.6
        });

        if is_real {
            validated.push(example.clone());
        }
    }

    // If LLM fabricated most examples, fall back to top real samples
    if validated.is_empty() {
        tracing::warn!(
            "LLM fabricated {} of {} examples — falling back to real samples",
            claimed.len() - validated.len(),
            claimed.len()
        );
        validated.clear();
        for sample in samples.iter().take(5) {
            if sample.text.len() >= 20 {
                validated.push(sample.text.clone());
            }
        }
    }

    validated.truncate(10);
    validated
}

/// Fuzzy match: what fraction of `a` appears as a substring in `b` (or vice versa).
fn fuzzy_match(a: &str, b: &str) -> f64 {
    let (shorter, longer) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    if shorter.is_empty() {
        return 0.0;
    }

    // Check if a significant prefix matches
    let prefix_len = shorter.len().min(30);
    let prefix = &shorter[..prefix_len];
    if longer.contains(prefix) {
        return 0.7;
    }

    // Word-level overlap
    let a_words: std::collections::HashSet<&str> = shorter.split_whitespace().collect();
    let b_words: std::collections::HashSet<&str> = longer.split_whitespace().collect();
    if a_words.is_empty() {
        return 0.0;
    }
    let overlap = a_words.intersection(&b_words).count() as f64;
    overlap / a_words.len() as f64
}

/// Raw LLM extraction response (internal).
#[derive(serde::Deserialize)]
struct ExtractedPersona {
    tone_words: Vec<String>,
    writing_style: String,
    humor_style: String,
    emotional_range: String,
    sentence_length: String,
    punctuation_style: String,
    voice_summary: String,
    bio: String,
    #[serde(default)]
    expertise: Vec<String>,
    #[serde(default)]
    perspective: String,
    #[serde(default)]
    example_posts: Vec<String>,
}

/// Parse JSON from an LLM response, handling markdown code fences.
fn parse_json_response<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T> {
    let trimmed = raw.trim();

    // Strip markdown code fences if present
    let json_str = if trimmed.starts_with("```") {
        let start = trimmed.find('{').unwrap_or(0);
        let end = trimmed.rfind('}').map(|i| i + 1).unwrap_or(trimmed.len());
        &trimmed[start..end]
    } else {
        trimmed
    };

    serde_json::from_str(json_str).context("Invalid JSON in LLM response")
}

const EXTRACTION_SYSTEM_PROMPT: &str = r#"You are a writing style analyst. Given text samples from a single author, extract their writing personality.

Respond with ONLY valid JSON (no markdown, no explanation) matching this exact schema:
{
  "tone_words": ["3-5 adjectives describing their voice"],
  "writing_style": "1 sentence describing how they write",
  "humor_style": "1 sentence about their humor (or 'none detected')",
  "emotional_range": "1 sentence about how they express emotions",
  "sentence_length": "short|medium|long",
  "punctuation_style": "description of punctuation habits",
  "voice_summary": "4-5 sentence coaching profile in 2nd person ('You write with...')",
  "bio": "1 sentence description of who they are based on content",
  "expertise": ["2-4 topics they clearly know about"],
  "perspective": "1 sentence about their worldview or lens",
  "example_posts": ["5 most representative samples — EXACT COPIES, never fabricate"]
}

CRITICAL RULES:
- ALL fields must be grounded in the actual text samples provided
- tone_words must describe patterns VISIBLE in the text
- expertise must be DIRECTLY EVIDENCED by the samples
- example_posts must be EXACT COPIES from the input — never fabricate
- BETTER to return fewer accurate insights than many speculative ones
- voice_summary is the most important field — write it as a vocal coach giving specific notes"#;

#[cfg(test)]
#[allow(clippy::useless_vec)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzy_match_exact() {
        assert!(fuzzy_match("hello world", "hello world") > 0.5);
    }

    #[test]
    fn test_fuzzy_match_partial() {
        assert!(fuzzy_match("hello world foo", "hello world foo bar baz") > 0.5);
    }

    #[test]
    fn test_fuzzy_match_no_overlap() {
        assert!(fuzzy_match("hello world", "completely different") < 0.3);
    }

    #[test]
    fn test_compute_similarity_identical() {
        let voice = PersonaVoice {
            tone_words: vec!["sharp".into(), "witty".into()],
            writing_style: "Short punchy sentences with attitude".into(),
            humor_style: "Dry sarcasm".into(),
            emotional_range: "Controlled intensity".into(),
            sentence_length: SentenceLength::Short,
            punctuation_style: "Heavy periods, rare commas".into(),
            voice_summary: "You write like a telegraph operator with opinions".into(),
            examples: vec![],
            voice_dna: vec![],
        };
        assert!((compute_similarity(&voice, &voice) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_compute_similarity_different() {
        let a = PersonaVoice {
            tone_words: vec!["sharp".into(), "aggressive".into()],
            writing_style: "Short punchy sentences".into(),
            humor_style: String::new(),
            emotional_range: String::new(),
            sentence_length: SentenceLength::Short,
            punctuation_style: String::new(),
            voice_summary: String::new(),
            examples: vec![],
            voice_dna: vec![],
        };
        let b = PersonaVoice {
            tone_words: vec!["gentle".into(), "warm".into()],
            writing_style: "Flowing descriptive paragraphs".into(),
            humor_style: String::new(),
            emotional_range: String::new(),
            sentence_length: SentenceLength::Long,
            punctuation_style: String::new(),
            voice_summary: String::new(),
            examples: vec![],
            voice_dna: vec![],
        };
        assert!(compute_similarity(&a, &b) < 0.3);
    }

    #[test]
    fn test_validate_examples_real() {
        let samples = vec![
            WeightedSample::from("This is a real sample that should match exactly as written"),
            WeightedSample::from("Another genuine piece of text from the corpus"),
            WeightedSample::from("Third real example for validation purposes here"),
        ];
        let refs: Vec<&WeightedSample> = samples.iter().collect();

        let claimed = vec![
            "This is a real sample that should match exactly as written".to_string(),
            "Another genuine piece of text from the corpus".to_string(),
            "Zxcvbnm asdfghjkl qwertyuiop".to_string(),
        ];

        let validated = validate_examples(&claimed, &refs);
        assert_eq!(validated.len(), 2);
        assert!(validated
            .contains(&"This is a real sample that should match exactly as written".to_string()));
    }

    #[test]
    fn test_validate_examples_all_fabricated() {
        let samples = vec![
            WeightedSample::from("Real text that exists in the corpus"),
            WeightedSample::from("Another real text from the author"),
            WeightedSample::from("Third genuine text sample here"),
        ];
        let refs: Vec<&WeightedSample> = samples.iter().collect();

        let claimed = vec![
            "Completely fabricated example one".to_string(),
            "Another made up example two".to_string(),
        ];

        let validated = validate_examples(&claimed, &refs);
        // Should fall back to real samples
        assert!(validated.len() >= 3);
    }

    #[test]
    fn test_parse_json_response_clean() {
        let raw = r#"{"tone_words":["sharp"],"writing_style":"Direct","humor_style":"none","emotional_range":"flat","sentence_length":"short","punctuation_style":"minimal","voice_summary":"You write bluntly.","bio":"A developer","expertise":["rust"],"perspective":"Pragmatic","example_posts":[]}"#;
        let result: Result<ExtractedPersona> = parse_json_response(raw);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_json_response_with_fences() {
        let raw = "```json\n{\"tone_words\":[\"sharp\"],\"writing_style\":\"Direct\",\"humor_style\":\"none\",\"emotional_range\":\"flat\",\"sentence_length\":\"short\",\"punctuation_style\":\"minimal\",\"voice_summary\":\"You write bluntly.\",\"bio\":\"A developer\",\"expertise\":[],\"perspective\":\"\",\"example_posts\":[]}\n```";
        let result: Result<ExtractedPersona> = parse_json_response(raw);
        assert!(result.is_ok());
    }

    // ── Quality scoring tests ───────────────────────────────

    #[test]
    fn test_quality_high_confidence() {
        let samples: Vec<WeightedSample> = vec![
            "Rust is the best systems language. Performance meets safety. No GC pauses ever."
                .into(),
            "Ship it first, optimize later. The compiler catches what tests miss.".into(),
            "Every abstraction has a cost. Make sure you're paying for something real.".into(),
            "Nobody reads your README. Write code that documents itself through types.".into(),
            "Hot take: most frameworks are just dependency trees in a trench coat.".into(),
            "The best code review comment is 'delete this'. Simplicity wins.".into(),
        ];
        let refs: Vec<&WeightedSample> = samples.iter().collect();
        let quality = compute_extraction_quality(&refs);

        assert!(
            quality.confidence > 0.6,
            "confidence={}",
            quality.confidence
        );
        assert!(
            quality.diversity_score > 0.4,
            "diversity={}",
            quality.diversity_score
        );
        assert_eq!(quality.short_samples, 0);
        assert!(quality.warnings.is_empty() || quality.warnings.len() <= 1);
    }

    #[test]
    fn test_quality_low_diversity() {
        // Extremely repetitive samples — near-identical structure with same words
        let samples: Vec<WeightedSample> = vec![
            "Rust is fast Rust is fast Rust is fast Rust is fast".into(),
            "Rust is fast Rust is fast Rust is fast Rust is fast".into(),
            "Rust is fast Rust is fast Rust is fast Rust is fast".into(),
        ];
        let refs: Vec<&WeightedSample> = samples.iter().collect();
        let quality = compute_extraction_quality(&refs);

        assert!(
            quality.diversity_score < 0.5,
            "diversity={}",
            quality.diversity_score
        );
    }

    #[test]
    fn test_quality_short_samples_warning() {
        let samples: Vec<WeightedSample> = vec![
            "Short.".into(),
            "Also short.".into(),
            "Very short too.".into(),
            "Tiny.".into(),
        ];
        let refs: Vec<&WeightedSample> = samples.iter().collect();
        let quality = compute_extraction_quality(&refs);

        assert!(quality.short_samples >= 3);
        assert!(quality.warnings.iter().any(|w| w.contains("short")));
    }

    #[test]
    fn test_quality_few_samples_warning() {
        let samples: Vec<WeightedSample> = vec![
            "This is a reasonable length sample with enough words to count.".into(),
            "Another sample that has sufficient length for analysis here.".into(),
            "Third sample with plenty of words for the extraction engine.".into(),
        ];
        let refs: Vec<&WeightedSample> = samples.iter().collect();
        let quality = compute_extraction_quality(&refs);

        assert!(quality.warnings.iter().any(|w| w.contains("recommend")));
    }
}
