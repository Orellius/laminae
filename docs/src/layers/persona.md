# Persona — Voice Extraction & Style Enforcement

Extracts a writing personality from text samples and enforces it on LLM output.

## What It Does

1. **Extract** — Feed it 5+ text samples → get a structured persona (7 voice dimensions)
2. **Compile** — Turn a persona into a compact prompt block for any LLM
3. **Filter** — Post-generation voice filter catches AI-sounding output (60+ patterns)
4. **Track** — Voice DNA tracks distinctive phrases confirmed by reuse

## The 7 Voice Dimensions

| Dimension | Example |
|-----------|---------|
| Tone | sharp, witty, blunt |
| Humor | dry sarcasm, never forced |
| Vocabulary | technical, casual |
| Formality | informal, no hedging |
| Perspective | pragmatic minimalist |
| Emotional range | controlled intensity |
| Sentence length | short, punchy |

## Extraction Quality

Persona extraction now includes quality scoring:

- **Minimum 3 samples required**, 5+ recommended
- **Diversity scoring** — detects if samples are too similar
- **Confidence score** (0.0–1.0) based on sample count, diversity, and content richness
- **Warnings** for low-quality extractions

```rust
use laminae::persona::{PersonaExtractor, VoiceFilter, VoiceFilterConfig, compile_persona};

let extractor = PersonaExtractor::new("qwen2.5:7b");
let persona = extractor.extract(&samples).await?;

// Check extraction quality
if let Some(quality) = &persona.meta.quality {
    println!("Confidence: {:.0}%", quality.confidence * 100.0);
    println!("Diversity: {:.0}%", quality.diversity_score * 100.0);
    for warning in &quality.warnings {
        eprintln!("Warning: {warning}");
    }
}

let prompt_block = compile_persona(&persona);
```

## Voice Filter

The voice filter catches AI-sounding output with 6 detection layers:

1. **AI vocabulary** — 60+ phrases like "it's important to note", "furthermore", "delve"
2. **Meta-commentary** — "The post highlights..." openers
3. **Multi-paragraph** — Optional rejection of multi-paragraph responses
4. **Trailing questions** — Generic AI questions at the end
5. **Em-dashes** — Replace with periods
6. **Length violations** — Sentence and character limits

```rust
let filter = VoiceFilter::new(VoiceFilterConfig::default());
let result = filter.check("It's important to note that...");
// result.passed = false
// result.violations = ["AI vocabulary detected: ..."]
// result.retry_hints = ["DO NOT use formal/academic language..."]
```

## Voice DNA

Tracks distinctive phrases that define a person's writing. When generated text receives positive feedback, distinctive phrases are recorded and reinforced.

```rust
use laminae::persona::VoiceDna;

let mut dna = VoiceDna::empty();
dna.record_success("Nobody reads your README. Ship it or delete it.");
// "Nobody reads" is now tracked as a distinctive phrase
```
