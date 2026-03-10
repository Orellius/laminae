# Recipe: Voice-Matched Responses

Use Persona extraction + voice filter to make any LLM write like a specific person.

## Step 1: Collect Samples

Gather 5-20 text samples from the person whose voice you want to match. More samples = better extraction.

```rust
use laminae::persona::WeightedSample;

let samples = vec![
    WeightedSample::from("Ship it. Fix it later. Perfection is the enemy of done."),
    WeightedSample::from("Nobody reads your README. Write code that doesn't need one."),
    WeightedSample::from("Hot take: most abstractions are just job security."),
    WeightedSample::from("Rust isn't hard. Your expectations of easy are just too low."),
    WeightedSample::from("The best code review comment is 'delete this'. Simplicity wins."),
    // High-engagement samples get more weight
    WeightedSample::with_weight("Zero dependencies or bust.", 2.0),
];
```

## Step 2: Extract the Persona

```rust
use laminae::persona::PersonaExtractor;

let extractor = PersonaExtractor::new("qwen2.5:7b");
let persona = extractor.extract(&samples).await?;

// Check quality
if let Some(q) = &persona.meta.quality {
    println!("Confidence: {:.0}%", q.confidence * 100.0);
}
```

## Step 3: Compile to Prompt

```rust
use laminae::persona::compile_persona;

let prompt_block = compile_persona(&persona);
// Insert this into your LLM's system prompt
```

## Step 4: Filter AI Output

```rust
use laminae::persona::{VoiceFilter, VoiceFilterConfig};

let filter = VoiceFilter::new(VoiceFilterConfig {
    reject_trailing_questions: true,
    fix_em_dashes: true,
    max_sentences: 3,
    ..Default::default()
});

let result = filter.check(&llm_response);
if result.passed {
    // Use result.cleaned (may have auto-fixes applied)
    send_to_user(&result.cleaned);
} else {
    // Retry with hints
    let retry_prompt = result.retry_hints.join("\n");
    let retried = llm.complete_with_hints(&retry_prompt).await?;
    send_to_user(&retried);
}
```

## Step 5: Track Voice DNA

Over time, reinforce distinctive phrases:

```rust
use laminae::persona::VoiceDna;

let mut dna = VoiceDna::new(persona.voice.voice_dna.clone());

// When a response gets positive feedback
dna.record_success(&approved_response);

// Update the persona
persona.voice.voice_dna = dna.into_phrases();
```
