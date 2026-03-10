# Cortex — Self-Improving Learning Loop

Tracks how users edit AI output and converts corrections into reusable instructions — without fine-tuning.

## How It Works

1. AI generates output
2. User edits it (shortens, removes filler, changes tone, etc.)
3. Cortex detects the edit pattern
4. Pattern becomes a reusable instruction for future generations

## 8 Pattern Types

| Pattern | What It Detects |
|---------|----------------|
| Shortened | User made it shorter |
| Removed Questions | User stripped trailing questions |
| Stripped AI Phrases | User removed "furthermore", "it's worth noting" |
| Tone Shifts | User changed formality level |
| Added Content | User added information the AI missed |
| Simplified Language | User replaced jargon with plain words |
| Changed Openers | User rewrote the first sentence |
| Structural Change | User reorganized paragraphs |

## Usage

```rust
use laminae::cortex::{Cortex, CortexConfig};

let mut cortex = Cortex::new(CortexConfig::default());

// Track edits over time
cortex.track_edit(
    "It's worth noting that Rust is fast.",
    "Rust is fast."
);
cortex.track_edit(
    "Furthermore, the type system is robust.",
    "The type system catches bugs."
);

// Detect patterns
let patterns = cortex.detect_patterns();
// → [RemovedAiPhrases: 100%, Shortened: 100%]

// Get prompt block for LLM injection
let hints = cortex.get_prompt_block();
// → "--- USER PREFERENCES (learned from actual edits) ---
//    - Never use academic hedging phrases
//    - Keep sentences short and direct
//    ---"
```

## Instruction Deduplication

Instructions are ranked by reinforcement count. When a new instruction has >80% word overlap with an existing one, it increments the existing instruction's count instead of creating a duplicate.

## Performance

Edit tracking is near-instant (85 ns per edit). Pattern detection scales linearly — 500 accumulated edits analyzed in ~2 ms.
