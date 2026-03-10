# Recipe: Full Stack Pipeline

All six layers working together in a complete AI pipeline.

```rust
use laminae::psyche::{PsycheEngine, EgoBackend};
use laminae::persona::{PersonaExtractor, VoiceFilter, VoiceFilterConfig, compile_persona};
use laminae::cortex::{Cortex, CortexConfig};
use laminae::shadow::{ShadowEngine, ShadowEvent, create_report_store};
use laminae::glassbox::{Glassbox, GlassboxConfig};
use laminae::ollama::OllamaClient;

// 1. Set up containment (Glassbox)
let gb = Glassbox::new(GlassboxConfig::default());

// 2. Extract voice persona
let extractor = PersonaExtractor::new("qwen2.5:7b");
let persona = extractor.extract(&samples).await?;
let voice_prompt = compile_persona(&persona);

// 3. Set up learning loop (Cortex)
let mut cortex = Cortex::new(CortexConfig::default());
let learned_hints = cortex.get_prompt_block();

// 4. Build the Ego with voice + learning context
struct SmartEgo {
    voice_prompt: String,
    learned_hints: String,
}

impl EgoBackend for SmartEgo {
    fn complete(&self, system: &str, user_msg: &str, context: &str)
        -> impl Future<Output = Result<String>> + Send
    {
        let full_system = format!(
            "{context}\n\n{}\n\n{}\n\n{system}",
            self.voice_prompt,
            self.learned_hints
        );
        async move {
            // Your LLM call here
            todo!()
        }
    }
}

// 5. Create the cognitive pipeline (Psyche)
let ego = SmartEgo { voice_prompt, learned_hints };
let engine = PsycheEngine::new(OllamaClient::new(), ego);

// 6. Process a message
gb.validate_input(&user_message)?;
let response = engine.reply(&user_message).await?;

// 7. Voice filter (Persona)
let filter = VoiceFilter::new(VoiceFilterConfig::default());
let checked = filter.check(&response);
let final_response = checked.cleaned;

// 8. Output validation (Glassbox)
gb.validate_output(&final_response)?;

// 9. Async red-teaming (Shadow)
let store = create_report_store();
let shadow = ShadowEngine::new(store);
let _rx = shadow.analyze_async("session".into(), final_response.clone());
// Shadow runs in background — doesn't block the user

// 10. Send to user
send_to_user(&final_response);
```

## The Full Flow

```
User Input
  → Glassbox: validate input (injection detection)
  → Psyche: Id + Superego shape context
  → Psyche: Ego generates response (with Persona voice + Cortex hints)
  → Persona: Voice filter catches AI slop
  → Glassbox: validate output (leak detection)
  → Shadow: async red-team analysis (background)
  → User receives response
```
