//! # Laminae — The Missing Layer Between Raw LLMs and Production AI
//!
//! Laminae is a modular SDK that adds personality, safety, sandboxing, and
//! containment to any AI application. Each layer works independently or
//! together as a full stack.
//!
//! ## The Four Layers
//!
//! | Layer | Crate | What It Does |
//! |-------|-------|-------------|
//! | **Psyche** | [`laminae-psyche`] | Multi-agent cognitive pipeline (Id + Superego → Ego) |
//! | **Shadow** | [`laminae-shadow`] | Adversarial red-teaming of AI output |
//! | **Ironclad** | [`laminae-ironclad`] | Process-level execution sandbox |
//! | **Glassbox** | [`laminae-glassbox`] | Input/output containment layer |
//!
//! Plus [`laminae-ollama`] for local LLM inference via Ollama.
//!
//! ## Quick Start
//!
//! ```toml
//! [dependencies]
//! laminae = "0.1"
//! ```
//!
//! Use individual crates for fine-grained control, or this meta-crate
//! for the full stack.

/// Multi-agent cognitive pipeline — personality and safety through
/// Id (creative), Superego (safety), and Ego (your LLM).
pub use laminae_psyche as psyche;

/// Adversarial red-teaming engine — automated security auditing
/// of AI output via static analysis, LLM review, and sandbox execution.
pub use laminae_shadow as shadow;

/// Process-level execution sandbox — command whitelist, network filter,
/// resource watchdog with SIGKILL.
pub use laminae_ironclad as ironclad;

/// Input/output containment — rate limiting, command blocklists,
/// immutable zones, injection prevention.
pub use laminae_glassbox as glassbox;

/// Ollama client for local LLM inference.
pub use laminae_ollama as ollama;
