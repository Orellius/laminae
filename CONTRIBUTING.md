# Contributing to Laminae

Thanks for your interest in Laminae. Here's how to contribute.

## Getting Started

```bash
git clone https://github.com/Orellius/laminae.git
cd laminae
cargo test --all
```

**Requirements:**
- Rust 1.75+
- Ollama (optional — needed for Psyche/Shadow LLM tests)

## Development Workflow

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run the full check suite:

```bash
cargo fmt --all          # Format
cargo clippy --all-targets -- -D warnings  # Lint
cargo test --all         # Test
```

4. Open a pull request against `main`

## What to Contribute

**High-impact areas:**
- New `Analyzer` implementations for Shadow (e.g., SAST for specific languages, dependency auditing)
- `EgoBackend` implementations for popular LLM providers
- `GlassboxLogger` implementations for logging frameworks (log, slog, etc.)
- Linux support for Ironclad (currently macOS-only via `sandbox-exec`)
- Documentation improvements and examples

**Before starting large changes**, open an issue to discuss the approach.

## Code Guidelines

- Follow standard Rust idioms
- Use `thiserror` for error types, `anyhow` for application errors
- Use `tracing` for logging (not `println!`)
- No `unwrap()` in library code — return `Result`
- Tests go in `#[cfg(test)] mod tests` blocks in the same file
- Keep dependencies minimal — every new dep is a liability

## Architecture Rules

- Each crate must work independently (except declared dependencies)
- No hardcoded paths — all paths must be configurable
- Security layers (Glassbox, Ironclad) must be deterministic — no LLM reasoning in the enforcement path
- The LLM operates *inside* containment, never outside it

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
