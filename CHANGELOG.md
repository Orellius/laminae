# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-03-10

### Security
- Fixed macOS Seatbelt network policy: replaced wildcard port 443 with per-host rules from whitelisted_hosts.
- Fixed Linux sandbox: fail-closed when network isolation (unshare) fails with NetworkPolicy::None.
- Restricted DNS rules to system resolvers only (127.0.0.1, ::1) on macOS sandbox.
- Windows sandbox now applies Job Object memory and process limits.
- Added Unicode NFKC normalization in Glassbox to prevent fullwidth character bypasses.
- Expanded environment variable scrubbing (added GOOGLE_APPLICATION_CREDENTIALS, AZURE_CLIENT_SECRET, NPM_TOKEN, DOCKER_AUTH_CONFIG, KUBECONFIG, FIREBASE_TOKEN, HEROKU_API_KEY, DIGITALOCEAN_ACCESS_TOKEN).

### Added
- Typed error enums: `IroncladError`, `ShadowError`, `PsycheError`, `OllamaError`, `ClaudeError`, `OpenAIError`.
- `#[must_use]` on Glassbox and Ironclad validation functions.
- `ShadowConfig` and `ShadowError` re-exported from crate root.
- `PsycheConfig` builder methods: `with_id_model()`, `with_superego_model()`, `with_id_temperature()`, `with_ego_system_prompt()`.
- `CHANGELOG.md` following keepachangelog format.
- `cargo-audit` security scanning in CI.
- Doc-test compilation in CI.

### Changed
- Pre-compiled regexes in Shadow static/dependency/secrets analyzers (5-10x performance improvement).
- Rate limiter in Glassbox now prunes stale entries to prevent memory growth.
- Fixed `pid as i32` overflow in Ironclad process tree termination.
- Renamed internal `uuid_v4()` to `generate_finding_id()` for accuracy.

### Fixed
- Version strings in lib.rs (was 0.1) and docs (was 0.2) now match actual version.
- MSRV consistently set to 1.75 across README, CONTRIBUTING.md, and Cargo.toml.

## [0.3.0] - 2026-03-10

### Added
- Python bindings via PyO3 for Glassbox, VoiceFilter, and Cortex.
- WASM support for Glassbox, Persona (voice filter), and Cortex.
- Windows sandbox support via Job Objects in Ironclad.
- First-class Anthropic (Claude) and OpenAI-compatible EgoBackend crates.
- Criterion.rs benchmarks across all crates.
- Quality scoring in Shadow with `SecretsAnalyzer` and `DependencyAnalyzer`.
- Shadow sandbox execution stage for ephemeral container testing.
- Documentation site.

### Changed
- MSRV raised to 1.75.

## [0.2.0] - 2026-01-15

### Added
- Cortex crate for self-improving learning from user edits.
- Persona crate for voice extraction and style enforcement.
- Shadow adversarial red-teaming engine with static analysis and LLM review.
- Ironclad process sandbox with command whitelist and resource watchdog.
- Glassbox I/O containment with input/output validation, command filtering, and rate limiting.
- Ollama HTTP client crate.

### Changed
- Workspace restructured into independent crates.

[Unreleased]: https://github.com/orellius/laminae/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/orellius/laminae/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/orellius/laminae/releases/tag/v0.2.0
