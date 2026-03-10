//! Python bindings for Laminae via PyO3.
//!
//! Exposes the browser-compatible layers to Python:
//! - **Glassbox** — Input/output validation, command filtering, rate limiting
//! - **Persona** — Voice filter (AI phrase detection), voice DNA tracking
//! - **Cortex** — Edit tracking, pattern detection, prompt block generation

use pyo3::prelude::*;

// ══════════════════════════════════════════════════════════
// Glassbox — I/O Containment
// ══════════════════════════════════════════════════════════

/// Python wrapper for Glassbox I/O containment.
///
/// Usage:
///     from laminae import Glassbox
///     gb = Glassbox()
///     gb.add_immutable_zone("/etc")
///     gb.validate_input("Hello")  # OK
///     gb.validate_command("rm -rf /")  # raises ValueError
#[pyclass]
struct Glassbox {
    inner: laminae_glassbox::Glassbox,
}

#[pymethods]
impl Glassbox {
    #[new]
    fn new() -> Self {
        Self {
            inner: laminae_glassbox::Glassbox::new(laminae_glassbox::GlassboxConfig::default()),
        }
    }

    /// Validate user input for prompt injection attempts.
    fn validate_input(&self, text: &str) -> PyResult<()> {
        self.inner
            .validate_input(text)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    /// Validate a command before execution.
    fn validate_command(&self, command: &str) -> PyResult<()> {
        self.inner
            .validate_command(command)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    /// Validate a file write path against immutable zones.
    fn validate_write_path(&self, path: &str) -> PyResult<()> {
        self.inner
            .validate_write_path(path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    /// Validate AI output for system prompt leaks.
    fn validate_output(&self, text: &str) -> PyResult<()> {
        self.inner
            .validate_output(text)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
}

// ══════════════════════════════════════════════════════════
// Persona — Voice Filter
// ══════════════════════════════════════════════════════════

/// Result from voice filter check.
#[pyclass]
#[derive(Clone)]
struct VoiceCheckResult {
    #[pyo3(get)]
    passed: bool,
    #[pyo3(get)]
    cleaned: String,
    #[pyo3(get)]
    violations: Vec<String>,
    #[pyo3(get)]
    severity: u8,
    #[pyo3(get)]
    retry_hints: Vec<String>,
}

/// Voice filter that catches AI-sounding output.
///
/// Usage:
///     from laminae import VoiceFilter
///     f = VoiceFilter()
///     result = f.check("It's important to note that...")
///     print(result.passed)  # False
///     print(result.violations)  # ["AI vocabulary detected: ..."]
#[pyclass]
struct VoiceFilter {
    inner: laminae_persona::VoiceFilter,
}

#[pymethods]
impl VoiceFilter {
    #[new]
    #[pyo3(signature = (max_sentences=0, max_chars=0, reject_trailing_questions=true, fix_em_dashes=true))]
    fn new(
        max_sentences: usize,
        max_chars: usize,
        reject_trailing_questions: bool,
        fix_em_dashes: bool,
    ) -> Self {
        Self {
            inner: laminae_persona::VoiceFilter::new(laminae_persona::VoiceFilterConfig {
                extra_ai_phrases: Vec::new(),
                max_sentences,
                max_chars,
                reject_trailing_questions,
                fix_em_dashes,
                reject_multi_paragraph: false,
            }),
        }
    }

    /// Check text for AI-sounding patterns.
    fn check(&self, text: &str) -> VoiceCheckResult {
        let result = self.inner.check(text);
        VoiceCheckResult {
            passed: result.passed,
            cleaned: result.cleaned,
            violations: result.violations,
            severity: result.severity,
            retry_hints: result.retry_hints,
        }
    }
}

// ══════════════════════════════════════════════════════════
// Cortex — Learning Loop
// ══════════════════════════════════════════════════════════

/// Edit pattern detected by Cortex.
#[pyclass]
#[derive(Clone)]
struct EditPattern {
    #[pyo3(get)]
    pattern_type: String,
    #[pyo3(get)]
    frequency_pct: f64,
    #[pyo3(get)]
    count: usize,
    #[pyo3(get)]
    examples: Vec<(String, String)>,
}

/// Self-improving learning loop.
///
/// Usage:
///     from laminae import Cortex
///     c = Cortex()
///     c.track_edit("It's worth noting X.", "X.")
///     c.track_edit("Furthermore, Y is true.", "Y is true.")
///     patterns = c.detect_patterns()
///     hints = c.get_prompt_block()
#[pyclass]
struct Cortex {
    inner: laminae_cortex::Cortex,
}

#[pymethods]
impl Cortex {
    #[new]
    #[pyo3(signature = (min_edits=5))]
    fn new(min_edits: usize) -> Self {
        Self {
            inner: laminae_cortex::Cortex::new(laminae_cortex::CortexConfig {
                min_edits_for_detection: min_edits,
                ..Default::default()
            }),
        }
    }

    /// Track an edit: AI generated `original`, user changed it to `edited`.
    fn track_edit(&mut self, original: &str, edited: &str) {
        self.inner.track_edit(original, edited);
    }

    /// Detect edit patterns from tracked edits.
    fn detect_patterns(&self) -> Vec<EditPattern> {
        self.inner
            .detect_patterns()
            .into_iter()
            .map(|p| EditPattern {
                pattern_type: format!("{:?}", p.pattern_type),
                frequency_pct: p.frequency_pct,
                count: p.count,
                examples: p.examples,
            })
            .collect()
    }

    /// Get learned instructions as a prompt block string.
    fn get_prompt_block(&self) -> String {
        self.inner.get_prompt_block()
    }

    /// Get edit statistics.
    fn stats(&self) -> PyResult<PyObject> {
        let stats = self.inner.stats();
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("total_edits", stats.total_edits)?;
            dict.set_item("edited_count", stats.edited_count)?;
            dict.set_item("unedited_count", stats.unedited_count)?;
            dict.set_item("edit_rate", stats.edit_rate)?;
            dict.set_item("instruction_count", stats.instruction_count)?;
            Ok(dict.into())
        })
    }
}

// ══════════════════════════════════════════════════════════
// Module Registration
// ══════════════════════════════════════════════════════════

/// Laminae — Python bindings for the AI safety SDK.
#[pymodule]
fn laminae(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Glassbox>()?;
    m.add_class::<VoiceFilter>()?;
    m.add_class::<VoiceCheckResult>()?;
    m.add_class::<Cortex>()?;
    m.add_class::<EditPattern>()?;
    Ok(())
}
