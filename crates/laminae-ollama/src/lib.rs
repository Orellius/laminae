//! # laminae-ollama — Ollama Client for Local LLM Inference
//!
//! Standalone HTTP client for [Ollama](https://ollama.ai). Supports both
//! blocking and streaming completions via the `/api/chat` endpoint.
//!
//! Zero internal dependencies — this crate talks to a local Ollama instance
//! and nothing else.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use laminae_ollama::OllamaClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = OllamaClient::new();
//!
//!     if !client.is_available().await {
//!         eprintln!("Ollama is not running — start it with `ollama serve`");
//!         return Ok(());
//!     }
//!
//!     let response = client.complete(
//!         "llama3.2",
//!         "You are a helpful assistant.",
//!         "What is 2 + 2?",
//!         0.7,
//!         256,
//!     ).await?;
//!
//!     println!("{response}");
//!     Ok(())
//! }
//! ```

use anyhow::{Context, Result};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;

// ── Typed Errors ──

/// Typed errors for the Ollama client.
#[derive(Debug, Error)]
pub enum OllamaError {
    /// Failed to connect to the Ollama server.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Request timed out waiting for a response.
    #[error("request timed out")]
    Timeout,

    /// The server returned a response that could not be parsed.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// The requested model is not available locally.
    #[error("model not found: {0}")]
    ModelNotFound(String),

    /// The Ollama server returned an HTTP error status.
    #[error("server error (HTTP {0})")]
    ServerError(u16),
}

/// Default Ollama API endpoint.
const DEFAULT_BASE_URL: &str = "http://127.0.0.1:11434";
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const RETRY_BACKOFF_MS: u64 = 1000;

/// Client for Ollama's local LLM API.
///
/// Runs entirely on-device — zero cost, no API key, no network egress.
#[derive(Clone)]
pub struct OllamaClient {
    http: reqwest::Client,
    base_url: String,
}

/// Configuration for creating an [`OllamaClient`].
#[derive(Debug, Clone)]
pub struct OllamaConfig {
    /// Base URL for the Ollama API (default: `http://127.0.0.1:11434`).
    pub base_url: String,
    /// Request timeout in seconds (default: 60).
    pub timeout_secs: u64,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    stream: bool,
    options: ChatOptions,
}

#[derive(Serialize)]
struct ChatOptions {
    temperature: f32,
    num_predict: i32,
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    message: Option<ResponseMessage>,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: String,
}

#[derive(Deserialize)]
struct StreamResponse {
    message: Option<ResponseMessage>,
    #[serde(default)]
    done: bool,
}

#[derive(Deserialize)]
struct TagsResponse {
    models: Option<Vec<ModelInfo>>,
}

#[derive(Deserialize)]
struct ModelInfo {
    name: String,
}

impl OllamaClient {
    /// Create a client with default settings (localhost:11434, 60s timeout).
    pub fn new() -> Self {
        Self::with_config(OllamaConfig::default())
    }

    /// Create a client with custom configuration.
    pub fn with_config(config: OllamaConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .unwrap_or_default();

        Self {
            http,
            base_url: config.base_url,
        }
    }

    /// Check if Ollama is running and reachable.
    pub async fn is_available(&self) -> bool {
        let url = format!("{}/api/tags", self.base_url);
        self.http
            .get(&url)
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Check if a specific model is pulled locally.
    pub async fn has_model(&self, model: &str) -> bool {
        let url = format!("{}/api/tags", self.base_url);
        match self.http.get(&url).send().await {
            Ok(resp) => {
                if let Ok(tags) = resp.json::<TagsResponse>().await {
                    if let Some(models) = tags.models {
                        return models
                            .iter()
                            .any(|m| m.name == model || m.name.starts_with(&format!("{model}:")));
                    }
                }
                false
            }
            Err(_) => false,
        }
    }

    /// Send a completion request (non-streaming).
    ///
    /// Retries once on transient connection errors.
    pub async fn complete(
        &self,
        model: &str,
        system: &str,
        user_message: &str,
        temperature: f32,
        max_tokens: i32,
    ) -> Result<String> {
        let body = ChatRequest {
            model,
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: system,
                },
                ChatMessage {
                    role: "user",
                    content: user_message,
                },
            ],
            stream: false,
            options: ChatOptions {
                temperature,
                num_predict: max_tokens,
            },
        };

        match self.send_request(&body).await {
            Ok(text) => return Ok(text),
            Err(e) => {
                if Self::is_retryable(&e) {
                    tracing::warn!(
                        "Ollama retryable error: {e} — retrying in {RETRY_BACKOFF_MS}ms"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(RETRY_BACKOFF_MS)).await;
                } else {
                    return Err(e);
                }
            }
        }

        self.send_request(&body).await
    }

    /// Send a completion with full message history (multi-turn conversation).
    pub async fn complete_with_history(
        &self,
        model: &str,
        messages: &[(&str, &str)], // (role, content) pairs
        temperature: f32,
        max_tokens: i32,
    ) -> Result<String> {
        let chat_messages: Vec<ChatMessage<'_>> = messages
            .iter()
            .map(|(role, content)| ChatMessage { role, content })
            .collect();

        let body = ChatRequest {
            model,
            messages: chat_messages,
            stream: false,
            options: ChatOptions {
                temperature,
                num_predict: max_tokens,
            },
        };

        self.send_request(&body).await
    }

    async fn send_request(&self, body: &ChatRequest<'_>) -> Result<String> {
        let url = format!("{}/api/chat", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .context("Failed to reach Ollama — is it running? (ollama serve)")?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ollama error ({}): {}", status.as_u16(), body_text);
        }

        let response: ChatResponse = resp
            .json()
            .await
            .context("Failed to parse Ollama response")?;

        let text = response.message.map(|m| m.content).unwrap_or_default();

        if text.trim().is_empty() {
            anyhow::bail!("Empty response from Ollama");
        }

        Ok(text)
    }

    /// Streaming completion — yields text chunks via an mpsc channel.
    ///
    /// ```rust,no_run
    /// # use laminae_ollama::OllamaClient;
    /// # async fn example() -> anyhow::Result<()> {
    /// let client = OllamaClient::new();
    /// let mut rx = client.complete_streaming(
    ///     "llama3.2", "You are helpful.", "Hello!", 0.7, 256,
    /// ).await?;
    ///
    /// while let Some(chunk) = rx.recv().await {
    ///     print!("{chunk}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn complete_streaming(
        &self,
        model: &str,
        system: &str,
        user_message: &str,
        temperature: f32,
        max_tokens: i32,
    ) -> Result<mpsc::Receiver<String>> {
        let (tx, rx) = mpsc::channel(64);

        let url = format!("{}/api/chat", self.base_url);
        let body = ChatRequest {
            model,
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: system,
                },
                ChatMessage {
                    role: "user",
                    content: user_message,
                },
            ],
            stream: true,
            options: ChatOptions {
                temperature,
                num_predict: max_tokens,
            },
        };

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Failed to reach Ollama for streaming")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "Ollama streaming error ({}): {}",
                status.as_u16(),
                body_text
            );
        }

        tokio::spawn(async move {
            let mut stream = resp.bytes_stream();
            let mut buffer = String::new();

            while let Some(chunk_result) = stream.next().await {
                let bytes = match chunk_result {
                    Ok(b) => b,
                    Err(_) => break,
                };

                buffer.push_str(&String::from_utf8_lossy(&bytes));

                while let Some(newline_pos) = buffer.find('\n') {
                    let line = buffer[..newline_pos].to_string();
                    buffer = buffer[newline_pos + 1..].to_string();

                    if line.trim().is_empty() {
                        continue;
                    }

                    if let Ok(resp) = serde_json::from_str::<StreamResponse>(&line) {
                        if let Some(msg) = resp.message {
                            if !msg.content.is_empty() && tx.send(msg.content).await.is_err() {
                                return;
                            }
                        }
                        if resp.done {
                            return;
                        }
                    }
                }
            }
        });

        Ok(rx)
    }

    fn is_retryable(error: &anyhow::Error) -> bool {
        let msg = error.to_string();
        msg.contains("connection refused")
            || msg.contains("timeout")
            || msg.contains("Connection reset")
    }
}

impl Default for OllamaClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = OllamaClient::new();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn test_custom_config() {
        let client = OllamaClient::with_config(OllamaConfig {
            base_url: "http://10.0.0.5:11434".to_string(),
            timeout_secs: 120,
        });
        assert_eq!(client.base_url, "http://10.0.0.5:11434");
    }

    #[test]
    fn test_retryable_errors() {
        assert!(OllamaClient::is_retryable(&anyhow::anyhow!(
            "connection refused"
        )));
        assert!(OllamaClient::is_retryable(&anyhow::anyhow!(
            "request timeout"
        )));
        assert!(!OllamaClient::is_retryable(&anyhow::anyhow!(
            "model not found"
        )));
    }

    #[test]
    fn test_default_config() {
        let config = OllamaConfig::default();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.timeout_secs, 60);
    }
}
