//! Optional AI judgment layer. Deterministic analysis resolves every
//! high-confidence finding on its own; this layer sends only the *ambiguous*
//! cases to a language model for a keep/delete/deprecate decision.
//!
//! Provider-neutral: it speaks the OpenAI-compatible chat-completions API, so
//! it works with any endpoint that implements it - a hosted API, a local
//! runner (ollama, llama.cpp, vLLM, LM Studio), or your own gateway. Configure
//! it entirely through the environment; nothing is hard-coded and nothing is
//! contacted unless you set an endpoint:
//!
//! * `VERUM_AI_ENDPOINT` - full chat-completions URL (e.g.
//!   `http://localhost:11434/v1/chat/completions`). Required; no network
//!   activity without it.
//! * `VERUM_AI_API_KEY` - bearer token, if the endpoint needs one.
//! * `VERUM_AI_MODEL` - model name to request (default `default`).

pub mod executor;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use verum_nucleus::{DecisionRequest, DecisionResponse};

pub struct AiHandoff {
    pub endpoint: Option<String>,
    pub api_key: Option<String>,
    pub model: String,
    pub max_tokens: u32,
}

impl Default for AiHandoff {
    fn default() -> Self {
        Self {
            endpoint: std::env::var("VERUM_AI_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty()),
            api_key: std::env::var("VERUM_AI_API_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
            model: std::env::var("VERUM_AI_MODEL").unwrap_or_else(|_| "default".to_string()),
            max_tokens: 8000,
        }
    }
}

#[derive(Serialize)]
pub struct HandoffRequest {
    pub verum_version: String,
    pub session_id: String,
    pub score_before: u8,
    pub auto_fixed: usize,
    pub decisions_needed: Vec<DecisionRequest>,
}

pub struct HandoffResult {
    pub decisions: Vec<DecisionResponse>,
    pub tokens_used: u32,
}

const SYSTEM_PROMPT: &str = r#"You are the judgment layer in a deterministic code-analysis pipeline.

The pipeline has already completed full deterministic analysis: mapped every
symbol, traced every call, analysed every flow. All high-confidence findings
have been auto-resolved.

You are presented ONLY with ambiguous cases requiring judgment.

For each decision:
1. Read the finding and context carefully
2. Choose the most appropriate action from the options provided
3. Provide brief reasoning (1-2 sentences maximum)
4. Be conservative: when uncertain, choose keep not delete

Return ONLY valid JSON. No markdown. No code blocks. No preamble.

Schema:
{
  "decisions": [
    {
      "id": "string",
      "action": "string (must be one of the provided options)",
      "reasoning": "string",
      "confidence": number
    }
  ]
}"#;

// OpenAI-compatible chat-completions request/response shapes.
#[derive(Serialize)]
struct ApiRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<ApiMessage>,
}

#[derive(Serialize)]
struct ApiMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ApiResponse {
    choices: Vec<Choice>,
    usage: Option<Usage>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: Option<String>,
}

#[derive(Deserialize)]
struct Usage {
    completion_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct DecisionsWrapper {
    decisions: Vec<DecisionResponse>,
}

/// Strip markdown code fences a model may wrap around JSON despite instructions
/// ("```json\n...\n```").
fn strip_code_fences(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(rest) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let rest = rest.split_once('\n').map(|(_, body)| body).unwrap_or(rest);
    rest.strip_suffix("```").unwrap_or(rest).trim()
}

impl AiHandoff {
    pub fn new() -> Self {
        Self::default()
    }

    /// True when an endpoint is configured. Without one, the layer is inert and
    /// makes no network calls.
    pub fn is_available(&self) -> bool {
        self.endpoint.is_some()
    }

    pub async fn send(&self, request: &HandoffRequest) -> Result<HandoffResult> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("VERUM_AI_ENDPOINT not set"))?;

        // The full handoff envelope (version, session, score, auto-fix count)
        // gives the model context to calibrate its judgment.
        let user_content = serde_json::to_string_pretty(request)?;

        let api_request = ApiRequest {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            messages: vec![
                ApiMessage {
                    role: "system".to_string(),
                    content: SYSTEM_PROMPT.to_string(),
                },
                ApiMessage {
                    role: "user".to_string(),
                    content: user_content,
                },
            ],
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(180))
            .build()?;
        let mut req = client
            .post(endpoint)
            .header("content-type", "application/json")
            .json(&api_request);
        if let Some(key) = &self.api_key {
            req = req.header("authorization", format!("Bearer {key}"));
        }
        let response = req.send().await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "AI endpoint returned {}: {}",
                status,
                body.chars().take(500).collect::<String>()
            );
        }

        let api_response: ApiResponse = response.json().await?;
        let choice = api_response
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("AI endpoint returned no choices"))?;

        if choice.finish_reason.as_deref() == Some("length") {
            anyhow::bail!(
                "AI response was truncated at {} tokens - reduce the batch of \
                 decisions or raise max_tokens",
                self.max_tokens
            );
        }

        let text = choice
            .message
            .content
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("No content in AI response"))?;

        let wrapper: DecisionsWrapper = serde_json::from_str(strip_code_fences(&text))?;
        let tokens_used = api_response
            .usage
            .and_then(|u| u.completion_tokens)
            .unwrap_or(0);

        Ok(HandoffResult {
            decisions: wrapper.decisions,
            tokens_used,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::strip_code_fences;

    #[test]
    fn strips_fenced_json() {
        assert_eq!(strip_code_fences("{\"a\":1}"), "{\"a\":1}");
        assert_eq!(strip_code_fences("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(strip_code_fences("```\n{\"a\":1}\n```"), "{\"a\":1}");
    }
}
