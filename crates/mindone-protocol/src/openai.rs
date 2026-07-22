use serde::{Deserialize, Serialize};

use crate::common::{validate_identifier, Validate};
use crate::ProtocolValidationError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAiModel {
    pub id: String,
    #[serde(default = "model_object")]
    pub object: String,
    pub created: i64,
    pub owned_by: String,
}

fn model_object() -> String {
    "model".to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelsResponse {
    #[serde(default = "list_object")]
    pub object: String,
    pub data: Vec<OpenAiModel>,
}

fn list_object() -> String {
    "list".to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    Developer,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text { text: String },
    ImageUrl { image_url: ImageUrl },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageUrl {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: MessageContent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatCompletionsRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// 固定采样随机种子；受管 llama.cpp 隐藏评价用它绑定确定性行为指纹。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopSequences>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl Validate for ChatCompletionsRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_identifier("model", &self.model, 256)?;
        if self.messages.is_empty() {
            return Err(ProtocolValidationError::new("messages", "至少需要一条消息"));
        }
        validate_sampling(
            self.temperature,
            self.top_p,
            self.max_tokens.or(self.max_completion_tokens),
            self.n,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StopSequences {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCompletionsResponse {
    pub id: String,
    pub object: String,
    pub created: i64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: Usage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: Option<FinishReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    Length,
    ContentFilter,
    ToolCalls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionsRequest {
    pub model: String,
    pub prompt: Prompt,
    #[serde(default)]
    pub stream: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopSequences>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl Validate for CompletionsRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_identifier("model", &self.model, 256)?;
        let has_prompt = match &self.prompt {
            Prompt::One(value) => !value.is_empty(),
            Prompt::Many(values) => {
                !values.is_empty() && values.iter().all(|value| !value.is_empty())
            }
        };
        if !has_prompt {
            return Err(ProtocolValidationError::new("prompt", "prompt 不能为空"));
        }
        validate_sampling(self.temperature, self.top_p, self.max_tokens, self.n)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Prompt {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionsResponse {
    pub id: String,
    pub object: String,
    pub created: i64,
    pub model: String,
    pub choices: Vec<CompletionChoice>,
    pub usage: Usage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionChoice {
    pub text: String,
    pub index: u32,
    pub finish_reason: Option<FinishReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatCompletionChunk {
    pub id: String,
    pub object: String,
    pub created: i64,
    pub model: String,
    pub choices: Vec<ChatChunkChoice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatChunkChoice {
    pub index: u32,
    pub delta: ChatDelta,
    pub finish_reason: Option<FinishReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ChatDelta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<ChatRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAiErrorResponse {
    pub error: OpenAiError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAiError {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

fn validate_sampling(
    temperature: Option<f64>,
    top_p: Option<f64>,
    max_tokens: Option<u32>,
    n: Option<u32>,
) -> Result<(), ProtocolValidationError> {
    if temperature.is_some_and(|value| !value.is_finite() || !(0.0..=2.0).contains(&value)) {
        return Err(ProtocolValidationError::new(
            "temperature",
            "必须在 0 到 2 之间",
        ));
    }
    if top_p.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
        return Err(ProtocolValidationError::new("top_p", "必须在 0 到 1 之间"));
    }
    if max_tokens == Some(0) {
        return Err(ProtocolValidationError::new("max_tokens", "必须大于零"));
    }
    if n.is_some_and(|value| !(1..=16).contains(&value)) {
        return Err(ProtocolValidationError::new("n", "必须在 1 到 16 之间"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_chat_example() {
        let request: ChatCompletionsRequest = serde_json::from_value(serde_json::json!({
            "model": "auto",
            "messages": [{"role": "user", "content": "只回复：MindOne 已连接"}]
        }))
        .expect("规范示例应可解析");
        assert!(!request.stream);
        assert!(request.validate().is_ok());
        assert_eq!(request.messages[0].role, ChatRole::User);
    }

    #[test]
    fn stream_flag_is_preserved_for_proxy_decision() {
        let request: ChatCompletionsRequest = serde_json::from_value(serde_json::json!({
            "model": "auto",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true
        }))
        .expect("应可解析 stream 请求");
        assert!(request.stream);
    }

    #[test]
    fn validates_sampling_limits() {
        let request = ChatCompletionsRequest {
            model: "auto".to_owned(),
            messages: vec![ChatMessage {
                role: ChatRole::User,
                content: MessageContent::Text("hello".to_owned()),
                name: None,
                tool_call_id: None,
            }],
            stream: false,
            max_tokens: Some(0),
            max_completion_tokens: None,
            temperature: Some(3.0),
            top_p: None,
            seed: None,
            n: None,
            stop: None,
            user: None,
        };
        assert!(request.validate().is_err());
    }
}
