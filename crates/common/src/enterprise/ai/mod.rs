/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

pub mod anthropic;
pub mod config;
pub mod error;
pub mod gemini;
pub mod limits;
pub mod ollama;
pub mod openai;
pub mod schema;
pub mod transport;
pub mod typesafe;
pub mod verdict;

pub use error::{AiError, StatusKind};
pub use limits::BreakerPolicy;
pub use schema::{PreparedFormat, SchemaNode};
pub use verdict::{
    AiCategory, AiClassifier, AiFacts, AiSignal, AiVerdict, ConfidenceSource, PreparedClassifier,
    VerbalConfidence,
};

use limits::AiLimits;
use reqwest::Client;
use serde::{Serialize, Serializer, ser::SerializeSeq};
use serde_json::value::{RawValue, to_raw_value};
use std::{
    fmt::{self, Display},
    sync::Arc,
    time::{Duration, Instant},
};
use trc::AiEvent;

pub struct AiModel {
    pub id: u64,
    pub name: Box<str>,
    pub model: Arc<str>,
    pub endpoint: Box<str>,
    pub timeout: Duration,
    pub backend: AiBackend,
    client: Client,
    limits: AiLimits,
}

pub enum AiBackend {
    Generative(GenerativeModel),
    TypeSafe,
}

pub struct GenerativeModel {
    pub dialect: Dialect,
    pub max_output_tokens: u32,
    pub temperature: Option<f32>,
    pub reasoning: Reasoning,
    pub logprobs: bool,
    pub extra: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    OpenAi(OpenAiProfile),
    Anthropic,
    Gemini,
    Ollama { keep_alive: Option<Duration> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAiProfile {
    OpenAi,
    Azure,
    Vllm,
    LlamaCpp,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reasoning {
    Default,
    Off,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy)]
pub struct AiRequest<'x> {
    pub system: Option<&'x JsonText>,
    pub user: &'x [&'x str],
    pub output: OutputSpec<'x>,
    pub temperature: Option<f32>,
    pub max_output_tokens: Option<u32>,
    pub logprobs: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputSpec<'x> {
    Text,
    Json(&'x RawValue),
}

#[derive(Debug)]
pub struct JsonText(Box<RawValue>);

#[derive(Clone, Copy)]
pub(crate) struct TextParts<'x>(pub &'x [&'x str]);

#[derive(Debug, Clone, Copy)]
pub struct AiCallOptions {
    pub deadline: Instant,
    pub breaker: BreakerPolicy,
    pub span_id: u64,
}

#[derive(Debug, Clone, Default)]
pub struct AiResponse {
    pub text: String,
    pub finish: Finish,
    pub usage: AiUsage,
    pub model: Option<Box<str>>,
    pub request_id: Option<Box<str>>,
    pub logprobs: Vec<TokenLogprob>,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Finish {
    #[default]
    Stop,
    Length,
    Refusal,
    ContentFilter,
    Other,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AiUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cached_tokens: u32,
    pub reasoning_tokens: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenLogprob {
    pub token: Box<str>,
    pub logprob: f32,
}

impl Reasoning {
    pub fn effort(self) -> Option<&'static str> {
        match self {
            Reasoning::Low => Some("low"),
            Reasoning::Medium => Some("medium"),
            Reasoning::High => Some("high"),
            Reasoning::Default | Reasoning::Off => None,
        }
    }
}

impl Finish {
    pub fn as_str(self) -> &'static str {
        match self {
            Finish::Stop => "stop",
            Finish::Length => "length",
            Finish::Refusal => "refusal",
            Finish::ContentFilter => "content_filter",
            Finish::Other => "other",
        }
    }
}

impl AiUsage {
    pub fn total(&self) -> u64 {
        self.input_tokens as u64 + self.output_tokens as u64
    }
}

impl JsonText {
    pub fn new(text: &str) -> serde_json::Result<Self> {
        to_raw_value(text).map(JsonText)
    }

    pub fn encoded_len(&self) -> usize {
        self.0.get().len()
    }
}

impl Serialize for JsonText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl TextParts<'_> {
    fn len(&self) -> usize {
        self.0.iter().map(|part| part.len()).sum()
    }
}

impl Display for TextParts<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|part| f.write_str(part))
    }
}

impl Serialize for TextParts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            [text] => serializer.serialize_str(text),
            _ => serializer.collect_str(self),
        }
    }
}

impl AiRequest<'_> {
    fn body_capacity(&self) -> usize {
        let user = TextParts(self.user).len();
        user + user / ESCAPE_HEADROOM_DIVISOR
            + self.system.map_or(0, JsonText::encoded_len)
            + match self.output {
                OutputSpec::Text => 0,
                OutputSpec::Json(format) => format.get().len(),
            }
            + REQUEST_OVERHEAD
    }
}

impl AiCallOptions {
    pub fn new(deadline: Instant) -> Self {
        AiCallOptions {
            deadline,
            breaker: BreakerPolicy::default(),
            span_id: 0,
        }
    }

    pub fn with_breaker(mut self, breaker: BreakerPolicy) -> Self {
        self.breaker = breaker;
        self
    }

    pub fn with_span_id(mut self, span_id: u64) -> Self {
        self.span_id = span_id;
        self
    }
}

impl AiModel {
    pub fn is_generative(&self) -> bool {
        matches!(self.backend, AiBackend::Generative(_))
    }

    pub fn is_available(&self, now: Instant) -> bool {
        !self.limits.breaker.is_open(now)
    }

    pub fn supports_logprobs(&self) -> bool {
        matches!(&self.backend, AiBackend::Generative(model) if model.logprobs)
    }

    pub async fn send(
        &self,
        request: &AiRequest<'_>,
        options: &AiCallOptions,
    ) -> Result<AiResponse, AiError> {
        let AiBackend::Generative(generative) = &self.backend else {
            return Err(AiError::NotSupported);
        };

        let mut body = Vec::with_capacity(request.body_capacity());
        generative.write_request(&self.model, request, &mut body)?;
        let raw = self.execute(body, options).await?;
        let mut response = generative.dialect.parse_response(&raw.body)?;
        response.request_id = raw.request_id;
        response.elapsed = raw.elapsed;
        self.emit_request_event(
            response.model.as_deref(),
            &response.usage,
            response.finish,
            response.request_id.as_deref(),
            response.elapsed,
            options.span_id,
        );

        match response.finish {
            Finish::Refusal => Err(AiError::Refusal(
                Some(response.text.trim())
                    .filter(|text| !text.is_empty())
                    .map(Box::from),
            )),
            Finish::ContentFilter => Err(AiError::ContentFilter),
            Finish::Length
                if matches!(request.output, OutputSpec::Json(_))
                    || response.text.trim().is_empty() =>
            {
                Err(AiError::Truncated)
            }
            _ if response.text.trim().is_empty() => {
                Err(AiError::InvalidResponse("Empty response".into()))
            }
            _ => Ok(response),
        }
    }

    pub(crate) fn emit_request_event(
        &self,
        resolved_model: Option<&str>,
        usage: &AiUsage,
        finish: Finish,
        request_id: Option<&str>,
        elapsed: Duration,
        span_id: u64,
    ) {
        trc::event!(
            Ai(AiEvent::Request),
            Name = self.name.clone(),
            Model = resolved_model.map(Box::<str>::from),
            InputTokens = usage.input_tokens,
            OutputTokens = usage.output_tokens,
            CachedTokens = usage.cached_tokens,
            FinishReason = finish.as_str(),
            Id = request_id.map(Box::<str>::from),
            Elapsed = elapsed,
            SpanId = span_id,
        );
    }
}

impl GenerativeModel {
    fn write_request(
        &self,
        model: &str,
        request: &AiRequest<'_>,
        body: &mut Vec<u8>,
    ) -> Result<(), AiError> {
        match self.dialect {
            Dialect::OpenAi(profile) => openai::write_request(self, profile, model, request, body),
            Dialect::Anthropic => anthropic::write_request(self, model, request, body),
            Dialect::Gemini => gemini::write_request(self, request, body),
            Dialect::Ollama { keep_alive } => {
                ollama::write_request(self, keep_alive, model, request, body)
            }
        }
        .map_err(AiError::from_serializer)?;

        if let Some(extra) = &self.extra
            && body.last() == Some(&b'}')
        {
            body.pop();
            body.push(b',');
            body.extend_from_slice(extra.as_bytes());
            body.push(b'}');
        }

        Ok(())
    }

    fn max_output_tokens(&self, request: &AiRequest<'_>) -> u32 {
        request.max_output_tokens.unwrap_or(self.max_output_tokens)
    }

    fn temperature(&self, request: &AiRequest<'_>) -> Option<f32> {
        request.temperature.or(self.temperature)
    }

    fn logprobs(&self, request: &AiRequest<'_>) -> bool {
        self.logprobs && request.logprobs
    }
}

impl Dialect {
    fn parse_response(self, body: &[u8]) -> Result<AiResponse, AiError> {
        match self {
            Dialect::OpenAi(_) => openai::parse_response(body),
            Dialect::Anthropic => anthropic::parse_response(body),
            Dialect::Gemini => gemini::parse_response(body),
            Dialect::Ollama { .. } => ollama::parse_response(body),
        }
    }
}

const REQUEST_OVERHEAD: usize = 512;
const ESCAPE_HEADROOM_DIVISOR: usize = 8;
const THINK_CLOSE: &str = "</think>";

pub(crate) struct ChatMessages<'x> {
    pub system: Option<&'x JsonText>,
    pub user: TextParts<'x>,
}

#[derive(Serialize)]
struct ChatMessage<T: Serialize> {
    role: &'static str,
    content: T,
}

impl Serialize for ChatMessages<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(1 + self.system.is_some() as usize))?;
        if let Some(system) = self.system {
            seq.serialize_element(&ChatMessage {
                role: "system",
                content: system,
            })?;
        }
        seq.serialize_element(&ChatMessage {
            role: "user",
            content: self.user,
        })?;
        seq.end()
    }
}

pub(crate) fn saturating_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

pub(crate) fn lenient_json(text: &str) -> Option<(usize, &str)> {
    let answer_start = text
        .rfind(THINK_CLOSE)
        .map_or(0, |pos| pos + THINK_CLOSE.len());
    let answer = text.as_bytes().get(answer_start..)?;
    let start = answer_start + memchr::memchr(b'{', answer)?;
    let end = answer_start + memchr::memrchr(b'}', answer)?;
    text.get(start..=end).map(|json| (start, json))
}
