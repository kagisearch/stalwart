/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use super::{
    AiError, AiRequest, AiResponse, AiUsage, ChatMessages, Finish, GenerativeModel, OpenAiProfile,
    OutputSpec, Reasoning, TextParts, TokenLogprob, saturating_u32,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

#[derive(Serialize)]
struct ChatRequest<'x> {
    model: &'x str,
    messages: ChatMessages<'x>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chat_template_kwargs: Option<TemplateKwargs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<&'x RawValue>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    logprobs: bool,
}

#[derive(Serialize)]
struct TemplateKwargs {
    enable_thinking: bool,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ChatResponse {
    model: Option<Box<str>>,
    choices: Vec<ChatChoice>,
    usage: ChatUsage,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ChatChoice {
    message: ChatMessage,
    finish_reason: Option<Box<str>>,
    logprobs: Option<ChatLogprobs>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ChatMessage {
    content: Option<Content>,
    refusal: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Content {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ContentPart {
    text: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ChatLogprobs {
    content: Option<Vec<ChatTokenLogprob>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ChatTokenLogprob {
    token: Box<str>,
    logprob: f32,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ChatUsage {
    prompt_tokens: u64,
    completion_tokens: u64,
    prompt_tokens_details: Option<PromptDetails>,
    completion_tokens_details: Option<CompletionDetails>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PromptDetails {
    cached_tokens: u64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CompletionDetails {
    reasoning_tokens: u64,
}

impl OpenAiProfile {
    fn uses_max_completion_tokens(self) -> bool {
        matches!(self, OpenAiProfile::OpenAi | OpenAiProfile::Azure)
    }
}

pub(crate) fn write_request(
    model: &GenerativeModel,
    profile: OpenAiProfile,
    model_id: &str,
    request: &AiRequest<'_>,
    body: &mut Vec<u8>,
) -> serde_json::Result<()> {
    let max_tokens = model.max_output_tokens(request);
    let (reasoning_effort, chat_template_kwargs) = match (model.reasoning, profile) {
        (Reasoning::Default, _) => (None, None),
        (Reasoning::Off, OpenAiProfile::Vllm) => (
            None,
            Some(TemplateKwargs {
                enable_thinking: false,
            }),
        ),
        (Reasoning::Off, _) => (Some("none"), None),
        (reasoning, _) => (reasoning.effort(), None),
    };

    serde_json::to_writer(
        body,
        &ChatRequest {
            model: model_id,
            messages: ChatMessages {
                system: request.system,
                user: TextParts(request.user),
            },
            max_tokens: (!profile.uses_max_completion_tokens()).then_some(max_tokens),
            max_completion_tokens: profile.uses_max_completion_tokens().then_some(max_tokens),
            temperature: model.temperature(request),
            reasoning_effort,
            chat_template_kwargs,
            response_format: match request.output {
                OutputSpec::Text => None,
                OutputSpec::Json(format) => Some(format),
            },
            logprobs: model.logprobs(request),
        },
    )
}

pub(crate) fn parse_response(body: &[u8]) -> Result<AiResponse, AiError> {
    let response = serde_json::from_slice::<ChatResponse>(body).map_err(AiError::from_parser)?;
    let choice = response
        .choices
        .into_iter()
        .next()
        .ok_or_else(|| AiError::InvalidResponse("Response contains no choices".into()))?;

    let refusal = choice
        .message
        .refusal
        .filter(|text| !text.trim().is_empty());
    let mut finish = choice
        .finish_reason
        .as_deref()
        .map_or(Finish::Stop, finish_reason);
    let text = if let Some(refusal) = refusal {
        finish = Finish::Refusal;
        refusal
    } else {
        match choice.message.content {
            Some(Content::Text(text)) => text,
            Some(Content::Parts(parts)) => parts.into_iter().filter_map(|part| part.text).collect(),
            None => String::new(),
        }
    };

    let usage = response.usage;
    Ok(AiResponse {
        text,
        finish,
        usage: AiUsage {
            input_tokens: saturating_u32(usage.prompt_tokens),
            output_tokens: saturating_u32(usage.completion_tokens),
            cached_tokens: saturating_u32(
                usage
                    .prompt_tokens_details
                    .map_or(0, |details| details.cached_tokens),
            ),
            reasoning_tokens: saturating_u32(
                usage
                    .completion_tokens_details
                    .map_or(0, |details| details.reasoning_tokens),
            ),
        },
        model: response.model,
        logprobs: choice
            .logprobs
            .and_then(|logprobs| logprobs.content)
            .unwrap_or_default()
            .into_iter()
            .map(|token| TokenLogprob {
                token: token.token,
                logprob: token.logprob,
            })
            .collect(),
        ..Default::default()
    })
}

fn finish_reason(reason: &str) -> Finish {
    hashify::map!(reason.as_bytes(), Finish,
        "stop" => Finish::Stop,
        "length" => Finish::Length,
        "content_filter" => Finish::ContentFilter,
        "refusal" => Finish::Refusal,
    )
    .copied()
    .unwrap_or(Finish::Other)
}
