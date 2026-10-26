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
    AiError, AiRequest, AiResponse, AiUsage, Finish, GenerativeModel, JsonText, OutputSpec,
    Reasoning, TextParts, TokenLogprob, saturating_u32,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateRequest<'x> {
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<RequestContent<&'x JsonText>>,
    contents: [RequestContent<TextParts<'x>>; 1],
    generation_config: GenerationConfig<'x>,
}

#[derive(Serialize)]
struct RequestContent<T: Serialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'static str>,
    parts: [RequestPart<T>; 1],
}

#[derive(Serialize)]
struct RequestPart<T: Serialize> {
    text: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerationConfig<'x> {
    max_output_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_mime_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_json_schema: Option<&'x RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking_config: Option<ThinkingConfig>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    response_logprobs: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThinkingConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking_budget: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking_level: Option<&'static str>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct GenerateResponse {
    candidates: Vec<Candidate>,
    prompt_feedback: Option<PromptFeedback>,
    usage_metadata: UsageMetadata,
    model_version: Option<Box<str>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Candidate {
    content: Option<CandidateContent>,
    finish_reason: Option<Box<str>>,
    logprobs_result: Option<LogprobsResult>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CandidateContent {
    parts: Vec<CandidatePart>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CandidatePart {
    text: Option<String>,
    thought: bool,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct LogprobsResult {
    chosen_candidates: Vec<ChosenCandidate>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ChosenCandidate {
    token: Box<str>,
    log_probability: f32,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct PromptFeedback {
    block_reason: Option<Box<str>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct UsageMetadata {
    prompt_token_count: u64,
    candidates_token_count: u64,
    cached_content_token_count: u64,
    thoughts_token_count: u64,
}

pub(crate) fn write_request(
    model: &GenerativeModel,
    request: &AiRequest<'_>,
    body: &mut Vec<u8>,
) -> serde_json::Result<()> {
    let (response_mime_type, response_json_schema) = match request.output {
        OutputSpec::Text => (None, None),
        OutputSpec::Json(format) => (Some("application/json"), Some(format)),
    };
    let thinking_config = match model.reasoning {
        Reasoning::Default => None,
        Reasoning::Off => Some(ThinkingConfig {
            thinking_budget: Some(0),
            thinking_level: None,
        }),
        reasoning => Some(ThinkingConfig {
            thinking_budget: None,
            thinking_level: reasoning.effort(),
        }),
    };

    serde_json::to_writer(
        body,
        &GenerateRequest {
            system_instruction: request.system.map(|text| RequestContent {
                role: None,
                parts: [RequestPart { text }],
            }),
            contents: [RequestContent {
                role: Some("user"),
                parts: [RequestPart {
                    text: TextParts(request.user),
                }],
            }],
            generation_config: GenerationConfig {
                max_output_tokens: model.max_output_tokens(request),
                temperature: model.temperature(request),
                response_mime_type,
                response_json_schema,
                thinking_config,
                response_logprobs: model.logprobs(request),
            },
        },
    )
}

pub(crate) fn parse_response(body: &[u8]) -> Result<AiResponse, AiError> {
    let response =
        serde_json::from_slice::<GenerateResponse>(body).map_err(AiError::from_parser)?;
    let usage = AiUsage {
        input_tokens: saturating_u32(response.usage_metadata.prompt_token_count),
        output_tokens: saturating_u32(
            response
                .usage_metadata
                .candidates_token_count
                .saturating_add(response.usage_metadata.thoughts_token_count),
        ),
        cached_tokens: saturating_u32(response.usage_metadata.cached_content_token_count),
        reasoning_tokens: saturating_u32(response.usage_metadata.thoughts_token_count),
    };

    let Some(candidate) = response.candidates.into_iter().next() else {
        return if response
            .prompt_feedback
            .is_some_and(|feedback| feedback.block_reason.is_some())
        {
            Ok(AiResponse {
                finish: Finish::ContentFilter,
                usage,
                model: response.model_version,
                ..Default::default()
            })
        } else {
            Err(AiError::InvalidResponse(
                "Response contains no candidates".into(),
            ))
        };
    };

    Ok(AiResponse {
        text: candidate
            .content
            .map(|content| {
                content
                    .parts
                    .into_iter()
                    .filter(|part| !part.thought)
                    .filter_map(|part| part.text)
                    .collect()
            })
            .unwrap_or_default(),
        finish: candidate
            .finish_reason
            .as_deref()
            .map_or(Finish::Stop, finish_reason),
        usage,
        model: response.model_version,
        logprobs: candidate
            .logprobs_result
            .map(|result| {
                result
                    .chosen_candidates
                    .into_iter()
                    .map(|candidate| TokenLogprob {
                        token: candidate.token,
                        logprob: candidate.log_probability,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        ..Default::default()
    })
}

fn finish_reason(reason: &str) -> Finish {
    hashify::map!(reason.as_bytes(), Finish,
        "STOP" => Finish::Stop,
        "MAX_TOKENS" => Finish::Length,
        "SAFETY" => Finish::ContentFilter,
        "RECITATION" => Finish::ContentFilter,
        "BLOCKLIST" => Finish::ContentFilter,
        "PROHIBITED_CONTENT" => Finish::ContentFilter,
        "SPII" => Finish::ContentFilter,
        "IMAGE_SAFETY" => Finish::ContentFilter,
    )
    .copied()
    .unwrap_or(Finish::Other)
}
