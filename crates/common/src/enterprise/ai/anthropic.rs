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
    TextParts, saturating_u32,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

pub const ANTHROPIC_VERSION: &str = "2023-06-01";

#[derive(Serialize)]
struct MessagesRequest<'x> {
    model: &'x str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<&'x JsonText>,
    messages: [UserMessage<'x>; 1],
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_config: Option<OutputConfig<'x>>,
}

#[derive(Serialize)]
struct UserMessage<'x> {
    role: &'static str,
    content: TextParts<'x>,
}

#[derive(Serialize)]
struct OutputConfig<'x> {
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'x RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effort: Option<&'static str>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct MessagesResponse {
    model: Option<Box<str>>,
    content: Vec<ContentBlock>,
    stop_reason: Option<Box<str>>,
    usage: MessagesUsage,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ContentBlock {
    #[serde(rename = "type")]
    typ: Option<Box<str>>,
    text: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct MessagesUsage {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: u64,
    cache_creation_input_tokens: u64,
}

pub(crate) fn write_request(
    model: &GenerativeModel,
    model_id: &str,
    request: &AiRequest<'_>,
    body: &mut Vec<u8>,
) -> serde_json::Result<()> {
    let format = match request.output {
        OutputSpec::Text => None,
        OutputSpec::Json(format) => Some(format),
    };
    let effort = model.reasoning.effort();

    serde_json::to_writer(
        body,
        &MessagesRequest {
            model: model_id,
            max_tokens: model.max_output_tokens(request),
            system: request.system,
            messages: [UserMessage {
                role: "user",
                content: TextParts(request.user),
            }],
            temperature: model.temperature(request),
            output_config: (format.is_some() || effort.is_some())
                .then_some(OutputConfig { format, effort }),
        },
    )
}

pub(crate) fn parse_response(body: &[u8]) -> Result<AiResponse, AiError> {
    let response =
        serde_json::from_slice::<MessagesResponse>(body).map_err(AiError::from_parser)?;
    let text = response
        .content
        .into_iter()
        .filter(|block| block.typ.as_deref().is_none_or(|typ| typ == "text"))
        .filter_map(|block| block.text)
        .collect::<String>();
    let finish = response
        .stop_reason
        .as_deref()
        .map_or(Finish::Stop, stop_reason);
    let usage = response.usage;

    Ok(AiResponse {
        text,
        finish,
        usage: AiUsage {
            input_tokens: saturating_u32(
                usage
                    .input_tokens
                    .saturating_add(usage.cache_read_input_tokens)
                    .saturating_add(usage.cache_creation_input_tokens),
            ),
            output_tokens: saturating_u32(usage.output_tokens),
            cached_tokens: saturating_u32(usage.cache_read_input_tokens),
            reasoning_tokens: 0,
        },
        model: response.model,
        ..Default::default()
    })
}

fn stop_reason(reason: &str) -> Finish {
    hashify::map!(reason.as_bytes(), Finish,
        "end_turn" => Finish::Stop,
        "stop_sequence" => Finish::Stop,
        "max_tokens" => Finish::Length,
        "model_context_window_exceeded" => Finish::Length,
        "refusal" => Finish::Refusal,
    )
    .copied()
    .unwrap_or(Finish::Other)
}
