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
    AiError, AiRequest, AiResponse, AiUsage, ChatMessages, Finish, GenerativeModel, OutputSpec,
    Reasoning, TextParts, TokenLogprob, saturating_u32,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::time::Duration;

#[derive(Serialize)]
struct ChatRequest<'x> {
    model: &'x str,
    messages: ChatMessages<'x>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'x RawValue>,
    options: ChatOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    think: Option<Think>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keep_alive: Option<u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    logprobs: bool,
}

#[derive(Serialize)]
struct ChatOptions {
    num_predict: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Think {
    Enabled(bool),
    Level(&'static str),
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ChatResponse {
    model: Option<Box<str>>,
    message: ResponseMessage,
    done_reason: Option<Box<str>>,
    prompt_eval_count: u64,
    eval_count: u64,
    logprobs: Option<Vec<ResponseLogprob>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ResponseMessage {
    content: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ResponseLogprob {
    token: Box<str>,
    logprob: f32,
}

pub(crate) fn write_request(
    model: &GenerativeModel,
    keep_alive: Option<Duration>,
    model_id: &str,
    request: &AiRequest<'_>,
    body: &mut Vec<u8>,
) -> serde_json::Result<()> {
    serde_json::to_writer(
        body,
        &ChatRequest {
            model: model_id,
            messages: ChatMessages {
                system: request.system,
                user: TextParts(request.user),
            },
            stream: false,
            format: match request.output {
                OutputSpec::Text => None,
                OutputSpec::Json(format) => Some(format),
            },
            options: ChatOptions {
                num_predict: model.max_output_tokens(request),
                temperature: model.temperature(request),
            },
            think: match model.reasoning {
                Reasoning::Default => None,
                Reasoning::Off => Some(Think::Enabled(false)),
                reasoning => reasoning.effort().map(Think::Level),
            },
            keep_alive: keep_alive.map(|duration| duration.as_secs()),
            logprobs: model.logprobs(request),
        },
    )
}

pub(crate) fn parse_response(body: &[u8]) -> Result<AiResponse, AiError> {
    let response = serde_json::from_slice::<ChatResponse>(body).map_err(AiError::from_parser)?;
    Ok(AiResponse {
        text: response.message.content,
        finish: match response.done_reason.as_deref() {
            None => Finish::Stop,
            Some(reason) => hashify::map!(reason.as_bytes(), Finish,
                "stop" => Finish::Stop,
                "length" => Finish::Length,
            )
            .copied()
            .unwrap_or(Finish::Other),
        },
        usage: AiUsage {
            input_tokens: saturating_u32(response.prompt_eval_count),
            output_tokens: saturating_u32(response.eval_count),
            cached_tokens: 0,
            reasoning_tokens: 0,
        },
        model: response.model,
        logprobs: response
            .logprobs
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
