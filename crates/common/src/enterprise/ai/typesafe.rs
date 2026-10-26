/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use super::{AiBackend, AiCallOptions, AiError, AiModel, AiUsage, Finish, saturating_u32};
use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::time::Duration;

pub(crate) struct SystemOneRequest {
    suffix: Box<[u8]>,
}

#[derive(Serialize)]
struct SystemOneTail<'x> {
    model: &'x str,
    questions: &'x RawValue,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SystemOneResponse {
    model: Option<Box<str>>,
    answers: AHashMap<String, SystemOneAnswer>,
    usage: SystemOneUsage,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SystemOneUsage {
    input_tokens: u64,
    output_tokens: u64,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SystemOneAnswer {
    Noul {
        #[serde(default)]
        noul: f32,
    },
    Choice {
        #[serde(default)]
        probabilities: AHashMap<String, f32>,
        #[serde(default)]
        confidence: Option<f32>,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Default)]
pub struct SystemOneAnswers {
    pub model: Option<Box<str>>,
    pub answers: AHashMap<String, SystemOneAnswer>,
    pub usage: AiUsage,
    pub request_id: Option<Box<str>>,
    pub elapsed: Duration,
}

const STATE_PREFIX: &[u8] = b"{\"state\":{\"email\":";
const STATE_SUFFIX: &str = "},";

impl SystemOneRequest {
    pub(crate) fn new(model: &str, questions: &RawValue) -> serde_json::Result<Self> {
        let tail = serde_json::to_string(&SystemOneTail { model, questions })?;
        let tail = tail
            .strip_prefix('{')
            .ok_or_else(|| serde::ser::Error::custom("request tail is not an object"))?;
        let mut suffix = String::with_capacity(STATE_SUFFIX.len() + tail.len());
        suffix.push_str(STATE_SUFFIX);
        suffix.push_str(tail);
        Ok(SystemOneRequest {
            suffix: suffix.into_bytes().into_boxed_slice(),
        })
    }

    pub(crate) fn body(&self, state_email: &str) -> Vec<u8> {
        let mut body =
            Vec::with_capacity(STATE_PREFIX.len() + state_email.len() + self.suffix.len());
        body.extend_from_slice(STATE_PREFIX);
        body.extend_from_slice(state_email.as_bytes());
        body.extend_from_slice(&self.suffix);
        body
    }
}

impl AiModel {
    pub(crate) async fn system_one(
        &self,
        body: Vec<u8>,
        options: &AiCallOptions,
    ) -> Result<SystemOneAnswers, AiError> {
        if !matches!(self.backend, AiBackend::TypeSafe) {
            return Err(AiError::NotSupported);
        }

        let raw = self.execute(body, options).await?;
        let response =
            serde_json::from_slice::<SystemOneResponse>(&raw.body).map_err(AiError::from_parser)?;
        let usage = AiUsage {
            input_tokens: saturating_u32(response.usage.input_tokens),
            output_tokens: saturating_u32(response.usage.output_tokens),
            cached_tokens: 0,
            reasoning_tokens: 0,
        };
        self.emit_request_event(
            response.model.as_deref(),
            &usage,
            Finish::Stop,
            raw.request_id.as_deref(),
            raw.elapsed,
            options.span_id,
        );

        if response.answers.is_empty() {
            return Err(AiError::InvalidResponse(
                "Response contains no answers".into(),
            ));
        }

        Ok(SystemOneAnswers {
            model: response.model,
            answers: response.answers,
            usage,
            request_id: raw.request_id,
            elapsed: raw.elapsed,
        })
    }
}
