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
    AiBackend, AiModel, Dialect, GenerativeModel, OpenAiProfile, Reasoning, anthropic,
    limits::AiLimits,
};
use crate::USER_AGENT;
use registry::{
    schema::{
        enums::{AiOpenAiProfile, AiReasoning},
        structs::{self, Rate, SecretKeyOptional},
    },
    types::{duration::Duration as RegistryDuration, float::Float, id::ObjectId},
};
use reqwest::{
    Url,
    header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue},
};
use std::{sync::Arc, time::Duration};
use store::registry::bootstrap::Bootstrap;
use utils::{http::build_http_headers, map::vec_map::VecMap};

struct Common {
    name: String,
    model: String,
    url: Option<String>,
    api_key: SecretKeyOptional,
    http_headers: VecMap<String, String>,
    allow_invalid_certs: bool,
    timeout: RegistryDuration,
    max_concurrent_requests: u64,
    rate_limit: Option<Rate>,
}

struct Generation {
    max_output_tokens: u64,
    temperature: Option<Float>,
    reasoning: AiReasoning,
    extra_parameters: Option<String>,
}

#[derive(Clone, Copy)]
enum AuthStyle {
    Bearer,
    Header(&'static str),
}

struct Endpoint {
    default_base: &'static str,
    tail: &'static str,
    version: &'static str,
    path: &'static str,
}

const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const OPENAI_ENDPOINT: Endpoint = Endpoint {
    default_base: "https://api.openai.com/v1",
    tail: "/chat/completions",
    version: "/v1",
    path: "/chat/completions",
};
const ANTHROPIC_ENDPOINT: Endpoint = Endpoint {
    default_base: "https://api.anthropic.com",
    tail: "/messages",
    version: "/v1",
    path: "/messages",
};
const GEMINI_ENDPOINT: Endpoint = Endpoint {
    default_base: "https://generativelanguage.googleapis.com/v1beta",
    tail: ":generateContent",
    version: "/v1beta",
    path: "/models/{model}:generateContent",
};
const OLLAMA_ENDPOINT: Endpoint = Endpoint {
    default_base: "http://localhost:11434",
    tail: "/api/chat",
    version: "/api",
    path: "/chat",
};
const TYPESAFE_ENDPOINT: Endpoint = Endpoint {
    default_base: "https://api.typesafe.ai",
    tail: "/systemone",
    version: "/v1",
    path: "/systemone",
};

macro_rules! split_model {
    ($model:expr) => {
        (
            Common {
                name: $model.name,
                model: $model.model,
                url: $model.url,
                api_key: $model.api_key,
                http_headers: $model.http_headers,
                allow_invalid_certs: $model.allow_invalid_certs,
                timeout: $model.timeout,
                max_concurrent_requests: $model.max_concurrent_requests,
                rate_limit: $model.rate_limit,
            },
            Generation {
                max_output_tokens: $model.max_output_tokens,
                temperature: $model.temperature,
                reasoning: $model.reasoning,
                extra_parameters: $model.extra_parameters,
            },
        )
    };
}

impl AiModel {
    pub async fn build(bp: &mut Bootstrap, id: ObjectId, model: structs::AiModel) -> Option<Self> {
        let (common, backend, endpoint, auth) = match model {
            structs::AiModel::OpenAi(model) => {
                let profile = match model.profile {
                    AiOpenAiProfile::OpenAi => OpenAiProfile::OpenAi,
                    AiOpenAiProfile::Azure => OpenAiProfile::Azure,
                    AiOpenAiProfile::Vllm => OpenAiProfile::Vllm,
                    AiOpenAiProfile::LlamaCpp => OpenAiProfile::LlamaCpp,
                    AiOpenAiProfile::Generic => OpenAiProfile::Generic,
                };
                let logprobs = model.logprobs;
                let (common, generation) = split_model!(model);
                let auth = if profile == OpenAiProfile::Azure {
                    AuthStyle::Header("api-key")
                } else {
                    AuthStyle::Bearer
                };
                (
                    common,
                    generation.build(bp, id, Dialect::OpenAi(profile), logprobs)?,
                    &OPENAI_ENDPOINT,
                    auth,
                )
            }
            structs::AiModel::Anthropic(model) => {
                let (common, generation) = split_model!(model);
                (
                    common,
                    generation.build(bp, id, Dialect::Anthropic, false)?,
                    &ANTHROPIC_ENDPOINT,
                    AuthStyle::Header("x-api-key"),
                )
            }
            structs::AiModel::Gemini(model) => {
                let logprobs = model.logprobs;
                let (common, generation) = split_model!(model);
                (
                    common,
                    generation.build(bp, id, Dialect::Gemini, logprobs)?,
                    &GEMINI_ENDPOINT,
                    AuthStyle::Header("x-goog-api-key"),
                )
            }
            structs::AiModel::Ollama(model) => {
                let logprobs = model.logprobs;
                let keep_alive = model.keep_alive.map(|duration| duration.into_inner());
                let (common, generation) = split_model!(model);
                (
                    common,
                    generation.build(bp, id, Dialect::Ollama { keep_alive }, logprobs)?,
                    &OLLAMA_ENDPOINT,
                    AuthStyle::Bearer,
                )
            }
            structs::AiModel::TypeSafe(model) => (
                Common {
                    name: model.name,
                    model: model.model,
                    url: model.url,
                    api_key: model.api_key,
                    http_headers: model.http_headers,
                    allow_invalid_certs: model.allow_invalid_certs,
                    timeout: model.timeout,
                    max_concurrent_requests: model.max_concurrent_requests,
                    rate_limit: model.rate_limit,
                },
                AiBackend::TypeSafe,
                &TYPESAFE_ENDPOINT,
                AuthStyle::Bearer,
            ),
        };

        let endpoint = match endpoint.resolve(common.url.as_deref(), &common.model) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                bp.build_error(id, format!("Invalid AI model URL: {err}"));
                return None;
            }
        };

        let api_key = match common.api_key.secret().await {
            Ok(api_key) => api_key.map(|key| key.into_owned()),
            Err(err) => {
                bp.build_error(id, format!("Unable to obtain AI model API key: {err}"));
                return None;
            }
        };

        let headers = match build_headers(
            common.http_headers,
            api_key.as_deref(),
            auth,
            matches!(
                backend,
                AiBackend::Generative(GenerativeModel {
                    dialect: Dialect::Anthropic,
                    ..
                })
            ),
        ) {
            Ok(headers) => headers,
            Err(err) => {
                bp.build_error(id, format!("Unable to build HTTP headers: {err}"));
                return None;
            }
        };

        let timeout = common.timeout.into_inner();
        let client = match utils::http::http_client_builder(common.allow_invalid_certs)
            .default_headers(headers)
            .connect_timeout(timeout.min(MAX_CONNECT_TIMEOUT))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                bp.build_error(id, format!("Unable to build HTTP client: {err}"));
                return None;
            }
        };

        Some(AiModel {
            id: id.id().id(),
            name: common.name.into_boxed_str(),
            model: Arc::from(common.model),
            endpoint: endpoint.into_boxed_str(),
            timeout,
            backend,
            client,
            limits: AiLimits::new(
                usize::try_from(common.max_concurrent_requests).unwrap_or(usize::MAX),
                common.rate_limit,
            ),
        })
    }
}

impl Generation {
    fn build(
        self,
        bp: &mut Bootstrap,
        id: ObjectId,
        dialect: Dialect,
        logprobs: bool,
    ) -> Option<AiBackend> {
        let extra = match self.extra_parameters.as_deref().map(str::trim) {
            Some(extra) if !extra.is_empty() => {
                match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(extra) {
                    Ok(map) if map.is_empty() => None,
                    Ok(map) => {
                        let json = serde_json::Value::Object(map).to_string();
                        json.strip_prefix('{')
                            .and_then(|json| json.strip_suffix('}'))
                            .map(Box::from)
                    }
                    Err(err) => {
                        bp.build_error(
                            id,
                            format!("Extra parameters must be a JSON object: {err}"),
                        );
                        return None;
                    }
                }
            }
            _ => None,
        };

        Some(AiBackend::Generative(GenerativeModel {
            dialect,
            max_output_tokens: u32::try_from(self.max_output_tokens).unwrap_or(u32::MAX),
            temperature: self
                .temperature
                .map(|temperature| temperature.into_inner() as f32),
            reasoning: match self.reasoning {
                AiReasoning::Default => Reasoning::Default,
                AiReasoning::Off => Reasoning::Off,
                AiReasoning::Low => Reasoning::Low,
                AiReasoning::Medium => Reasoning::Medium,
                AiReasoning::High => Reasoning::High,
            },
            logprobs,
            extra,
        }))
    }
}

impl Endpoint {
    fn resolve(&self, base: Option<&str>, model: &str) -> Result<String, String> {
        let base = base
            .map(str::trim)
            .filter(|base| !base.is_empty())
            .unwrap_or(self.default_base);
        let mut url = Url::parse(base).map_err(|err| err.to_string())?;
        let path = url.path().trim_end_matches('/');
        if !path.ends_with(self.tail) {
            let model = model.strip_prefix("models/").unwrap_or(model);
            let suffix = self.path.replace("{model}", model);
            let new_path = if path.is_empty() {
                format!("{}{suffix}", self.version)
            } else {
                format!("{path}{suffix}")
            };
            url.set_path(&new_path);
        }
        Ok(url.into())
    }
}

fn build_headers(
    extra: VecMap<String, String>,
    api_key: Option<&str>,
    auth: AuthStyle,
    is_anthropic: bool,
) -> Result<HeaderMap, String> {
    let mut headers = build_http_headers(extra, None, None, None, Some("application/json"))?;
    headers.insert(
        reqwest::header::USER_AGENT,
        HeaderValue::from_static(USER_AGENT),
    );
    if is_anthropic {
        headers.insert(
            HeaderName::from_static("anthropic-version"),
            HeaderValue::from_static(anthropic::ANTHROPIC_VERSION),
        );
    }
    if let Some(api_key) = api_key.map(str::trim).filter(|key| !key.is_empty()) {
        let (name, value) = match auth {
            AuthStyle::Bearer => (AUTHORIZATION, format!("Bearer {api_key}")),
            AuthStyle::Header(name) => (HeaderName::from_static(name), api_key.to_string()),
        };
        let mut value = HeaderValue::try_from(value).map_err(|err| err.to_string())?;
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    Ok(headers)
}
