/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use super::AiModel;
use serde::Deserialize;
use std::{fmt::Display, time::Duration};
use trc::AiEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiError {
    CircuitOpen,
    Busy,
    Timeout,
    Transport(Box<str>),
    Status {
        status: u16,
        kind: StatusKind,
        retry_after: Option<Duration>,
        message: Box<str>,
    },
    Refusal(Option<Box<str>>),
    ContentFilter,
    Truncated,
    InvalidResponse(Box<str>),
    NotSupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    RateLimit,
    Overloaded,
    Auth,
    Billing,
    InvalidRequest,
    Server,
    Other,
}

const MAX_ERROR_MESSAGE: usize = 256;

impl AiError {
    pub fn is_retryable(&self) -> bool {
        match self {
            AiError::Timeout | AiError::Transport(_) => true,
            AiError::Status { kind, .. } => matches!(
                kind,
                StatusKind::RateLimit | StatusKind::Overloaded | StatusKind::Server
            ),
            _ => false,
        }
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            AiError::Status { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    pub fn counts_as_failure(&self) -> bool {
        matches!(
            self,
            AiError::Timeout | AiError::Transport(_) | AiError::Status { .. }
        )
    }

    pub fn trips_breaker(&self) -> bool {
        matches!(
            self,
            AiError::Status {
                kind: StatusKind::Auth | StatusKind::Billing,
                ..
            }
        )
    }

    pub fn into_trc(self, model: &AiModel) -> trc::Error {
        let err = trc::Error::new(trc::EventType::Ai(AiEvent::ApiError))
            .id(model.name.clone())
            .ctx(trc::Key::Url, model.endpoint.clone());
        match self {
            AiError::Status {
                status, message, ..
            } => err.details("Request failed").code(status).reason(message),
            other => err.details(other.description()).reason(other),
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AiError::CircuitOpen => "Circuit breaker open",
            AiError::Busy => "Concurrency or rate limit reached",
            AiError::Timeout => "Request timed out",
            AiError::Transport(_) => "Transport error",
            AiError::Status { .. } => "Request failed",
            AiError::Refusal(_) => "Model refused to answer",
            AiError::ContentFilter => "Response blocked by content filter",
            AiError::Truncated => "Response truncated by the output token limit",
            AiError::InvalidResponse(_) => "Invalid response",
            AiError::NotSupported => "Operation not supported by this model",
        }
    }

    pub(crate) fn from_transport(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            AiError::Timeout
        } else {
            AiError::Transport(err.to_string().into_boxed_str())
        }
    }

    pub(crate) fn from_serializer(err: serde_json::Error) -> Self {
        AiError::InvalidResponse(format!("Failed to serialize request: {err}").into_boxed_str())
    }

    pub(crate) fn from_parser(err: serde_json::Error) -> Self {
        AiError::InvalidResponse(format!("Failed to parse response: {err}").into_boxed_str())
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn from_status(status: u16, retry_after: Option<Duration>, body: &[u8]) -> Self {
        let has = |needle: &[u8]| memchr::memmem::find(body, needle).is_some();
        let kind = match status {
            401 | 403 => StatusKind::Auth,
            402 => StatusKind::Billing,
            429 if has(b"enforced_spend_limit_reached") || has(b"insufficient_quota") => {
                StatusKind::Billing
            }
            429 => StatusKind::RateLimit,
            400 if has(b"content_filter") => return AiError::ContentFilter,
            400 if has(b"spend_limit") || has(b"credit balance") => StatusKind::Billing,
            408 | 409 | 500..=502 | 504 => StatusKind::Server,
            503 | 529 => StatusKind::Overloaded,
            400..=499 => StatusKind::InvalidRequest,
            505..=599 => StatusKind::Server,
            _ => StatusKind::Other,
        };

        AiError::Status {
            status,
            kind,
            retry_after: retry_after.filter(|_| kind != StatusKind::Billing),
            message: error_message(body),
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ErrorBody {
    error: Option<ErrorField>,
    detail: Option<serde_json::Value>,
    message: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ErrorField {
    Text(String),
    Object {
        #[serde(default)]
        message: Option<String>,
    },
    Other(serde::de::IgnoredAny),
}

fn error_message(body: &[u8]) -> Box<str> {
    let message = serde_json::from_slice::<ErrorBody>(body)
        .ok()
        .and_then(|body| match body.error {
            Some(ErrorField::Text(text)) => Some(text),
            Some(ErrorField::Object {
                message: Some(message),
            }) => Some(message),
            _ => body.message.or_else(|| {
                body.detail.map(|detail| match detail {
                    serde_json::Value::String(text) => text,
                    other => other.to_string(),
                })
            }),
        });

    match message {
        Some(message) => truncate(&message).into(),
        None => truncate(&String::from_utf8_lossy(body)).into(),
    }
}

fn truncate(text: &str) -> &str {
    let text = text.trim();
    text.get(..text.floor_char_boundary(MAX_ERROR_MESSAGE))
        .unwrap_or(text)
}

impl Display for AiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiError::Transport(message) | AiError::InvalidResponse(message) => {
                write!(f, "{}: {message}", self.description())
            }
            AiError::Status {
                status, message, ..
            } => write!(f, "Request failed with status {status}: {message}"),
            AiError::Refusal(Some(message)) => {
                write!(f, "{}: {message}", self.description())
            }
            _ => f.write_str(self.description()),
        }
    }
}

impl std::error::Error for AiError {}
