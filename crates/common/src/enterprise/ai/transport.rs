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
    AiCallOptions, AiError, AiModel,
    limits::{Admission, RateSlot},
};
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, RETRY_AFTER};
use std::time::{Duration, Instant};
use trc::AiEvent;
use utils::HttpLimitResponse;

pub(crate) struct RawResponse {
    pub body: Vec<u8>,
    pub request_id: Option<Box<str>>,
    pub elapsed: Duration,
}

const MAX_ATTEMPTS: u32 = 2;
const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(500);
const MAX_RESPONSE_SIZE: usize = 8 * 1024 * 1024;
const REQUEST_ID_HEADERS: [HeaderName; 4] = [
    HeaderName::from_static("x-request-id"),
    HeaderName::from_static("request-id"),
    HeaderName::from_static("x-typesafe-request-id"),
    HeaderName::from_static("x-goog-request-id"),
];
const RETRY_AFTER_MS: HeaderName = HeaderName::from_static("retry-after-ms");

impl AiModel {
    pub(crate) async fn execute(
        &self,
        body: Vec<u8>,
        options: &AiCallOptions,
    ) -> Result<RawResponse, AiError> {
        let started = Instant::now();
        let admission = self
            .limits
            .breaker
            .admit(started, options.breaker.cooldown)
            .ok_or(AiError::CircuitOpen)?;

        let _permit = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(options.deadline),
            self.limits.semaphore.acquire(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            _ => return Err(AiError::Busy),
        };
        if admission == Admission::Closed && self.limits.breaker.is_open(Instant::now()) {
            return Err(AiError::CircuitOpen);
        }

        if let Some(rate) = &self.limits.rate {
            match rate.reserve(Instant::now(), options.deadline) {
                RateSlot::Now => {}
                RateSlot::At(at) => {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
                }
                RateSlot::Exceeded => return Err(AiError::Busy),
            }
        }

        let body = Bytes::from(body);
        let mut attempt = 1;
        loop {
            match self.attempt(body.clone(), options.deadline).await {
                Ok((body, request_id)) => {
                    self.limits.breaker.record_success();
                    return Ok(RawResponse {
                        body,
                        request_id,
                        elapsed: started.elapsed(),
                    });
                }
                Err(err) => {
                    if attempt < MAX_ATTEMPTS && err.is_retryable() {
                        let resume =
                            Instant::now() + err.retry_after().unwrap_or(DEFAULT_RETRY_DELAY);
                        if resume < options.deadline {
                            attempt += 1;
                            tokio::time::sleep_until(tokio::time::Instant::from_std(resume)).await;
                            continue;
                        }
                    }

                    if err.counts_as_failure()
                        && self.limits.breaker.record_failure(
                            &options.breaker,
                            Instant::now(),
                            err.trips_breaker(),
                            admission,
                        )
                    {
                        trc::event!(
                            Ai(AiEvent::BreakerOpen),
                            Name = self.name.clone(),
                            Reason = err.to_string(),
                            Period = options.breaker.cooldown,
                            SpanId = options.span_id,
                        );
                    }

                    return Err(err);
                }
            }
        }
    }

    async fn attempt(
        &self,
        body: Bytes,
        deadline: Instant,
    ) -> Result<(Vec<u8>, Option<Box<str>>), AiError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(AiError::Timeout)?;
        let response = self
            .client
            .post(&*self.endpoint)
            .timeout(remaining.min(self.timeout))
            .body(body)
            .send()
            .await
            .map_err(AiError::from_transport)?;
        let status = response.status();
        let request_id = request_id(response.headers());
        let retry_after = (!status.is_success())
            .then(|| retry_after(response.headers()))
            .flatten();
        let body = response
            .bytes_with_limit(MAX_RESPONSE_SIZE)
            .await
            .map_err(AiError::from_transport)?
            .ok_or_else(|| AiError::InvalidResponse("Response exceeds size limit".into()))?;

        if status.is_success() {
            Ok((body, request_id))
        } else {
            Err(AiError::from_status(status.as_u16(), retry_after, &body))
        }
    }
}

fn request_id(headers: &HeaderMap) -> Option<Box<str>> {
    REQUEST_ID_HEADERS
        .iter()
        .find_map(|name| headers.get(name)?.to_str().ok())
        .map(Box::from)
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    if let Some(ms) = headers
        .get(RETRY_AFTER_MS)
        .and_then(|value| value.to_str().ok()?.trim().parse::<f64>().ok())
        .filter(|ms| ms.is_finite() && *ms >= 0.0 && *ms < 86_400_000.0)
    {
        return Some(Duration::from_secs_f64(ms / 1000.0));
    }
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok()?.trim().parse::<f64>().ok())
        .filter(|secs| secs.is_finite() && *secs >= 0.0 && *secs < 86400.0)
        .map(Duration::from_secs_f64)
}
