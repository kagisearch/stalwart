/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::HttpLimitResponse;
use common::config::smtp::session::DeliveryHook;

use super::{Request, Response};

pub async fn send_delivery_hook_request(hook: &DeliveryHook, request: Request) -> Result<Response, String> {
    let response = reqwest::Client::builder()
        .timeout(hook.timeout)
        .danger_accept_invalid_certs(hook.tls_allow_invalid_certs)
        .build()
        .map_err(|err| format!("Failed to create HTTP client: {}", err))?
        .post(&hook.url)
        .headers(hook.headers.clone())
        .body(
            serde_json::to_string(&request)
                .map_err(|err| format!("Failed to serialize delivery hook request: {}", err))?,
        )
        .send()
        .await
        .map_err(|err| format!("Delivery hook request failed: {err}"))?;

    if response.status().is_success() {
        serde_json::from_slice(
            response
                .bytes_with_limit(hook.max_response_size)
                .await
                .map_err(|err| format!("Failed to parse delivery hook response: {}", err))?
                .ok_or_else(|| "Delivery hook response too large".to_string())?
                .as_ref(),
        )
        .map_err(|err| format!("Failed to parse delivery hook response: {}", err))
    } else {
        Err(format!(
            "Delivery hook request failed with code {}: {}",
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ))
    }
}
