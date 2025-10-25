/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;
use utils::HttpLimitResponse;

use super::{Request, Response};

const DELIVERY_HOOK_URL: &str = "http://localhost:8080/delivery-hook";
const DELIVERY_HOOK_TIMEOUT: Duration = Duration::from_secs(10);
const DELIVERY_HOOK_MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB

pub async fn send_delivery_hook_request(request: Request) -> Result<Response, String> {
    let response = reqwest::Client::builder()
        .timeout(DELIVERY_HOOK_TIMEOUT)
        .build()
        .map_err(|err| format!("Failed to create HTTP client: {}", err))?
        .post(DELIVERY_HOOK_URL)
        .header("Content-Type", "application/json")
        .header("Authorization", "basic YWRtaW46YW5leHRyZW1lbHl1bmNvbnZpbmNpbmdwYXNzd29yZA==")
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
                .bytes_with_limit(DELIVERY_HOOK_MAX_RESPONSE_SIZE)
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
