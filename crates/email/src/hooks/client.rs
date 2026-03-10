/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::HttpLimitResponse;
use common::config::smtp::delivery_hooks::DeliveryHook;

use super::{Action, Request, Response};

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
        let bytes = response
            .bytes_with_limit(hook.max_response_size)
            .await
            .map_err(|err| format!("Failed to parse delivery hook response: {}", err))?
            .ok_or_else(|| "Delivery hook response too large".to_string())?;
        let trimmed = AsRef::<[u8]>::as_ref(&bytes).trim_ascii();
        match serde_json::from_slice(trimmed) {
            Ok(parsed) => Ok(parsed),
            Err(err) => {
                trc::event!(
                    Delivery(trc::DeliveryEvent::RawOutput),
                    Reason = format!("Failed to parse delivery hook response: {err}"),
                    Contents = String::from_utf8_lossy(trimmed).into_owned(),
                );
                Ok(Response {
                    action: Action::Accept,
                    modifications: Vec::new(),
                    skip_inbox: false,
                    flags: Vec::new(),
                    preview_text: None,
                })
            }
        }
    } else {
        Err(format!(
            "Delivery hook request failed with code {}: {}",
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ))
    }
}
