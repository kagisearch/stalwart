/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Configuration parsing for delivery hooks
//!
//! This module provides the configuration structure and parsing logic
//! for delivery hooks, extending the base session configuration.

use std::str::FromStr;
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::{HeaderMap, header::{AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue}};
use utils::config::Config;
use crate::expr::{if_block::IfBlock, tokenizer::TokenMap};

/// Configuration for a delivery hook
#[derive(Clone)]
pub struct DeliveryHook {
    pub enable: IfBlock,
    pub id: String,
    pub url: String,
    pub timeout: std::time::Duration,
    pub headers: HeaderMap,
    pub tls_allow_invalid_certs: bool,
    pub tempfail_on_error: bool,
    pub max_response_size: usize,
}

/// Parse delivery hook configuration from TOML config
pub fn parse_delivery_hooks(config: &mut Config, id: &str, token_map: &TokenMap) -> Option<DeliveryHook> {
    let mut headers = HeaderMap::new();

    for (header, value) in config
        .values(("session.delivery_hook", id, "headers"))
        .map(|(_, v)| {
            if let Some((k, v)) = v.split_once(':') {
                Ok((
                    HeaderName::from_str(k.trim()).map_err(|err| {
                        format!(
                            "Invalid header found in property \"session.delivery_hook.{id}.headers\": {err}",
                        )
                    })?,
                    HeaderValue::from_str(v.trim()).map_err(|err| {
                        format!(
                            "Invalid header found in property \"session.delivery_hook.{id}.headers\": {err}",
                        )
                    })?,
                ))
            } else {
                Err(format!(
                    "Invalid header found in property \"session.delivery_hook.{id}.headers\": {v}",
                ))
            }
        })
        .collect::<Result<Vec<(HeaderName, HeaderValue)>, String>>()
        .map_err(|e| config.new_parse_error(("session.delivery_hook", id, "headers"), e))
        .unwrap_or_default()
    {
        headers.insert(header, value);
    }

    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    if let (Some(name), Some(secret)) = (
        config.value(("session.delivery_hook", id, "auth.username")),
        config.value(("session.delivery_hook", id, "auth.secret")),
    ) {
        headers.insert(
            AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{}:{}", name, secret)))
                .parse()
                .unwrap(),
        );
    }

    Some(DeliveryHook {
        enable: IfBlock::try_parse(config, ("session.delivery_hook", id, "enable"), token_map)
            .unwrap_or_else(|| {
                IfBlock::new::<()>(format!("delivery.hook.{id}.enable"), [], "false")
            }),
        id: id.to_string(),
        url: config
            .value_require(("session.delivery_hook", id, "url"))?
            .to_string(),
        timeout: config
            .property_or_default(("session.delivery_hook", id, "timeout"), "30s")
            .unwrap_or_else(|| std::time::Duration::from_secs(30)),
        tls_allow_invalid_certs: config
            .property_or_default(("session.delivery_hook", id, "allow-invalid-certs"), "false")
            .unwrap_or_default(),
        tempfail_on_error: config
            .property_or_default(("session.delivery_hook", id, "options.tempfail-on-error"), "true")
            .unwrap_or(true),
        max_response_size: config
            .property_or_default(
                ("session.delivery_hook", id, "options.max-response-size"),
                "52428800",
            )
            .unwrap_or(52428800),
        headers,
    })
}
