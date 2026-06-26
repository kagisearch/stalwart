/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Delivery hook configuration.
//!
//! A delivery hook is an HTTP webhook invoked during message delivery (before
//! the user's Sieve script runs) that can accept, discard, reject, or
//! quarantine a message and apply modifications (fileInto, headers, preview
//! text). The runtime lives in `email::message::delivery_hooks`.
//!
//! In `v0.15` these were parsed from the `session.delivery_hook.*` TOML keys.
//! `v0.16` removed the TOML config layer entirely, so this list is currently
//! populated empty in `SessionConfig::parse` and the runtime stays dormant.
//! TODO(EMAIL-811): define a `DeliveryHook` registry object type (mirroring the
//! `MtaHook` object) and build this struct from `bp.list_infallible`, the same
//! way `MTAHook` is now built.

use crate::expr::if_block::IfBlock;
use hyper::HeaderMap;

/// Configuration for a delivery hook.
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
