/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::error::Result;
use scim_proto::{ResourceType, message::error::Error, message::search::SearchRequest};
use std::fmt::Write;
use types::id::Id;

const CURSOR_LEN: usize = 48;

pub fn signature(resource_type: ResourceType, request: &SearchRequest<'_>) -> u64 {
    let mut buffer = Vec::with_capacity(64);
    buffer.push(resource_type as u8);
    buffer.extend_from_slice(request.filter.as_deref().unwrap_or_default().as_bytes());
    buffer.push(0);
    buffer.extend_from_slice(request.sort_by.as_deref().unwrap_or_default().as_bytes());
    buffer.push(0);
    buffer.extend_from_slice(request.sort_order.unwrap_or_default().as_str().as_bytes());

    xxhash_rust::xxh3::xxh3_64(&buffer)
}

pub fn encode(signature: u64, position: usize, anchor: Id) -> String {
    let mut cursor = String::with_capacity(CURSOR_LEN);
    let _ = write!(
        &mut cursor,
        "{signature:016x}{position:016x}{:016x}",
        anchor.id()
    );
    cursor
}

pub fn decode(cursor: &str, signature: u64, ids: &[Id]) -> Result<usize> {
    let invalid = || Error::invalid_cursor("The supplied cursor is not valid.");

    if cursor.len() != CURSOR_LEN || !cursor.is_ascii() {
        return Err(invalid().into());
    }

    let cursor_signature = u64::from_str_radix(&cursor[..16], 16).map_err(|_| invalid())?;
    let position = u64::from_str_radix(&cursor[16..32], 16).map_err(|_| invalid())? as usize;
    let anchor = u64::from_str_radix(&cursor[32..], 16).map_err(|_| invalid())?;

    if cursor_signature != signature {
        return Err(
            Error::invalid_cursor("The supplied cursor was issued for a different query.").into(),
        );
    }

    Ok(match ids.iter().position(|id| id.id() == anchor) {
        Some(anchor_position) => anchor_position + 1,
        None => position.min(ids.len()),
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/scim/src/query/cursor/tests.rs"]
mod tests;
