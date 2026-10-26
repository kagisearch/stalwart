/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

pub fn weak_etag(revision: u64) -> String {
    format!("W/\"{revision:016x}\"")
}

pub fn opaque_value(etag: &str) -> &str {
    etag.strip_prefix("W/")
        .unwrap_or(etag)
        .trim()
        .trim_matches('"')
}

pub fn is_weak(etag: &str) -> bool {
    etag.starts_with("W/")
}

pub fn matches(header: &str, version: &str) -> bool {
    let version = opaque_value(version);

    split_list(header).any(|candidate| candidate == "*" || opaque_value(candidate) == version)
}

fn split_list(header: &str) -> impl Iterator<Item = &str> {
    let mut quoted = false;

    header
        .split(move |ch| {
            match ch {
                '"' => quoted = !quoted,
                ',' if !quoted => return true,
                _ => {}
            }

            false
        })
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/scim-proto/src/etag/tests.rs"]
mod tests;
