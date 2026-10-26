/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::analysis::score::push_two_decimals;
use common::{
    enterprise::{SpamAiConfig, ai::AiVerdict},
    scripts::functions::unicode::CharUtils,
};
use mail_auth::headers::{HeaderFolder, Writer};
use std::fmt::Write as _;

pub struct TierVerdict {
    pub tier: usize,
    pub verdict: AiVerdict,
}

#[derive(Clone, Copy)]
pub enum Outcome<'x> {
    Verdict(&'x TierVerdict),
    Error { tier: usize, error: &'static str },
}

const HEADER_NAME: &[u8] = b"X-Spam-AI: ";
const HEADER_CAPACITY: usize = 192;
const MAX_REASON_BYTES: usize = 200;
const MAX_TOKEN_BYTES: usize = 64;

pub fn header(
    config: &SpamAiConfig,
    outcome: Outcome<'_>,
    previous: &[TierVerdict],
    shadow: bool,
) -> String {
    let mut value = String::with_capacity(HEADER_CAPACITY);
    match outcome {
        Outcome::Verdict(TierVerdict { tier, verdict }) => {
            push_token(&mut value, config.category_name(verdict.category));
            value.push_str("; p=");
            push_two_decimals(&mut value, verdict.probability);
            value.push_str("; confidence=");
            push_two_decimals(&mut value, verdict.confidence);
            value.push_str("; model=");
            push_token(&mut value, &verdict.model);
            let _ = write!(value, "; tier={}", tier + 1);
            if config.is_uncertain(verdict) {
                value.push_str("; uncertain");
            }
        }
        Outcome::Error { tier, error } => {
            let _ = write!(value, "error; tier={}; error=\"", tier + 1);
            push_reason(&mut value, error);
            value.push('"');
        }
    }
    for TierVerdict { tier, verdict } in previous {
        let _ = write!(value, "; tier{}=", tier + 1);
        push_token(&mut value, config.category_name(verdict.category));
        value.push('/');
        push_two_decimals(&mut value, verdict.probability);
    }
    if shadow {
        value.push_str("; shadow");
    }
    let mut reason = String::new();
    if let Outcome::Verdict(TierVerdict { verdict, .. }) = outcome
        && let Some(verdict_reason) = &verdict.reason
    {
        push_reason(&mut reason, verdict_reason);
    }

    let mut header = Vec::with_capacity(HEADER_NAME.len() + value.len() + reason.len() + 16);
    {
        let mut folder = HeaderFolder::new(&mut header);
        folder.write(HEADER_NAME);
        if !reason.is_empty() {
            value.push_str("; reason=\"");
        }
        folder.write(value.as_bytes());
        if !reason.is_empty() {
            for (idx, word) in reason.split(' ').enumerate() {
                if idx > 0 {
                    folder.write(b" ");
                }
                folder.write(word.as_bytes());
            }
            folder.write(b"\"");
        }
    }
    header.extend_from_slice(b"\r\n");
    String::from_utf8(header)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

fn push_token(out: &mut String, token: &str) {
    for ch in token.chars().take(MAX_TOKEN_BYTES) {
        out.push(
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | ':' | '/' | '@' | '+') {
                ch
            } else {
                '_'
            },
        );
    }
}

pub(crate) fn push_reason(out: &mut String, reason: &str) {
    let start = out.len();
    let mut last_space = true;
    for ch in reason.chars() {
        let ch = match ch {
            '"' | '\\' => '\'',
            ';' => ',',
            '<' | '>' => ' ',
            ch if ch.is_ascii_graphic() => ch,
            ch if ch.is_whitespace() || ch.is_control() || ch.is_obscured() || ch.is_zwsp() => ' ',
            _ => '?',
        };
        if ch == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        if out.len() - start >= MAX_REASON_BYTES {
            break;
        }
        out.push(ch);
    }
    let trimmed = out.trim_end().len().max(start);
    out.truncate(trimmed);
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/spam-filter/src/analysis/ai/verdict/tests.rs"]
mod tests;
