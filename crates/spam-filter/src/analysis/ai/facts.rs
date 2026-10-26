/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::{
    SpamFilterContext, TextPart,
    analysis::{to_lowercase_cow, url::UrlParts},
    modules::html::{
        A, HREF, HtmlToken, QuoteMode, VisibleTextOptions, html_visible_text, is_invisible,
        is_visible_ascii,
    },
};
use common::{
    config::mailstore::spamfilter::Location,
    enterprise::{SpamAiInput, ai::AiFacts},
};
use mail_auth::{DkimResult, DmarcResult, SpfResult};
use serde::{Serialize, Serializer};
use serde_json::value::RawValue;
use std::borrow::Cow;
use store::ahash::AHashSet;

#[derive(Serialize)]
pub struct MessageFacts<'x> {
    from: Address<'x>,
    #[serde(skip_serializing_if = "str::is_empty")]
    envelope_from: &'x str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<Address<'x>>,
    recipient_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    to_domains: Vec<&'x str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<Auth<'x>>,
    subject: Cow<'x, str>,
    list_unsubscribe: bool,
    is_reply: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachments: Option<Vec<Attachment<'x>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<Link<'x>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    web_context: Option<&'x RawValue>,
    body: Cow<'x, str>,
    truncated: bool,
}

#[derive(Serialize)]
struct Address<'x> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<Cow<'x, str>>,
    address: &'x str,
    domain: &'x str,
}

#[derive(Serialize)]
struct Auth<'x> {
    spf: &'static str,
    dkim: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dkim_domains: Vec<&'x str>,
    dmarc: &'static str,
    arc: &'static str,
}

#[derive(Serialize)]
struct Link<'x> {
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<Cow<'x, str>>,
    host: &'x str,
    #[serde(skip_serializing_if = "Option::is_none")]
    final_host: Option<&'x str>,
}

#[derive(Serialize)]
struct Attachment<'x> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<Cow<'x, str>>,
    #[serde(serialize_with = "serialize_content_type")]
    content_type: (&'x str, Option<&'x str>),
}

const MAX_TO_DOMAINS: usize = 8;
const MAX_DKIM_DOMAINS: usize = 4;
const MAX_LINK_TEXT_CHARS: usize = 100;
const MAX_SUBJECT_CHARS: usize = 512;
const MAX_NAME_CHARS: usize = 128;
const MAX_ADDRESS_CHARS: usize = 320;
const MAX_LINKS_RESERVE: usize = 32;
const FACTS_OVERHEAD: usize = 2048;

impl<'x> MessageFacts<'x> {
    pub fn has_content(ctx: &SpamFilterContext<'_>) -> bool {
        ctx.input.message.attachments().len() > 0
            || ctx.output.text_parts.iter().any(|part| match part {
                TextPart::Plain { text_body, .. } | TextPart::Html { text_body, .. } => {
                    !text_body.trim().is_empty()
                }
                TextPart::None => false,
            })
    }

    pub fn build(
        ctx: &'x SpamFilterContext<'_>,
        input: &SpamAiInput,
        web_context: Option<&'x RawValue>,
    ) -> Self {
        let message = ctx.input.message;
        let output = &ctx.output;
        let (body, truncated) = body(ctx, input);

        MessageFacts {
            from: Address {
                name: message
                    .from()
                    .and_then(|from| from.first())
                    .and_then(|from| from.name())
                    .map(|name| clean_field(name, MAX_NAME_CHARS)),
                address: field(&output.from.email.address),
                domain: field(&output.from.email.domain_part.fqdn),
            },
            envelope_from: field(&output.env_from_addr.address),
            reply_to: output.reply_to.as_ref().map(|reply_to| Address {
                name: message
                    .reply_to()
                    .and_then(|reply_to| reply_to.first())
                    .and_then(|reply_to| reply_to.name())
                    .map(|name| clean_field(name, MAX_NAME_CHARS)),
                address: field(&reply_to.email.address),
                domain: field(&reply_to.email.domain_part.fqdn),
            }),
            recipient_count: ctx.input.env_rcpt_orig_to.len(),
            to_domains: to_domains(ctx),
            auth: input.include_auth.then(|| auth(ctx)),
            subject: clean_field(&output.subject, MAX_SUBJECT_CHARS),
            list_unsubscribe: message.list_unsubscribe().is_some(),
            is_reply: message.in_reply_to().is_some() || message.references().is_some(),
            attachments: input
                .include_attachments
                .then(|| attachments(ctx, input.max_attachments)),
            links: input.include_links.then(|| links(ctx, input.max_links)),
            web_context,
            body,
            truncated,
        }
    }

    pub fn serialize(&self) -> serde_json::Result<AiFacts> {
        AiFacts::new(self, self.body.len() + FACTS_OVERHEAD)
    }
}

fn serialize_content_type<S: Serializer>(
    content_type: &(&str, Option<&str>),
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match content_type {
        (ctype, Some(subtype)) => serializer.collect_str(&format_args!("{ctype}/{subtype}")),
        (ctype, None) => serializer.serialize_str(ctype),
    }
}

fn to_domains<'x>(ctx: &'x SpamFilterContext<'_>) -> Vec<&'x str> {
    let mut domains: Vec<&'x str> = Vec::new();
    for rcpt in &ctx.output.env_to_orig_addr {
        let domain = field(&rcpt.domain_part.fqdn);
        if !domain.is_empty() && !domains.contains(&domain) {
            domains.push(domain);
            if domains.len() == MAX_TO_DOMAINS {
                break;
            }
        }
    }
    domains.sort_unstable();
    domains
}

fn auth<'x>(ctx: &'x SpamFilterContext<'_>) -> Auth<'x> {
    let input = &ctx.input;
    let mut dkim_domains: Vec<&'x str> = Vec::new();
    for output in input.dkim_result {
        if matches!(output.result(), DkimResult::Pass)
            && let Some(signature) = output.signature()
        {
            let domain = field(&signature.d);
            if !dkim_domains.contains(&domain) && dkim_domains.len() < MAX_DKIM_DOMAINS {
                dkim_domains.push(domain);
            }
        }
    }

    Auth {
        spf: input
            .spf_mail_from_result
            .map_or("none", |spf| match spf.result() {
                SpfResult::Pass => "pass",
                SpfResult::Fail => "fail",
                SpfResult::SoftFail => "softfail",
                SpfResult::Neutral => "neutral",
                SpfResult::TempError => "temperror",
                SpfResult::PermError => "permerror",
                SpfResult::None => "none",
            }),
        dkim: if !dkim_domains.is_empty() {
            "pass"
        } else {
            input
                .dkim_result
                .first()
                .map_or("none", |output| dkim_result(output.result()))
        },
        dkim_domains,
        dmarc: input.dmarc_result.map_or("none", |dmarc| match dmarc {
            DmarcResult::Pass => "pass",
            DmarcResult::Fail(_) => "fail",
            DmarcResult::TempError(_) => "temperror",
            DmarcResult::PermError(_) => "permerror",
            DmarcResult::None => "none",
        }),
        arc: input
            .arc_result
            .map_or("none", |arc| dkim_result(arc.result())),
    }
}

fn dkim_result(result: &DkimResult) -> &'static str {
    match result {
        DkimResult::Pass => "pass",
        DkimResult::Neutral(_) => "neutral",
        DkimResult::Fail(_) => "fail",
        DkimResult::PermError(_) => "permerror",
        DkimResult::TempError(_) => "temperror",
        DkimResult::None => "none",
    }
}

fn attachments<'x>(ctx: &'x SpamFilterContext<'_>, max: usize) -> Vec<Attachment<'x>> {
    let parts = ctx.input.message.attachments();
    let mut attachments = Vec::with_capacity(parts.len().min(max));
    for part in parts.take(max) {
        let content_type = part.content_type();
        attachments.push(Attachment {
            name: part
                .attachment_name()
                .map(|name| clean_field(name, MAX_NAME_CHARS)),
            content_type: content_type.as_ref().map_or(("application", None), |ct| {
                (
                    truncate_chars(ct.ctype(), MAX_NAME_CHARS).0,
                    ct.subtype()
                        .map(|subtype| truncate_chars(subtype, MAX_NAME_CHARS).0),
                )
            }),
        });
    }
    attachments
}

fn links<'x>(ctx: &'x SpamFilterContext<'_>, max: usize) -> Vec<Link<'x>> {
    let mut links = Vec::with_capacity(max.min(MAX_LINKS_RESERVE));
    if max == 0 {
        return links;
    }
    let mut seen: AHashSet<&'x str> = AHashSet::with_capacity(max.min(MAX_LINKS_RESERVE));
    let urls = &ctx.output.urls;

    'outer: for (idx, part) in ctx.output.text_parts.iter().enumerate() {
        let TextPart::Html { html_tokens, .. } = part else {
            continue;
        };
        if !u32::try_from(idx).is_ok_and(|idx| ctx.input.is_body(idx)) {
            continue;
        }

        let mut anchor: Option<(&'x str, Cow<'x, str>)> = None;
        for token in html_tokens {
            match token {
                HtmlToken::StartTag {
                    name: A,
                    attributes,
                    is_self_closing,
                } => {
                    anchor = attributes
                        .iter()
                        .find_map(|(key, value)| {
                            value
                                .as_deref()
                                .filter(|_| *key == HREF)
                                .map(str::trim)
                                .filter(|value| !value.is_empty())
                        })
                        .filter(|_| !*is_self_closing)
                        .map(|href| (href, Cow::Borrowed("")));
                }
                HtmlToken::Text { text } => {
                    if let Some((_, anchor_text)) = &mut anchor {
                        append_link_text(anchor_text, text.as_ref());
                    }
                }
                HtmlToken::EndTag { name: A } => {
                    if let Some((href, text)) = anchor.take()
                        && let Some(url) = urls.get(to_lowercase_cow(href).as_ref())
                        && seen.insert(url.element.url.as_str())
                        && let Some(link) = link(&url.element, Some(text))
                    {
                        links.push(link);
                        if links.len() == max {
                            break 'outer;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if links.len() < max {
        let mut remaining = urls
            .iter()
            .filter(|url| {
                matches!(
                    url.location,
                    Location::BodyText | Location::BodyHtml | Location::HeaderSubject
                ) && url.element.url_parsed.is_some()
                    && url.element.url.contains("://")
                    && !seen.contains(url.element.url.as_str())
            })
            .map(|url| &url.element)
            .collect::<Vec<_>>();
        remaining.sort_unstable_by(|a, b| a.url.cmp(&b.url));
        for url in remaining {
            if let Some(link) = link(url, None) {
                links.push(link);
                if links.len() == max {
                    break;
                }
            }
        }
    }

    links
}

fn link<'x>(url: &'x UrlParts<'_>, text: Option<Cow<'x, str>>) -> Option<Link<'x>> {
    let host = field(&url.url_parsed.as_ref()?.host.fqdn);
    let final_host = url
        .final_host
        .as_deref()
        .map(field)
        .filter(|final_host| *final_host != host);
    Some(Link {
        text: text
            .map(|text| match text {
                Cow::Borrowed(text) => clean_text(text.trim()),
                Cow::Owned(text) => Cow::Owned(clean_text(text.trim()).into_owned()),
            })
            .filter(|text| !text.is_empty()),
        host,
        final_host,
    })
}

fn append_link_text<'x>(anchor_text: &mut Cow<'x, str>, text: &'x str) {
    let current = anchor_text.chars().count();
    if current >= MAX_LINK_TEXT_CHARS {
        return;
    }
    if anchor_text.is_empty() {
        *anchor_text = Cow::Borrowed(truncate_chars(text, MAX_LINK_TEXT_CHARS).0);
    } else {
        let anchor_text = anchor_text.to_mut();
        if !anchor_text.ends_with(' ') && !text.starts_with(' ') {
            anchor_text.push(' ');
        }
        anchor_text.push_str(truncate_chars(text, MAX_LINK_TEXT_CHARS - current).0);
    }
}

fn body<'x>(ctx: &'x SpamFilterContext<'_>, input: &SpamAiInput) -> (Cow<'x, str>, bool) {
    let message = ctx.input.message;
    let Some(part) = message
        .html_body()
        .next()
        .or_else(|| message.text_body().next())
        .and_then(|part| ctx.output.text_parts.get(part.id() as usize))
    else {
        return (Cow::Borrowed(""), false);
    };

    match part {
        TextPart::Html { html_tokens, .. } => {
            let (text, truncated) = html_visible_text(
                html_tokens,
                VisibleTextOptions {
                    quotes: if input.trim_quotes {
                        QuoteMode::Trim
                    } else {
                        QuoteMode::Keep
                    },
                    max_chars: input.max_input_chars,
                },
                None,
            );
            (Cow::Owned(text), truncated)
        }
        TextPart::Plain { text_body, .. } => {
            let text = if input.trim_quotes {
                trim_quotes(text_body)
            } else {
                Cow::Borrowed(*text_body)
            };
            let text = strip_invisible(text);
            let (end, truncated) = {
                let trimmed = text.trim_end();
                let (cut, truncated) = truncate_chars(trimmed, input.max_input_chars);
                (cut.len(), truncated)
            };
            let text = match text {
                Cow::Borrowed(text) => Cow::Borrowed(text.get(..end).unwrap_or(text)),
                Cow::Owned(mut text) => {
                    text.truncate(end);
                    Cow::Owned(text)
                }
            };
            (text, truncated)
        }
        TextPart::None => (Cow::Borrowed(""), false),
    }
}

pub(crate) fn trim_quotes(text: &str) -> Cow<'_, str> {
    let mut owned: Option<String> = None;
    let mut kept_end = 0usize;
    let mut offset = 0usize;
    let mut attribution: Option<&str> = None;

    for line in text.split_inclusive('\n') {
        let line_start = offset;
        offset += line.len();
        let content = line.trim_end_matches(['\r', '\n']);
        let trimmed = content.trim_start();

        if is_separator(content) {
            break;
        }

        if trimmed.starts_with('>') {
            if owned.is_none() {
                owned = Some(text.get(..kept_end).unwrap_or_default().to_string());
            }
            attribution = None;
            continue;
        }

        if let Some(pending) = attribution.take()
            && let Some(owned) = &mut owned
        {
            owned.push_str(pending);
        }

        if content.trim_end().ends_with("wrote:") {
            if owned.is_none() {
                kept_end = line_start;
            }
            attribution = Some(line);
            continue;
        }

        match &mut owned {
            Some(owned) => owned.push_str(line),
            None => kept_end = offset,
        }
    }

    match owned {
        Some(owned) => Cow::Owned(owned),
        None => Cow::Borrowed(text.get(..kept_end).unwrap_or_default()),
    }
}

fn is_separator(line: &str) -> bool {
    hashify::set_ignore_case!(
        line.trim().as_bytes(),
        "--",
        "-----original message-----",
        "________________________________",
    )
}

pub(crate) fn strip_invisible(text: Cow<'_, str>) -> Cow<'_, str> {
    if is_visible_ascii(&text) || !text.chars().any(is_invisible) {
        return text;
    }
    Cow::Owned(text.chars().filter(|ch| !is_invisible(*ch)).collect())
}

fn field(text: &str) -> &str {
    truncate_chars(text, MAX_ADDRESS_CHARS).0
}

fn clean_field(text: &str, max_chars: usize) -> Cow<'_, str> {
    clean_text(truncate_chars(text, max_chars).0)
}

fn clean_text(text: &str) -> Cow<'_, str> {
    strip_invisible(Cow::Borrowed(text))
}

pub(crate) fn truncate_chars(text: &str, max_chars: usize) -> (&str, bool) {
    match text.char_indices().nth(max_chars) {
        Some((end, _)) => (text.get(..end).unwrap_or(text), true),
        None => (text, false),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/spam-filter/src/analysis/ai/facts/tests.rs"]
mod tests;
