/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! FORK: delivery hooks.
//!
//! A delivery hook is an HTTP webhook invoked while a message is delivered to
//! a local account, after the user's Sieve script (or the default Inbox
//! filing) has chosen where the message goes and before it is ingested. The
//! hook sees the message, the envelope, the current filing and the thread the
//! message is expected to join, and answers with an action (accept, discard,
//! reject, quarantine) plus filing changes: extra or replacement mailboxes,
//! flags, header additions and replacements, and preview text.
//!
//! `email_ingest_with_hooks` is the one entry point: the delivery paths call
//! it in place of `email_ingest`, and everything about hooks and the fork's
//! filing policy lives here, so the upstream delivery and ingest code carries
//! nothing but that call.
//!
//! Hooks are configured as `MtaHook` registry objects that declare no SMTP
//! stages, see `common::config::smtp::delivery_hooks`.

use crate::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    hooks::{
        self, Action as HookAction, Modification, ModificationOut,
        client::send_delivery_hook_request,
    },
    mailbox::{DRAFTS_ID, INBOX_ID, JUNK_ID, TRASH_ID, manage::MailboxFnc},
    message::{
        index::PREVIEW_LENGTH,
        ingest::{EmailIngest, IngestEmail, IngestSource, IngestedEmail},
        thread::ThreadFields,
    },
};
use common::{
    Server,
    expr::{Bump, Variable, functions::ResolveVariable},
};
use futures::future::join_all;
use mail_parser::{Message, MessageParser};
use registry::schema::enums::ExpressionVariable;
use std::{borrow::Cow, collections::HashSet, future::Future, str::FromStr, time::Instant};
use trc::AddContext;
use types::{id::Id, keyword::Keyword, special_use::SpecialUse};

pub trait DeliveryHookIngest: Sync + Send {
    /// `email_ingest` for a message delivered to a local account over SMTP or
    /// LMTP, with the delivery hooks and the fork's filing policy applied
    /// first.
    ///
    /// `params.source` must be `IngestSource::Smtp`. `spam_verdict` is the
    /// classifier's verdict for the recipient and `did_file_into` whether the
    /// Sieve script filed the message explicitly; the `is_spam` handed to
    /// ingest is recomputed from them once the hooks have run.
    ///
    /// A message a hook discards is reported as ingested with a `change_id`
    /// of `u64::MAX`, the way a duplicate is, so the delivery succeeds without
    /// a push notification.
    fn email_ingest_with_hooks(
        &self,
        params: IngestEmail<'_>,
        spam_verdict: bool,
        did_file_into: bool,
    ) -> impl Future<Output = trc::Result<IngestedEmail>> + Send;
}

impl DeliveryHookIngest for Server {
    async fn email_ingest_with_hooks(
        &self,
        mut params: IngestEmail<'_>,
        spam_verdict: bool,
        mut did_file_into: bool,
    ) -> trc::Result<IngestedEmail> {
        let IngestSource::Smtp {
            deliver_to,
            envelope_from,
            sender_authentication,
            ..
        } = params.source
        else {
            debug_assert!(false, "delivery hooks apply to SMTP ingest only");
            return self.email_ingest(params).await;
        };
        let Some(message) = params.message.take() else {
            // Ingest reports the parse failure
            return self.email_ingest(params).await;
        };
        let account_id = params.access_token.account_id();
        let session_id = params.session_id;

        let hooks = try_delivery_hook(
            self,
            account_id,
            envelope_from,
            sender_authentication.is_authenticated(),
            deliver_to,
            &message,
            &params.mailbox_ids,
            &params.keywords,
            did_file_into,
            session_id,
        )
        .await?;
        if hooks.discarded {
            return Ok(IngestedEmail {
                change_id: u64::MAX,
                ..Default::default()
            });
        }

        // Hook targets add to the Sieve or default filing, or replace it when
        // asked to. An effective hook fileInto is explicit filing, like a
        // Sieve fileinto.
        did_file_into |= !hooks.mailbox_ids.is_empty();
        if hooks.replace_mailboxes {
            params.mailbox_ids.clear();
        }
        for id in hooks.mailbox_ids {
            if !params.mailbox_ids.contains(&id) {
                params.mailbox_ids.push(id);
            }
        }
        for keyword in hooks.flags.into_iter().map(Keyword::from) {
            if !params.keywords.contains(&keyword) {
                params.keywords.push(keyword);
            }
        }

        // A $NotJunk or $Junk flag, from the script or a hook, overrides the
        // classifier. Otherwise explicit filing is not treated as spam.
        let is_spam = if params.keywords.contains(&Keyword::NotJunk) {
            false
        } else if params.keywords.contains(&Keyword::Junk) {
            true
        } else {
            spam_verdict && !did_file_into
        };

        if hooks.skip_inbox {
            params.mailbox_ids.retain(|&id| id != INBOX_ID);

            // A message nothing else claimed falls back to the Archive, or
            // stays in the Inbox when the account has none or when ingest is
            // about to junk it.
            if params.mailbox_ids.is_empty() {
                params
                    .mailbox_ids
                    .push(hooks.archive_id.filter(|_| !is_spam).unwrap_or(INBOX_ID));
            }
        }
        apply_flag_filing(&mut params.mailbox_ids, &params.keywords);

        params.source = IngestSource::Smtp {
            deliver_to,
            envelope_from,
            sender_authentication,
            is_spam,
        };
        params.preview_text = hooks
            .preview_text
            .map(normalize_preview)
            .filter(|preview| !preview.is_empty());

        // Header modifications, additions first
        let mut add_headers = Vec::new();
        let mut replace_headers = Vec::new();
        for modification in hooks.modifications {
            match modification {
                ModificationOut::AddHeader { name, value } => add_headers.push((name, value)),
                ModificationOut::ReplaceHeader { index, name, value } => {
                    replace_headers.push((index, name, value))
                }
            }
        }
        let mut modified = None;
        if !add_headers.is_empty() {
            modified = Some(apply_add_header_modifications(
                &add_headers,
                params.raw_message,
            ));
        }
        if !replace_headers.is_empty()
            && let Some(replaced) = apply_replace_header_modifications(
                &replace_headers,
                modified.as_deref().unwrap_or(params.raw_message),
                session_id,
            )
        {
            modified = Some(replaced);
        }

        match modified {
            Some(raw_message) => match MessageParser::new().parse(&raw_message) {
                Some(message) => {
                    // The stored blob holds the message as received, so ingest
                    // stores the modified one itself.
                    self.email_ingest(IngestEmail {
                        raw_message: &raw_message,
                        message: Some(message),
                        blob_hash: None,
                        access_token: params.access_token,
                        mailbox_ids: params.mailbox_ids,
                        keywords: params.keywords,
                        received_at: params.received_at,
                        source: params.source,
                        metadata: params.metadata,
                        preview_text: params.preview_text,
                        session_id: params.session_id,
                    })
                    .await
                }
                None => {
                    trc::event!(
                        MessageIngest(trc::MessageIngestEvent::Error),
                        Details = "Failed to parse message after header modifications, delivering it unmodified.",
                        SpanId = session_id
                    );
                    params.message = Some(message);
                    self.email_ingest(params).await
                }
            },
            None => {
                params.message = Some(message);
                self.email_ingest(params).await
            }
        }
    }
}

/// Hook preview text as stored: without carriage returns and no longer than
/// the preview a message body yields, which is what the metadata string pool
/// budgets for it.
fn normalize_preview(text: String) -> String {
    let text = text.replace('\r', "");
    let end = text.floor_char_boundary(PREVIEW_LENGTH);
    if end < text.len() {
        text[..end].to_string()
    } else {
        text
    }
}

/// Applies flag-based mailbox filing during delivery.
///
/// The `$Junk`, `\Deleted` and `\Draft` keywords file the message into the
/// Junk, Trash or Drafts mailbox respectively. These mailboxes are exclusive:
/// a message that belongs in one of them is filed *only* there, replacing any
/// mailboxes selected by the user's Sieve script or by a delivery hook. This
/// avoids the confusing situation where a message a delivery hook marked as
/// junk also shows up in a folder a Sieve rule filed it into.
///
/// When more than one of these keywords is present, precedence is
/// Junk > Trash > Drafts.
fn apply_flag_filing(mailbox_ids: &mut Vec<u32>, keywords: &[Keyword]) {
    let target = if keywords.contains(&Keyword::Junk) {
        JUNK_ID
    } else if keywords.contains(&Keyword::Deleted) {
        TRASH_ID
    } else if keywords.contains(&Keyword::Draft) {
        DRAFTS_ID
    } else {
        return;
    };

    mailbox_ids.clear();
    mailbox_ids.push(target);
}

struct DeliveryResolver;

impl ResolveVariable for DeliveryResolver {
    fn resolve_variable<'a>(&'a self, _: ExpressionVariable, _: &'a Bump) -> Variable<'a> {
        // Delivery hooks have no session to draw variables from
        Variable::default()
    }

    fn resolve_global<'a>(&'a self, _: &str, _: &'a Bump) -> Variable<'a> {
        Variable::default()
    }
}

#[derive(Default)]
struct DeliveryHookResult {
    /// Resolved fileInto targets in hook and modification order. Ingest uses
    /// the first mailbox for duplicate detection, so the order matters.
    mailbox_ids: Vec<u32>,
    flags: HashSet<String>,
    /// Remove the Inbox from the current filing. Never set together with
    /// `replace_mailboxes`.
    skip_inbox: bool,
    /// The account's Archive mailbox, looked up by its special-use role after
    /// the hooks have run (including any mailbox creations). `None` when the
    /// account has no Archive.
    archive_id: Option<u32>,
    /// Replace the current filing with `mailbox_ids` instead of adding to it.
    /// When set, `mailbox_ids` holds only the targets of the hooks that asked
    /// for replacement.
    replace_mailboxes: bool,
    modifications: Vec<ModificationOut>,
    preview_text: Option<String>,
    /// Discard the message without returning an error
    discarded: bool,
}

/// Calls the enabled delivery hooks and merges their answers.
///
/// `current_mailbox_ids`, `current_keywords` and `did_file_into` describe the
/// filing chosen by the user's Sieve script (or the default Inbox filing) and
/// are sent to the hooks.
#[allow(clippy::too_many_arguments)]
async fn try_delivery_hook(
    server: &Server,
    account_id: u32,
    sender: &str,
    is_sender_authenticated: bool,
    recipient: &str,
    message: &Message<'_>,
    current_mailbox_ids: &[u32],
    current_keywords: &[Keyword],
    did_file_into: bool,
    session_id: u64,
) -> trc::Result<DeliveryHookResult> {
    // No delivery hooks configured: nothing to do.
    let delivery_hooks = &server.core.smtp.session.delivery_hooks;
    if delivery_hooks.is_empty() {
        return Ok(DeliveryHookResult::default());
    }

    // Filter enabled hooks
    let resolver = DeliveryResolver;
    let mut arena = Bump::new();
    let mut enabled_hooks = Vec::new();
    for hook in delivery_hooks {
        if server
            .eval_if::<bool, _>(&hook.enable, &resolver, &mut arena, session_id)
            .await
            .unwrap_or(false)
        {
            enabled_hooks.push(hook);
        }
    }

    if enabled_hooks.is_empty() {
        return Ok(DeliveryHookResult::default());
    }

    let filing = hooks::Filing {
        mailbox_ids: current_mailbox_ids
            .iter()
            .map(|&id| Id::from(id).as_string())
            .collect(),
        flags: current_keywords.iter().map(|k| k.to_string()).collect(),
        filed_by_script: did_file_into,
    };

    let envelope = hooks::Envelope {
        from: hooks::Address {
            address: sender.to_string(),
        },
        to: hooks::Address {
            address: recipient.to_string(),
        },
        sender_authenticated: is_sender_authenticated,
    };

    // Header names as the parser knows them, values as written
    let headers = message
        .headers()
        .iter()
        .map(|header| {
            (
                header.name().to_string(),
                String::from_utf8_lossy(header.raw_value()).into_owned(),
            )
        })
        .collect();

    // Resolve the account's primary email for the hook payload, falling back to
    // the account id if the lookup fails or the account has no addresses.
    let principal_name = server
        .account_info(account_id)
        .await
        .ok()
        .and_then(|info| info.addresses.first().cloned())
        .unwrap_or_else(|| Id::from(account_id).as_string());

    // Best effort: the thread is extra context for the hook, so a failed
    // lookup leaves it out rather than failing the delivery.
    let thread = match find_message_thread(server, account_id, message).await {
        Ok(thread) => Some(thread),
        Err(err) => {
            trc::error!(err.caused_by(trc::location!()).account_id(account_id));
            None
        }
    };

    let request = hooks::Request::new(Id::from(account_id).as_string(), principal_name)
        .with_envelope(envelope)
        .with_message(hooks::Message {
            headers,
            server_headers: vec![],
            contents: String::from_utf8_lossy(message.raw()).into_owned(),
            size: message.raw().len(),
        })
        .with_filing(filing)
        .with_thread(thread);

    // Run all enabled hooks in parallel
    let mut hook_futures = Vec::new();
    for hook in enabled_hooks {
        let hook_request = request.clone();
        let time = Instant::now();
        hook_futures.push(async move {
            let result = send_delivery_hook_request(hook, hook_request).await;
            (hook, result, time.elapsed())
        });
    }

    let hook_results = join_all(hook_futures).await;

    // Process all hook results
    let mut add_mailbox_ids = Vec::new();
    // Targets from hooks that asked to replace the filing. When non-empty these
    // win over both the existing filing and the targets of additive hooks.
    let mut replace_mailbox_ids = Vec::new();
    let mut flags = HashSet::new();
    let mut skip_inbox = false;
    let mut modifications_out: Vec<ModificationOut> = Vec::new();
    let mut preview_text: Option<String> = None;
    let mut should_tempfail = false;
    let mut should_permfail = false;

    // Get mailbox cache for resolving mailbox names and special use folders
    let mut cache = server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?;

    for (hook, result, elapsed) in hook_results {
        match result {
            Ok(response) => {
                if response.skip_inbox {
                    skip_inbox = true;
                }

                let mailbox_ids = if response.replace_mailboxes {
                    &mut replace_mailbox_ids
                } else {
                    &mut add_mailbox_ids
                };

                if preview_text.is_none() {
                    preview_text = response.preview_text;
                }

                for flag in response.flags {
                    flags.insert(flag);
                }

                let mut resolved_file_into = false;
                for modification in response.modifications {
                    match modification {
                        Modification::FileInto {
                            folder: mailbox,
                            mailbox_id,
                            special_use,
                            create,
                        } => {
                            let mut target_id = u32::MAX;

                            // Find mailbox by Id first (similar to sieve ingest logic)
                            if !mailbox_id.is_empty()
                                && let Ok(id) = Id::from_str(&mailbox_id)
                            {
                                let document_id = id.document_id();
                                if cache.has_mailbox_id(&document_id) {
                                    target_id = document_id;
                                }
                            }

                            // Find mailbox by special_use role if ID not found
                            if let Some(special_use_role) = &special_use
                                && target_id == u32::MAX
                            {
                                if special_use_role.eq_ignore_ascii_case("inbox") {
                                    target_id = INBOX_ID;
                                } else if special_use_role.eq_ignore_ascii_case("trash") {
                                    target_id = TRASH_ID;
                                } else if let Some(role) = SpecialUse::parse(special_use_role)
                                    && let Some(item) = cache.mailbox_by_role(&role)
                                {
                                    target_id = item.document_id;
                                }
                            }

                            // Find mailbox by name
                            if target_id == u32::MAX {
                                if !create {
                                    if let Some(m) = cache.mailbox_by_path(&mailbox) {
                                        target_id = m.document_id;
                                    }
                                } else if let Some(document_id) = server
                                    .mailbox_create_path(account_id, &mailbox)
                                    .await
                                    .caused_by(trc::location!())?
                                {
                                    // Refresh cache after creating mailbox
                                    cache = server
                                        .get_cached_messages(account_id)
                                        .await
                                        .caused_by(trc::location!())?;
                                    target_id = document_id;
                                }
                            }

                            // Don't file into invalid mailboxes
                            if target_id != u32::MAX {
                                resolved_file_into = true;
                                if !mailbox_ids.contains(&target_id) {
                                    mailbox_ids.push(target_id);
                                }
                            }
                        }
                        Modification::AddHeader { name, value } => {
                            modifications_out.push(ModificationOut::AddHeader { name, value });
                        }
                        Modification::ReplaceHeader { index, name, value } => {
                            modifications_out.push(ModificationOut::ReplaceHeader {
                                index,
                                name,
                                value,
                            });
                        }
                    }
                }

                if response.replace_mailboxes && !resolved_file_into {
                    trc::event!(
                        MtaHook(trc::MtaHookEvent::Error),
                        AccountId = account_id,
                        Details = format!(
                            "Delivery hook '{}' requested replace_mailboxes but no fileInto target resolved, ignoring replacement",
                            hook.id
                        ),
                        Elapsed = elapsed,
                    );
                }

                match response.action {
                    HookAction::Accept => {
                        trc::event!(
                            MtaHook(trc::MtaHookEvent::ActionAccept),
                            AccountId = account_id,
                            Details = format!("Delivery hook '{}' accepted", hook.id),
                            Elapsed = elapsed,
                        );
                    }
                    HookAction::Discard => {
                        trc::event!(
                            MtaHook(trc::MtaHookEvent::ActionDiscard),
                            AccountId = account_id,
                            Details = format!("Delivery hook '{}' discarded", hook.id),
                            Elapsed = elapsed,
                        );
                        // Discard means we stop processing further hooks and do not deliver
                        return Ok(DeliveryHookResult {
                            discarded: true,
                            ..Default::default()
                        });
                    }
                    HookAction::Quarantine => {
                        trc::event!(
                            MtaHook(trc::MtaHookEvent::ActionQuarantine),
                            AccountId = account_id,
                            Details = format!("Delivery hook '{}' quarantined", hook.id),
                            Elapsed = elapsed,
                        );
                        modifications_out.push(ModificationOut::AddHeader {
                            name: "X-Quarantine".into(),
                            value: "true".into(),
                        });
                    }
                    HookAction::Reject => {
                        trc::event!(
                            MtaHook(trc::MtaHookEvent::ActionReject),
                            AccountId = account_id,
                            Details = format!("Delivery hook '{}' rejected", hook.id),
                            Elapsed = elapsed,
                        );

                        // Check if this rejection should be a tempfail or permfail
                        if hook.tempfail_on_error {
                            should_tempfail = true;
                        } else {
                            should_permfail = true;
                        }
                    }
                }
            }
            Err(err) => {
                // Hook error - log and potentially fail
                trc::event!(
                    MtaHook(trc::MtaHookEvent::Error),
                    AccountId = account_id,
                    Details = format!("Delivery hook '{}': {}", hook.id, err),
                    Elapsed = elapsed,
                );

                // If tempfail_on_error is set, hook errors should cause tempfail
                if hook.tempfail_on_error {
                    should_tempfail = true;
                }
            }
        }
    }

    // Check for failures - tempfail takes precedence over permfail for retry
    // behavior. A temporary failure is any error the delivery code does not
    // map to a permanent one, which `MessageIngest(Error)` is.
    if should_tempfail {
        return Err(trc::EventType::MtaHook(trc::MtaHookEvent::Error)
            .ctx(
                trc::Key::Reason,
                "Message temporarily rejected by delivery hook",
            )
            .ctx(trc::Key::Code, 451));
    }

    if should_permfail {
        return Err(
            trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                .ctx(trc::Key::Reason, "Message rejected by delivery hook")
                .ctx(trc::Key::Code, 550),
        );
    }

    // A replacing hook whose targets did not resolve is ignored rather than
    // replacing the filing with nothing. When the filing is replaced there is
    // no existing filing left for skip_inbox to act on, so it is dropped too.
    let (mailbox_ids, replace_mailboxes, skip_inbox) = if !replace_mailbox_ids.is_empty() {
        (replace_mailbox_ids, true, false)
    } else {
        (add_mailbox_ids, false, skip_inbox)
    };

    Ok(DeliveryHookResult {
        mailbox_ids,
        flags,
        skip_inbox,
        archive_id: cache
            .mailbox_by_role(&SpecialUse::Archive)
            .map(|m| m.document_id),
        replace_mailboxes,
        modifications: modifications_out,
        preview_text,
        discarded: false,
    })
}

/// Resolves the thread the message is expected to join in `account_id`, with
/// the same header scan and lookup ingest uses.
async fn find_message_thread(
    server: &Server,
    account_id: u32,
    message: &Message<'_>,
) -> trc::Result<hooks::Thread> {
    let fields = ThreadFields::scan(message);
    let result = server
        .find_thread_id(account_id, fields.subject, &fields.message_ids)
        .await?;

    Ok(hooks::Thread {
        id: result.thread_id.map(|id| Id::from(id).as_string()),
        merged_ids: result
            .merge_ids
            .into_iter()
            .map(|id| Id::from(id).as_string())
            .collect(),
    })
}

// Prepend AddHeader modifications to a raw RFC 5322 message
fn apply_add_header_modifications(
    add_headers: &[(String, String)],
    original_raw: &[u8],
) -> Vec<u8> {
    let extra_len: usize = add_headers
        .iter()
        .map(|(h, v)| h.len() + 2 + v.len() + 2) // ": " + CRLF
        .sum();
    let mut new_message = Vec::with_capacity(original_raw.len() + extra_len);

    for (name, value) in add_headers {
        new_message.extend_from_slice(name.as_bytes());
        new_message.extend_from_slice(b": ");

        // Encode LF and CR per RFC 8187 to prevent header corruption
        for byte in value.bytes() {
            match byte {
                b'\r' => new_message.extend_from_slice(b"%0D"),
                b'\n' => new_message.extend_from_slice(b"%0A"),
                _ => new_message.push(byte),
            }
        }

        new_message.extend_from_slice(b"\r\n");
    }

    new_message.extend_from_slice(original_raw);
    new_message
}

// Replace headers in a raw RFC 5322 message using index-based targeting
fn apply_replace_header_modifications(
    replace_headers: &[(u32, String, String)],
    original_raw: &[u8],
    session_id: u64,
) -> Option<Vec<u8>> {
    // Find the header/body boundary
    let body_start = original_raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(original_raw.len());

    let headers_section = &original_raw[..body_start.saturating_sub(2)];
    let body_section = &original_raw[body_start..];

    // Parse headers into mutable list of (name, value) pairs
    let mut headers: Vec<(Cow<[u8]>, Cow<[u8]>)> = Vec::new();
    let mut current_name: Option<Vec<u8>> = None;
    let mut current_value: Vec<u8> = Vec::new();

    for line in headers_section.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);

        if line.is_empty() {
            continue;
        }

        // Check if this is a continuation line (starts with whitespace)
        if line.first().is_some_and(|&c| c == b' ' || c == b'\t') {
            if current_name.is_some() {
                current_value.extend_from_slice(b"\r\n");
                current_value.extend_from_slice(line);
            }
        } else {
            // Save previous header if exists
            if let Some(name) = current_name.take() {
                headers.push((Cow::Owned(name), Cow::Owned(current_value.clone())));
                current_value.clear();
            }

            // Parse new header
            if let Some(colon_pos) = line.iter().position(|&b| b == b':') {
                current_name = Some(line[..colon_pos].to_vec());
                let value_start = colon_pos + 1;
                if value_start < line.len() {
                    let value_bytes = &line[value_start..];
                    // Skip leading space if present
                    let value_bytes = value_bytes.strip_prefix(b" ").unwrap_or(value_bytes);
                    current_value.extend_from_slice(value_bytes);
                }
            }
        }
    }

    // Save last header
    if let Some(name) = current_name {
        headers.push((Cow::Owned(name), Cow::Owned(current_value)));
    }

    let mut had_modifications = false;

    // Apply each replace operation
    for (target_index, target_name, new_value) in replace_headers {
        let mut occurrence_count = 0u32;
        let mut found = false;

        headers.retain_mut(|(name, value)| {
            if name.len() == target_name.len()
                && name
                    .iter()
                    .zip(target_name.as_bytes())
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                occurrence_count += 1;
                if occurrence_count == *target_index {
                    found = true;
                    if new_value.is_empty() {
                        // Delete header
                        had_modifications = true;
                        return false;
                    } else {
                        // Replace value with RFC 8187 encoding
                        let mut encoded_value = Vec::new();
                        for byte in new_value.bytes() {
                            match byte {
                                b'\r' => encoded_value.extend_from_slice(b"%0D"),
                                b'\n' => encoded_value.extend_from_slice(b"%0A"),
                                _ => encoded_value.push(byte),
                            }
                        }
                        *value = Cow::Owned(encoded_value);
                        had_modifications = true;
                    }
                }
            }
            true
        });

        if !found {
            trc::event!(
                MessageIngest(trc::MessageIngestEvent::Error),
                Details = format!(
                    "ReplaceHeader: header '{}' occurrence {} not found",
                    target_name, target_index
                ),
                SpanId = session_id
            );
        }
    }

    if !had_modifications {
        return None;
    }

    // Rebuild message
    let estimated_size = headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>()
        + body_section.len()
        + 4;
    let mut new_message = Vec::with_capacity(estimated_size);

    for (name, value) in headers {
        new_message.extend_from_slice(&name);
        // Check if value has leading whitespace (header folding)
        if value.first().is_some_and(|&c| c == b' ' || c == b'\t') {
            new_message.extend_from_slice(b":");
        } else {
            new_message.extend_from_slice(b": ");
        }
        new_message.extend_from_slice(&value);
        // Check if value already ends with newline
        if value.last().is_none_or(|&c| c != b'\n') {
            new_message.extend_from_slice(b"\r\n");
        }
    }

    new_message.extend_from_slice(b"\r\n");
    new_message.extend_from_slice(body_section);

    Some(new_message)
}

#[cfg(test)]
mod tests {
    use super::{
        apply_add_header_modifications, apply_flag_filing, apply_replace_header_modifications,
        normalize_preview,
    };
    use crate::mailbox::{ARCHIVE_ID, DRAFTS_ID, INBOX_ID, JUNK_ID, SENT_ID, TRASH_ID};
    use mail_parser::MessageParser;
    use types::keyword::Keyword;

    /// Header names as the parser knows them and raw values without the
    /// surrounding whitespace.
    fn parse_headers(raw: &[u8]) -> Vec<(String, String)> {
        let message = MessageParser::new().parse(raw).expect("parse message");
        message
            .headers()
            .iter()
            .map(|header| {
                (
                    header.name().to_string(),
                    String::from_utf8_lossy(header.raw_value())
                        .trim()
                        .to_string(),
                )
            })
            .collect()
    }

    fn has_header(headers: &[(String, String)], name: &str, value: &str) -> bool {
        headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case(name) && v == value)
    }

    fn has_header_named(headers: &[(String, String)], name: &str) -> bool {
        headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
    }

    #[test]
    fn add_single_header_prepends_and_parses() {
        let base = b"Subject: Hi\r\n\r\nBody";
        let out =
            apply_add_header_modifications(&[("X-Test".to_string(), "foo".to_string())], base);

        // Prepend before original headers
        let expected_prefix = b"X-Test: foo\r\nSubject: Hi\r\n\r\n";
        assert!(out.starts_with(expected_prefix));

        // Parser must see the new header
        assert!(has_header(&parse_headers(&out), "X-Test", "foo"));
    }

    #[test]
    fn add_multiple_headers_preserves_order() {
        let base = b"Subject: Hi\r\n\r\nBody";
        let out = apply_add_header_modifications(
            &[
                ("X-A".to_string(), "1".to_string()),
                ("X-B".to_string(), "2".to_string()),
            ],
            base,
        );

        // Ensure order X-A then X-B at the top
        let s = String::from_utf8_lossy(&out);
        let pos_a = s.find("X-A: 1").unwrap();
        let pos_b = s.find("X-B: 2").unwrap();
        assert!(pos_a < pos_b);

        let headers = parse_headers(&out);
        assert!(has_header(&headers, "X-A", "1"));
        assert!(has_header(&headers, "X-B", "2"));
    }

    #[test]
    fn add_header_with_trailing_lf_encodes_it() {
        let base = b"Subject: Hi\r\n\r\nBody";
        let out =
            apply_add_header_modifications(&[("X-LF".to_string(), "val\n".to_string())], base);

        // Trailing LF should be encoded per RFC 8187
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("X-LF: val%0A\r\n"));

        // Ensure message remains parseable
        assert!(has_header_named(&parse_headers(&out), "X-LF"));
    }

    #[test]
    fn add_header_encodes_newlines_per_rfc8187() {
        let base = b"Subject: Hi\r\n\r\nBody";

        // Test LF encoding
        let out = apply_add_header_modifications(
            &[("X-NewLine".to_string(), "before\nafter".to_string())],
            base,
        );
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("X-NewLine: before%0Aafter\r\n"));

        // Test CR encoding
        let out = apply_add_header_modifications(
            &[("X-CR".to_string(), "before\rafter".to_string())],
            base,
        );
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("X-CR: before%0Dafter\r\n"));

        // Test CRLF encoding
        let out = apply_add_header_modifications(
            &[("X-CRLF".to_string(), "before\r\nafter".to_string())],
            base,
        );
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("X-CRLF: before%0D%0Aafter\r\n"));

        // Ensure the message remains parseable
        assert!(has_header_named(&parse_headers(&out), "X-CRLF"));
    }

    #[test]
    fn test_replace_single_header() {
        let base = b"Subject: Old Subject\r\nFrom: sender@example.com\r\n\r\nBody";
        let modified = apply_replace_header_modifications(
            &[(1, "Subject".to_string(), "New Subject".to_string())],
            base,
            12345,
        )
        .unwrap();
        let headers = parse_headers(&modified);

        assert!(has_header(&headers, "Subject", "New Subject"));
        assert!(has_header(&headers, "From", "sender@example.com"));
    }

    #[test]
    fn test_replace_by_index_second_occurrence() {
        let base = b"Received: from server1\r\nReceived: from server2\r\nReceived: from server3\r\n\r\nBody";
        let modified = apply_replace_header_modifications(
            &[(2, "Received".to_string(), "from modified-server2".to_string())],
            base,
            12345,
        )
        .unwrap();
        let s = String::from_utf8_lossy(&modified);

        // Verify the second occurrence was modified
        assert_eq!(s.matches("Received:").count(), 3);
        assert!(s.contains("from server1"));
        assert!(s.contains("from modified-server2"));
        assert!(s.contains("from server3"));
        assert!(!s.contains("from server2"));
    }

    #[test]
    fn test_replace_with_empty_deletes() {
        let base = b"Subject: Test\r\nX-Custom: value\r\nFrom: sender@example.com\r\n\r\nBody";
        let modified = apply_replace_header_modifications(
            &[(1, "X-Custom".to_string(), "".to_string())],
            base,
            12345,
        )
        .unwrap();
        let headers = parse_headers(&modified);

        assert!(!has_header_named(&headers, "X-Custom"));
        assert!(has_header_named(&headers, "Subject"));
        assert!(has_header_named(&headers, "From"));
    }

    #[test]
    fn test_replace_nonexistent_returns_none() {
        let base = b"Subject: Test\r\n\r\nBody";
        let result = apply_replace_header_modifications(
            &[(1, "X-NonExistent".to_string(), "value".to_string())],
            base,
            12345,
        );

        // Should return None since no modifications were made
        assert!(result.is_none());
    }

    #[test]
    fn test_replace_encodes_newlines_rfc8187() {
        let base = b"Subject: Old\r\n\r\nBody";

        // Test LF encoding
        let ops_lf = vec![(1, "Subject".to_string(), "before\nafter".to_string())];
        let modified_lf = apply_replace_header_modifications(&ops_lf, base, 12345).unwrap();
        assert!(String::from_utf8_lossy(&modified_lf).contains("Subject: before%0Aafter"));

        // Test CR encoding
        let ops_cr = vec![(1, "Subject".to_string(), "before\rafter".to_string())];
        let modified_cr = apply_replace_header_modifications(&ops_cr, base, 12345).unwrap();
        assert!(String::from_utf8_lossy(&modified_cr).contains("Subject: before%0Dafter"));

        // Test CRLF encoding
        let ops_crlf = vec![(1, "Subject".to_string(), "before\r\nafter".to_string())];
        let modified_crlf = apply_replace_header_modifications(&ops_crlf, base, 12345).unwrap();
        assert!(String::from_utf8_lossy(&modified_crlf).contains("Subject: before%0D%0Aafter"));
    }

    #[test]
    fn test_replace_preserves_body() {
        let base = b"Subject: Test\r\n\r\nThis is the body\r\nwith multiple lines";
        let modified = apply_replace_header_modifications(
            &[(1, "Subject".to_string(), "New".to_string())],
            base,
            12345,
        )
        .unwrap();
        let s = String::from_utf8_lossy(&modified);
        assert!(s.contains("This is the body\r\nwith multiple lines"));
    }

    #[test]
    fn test_replace_case_insensitive() {
        let base = b"subject: Test\r\n\r\nBody";
        let modified = apply_replace_header_modifications(
            &[(1, "Subject".to_string(), "New".to_string())],
            base,
            12345,
        )
        .unwrap();
        assert!(has_header(&parse_headers(&modified), "Subject", "New"));
    }

    #[test]
    fn test_replace_index_out_of_bounds() {
        let base = b"Subject: Test\r\n\r\nBody";
        // Try to replace the 2nd occurrence when only 1 exists
        let result = apply_replace_header_modifications(
            &[(2, "Subject".to_string(), "New".to_string())],
            base,
            12345,
        );

        // Should return None - no modifications made
        assert!(result.is_none());
    }

    #[test]
    fn test_replace_multiple_operations() {
        let base = b"Subject: Old\r\nFrom: old@example.com\r\nX-Delete: value\r\n\r\nBody";
        let modified = apply_replace_header_modifications(
            &[
                (1, "Subject".to_string(), "New Subject".to_string()),
                (1, "From".to_string(), "new@example.com".to_string()),
                (1, "X-Delete".to_string(), "".to_string()),
            ],
            base,
            12345,
        )
        .unwrap();
        let headers = parse_headers(&modified);

        assert!(has_header(&headers, "Subject", "New Subject"));
        assert!(has_header(&headers, "From", "new@example.com"));
        assert!(!has_header_named(&headers, "X-Delete"));
    }

    #[test]
    fn test_replace_preserves_header_order() {
        let base = b"From: sender\r\nTo: recipient\r\nSubject: Test\r\n\r\nBody";
        let modified = apply_replace_header_modifications(
            &[(1, "Subject".to_string(), "New".to_string())],
            base,
            12345,
        )
        .unwrap();
        let s = String::from_utf8_lossy(&modified);

        // Check that From comes before To, and To comes before Subject
        let from_pos = s.find("From:").unwrap();
        let to_pos = s.find("To:").unwrap();
        let subject_pos = s.find("Subject:").unwrap();

        assert!(from_pos < to_pos);
        assert!(to_pos < subject_pos);
    }

    #[test]
    fn test_junk_flag_replaces_inbox() {
        let mut mailbox_ids = vec![INBOX_ID];
        apply_flag_filing(&mut mailbox_ids, &[Keyword::Junk]);
        assert_eq!(mailbox_ids, vec![JUNK_ID]);
    }

    #[test]
    fn test_junk_flag_replaces_multiple() {
        let mut mailbox_ids = vec![INBOX_ID, ARCHIVE_ID];
        apply_flag_filing(&mut mailbox_ids, &[Keyword::Junk]);
        assert_eq!(mailbox_ids, vec![JUNK_ID]);
    }

    #[test]
    fn test_deleted_flag_filing() {
        let mut mailbox_ids = vec![INBOX_ID];
        apply_flag_filing(&mut mailbox_ids, &[Keyword::Deleted]);
        assert_eq!(mailbox_ids, vec![TRASH_ID]);
    }

    #[test]
    fn test_draft_flag_filing() {
        let mut mailbox_ids = vec![INBOX_ID];
        apply_flag_filing(&mut mailbox_ids, &[Keyword::Draft]);
        assert_eq!(mailbox_ids, vec![DRAFTS_ID]);
    }

    #[test]
    fn test_junk_overrides_explicit_fileinto() {
        // A Sieve `fileinto` must not leave the message in both the target
        // mailbox and Junk: Junk is exclusive.
        let mut mailbox_ids = vec![ARCHIVE_ID];
        apply_flag_filing(&mut mailbox_ids, &[Keyword::Junk]);
        assert_eq!(mailbox_ids, vec![JUNK_ID]);
    }

    #[test]
    fn test_multiple_special_flags_junk_wins() {
        let mut mailbox_ids = vec![INBOX_ID];
        apply_flag_filing(
            &mut mailbox_ids,
            &[Keyword::Deleted, Keyword::Draft, Keyword::Junk],
        );
        assert_eq!(mailbox_ids, vec![JUNK_ID]);
    }

    #[test]
    fn test_multiple_special_flags_trash_over_drafts() {
        let mut mailbox_ids = vec![INBOX_ID];
        apply_flag_filing(&mut mailbox_ids, &[Keyword::Draft, Keyword::Deleted]);
        assert_eq!(mailbox_ids, vec![TRASH_ID]);
    }

    #[test]
    fn test_non_special_flags_ignored() {
        let mut mailbox_ids = vec![INBOX_ID, ARCHIVE_ID];
        apply_flag_filing(&mut mailbox_ids, &[Keyword::Seen, Keyword::Flagged]);
        assert_eq!(mailbox_ids, vec![INBOX_ID, ARCHIVE_ID]);
    }

    #[test]
    fn test_junk_already_in_target_mailbox() {
        let mut mailbox_ids = vec![JUNK_ID];
        apply_flag_filing(&mut mailbox_ids, &[Keyword::Junk]);
        assert_eq!(mailbox_ids, vec![JUNK_ID]);
    }

    #[test]
    fn test_deleted_replaces_other_mailboxes() {
        let mut mailbox_ids = vec![INBOX_ID, ARCHIVE_ID, SENT_ID];
        apply_flag_filing(&mut mailbox_ids, &[Keyword::Deleted]);
        assert_eq!(mailbox_ids, vec![TRASH_ID]);
    }

    #[test]
    fn test_empty_mailboxes_get_target() {
        let mut mailbox_ids: Vec<u32> = vec![];
        apply_flag_filing(&mut mailbox_ids, &[Keyword::Junk]);
        assert_eq!(mailbox_ids, vec![JUNK_ID]);
    }

    #[test]
    fn preview_is_stripped_and_capped() {
        assert_eq!(normalize_preview("a\r\nb".to_string()), "a\nb");
        let long = "é".repeat(300);
        let preview = normalize_preview(long);
        assert!(preview.len() <= super::PREVIEW_LENGTH);
        assert!(preview.chars().all(|c| c == 'é'));
    }
}
