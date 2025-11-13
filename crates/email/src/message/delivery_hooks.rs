/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Delivery hook functionality for intercepting and processing email delivery
//!
//! This module provides functionality to call external webhooks during email delivery,
//! allowing for custom routing, filtering, and message modification logic.

use common::{Server, config::jmap::settings::SpecialUse, expr::functions::ResolveVariable};
use futures::future::join_all;
use std::{collections::HashSet, time::Instant};
use trc::AddContext;
use utils::config::utils::ParseValue;

use crate::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    hooks::{self, Action as HookAction, Modification, client::send_delivery_hook_request},
    mailbox::{INBOX_ID, TRASH_ID, manage::MailboxFnc},
};

// Simple resolver for delivery hooks (no variables needed)
pub struct DeliveryResolver;

impl ResolveVariable for DeliveryResolver {
    fn resolve_variable(&self, _variable: u32) -> common::expr::Variable<'_> {
        // Delivery hooks don't use session variables, so return empty
        common::expr::Variable::default()
    }

    fn resolve_global(&self, _variable: &str) -> common::expr::Variable<'_> {
        // Delivery hooks don't use global variables, so return empty
        common::expr::Variable::default()
    }
}

/// Try to call the delivery hook to determine mailbox filing
/// Returns:
/// - (mailbox_ids, flags, skip_inbox, modifications)
pub async fn try_delivery_hook(
    server: &Server,
    user_id: u32,
    sender: &str,
    recipient: &str,
    parsed_message: &mail_parser::Message<'_>,
) -> trc::Result<(HashSet<u32>, HashSet<String>, bool, Vec<Modification>)> {
    // Build envelope with SMTP hook types
    let envelope = hooks::Envelope {
        from: hooks::Address {
            address: sender.to_string(),
        },
        to: hooks::Address {
            address: recipient.to_string(),
        },
    };

    let headers = parsed_message
        .root_part()
        .headers()
        .iter()
        .map(|h| {
            (
                h.name().to_string(),
                h.value().as_text().unwrap_or_default().to_string(),
            )
        })
        .collect();

    let request = hooks::Request::new(
        jmap_proto::types::id::Id::from(user_id).as_string(),
        user_id,
    )
    .with_envelope(envelope)
    .with_message(hooks::Message {
        headers,
        server_headers: vec![],
        contents: String::from_utf8_lossy(&parsed_message.raw_message).into_owned(),
        size: parsed_message.raw_message.len(),
    });

    // Get configured delivery hooks
    let delivery_hooks = &server.core.smtp.session.delivery_hooks;

    // If no hooks configured, return None to continue normal flow
    if delivery_hooks.is_empty() {
        return Ok((HashSet::new(), HashSet::new(), false, Vec::new()));
    }

    // Filter enabled hooks
    let resolver = DeliveryResolver;
    let mut enabled_hooks = Vec::new();
    for hook in delivery_hooks {
        if server
            .eval_if(&hook.enable, &resolver, 0)
            .await
            .unwrap_or(false)
        {
            enabled_hooks.push(hook);
        }
    }

    if enabled_hooks.is_empty() {
        return Ok((HashSet::new(), HashSet::new(), false, Vec::new()));
    }

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
    let mut mailbox_ids = HashSet::new();
    let mut flags = HashSet::new();
    let mut skip_inbox = false;
    let mut modifications_out: Vec<Modification> = Vec::new();
    let mut should_tempfail = false;
    let mut should_permfail = false;

    // Get mailbox cache for resolving mailbox names and special use folders
    let mut cache = server
        .get_cached_messages(user_id)
        .await
        .caused_by(trc::location!())?;

    for (hook, result, elapsed) in hook_results {
        match result {
            Ok(response) => {
                match response.action {
                    HookAction::Accept => {
                        trc::event!(
                            DeliveryHook(trc::DeliveryHookEvent::ActionAccept),
                            AccountId = user_id,
                            Details = format!("Hook '{}' accepted", hook.id),
                            Elapsed = elapsed,
                        );

                        if response.skip_inbox {
                            skip_inbox = true;
                        }

                        for flag in response.flags {
                            flags.insert(flag);
                        }

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
                                    if !mailbox_id.is_empty() {
                                        if let Some(id) = jmap_proto::types::id::Id::from_bytes(
                                            mailbox_id.as_bytes(),
                                        ) {
                                            let document_id = id.document_id();
                                            if cache.has_mailbox_id(&document_id) {
                                                target_id = document_id;
                                            }
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
                                        } else if let Ok(role) =
                                            SpecialUse::parse_value(special_use_role)
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
                                            .mailbox_create_path(user_id, &mailbox)
                                            .await
                                            .caused_by(trc::location!())?
                                        {
                                            // Refresh cache after creating mailbox
                                            cache = server
                                                .get_cached_messages(user_id)
                                                .await
                                                .caused_by(trc::location!())?;
                                            target_id = document_id;
                                        }
                                    }

                                    // Don't file into invalid mailboxes
                                    if target_id != u32::MAX {
                                        trc::event!(
                                            DeliveryHook(trc::DeliveryHookEvent::ActionFileInto),
                                            AccountId = user_id,
                                            Details = format!(
                                                "Hook '{}': Filing into mailbox '{}' (resolved ID: {}), special_use: {:?}, create: {}",
                                                hook.id, mailbox, target_id, special_use, create
                                            ),
                                        );

                                        mailbox_ids.insert(target_id);
                                    }
                                }
                                // Push through other modifications (e.g., AddHeader) for per-recipient handling
                                other => modifications_out.push(other),
                            }
                        }
                    }
                    HookAction::Reject => {
                        trc::event!(
                            DeliveryHook(trc::DeliveryHookEvent::ActionReject),
                            AccountId = user_id,
                            Details = format!("Hook '{}' rejected", hook.id),
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
                    DeliveryHook(trc::DeliveryHookEvent::Error),
                    AccountId = user_id,
                    Details = format!("Hook '{}': {}", hook.id, err),
                    Elapsed = elapsed,
                );

                // If tempfail_on_error is set, hook errors should cause tempfail
                if hook.tempfail_on_error {
                    should_tempfail = true;
                }
            }
        }
    }

    // Check for failures - tempfail takes precedence over permfail for retry behavior
    if should_tempfail {
        return Err(
            trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                .ctx(
                    trc::Key::Reason,
                    "Message temporarily rejected by delivery hook",
                )
                .ctx(trc::Key::Code, 451),
        );
    }

    if should_permfail {
        return Err(
            trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                .ctx(trc::Key::Reason, "Message rejected by delivery hook")
                .ctx(trc::Key::Code, 550),
        );
    }

    trc::event!(
        DeliveryHook(trc::DeliveryHookEvent::ActionFileInto),
        AccountId = user_id,
        Details = format!("Filed into mailboxes: {:?}", mailbox_ids),
    );

    Ok((mailbox_ids, flags, skip_inbox, modifications_out))
}
