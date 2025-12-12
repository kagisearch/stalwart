/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;

use directory::Permission;
use jmap_proto::types::{id::Id, state::StateChange, type_state::DataType};
use mail_parser::MessageParser;
use std::{borrow::Cow, future::Future};
use store::ahash::AHashMap;
use utils::BlobHash;

use crate::{
    mailbox::INBOX_ID,
    message::ingest::IngestedEmail,
    sieve::ingest::{SieveOutputMessage, SieveScriptIngest},
};

use super::{
    delivery_hooks::try_delivery_hook,
    ingest::{EmailIngest, IngestEmail, IngestSource},
};
use crate::hooks::ModificationOut as HookModification;

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

#[derive(Debug)]
pub struct IngestMessage {
    pub sender_address: String,
    pub sender_authenticated: bool,
    pub recipients: Vec<String>,
    pub message_blob: BlobHash,
    pub message_size: u64,
    pub session_id: u64,
}

#[cfg(test)]
mod tests {
    use super::apply_add_header_modifications;
    use mail_parser::MessageParser;

    fn parse_headers(raw: &[u8]) -> Vec<(String, String)> {
        let msg = MessageParser::new().parse(raw).expect("parse message");
        msg.root_part()
            .headers()
            .iter()
            .map(|h| {
                (
                    h.name().to_string(),
                    h.value().as_text().unwrap_or_default().to_string(),
                )
            })
            .collect()
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
        let headers = parse_headers(&out);
        assert!(headers.iter().any(|(n, v)| n == "X-Test" && v == "foo"));
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
        // Both must be present
        assert!(headers.iter().any(|(n, v)| n == "X-A" && v == "1"));
        assert!(headers.iter().any(|(n, v)| n == "X-B" && v == "2"));
    }

    #[test]
    fn add_header_with_trailing_lf_is_accepted() {
        let base = b"Subject: Hi\r\n\r\nBody";
        let out =
            apply_add_header_modifications(&[("X-LF".to_string(), "val\n".to_string())], base);

        // We don't normalize existing trailing LF to CRLF; parser should still accept
        let headers = parse_headers(&out);
        assert!(headers.iter().any(|(n, v)| n == "X-LF" && v == "val"));
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
        let headers = parse_headers(&out);
        assert!(headers.iter().any(|(n, _)| n == "X-CRLF"));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalDeliveryStatus {
    Success,
    TemporaryFailure {
        reason: Cow<'static, str>,
    },
    PermanentFailure {
        code: [u8; 3],
        reason: Cow<'static, str>,
    },
}

pub struct LocalDeliveryResult {
    pub status: Vec<LocalDeliveryStatus>,
    pub autogenerated: Vec<AutogeneratedMessage>,
}

pub struct AutogeneratedMessage {
    pub sender_address: String,
    pub recipients: Vec<String>,
    pub message: Vec<u8>,
}

pub trait MailDelivery: Sync + Send {
    fn deliver_message(
        &self,
        message: IngestMessage,
    ) -> impl Future<Output = LocalDeliveryResult> + Send;
}

impl MailDelivery for Server {
    async fn deliver_message(&self, message: IngestMessage) -> LocalDeliveryResult {
        // Read message
        let raw_message = match self
            .core
            .storage
            .blob
            .get_blob(message.message_blob.as_slice(), 0..usize::MAX)
            .await
        {
            Ok(Some(raw_message)) => raw_message,
            Ok(None) => {
                trc::event!(
                    MessageIngest(trc::MessageIngestEvent::Error),
                    Reason = "Blob not found.",
                    SpanId = message.session_id,
                    CausedBy = trc::location!()
                );

                return LocalDeliveryResult {
                    status: (0..message.recipients.len())
                        .map(|_| LocalDeliveryStatus::TemporaryFailure {
                            reason: "Blob not found.".into(),
                        })
                        .collect::<Vec<_>>(),
                    autogenerated: vec![],
                };
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to fetch message blob.")
                        .span_id(message.session_id)
                        .caused_by(trc::location!())
                );

                return LocalDeliveryResult {
                    status: (0..message.recipients.len())
                        .map(|_| LocalDeliveryStatus::TemporaryFailure {
                            reason: "Temporary I/O error.".into(),
                        })
                        .collect::<Vec<_>>(),
                    autogenerated: vec![],
                };
            }
        };

        // Obtain the UIDs for each recipient
        let mut uids: AHashMap<u32, usize> = AHashMap::with_capacity(message.recipients.len());
        let mut result = LocalDeliveryResult {
            status: Vec::with_capacity(message.recipients.len()),
            autogenerated: Vec::new(),
        };

        for rcpt in message.recipients {
            let uid = match self
                .email_to_id(&self.core.storage.directory, &rcpt, message.session_id)
                .await
            {
                Ok(Some(uid)) => uid,
                Ok(None) => {
                    // Something went wrong
                    result.status.push(LocalDeliveryStatus::PermanentFailure {
                        code: [5, 5, 0],
                        reason: "Mailbox not found.".into(),
                    });
                    continue;
                }
                Err(err) => {
                    trc::error!(
                        err.details("Failed to lookup recipient.")
                            .ctx(trc::Key::To, rcpt)
                            .span_id(message.session_id)
                            .caused_by(trc::location!())
                    );
                    result.status.push(LocalDeliveryStatus::TemporaryFailure {
                        reason: "Address lookup failed.".into(),
                    });
                    continue;
                }
            };
            if let Some(status) = uids.get(&uid).and_then(|pos| result.status.get(*pos)) {
                result.status.push(status.clone());
                continue;
            }

            uids.insert(uid, result.status.len());

            result.status.push(
                match deliver_to_recipient(
                    self,
                    uid,
                    &rcpt,
                    &message.sender_address,
                    message.sender_authenticated,
                    message.session_id,
                    &raw_message,
                    &mut result.autogenerated,
                )
                .await
                {
                    Ok(ingested_message) => {
                        if ingested_message.change_id != u64::MAX {
                            self.broadcast_state_change(
                                StateChange::new(uid, ingested_message.change_id)
                                    .with_change(DataType::EmailDelivery)
                                    .with_change(DataType::Email)
                                    .with_change(DataType::Mailbox)
                                    .with_change(DataType::Thread),
                            )
                            .await;
                        }

                        LocalDeliveryStatus::Success
                    }
                    Err(err) => match err.as_ref() {
                        trc::EventType::Limit(trc::LimitEvent::Quota) => {
                            LocalDeliveryStatus::TemporaryFailure {
                                reason: "Mailbox over quota.".into(),
                            }
                        }
                        trc::EventType::Limit(trc::LimitEvent::TenantQuota) => {
                            LocalDeliveryStatus::TemporaryFailure {
                                reason: "Organization over quota.".into(),
                            }
                        }
                        trc::EventType::Security(trc::SecurityEvent::Unauthorized) => {
                            LocalDeliveryStatus::PermanentFailure {
                                code: [5, 5, 0],
                                reason: "This account is not authorized to receive email.".into(),
                            }
                        }
                        trc::EventType::MessageIngest(trc::MessageIngestEvent::Error) => {
                            LocalDeliveryStatus::PermanentFailure {
                                code: err
                                    .value(trc::Key::Code)
                                    .and_then(|v| v.to_uint())
                                    .map(|n| {
                                        [(n / 100) as u8, ((n % 100) / 10) as u8, (n % 10) as u8]
                                    })
                                    .unwrap_or([5, 5, 0]),
                                reason: err
                                    .value_as_str(trc::Key::Reason)
                                    .unwrap_or_default()
                                    .to_string()
                                    .into(),
                            }
                        }
                        _ => LocalDeliveryStatus::TemporaryFailure {
                            reason: "Transient server failure.".into(),
                        },
                    },
                },
            )
        }

        result
    }
}

async fn deliver_to_recipient(
    server: &Server,
    uid: u32,
    rcpt: &str,
    sender: &str,
    is_sender_authenticated: bool,
    session_id: u64,
    raw_message: &[u8],
    autogenerated: &mut Vec<AutogeneratedMessage>,
) -> trc::Result<IngestedEmail> {
    // Obtain access token
    let access_token = match server.get_access_token(uid).await.and_then(|token| {
        token
            .assert_has_permission(Permission::EmailReceive)
            .map(|_| token)
    }) {
        Ok(access_token) => access_token,
        Err(err) => return Err(err),
    };

    // Parse original message, sieve may generate changes later
    let original_message = match MessageParser::new().parse(&raw_message) {
        Some(msg) => msg,
        None => {
            return Err(
                trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                    .ctx(trc::Key::Code, 550)
                    .ctx(trc::Key::Reason, "Failed to parse e-mail message."),
            );
        }
    };

    // Obtain active sieve script
    let active_script = match server.sieve_script_get_active(uid).await {
        Ok(script) => script,
        Err(err) => return Err(err),
    };

    let mut final_ingested_message = IngestedEmail {
        id: Id::default(),
        change_id: u64::MAX,
        blob_id: Default::default(),
        size: raw_message.len(),
        imap_uids: Vec::new(),
    };

    // Process sieve script, which produces messages to deliver
    let messages = if let Some(active_script) = active_script {
        match server
            .sieve_script_ingest(
                &access_token,
                &original_message,
                &sender,
                &rcpt,
                session_id,
                active_script,
                autogenerated,
            )
            .await
        {
            Ok(sieve_result) => {
                if let Some(reason) = sieve_result.reject_reason.as_ref() {
                    // Rejection
                    let err = trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                        .ctx(trc::Key::Code, 571)
                        .ctx(trc::Key::Reason, reason.clone());
                    return Err(err);
                } else if sieve_result.discarded {
                    // Discard (internally looks like success, without ingest)
                    return Ok(final_ingested_message);
                } else {
                    sieve_result.messages
                }
            }
            Err(err) => return Err(err),
        }
    } else {
        vec![SieveOutputMessage {
            raw: raw_message.to_vec(),
            mailbox_ids: vec![INBOX_ID],
            keywords: vec![],
            changed: false,
            did_file_into: false,
        }]
    };

    let can_spam_classify = access_token.has_permission(Permission::SpamFilterClassify);
    let spam_train = server.email_bayes_can_train(&access_token);

    let mut last_temp_error = None;
    let mut has_delivered = false;

    for output_message in messages {
        // Parse message if needed
        let parsed_output_message = if !output_message.changed {
            original_message.clone()
        } else if let Some(message) = MessageParser::new().parse(&output_message.raw) {
            message
        } else {
            trc::event!(
                MessageIngest(trc::MessageIngestEvent::Error),
                Details = "Failed to parse Sieve generated message.",
                SpanId = session_id
            );

            continue;
        };

        // Final delivery parameters
        let mut mailbox_ids: Vec<u32> = output_message.mailbox_ids;
        let mut keywords: Vec<jmap_proto::types::keyword::Keyword> = output_message.keywords;

        // Apply delivery hooks (mailboxes/flags/skip_inbox + per-recipient modifications)
        let mut owned_new_raw: Option<Vec<u8>> = None;
        let mut use_modified = false;
        let mut parsed_for_ingest = parsed_output_message.clone();
        match try_delivery_hook(server, uid, &sender, &rcpt, &parsed_output_message).await {
            Ok(result) => {
                let (hook_mailboxes, hook_flags, skip_inbox, hook_modifications) = match result {
                    Some(v) => v,
                    None => {
                        // Discard without error
                        return Ok(IngestedEmail {
                            id: Id::default(),
                            change_id: u64::MAX, // this is specially handled and the message is not ingested
                            blob_id: Default::default(),
                            imap_uids: Vec::new(),
                            size: 0,
                        });
                    }
                };

                for id in hook_mailboxes {
                    if !mailbox_ids.contains(&id) {
                        mailbox_ids.push(id);
                    }
                }

                for k in hook_flags
                    .iter()
                    .map(jmap_proto::types::keyword::Keyword::from)
                {
                    if !keywords.contains(&k) {
                        keywords.push(k);
                    }
                }

                if skip_inbox {
                    mailbox_ids.retain(|&id| id != INBOX_ID);
                }

                // Filter and apply AddHeader modifications
                let add_headers: Vec<(String, String)> = hook_modifications
                    .into_iter()
                    .filter_map(|m| match m {
                        HookModification::AddHeader { name, value } => Some((name, value)),
                    })
                    .collect();

                if !add_headers.is_empty() {
                    owned_new_raw = Some(apply_add_header_modifications(
                        &add_headers,
                        &output_message.raw,
                    ));

                    // Try to re-parse the modified message; rollback on failure
                    let parse_ok = if let Some(ref bytes) = owned_new_raw {
                        if let Some(new_parsed) = MessageParser::new().parse(bytes) {
                            parsed_for_ingest = new_parsed;
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if !parse_ok {
                        trc::event!(
                            MessageIngest(trc::MessageIngestEvent::Error),
                            Details = "Failed to parse message after AddHeader modifications.",
                            SpanId = session_id
                        );
                        use_modified = false;
                    } else {
                        use_modified = true;
                    }
                }
            }
            Err(err) => return Err(err),
        }

        // Use modified raw bytes if present
        let raw_for_ingest: &[u8] = if use_modified {
            owned_new_raw
                .as_deref()
                .expect("modified bytes must exist when flagged")
        } else {
            &output_message.raw
        };

        match server
            .email_ingest(IngestEmail {
                raw_message: raw_for_ingest,
                message: Some(parsed_for_ingest),
                access_token: &access_token,
                mailbox_ids,
                keywords,
                received_at: None,
                source: IngestSource::Smtp {
                    deliver_to: &rcpt,
                    is_sender_authenticated,
                },
                spam_classify: can_spam_classify && !output_message.did_file_into,
                spam_train,
                session_id: session_id,
            })
            .await
        {
            Ok(ingested_message) => {
                has_delivered = true;
                final_ingested_message = ingested_message;
            }
            Err(err) => {
                last_temp_error = err.into();
            }
        }
    }

    if has_delivered || last_temp_error.is_none() {
        Ok(final_ingested_message)
    } else {
        // There were problems during delivery
        #[allow(clippy::unnecessary_unwrap)]
        Err(last_temp_error.unwrap())
    }
}
