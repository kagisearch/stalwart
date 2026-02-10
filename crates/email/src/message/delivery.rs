/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ingest::{EmailIngest, IngestEmail, IngestSource};
use crate::{mailbox::{DRAFTS_ID, INBOX_ID, JUNK_ID, TRASH_ID}, sieve::ingest::SieveScriptIngest};
use common::{
    Server,
    ipc::{EmailPush, PushNotification},
};
use directory::Permission;
use types::{keyword::Keyword};
use mail_parser::MessageParser;
use std::{borrow::Cow, future::Future};
use store::ahash::AHashMap;
use types::blob_hash::BlobHash;

use crate::{
    message::ingest::IngestedEmail,
    sieve::ingest::SieveOutputMessage,
};

use super::delivery_hooks::try_delivery_hook;
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
        let line = if line.ends_with(b"\r") {
            &line[..line.len() - 1]
        } else {
            line
        };

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
                    let value_bytes = if value_bytes.first() == Some(&b' ') {
                        &value_bytes[1..]
                    } else {
                        value_bytes
                    };
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
            if name
                .iter()
                .zip(target_name.as_bytes())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
                && name.len() == target_name.len()
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

#[derive(Debug)]
pub struct IngestMessage {
    pub sender_address: String,
    pub sender_authenticated: bool,
    pub recipients: Vec<IngestRecipient>,
    pub message_blob: BlobHash,
    pub message_size: u64,
    pub session_id: u64,
}

#[derive(Debug)]
pub struct IngestRecipient {
    pub address: String,
    pub is_spam: bool,
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
    fn add_header_with_trailing_lf_encodes_it() {
        let base = b"Subject: Hi\r\n\r\nBody";
        let out =
            apply_add_header_modifications(&[("X-LF".to_string(), "val\n".to_string())], base);

        // Trailing LF should be encoded per RFC 8187
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("X-LF: val%0A\r\n"));

        // Ensure message remains parseable
        let headers = parse_headers(&out);
        assert!(headers.iter().any(|(n, _)| n == "X-LF"));
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

#[cfg(test)]
mod replace_header_tests {
    use super::apply_replace_header_modifications;
    use mail_parser::MessageParser;

    fn parse_headers(raw: &[u8]) -> Vec<(String, String)> {
        let msg = MessageParser::new().parse(raw).expect("parse message");
        msg.root_part()
            .headers()
            .iter()
            .map(|h| {
                let value = match h.value() {
                    mail_parser::HeaderValue::Text(t) => t.to_string(),
                    mail_parser::HeaderValue::TextList(list) => {
                        list.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join(", ")
                    }
                    mail_parser::HeaderValue::Address(addr_list) => {
                        addr_list.iter()
                            .filter_map(|addr| addr.address.as_ref().map(|a| a.as_ref().to_string()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                    _ => h.value().as_text().unwrap_or_default().to_string(),
                };
                (h.name().to_string(), value)
            })
            .collect()
    }

    #[test]
    fn test_replace_single_header() {
        let base = b"Subject: Old Subject\r\nFrom: sender@example.com\r\n\r\nBody";
        let result = apply_replace_header_modifications(
            &[(1, "Subject".to_string(), "New Subject".to_string())],
            base,
            12345,
        );

        assert!(result.is_some());
        let modified = result.unwrap();
        let headers = parse_headers(&modified);

        assert!(headers.iter().any(|(n, v)| n == "Subject" && v == "New Subject"));
        assert!(headers.iter().any(|(n, v)| n == "From" && v == "sender@example.com"));
    }

    #[test]
    fn test_replace_by_index_second_occurrence() {
        let base = b"Received: from server1\r\nReceived: from server2\r\nReceived: from server3\r\n\r\nBody";
        let result = apply_replace_header_modifications(
            &[(2, "Received".to_string(), "from modified-server2".to_string())],
            base,
            12345,
        );

        assert!(result.is_some());
        let modified = result.unwrap();
        let s = String::from_utf8_lossy(&modified);

        // Verify the second occurrence was modified
        let received_count = s.matches("Received:").count();
        assert_eq!(received_count, 3);
        assert!(s.contains("from server1"));
        assert!(s.contains("from modified-server2"));
        assert!(s.contains("from server3"));
        assert!(!s.contains("from server2"));
    }

    #[test]
    fn test_replace_with_empty_deletes() {
        let base = b"Subject: Test\r\nX-Custom: value\r\nFrom: sender@example.com\r\n\r\nBody";
        let result = apply_replace_header_modifications(
            &[(1, "X-Custom".to_string(), "".to_string())],
            base,
            12345,
        );

        assert!(result.is_some());
        let modified = result.unwrap();
        let headers = parse_headers(&modified);

        assert!(!headers.iter().any(|(n, _)| n == "X-Custom"));
        assert!(headers.iter().any(|(n, _)| n == "Subject"));
        assert!(headers.iter().any(|(n, _)| n == "From"));
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
        let result = apply_replace_header_modifications(
            &[(1, "Subject".to_string(), "New".to_string())],
            base,
            12345,
        );

        assert!(result.is_some());
        let modified = result.unwrap();
        let s = String::from_utf8_lossy(&modified);
        assert!(s.contains("This is the body\r\nwith multiple lines"));
    }

    #[test]
    fn test_replace_case_insensitive() {
        let base = b"subject: Test\r\n\r\nBody";
        let result = apply_replace_header_modifications(
            &[(1, "Subject".to_string(), "New".to_string())],
            base,
            12345,
        );

        assert!(result.is_some());
        let modified = result.unwrap();
        let headers = parse_headers(&modified);
        assert!(headers.iter().any(|(n, v)| n == "Subject" && v == "New"));
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
        let result = apply_replace_header_modifications(
            &[
                (1, "Subject".to_string(), "New Subject".to_string()),
                (1, "From".to_string(), "new@example.com".to_string()),
                (1, "X-Delete".to_string(), "".to_string()),
            ],
            base,
            12345,
        );

        assert!(result.is_some());
        let modified = result.unwrap();
        let headers = parse_headers(&modified);

        assert!(headers.iter().any(|(n, v)| n == "Subject" && v == "New Subject"));
        assert!(headers.iter().any(|(n, v)| n == "From" && v == "new@example.com"));
        assert!(!headers.iter().any(|(n, _)| n == "X-Delete"));
    }

    #[test]
    fn test_replace_preserves_header_order() {
        let base = b"From: sender\r\nTo: recipient\r\nSubject: Test\r\n\r\nBody";
        let result = apply_replace_header_modifications(
            &[(1, "Subject".to_string(), "New".to_string())],
            base,
            12345,
        );

        assert!(result.is_some());
        let modified = result.unwrap();
        let s = String::from_utf8_lossy(&modified);

        // Check that From comes before To, and To comes before Subject
        let from_pos = s.find("From:").unwrap();
        let to_pos = s.find("To:").unwrap();
        let subject_pos = s.find("Subject:").unwrap();

        assert!(from_pos < to_pos);
        assert!(to_pos < subject_pos);
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

        // Obtain the account IDs for each recipient
        let mut account_ids: AHashMap<u32, usize> =
            AHashMap::with_capacity(message.recipients.len());
        let mut result = LocalDeliveryResult {
            status: Vec::with_capacity(message.recipients.len()),
            autogenerated: Vec::new(),
        };

        for rcpt in message.recipients {
            let account_id = match self
                .email_to_id(
                    &self.core.storage.directory,
                    &rcpt.address,
                    message.session_id,
                )
                .await
            {
                Ok(Some(account_id)) => account_id,
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
                            .ctx(trc::Key::To, rcpt.address.to_string())
                            .span_id(message.session_id)
                            .caused_by(trc::location!())
                    );
                    result.status.push(LocalDeliveryStatus::TemporaryFailure {
                        reason: "Address lookup failed.".into(),
                    });
                    continue;
                }
            };
            if let Some(status) = account_ids
                .get(&account_id)
                .and_then(|pos| result.status.get(*pos))
            {
                result.status.push(status.clone());
                continue;
            }

            account_ids.insert(account_id, result.status.len());

            result.status.push(
                match deliver_to_recipient(
                    self,
                    account_id,
                    &rcpt,
                    &message.sender_address,
                    message.sender_authenticated,
                    message.session_id,
                    &raw_message,
                    &message.message_blob,
                    &mut result.autogenerated,
                )
                .await
                {
                    Ok(ingested_message) => {
                        if ingested_message.change_id != u64::MAX {
                            self.broadcast_push_notification(PushNotification::EmailPush(
                                EmailPush {
                                    account_id,
                                    email_id: ingested_message.document_id,
                                    change_id: ingested_message.change_id,
                                },
                            ))
                            .await;
                        }

                        LocalDeliveryStatus::Success
                    }
                    Err(err) => {
                        let status = match err.as_ref() {
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
                    };

                    trc::error!(
                        err.ctx(trc::Key::To, rcpt.address.to_string())
                            .span_id(message.session_id)
                    );

                    status
                }
            },
            );
        }

        result
    }
}

async fn deliver_to_recipient(
    server: &Server,
    uid: u32,
    rcpt: &IngestRecipient,
    sender: &str,
    is_sender_authenticated: bool,
    session_id: u64,
    raw_message: &[u8],
    message_blob: &BlobHash,
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
        document_id: 0,
        thread_id: 0,
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
                message_blob,
                &sender,
                rcpt,
                session_id,
                active_script,
                autogenerated,
            )
            .await
        {
            Ok(sieve_result) => {
                if let Some(reason) = &sieve_result.reject_reason {
                    // Rejection
                    let err = trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                        .ctx(trc::Key::Code, 571)
                        .ctx(trc::Key::Reason, reason.to_string());
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
        let mut keywords: Vec<Keyword> = output_message.keywords;

        // Apply delivery hooks (mailboxes/flags/skip_inbox + per-recipient modifications)
        let mut owned_new_raw: Option<Vec<u8>> = None;
        let mut use_modified = false;
        let mut parsed_for_ingest = parsed_output_message.clone();
        match try_delivery_hook(server, uid, &sender, &rcpt.address, &parsed_output_message).await
        {
            Ok(result) => {
                let (hook_mailboxes, hook_flags, skip_inbox, hook_modifications) = match result {
                    Some(v) => v,
                    None => {
                        // Discard without error
                        return Ok(IngestedEmail {
                            document_id: 0,
                            thread_id: 0,
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
                    .into_iter()
                    .map(types::keyword::Keyword::from)
                {
                    if !keywords.contains(&k) {
                        keywords.push(k);
                    }
                }

                if skip_inbox {
                    mailbox_ids.retain(|&id| id != INBOX_ID);
                }

                // Apply flag-based mailbox filing: certain keywords trigger automatic
                // filing into special-use mailboxes during delivery
                for keyword in &keywords {
                    let target_mailbox = match keyword {
                        Keyword::Junk => Some(JUNK_ID),
                        Keyword::Deleted => Some(TRASH_ID),
                        Keyword::Draft => Some(DRAFTS_ID),
                        _ => None,
                    };

                    if let Some(target_id) = target_mailbox {
                        // If only INBOX is targeted, replace it with the flag-based mailbox
                        if mailbox_ids.len() == 1 && mailbox_ids[0] == INBOX_ID {
                            mailbox_ids[0] = target_id;
                        }
                        // If INBOX is among multiple mailboxes, remove it and add target
                        else if mailbox_ids.contains(&INBOX_ID) {
                            mailbox_ids.retain(|&id| id != INBOX_ID);
                            if !mailbox_ids.contains(&target_id) {
                                mailbox_ids.push(target_id);
                            }
                        }
                        // Otherwise, just ensure target mailbox is in the list
                        else if !mailbox_ids.contains(&target_id) {
                            mailbox_ids.push(target_id);
                        }
                    }
                }

                // Separate modifications by type
                let mut add_headers: Vec<(String, String)> = Vec::new();
                let mut replace_headers: Vec<(u32, String, String)> = Vec::new();

                for m in hook_modifications {
                    match m {
                        HookModification::AddHeader { name, value } => {
                            add_headers.push((name, value));
                        }
                        HookModification::ReplaceHeader { index, name, value } => {
                            replace_headers.push((index, name, value));
                        }
                    }
                }

                // Apply AddHeader modifications first
                let mut current_raw = &output_message.raw[..];
                if !add_headers.is_empty() {
                    owned_new_raw = Some(apply_add_header_modifications(
                        &add_headers,
                        current_raw,
                    ));
                    current_raw = owned_new_raw.as_deref().unwrap();
                }

                // Apply ReplaceHeader modifications
                if !replace_headers.is_empty() {
                    if let Some(modified) =
                        apply_replace_header_modifications(&replace_headers, current_raw, session_id)
                    {
                        owned_new_raw = Some(modified);
                    }
                }

                // Try to re-parse the modified message; rollback on failure
                if owned_new_raw.is_some() {
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
                            Details = "Failed to parse message after header modifications.",
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
                // we don't use blob_hash here since the message may be modified by the per-recipient hook
                // and thus differ from the original blob
                blob_hash: None,
                message: Some(parsed_for_ingest),
                access_token: &access_token,
                mailbox_ids,
                keywords,
                received_at: None,
                source: IngestSource::Smtp {
                    deliver_to: &rcpt.address,
                    is_sender_authenticated,
                    is_spam: rcpt.is_spam,
                },
                session_id,
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

#[cfg(test)]
mod flag_filing_tests {
    use crate::mailbox::{ARCHIVE_ID, INBOX_ID, JUNK_ID, SENT_ID, TRASH_ID};
    use types::keyword::Keyword;

    /// Helper function that applies the flag-based filing logic
    fn apply_flag_filing(mailbox_ids: &mut Vec<u32>, keywords: &[Keyword]) {
        for keyword in keywords {
            let target_mailbox = match keyword {
                Keyword::Junk => Some(JUNK_ID),
                Keyword::Deleted => Some(TRASH_ID),
                _ => None,
            };

            if let Some(target_id) = target_mailbox {
                if mailbox_ids.len() == 1 && mailbox_ids[0] == INBOX_ID {
                    mailbox_ids[0] = target_id;
                } else if mailbox_ids.contains(&INBOX_ID) {
                    mailbox_ids.retain(|&id| id != INBOX_ID);
                    if !mailbox_ids.contains(&target_id) {
                        mailbox_ids.push(target_id);
                    }
                } else if !mailbox_ids.contains(&target_id) {
                    mailbox_ids.push(target_id);
                }
            }
        }
    }

    #[test]
    fn test_junk_flag_replaces_inbox() {
        let mut mailbox_ids = vec![INBOX_ID];
        let keywords = vec![Keyword::Junk];

        apply_flag_filing(&mut mailbox_ids, &keywords);

        assert_eq!(mailbox_ids, vec![JUNK_ID]);
    }

    #[test]
    fn test_junk_flag_removes_inbox_from_multiple() {
        let mut mailbox_ids = vec![INBOX_ID, ARCHIVE_ID];
        let keywords = vec![Keyword::Junk];

        apply_flag_filing(&mut mailbox_ids, &keywords);

        assert!(mailbox_ids.contains(&JUNK_ID));
        assert!(mailbox_ids.contains(&ARCHIVE_ID));
        assert!(!mailbox_ids.contains(&INBOX_ID));
    }

    #[test]
    fn test_deleted_flag_filing() {
        let mut mailbox_ids = vec![INBOX_ID];
        let keywords = vec![Keyword::Deleted];

        apply_flag_filing(&mut mailbox_ids, &keywords);

        assert_eq!(mailbox_ids, vec![TRASH_ID]);
    }

    #[test]
    fn test_explicit_fileinto_preserved() {
        let mut mailbox_ids = vec![ARCHIVE_ID];
        let keywords = vec![Keyword::Junk];

        apply_flag_filing(&mut mailbox_ids, &keywords);

        assert!(mailbox_ids.contains(&ARCHIVE_ID));
        assert!(mailbox_ids.contains(&JUNK_ID));
    }

    #[test]
    fn test_multiple_special_flags() {
        let mut mailbox_ids = vec![INBOX_ID];
        let keywords = vec![Keyword::Junk, Keyword::Deleted];

        apply_flag_filing(&mut mailbox_ids, &keywords);

        // First flag (Junk) replaces INBOX, second flag (Deleted) adds to list
        assert!(mailbox_ids.contains(&JUNK_ID) || mailbox_ids.contains(&TRASH_ID));
        assert!(!mailbox_ids.contains(&INBOX_ID));
    }

    #[test]
    fn test_non_special_flags_ignored() {
        let mut mailbox_ids = vec![INBOX_ID];
        let keywords = vec![Keyword::Seen, Keyword::Flagged];

        apply_flag_filing(&mut mailbox_ids, &keywords);

        // Non-special flags should not trigger mailbox filing
        assert_eq!(mailbox_ids, vec![INBOX_ID]);
    }

    #[test]
    fn test_junk_already_in_target_mailbox() {
        let mut mailbox_ids = vec![JUNK_ID];
        let keywords = vec![Keyword::Junk];

        apply_flag_filing(&mut mailbox_ids, &keywords);

        // Should remain idempotent
        assert_eq!(mailbox_ids, vec![JUNK_ID]);
    }

    #[test]
    fn test_deleted_with_other_mailboxes() {
        let mut mailbox_ids = vec![INBOX_ID, ARCHIVE_ID, SENT_ID];
        let keywords = vec![Keyword::Deleted];

        apply_flag_filing(&mut mailbox_ids, &keywords);

        // Should remove INBOX and add TRASH
        assert!(!mailbox_ids.contains(&INBOX_ID));
        assert!(mailbox_ids.contains(&TRASH_ID));
        assert!(mailbox_ids.contains(&ARCHIVE_ID));
        assert!(mailbox_ids.contains(&SENT_ID));
    }
}
