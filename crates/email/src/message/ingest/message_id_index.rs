/*
 * FORK: Message-ID threading without a subject match.
 *
 * Upstream threads a message only against messages with the same normalized
 * subject: the `EmailField::Threading` index is keyed by the subject hash and
 * holds the referenced Message-IDs of each message in that bucket. A reply
 * whose subject changed can never find the message it references.
 *
 * This module keeps a second index, `EmailField::ThreadingId`, keyed by the
 * hash of each message's own `Message-ID` header. The key carries the
 * document id; the value is empty. A lookup reads the referenced ids from
 * this index and resolves each document to its current thread through
 * `MessageData`, so a thread merge needs no index rewrite and a stale entry
 * for a deleted message resolves to nothing.
 *
 * A thread may therefore span subject buckets, and the code that assumed it
 * never does is adjusted to match. The in-batch grouping (`ingest/group.rs`)
 * matches pending messages on a shared Message-ID alone. The merge task
 * (`task_manager/tasks/merge_threads.rs`) consults this index as well as the
 * subject bucket, and moves every message of a losing thread under its own
 * subject hash, so no message is left on a thread id logged as deleted.
 *
 * Known gaps:
 *
 * - Messages ingested before this index existed have no entry and still
 *   fall back to the subject match.
 * - The post-commit recheck (`ingest/recheck.rs`) only looks for forks inside
 *   a subject bucket. Two processes ingesting a parent and a changed-subject
 *   reply at the same time can still end up with two threads. The 0.16 fork
 *   had the same race and no recheck at all.
 * - Every ingest pays one extra point-range read, even for messages with no
 *   references.
 */

use crate::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{
        index::extractors::VisitText,
        messagedata::EmailMessageData,
        metadata::{HeaderId, HeaderList},
    },
};
use common::Server;
use mail_parser::{HeaderForm, HeaderName, Message};
use store::{
    IterateParams, U32_LEN, ValueKey,
    write::{BatchBuilder, IndexPropertyClass, ValueClass, key::DeserializeBigEndian},
    xxhash_rust::xxh3::xxh3_128,
};
use trc::AddContext;
use types::{collection::Collection, field::EmailField};
use utils::hash128::Hash128;

/// Hashes of the `Message-ID` header(s) of a parsed message, computed the
/// same way `ThreadFields::scan` hashes referenced ids.
pub fn own_message_ids(message: &Message<'_>) -> Vec<u128> {
    let mut ids = Vec::with_capacity(1);
    for header in message.root_part().headers() {
        if matches!(header.name(), HeaderName::MessageId) {
            header.value().visit_text(|id| push_id(&mut ids, id));
        }
    }
    ids
}

/// Hashes of the `Message-ID` header(s) of a stored message, read from its
/// metadata header list and raw headers.
pub fn own_message_ids_in(root: HeaderList<'_>, headers: &[u8]) -> Vec<u128> {
    let mut ids = Vec::with_capacity(1);
    for header in root.iter() {
        if header.id() == HeaderId::MESSAGE_ID
            && let Some(raw) = headers.get(header.value_range())
        {
            HeaderForm::MessageIds
                .parse(raw)
                .value()
                .visit_text(|id| push_id(&mut ids, id));
        }
    }
    ids
}

fn push_id(ids: &mut Vec<u128>, id: &str) {
    if !id.is_empty() {
        let hash = xxh3_128(id.as_bytes());
        if !ids.contains(&hash) {
            ids.push(hash);
        }
    }
}

/// Writes one index entry per own Message-ID for the batch's current
/// document.
pub fn index(batch: &mut BatchBuilder, own_ids: &[u128]) {
    for &id in own_ids {
        batch.set(ValueClass::IndexProperty(index_class(id)), vec![1u8]);
    }
}

/// Removes the index entries for the batch's current document.
pub fn unindex(batch: &mut BatchBuilder, own_ids: &[u128]) {
    for &id in own_ids {
        batch.clear(ValueClass::IndexProperty(index_class(id)));
    }
}

/// Finds the messages whose own Message-ID is one of `message_ids` and
/// returns `(thread_id, document_id)` for each one that still exists.
pub async fn threads_by_message_id(
    server: &Server,
    account_id: u32,
    message_ids: &[u128],
) -> trc::Result<Vec<(u32, u32)>> {
    if message_ids.is_empty() {
        return Ok(Vec::new());
    }

    let key_len = index_class(0).key_len();
    let document_id_pos = key_len - U32_LEN;
    let mut documents: Vec<u32> = Vec::new();
    let mut observe = |key: &[u8], _: &[u8]| {
        if key.len() == key_len {
            // The key stores the inverted document id.
            let document_id = !key.deserialize_be_u32(document_id_pos)?;
            if !documents.contains(&document_id) {
                documents.push(document_id);
            }
        }
        Ok(true)
    };

    let store = server.store();
    let mut ranges = message_ids
        .iter()
        .map(|&id| {
            IterateParams::new(
                index_key(account_id, id, u32::MAX),
                index_key(account_id, id, 0),
            )
            .no_values()
        })
        .collect::<Vec<_>>();
    if ranges.len() > 1 {
        store.iterate_many(ranges, &mut observe).await
    } else {
        store.iterate(ranges.pop().unwrap(), &mut observe).await
    }
    .caused_by(trc::location!())?;

    if documents.is_empty() {
        return Ok(Vec::new());
    }
    documents.sort_unstable();

    // Resolve each document to its current thread.
    let mut threads = Vec::with_capacity(documents.len());
    if let Some(cache) = server.fresh_messages(account_id) {
        for document_id in documents {
            if let Some(message) = cache.email_by_id(&document_id) {
                threads.push((message.thread_id(), document_id));
            }
        }
    } else {
        server
            .message_datas(account_id, &documents, |document_id, data| {
                threads.push((data.thread_id, document_id));
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
    }

    Ok(threads)
}

fn index_class(id: u128) -> IndexPropertyClass {
    IndexPropertyClass::Hash {
        property: EmailField::ThreadingId.into(),
        hash: Hash128::from(id),
    }
}

fn index_key(account_id: u32, id: u128, document_id: u32) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: Collection::Email.into(),
        document_id,
        class: ValueClass::IndexProperty(index_class(id)),
    }
}

#[cfg(test)]
mod tests {
    use super::own_message_ids;
    use crate::message::thread::ThreadFields;
    use mail_parser::MessageParser;

    #[test]
    fn own_ids_hash_like_thread_fields() {
        let raw = concat!(
            "Message-ID: <a@example.com>\r\n",
            "In-Reply-To: <b@example.com>\r\n",
            "References: <c@example.com> <b@example.com>\r\n",
            "Subject: Re: hello\r\n",
            "\r\n",
            "body\r\n"
        );
        let message = MessageParser::new().parse(raw.as_bytes()).unwrap();
        let own = own_message_ids(&message);
        let fields = ThreadFields::scan(&message);

        assert_eq!(own.len(), 1);
        assert!(fields.message_ids.contains(&own[0]));
        assert_eq!(fields.message_ids.len(), 3);
    }

    #[test]
    fn own_ids_skip_missing_and_empty() {
        let raw = "Subject: hi\r\nMessage-ID: <>\r\n\r\nbody\r\n";
        let message = MessageParser::new().parse(raw.as_bytes()).unwrap();
        assert!(own_message_ids(&message).is_empty());
    }
}
