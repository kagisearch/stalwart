/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::outcome::{Failure, Outcome, RetryClass};
use common::{Server, storage::index::ObjectIndexBuilder};
use email::message::{
    ingest::{ThreadMerge, has_message_id},
    messagedata::MessageData,
};
// FORK: Message-ID threading without a subject match.
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{
        ingest::message_id_index, messagedata::EmailMessageData, metadata::MetadataRow,
        thread::ThreadSubject,
    },
};
use registry::schema::structs::TaskMergeThreads;
use std::{borrow::Cow, ops::RangeInclusive, str::FromStr, time::Duration};
use store::Deserialize;
use store::{
    IterateParams, Key, U32_LEN, ValueKey,
    ahash::AHashMap,
    rand::RngExt,
    write::{BatchBuilder, IndexPropertyClass, MergeResult, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::EmailField,
};
use utils::hash128::Hash128;

const MAX_RETRIES: usize = 5;
const MAX_PASSES: usize = 5;
const RETRY_BACKOFF_MS: RangeInclusive<u64> = 50..=300;

pub(crate) trait MergeThreadsTask: Sync + Send {
    fn merge_threads(&self, threads: &TaskMergeThreads) -> impl Future<Output = Outcome> + Send;
}

impl MergeThreadsTask for Server {
    async fn merge_threads(&self, threads: &TaskMergeThreads) -> Outcome {
        match merge_threads(self, threads).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let result = Outcome::error(&err);
                trc::error!(
                    err.account_id(threads.account_id.document_id())
                        .details("Failed to merge threads")
                );
                result
            }
        }
    }
}

async fn merge_threads(
    server: &Server,
    task_merge_threads: &TaskMergeThreads,
) -> trc::Result<Outcome> {
    #[cfg(stalwart_tests)]
    if task_merge_threads.thread_name == "bench-transient" {
        return Ok(Outcome::transient("Simulated transient failure"));
    }

    let Ok(thread_hash) = Hash128::from_str(&task_merge_threads.thread_name) else {
        return Ok(Outcome::fatal("Invalid thread hash"));
    };
    let Ok(mut message_ids) = task_merge_threads
        .message_ids
        .iter()
        .map(|id| u128::from_str(id))
        .collect::<Result<Vec<_>, _>>()
    else {
        return Ok(Outcome::fatal("Invalid message ids"));
    };
    message_ids.sort_unstable();

    let account_id = task_merge_threads.account_id.document_id();
    let mut try_count = 0;

    let from_key = ValueKey {
        account_id,
        collection: Collection::Email.into(),
        document_id: u32::MAX,
        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
            property: EmailField::Threading.into(),
            hash: thread_hash,
        }),
    };
    let to_key = ValueKey {
        account_id,
        collection: Collection::Email.into(),
        document_id: 0,
        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
            property: EmailField::Threading.into(),
            hash: thread_hash,
        }),
    };
    let mut prefix = from_key.serialize(0);
    let key_len = prefix.len();
    let document_id_pos = key_len - U32_LEN;
    prefix.truncate(document_id_pos);
    let mut merged_away: Vec<u32> = Vec::new();
    let mut passes = 0;

    'retry: loop {
        // Merge threads
        let mut thread_merge = ThreadMerge::new();
        let mut same_subject_messages: AHashMap<u32, Vec<u32>> = AHashMap::new();

        // Find thread ids
        server
            .store()
            .iterate(
                IterateParams::new(from_key.clone(), to_key.clone()).ascending(),
                |key, value| {
                    if key.len() == key_len && key.starts_with(&prefix) {
                        // Find matching references
                        let references = value.get(U32_LEN..).unwrap_or_default();
                        let thread_id = value.deserialize_be_u32(0)?;
                        let document_id = !key.deserialize_be_u32(document_id_pos)?;

                        if has_message_id(&message_ids, references)
                            || merged_away.contains(&thread_id)
                        {
                            thread_merge.add(thread_id, document_id);
                        } else {
                            // Keep track of messages with the same subject for potential future merges
                            same_subject_messages
                                .entry(thread_id)
                                .or_default()
                                .push(document_id);
                        }
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        // FORK: Message-ID threading without a subject match. Also match the
        // messages whose own Message-ID is referenced, whatever their subject,
        // as ingest did when it scheduled this task. Without this a merge
        // whose losing thread lives in another subject bucket is a no-op.
        {
            let seen = thread_merge
                .thread_groups()
                .flat_map(|(_, document_ids)| document_ids.iter().copied())
                .collect::<Vec<_>>();
            for (other_thread_id, document_id) in
                message_id_index::threads_by_message_id(server, account_id, &message_ids)
                    .await
                    .caused_by(trc::location!())?
            {
                if !seen.contains(&document_id) {
                    thread_merge.add(other_thread_id, document_id);
                }
            }
        }

        if thread_merge.num_thread_ids() < 2 {
            // Another process merged the threads already?
            return Ok(Outcome::done());
        }

        // Add other messages with the same subject to the merge if they share a
        // thread id with a message that has a matching message id
        for thread_id in thread_merge.thread_ids().copied().collect::<Vec<_>>() {
            if let Some(document_ids) = same_subject_messages.get(&thread_id) {
                for &document_id in document_ids {
                    thread_merge.add(thread_id, document_id);
                }
            }
        }

        let thread_id = thread_merge.merge_thread_id();

        // FORK: Message-ID threading without a subject match. A thread may
        // span subject buckets, so a losing thread can hold messages outside
        // the bucket scanned above. Every message of a losing thread is moved,
        // each under the subject hash its threading entry is keyed by, so none
        // is left on a thread id that is logged as deleted below.
        let mut groups: Vec<(u32, Vec<(u32, Hash128)>)> = Vec::new();
        {
            let cache = server
                .get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?;
            let mut unresolved: Vec<(u32, u32)> = Vec::new();
            for (&group_thread_id, document_ids) in thread_merge.thread_groups() {
                if group_thread_id != thread_id {
                    let mut group_documents = document_ids.clone();
                    group_documents.extend(
                        cache
                            .in_thread(group_thread_id)
                            .map(|message| message.document_id()),
                    );
                    group_documents.sort_unstable();
                    group_documents.dedup();
                    unresolved.extend(
                        group_documents
                            .into_iter()
                            .map(|document_id| (group_thread_id, document_id)),
                    );
                }
            }
            let mut document_ids = unresolved
                .iter()
                .map(|(_, document_id)| *document_id)
                .collect::<Vec<_>>();
            document_ids.sort_unstable();
            document_ids.dedup();
            let mut hashes: AHashMap<u32, Hash128> = AHashMap::with_capacity(document_ids.len());
            if !document_ids.is_empty() {
                server
                    .message_metadata(account_id, &document_ids, |document_id, bytes| {
                        let row = MetadataRow::deserialize(bytes)?;
                        let metadata = row.unarchive()?;
                        let headers;
                        let subject = match metadata.thread_subject() {
                            ThreadSubject::Resolved(name) => Cow::Borrowed(name),
                            ThreadSubject::InHeaders => {
                                headers = row.raw_headers()?;
                                metadata.thread_subject_in(&headers)
                            }
                        };
                        hashes.insert(document_id, email::message::ingest::thread_hash(&subject));
                        Ok(true)
                    })
                    .await
                    .caused_by(trc::location!())?;
            }
            for (group_thread_id, document_id) in unresolved {
                if let Some(&subject_hash) = hashes.get(&document_id) {
                    match groups.iter_mut().find(|(id, _)| *id == group_thread_id) {
                        Some((_, group)) => group.push((document_id, subject_hash)),
                        None => groups.push((group_thread_id, vec![(document_id, subject_hash)])),
                    }
                }
            }
        }

        // Delete all but the most common threadId
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Thread);

        for &delete_thread_id in thread_merge.thread_ids() {
            if delete_thread_id != thread_id {
                batch
                    .with_document(delete_thread_id)
                    .log_container_delete(SyncCollection::Thread);
            }
        }

        // Move messages to the new threadId
        batch.with_collection(Collection::Email);

        for &(group_thread_id, ref document_ids) in &groups {
            if thread_id != group_thread_id {
                for &(document_id, subject_hash) in document_ids {
                    if let Some(data) = server
                        .store()
                        .get_value::<MessageData>(ValueKey::archive(
                            account_id,
                            Collection::Email,
                            document_id,
                        ))
                        .await
                        .caused_by(trc::location!())?
                    {
                        if data.thread_id != group_thread_id {
                            try_count += 1;
                            if try_count > MAX_RETRIES {
                                return Ok(Outcome::Retry(Failure::new(
                                    RetryClass::Contention,
                                    "Thread ids keep changing while merging",
                                )));
                            }
                            retry_backoff().await;
                            continue 'retry;
                        }

                        // Update thread id
                        let mut new_data = data.clone();
                        new_data.thread_id = thread_id;
                        batch
                            .with_document(document_id)
                            .custom(
                                ObjectIndexBuilder::new()
                                    .with_current(data)
                                    .with_changes(new_data),
                            )
                            .caused_by(trc::location!())?;

                        // Update thread index property
                        batch.merge_fnc(
                            ValueClass::IndexProperty(IndexPropertyClass::Hash {
                                property: EmailField::Threading.into(),
                                hash: subject_hash,
                            }),
                            move |_, bytes| {
                                let mut thread_index = bytes
                                    .filter(|v| v.len() > U32_LEN)
                                    .ok_or_else(|| {
                                        trc::StoreEvent::AssertValueFailed
                                            .into_err()
                                            .details("Message no longer exists.")
                                            .caused_by(trc::location!())
                                    })?
                                    .to_vec();

                                if thread_index.as_slice().deserialize_be_u32(0)? != group_thread_id {
                                    return Err(
                                        trc::StoreEvent::AssertValueFailed
                                            .into_err()
                                            .details("Thread id mismatch, likely due to concurrent modification.")
                                            .caused_by(trc::location!())
                                    );
                                }

                                thread_index[0..U32_LEN].copy_from_slice(&thread_id.to_be_bytes());

                                Ok(MergeResult::Update(thread_index))
                            },
                        );
                    }
                }
            }
        }

        match server.commit_batch(batch).await {
            Ok(_) => {
                passes += 1;
                if passes == MAX_PASSES {
                    return Ok(Outcome::done());
                }
                for &merged in thread_merge.thread_ids() {
                    if merged != thread_id && !merged_away.contains(&merged) {
                        merged_away.push(merged);
                    }
                }
            }
            Err(err) if err.is_assertion_failure() && try_count < MAX_RETRIES => {
                retry_backoff().await;
                try_count += 1;
            }
            Err(err) => {
                return Err(err.caused_by(trc::location!()));
            }
        }
    }
}

async fn retry_backoff() {
    let backoff = store::rand::rng().random_range(RETRY_BACKOFF_MS);
    Box::pin(tokio::time::sleep(Duration::from_millis(backoff))).await;
}
