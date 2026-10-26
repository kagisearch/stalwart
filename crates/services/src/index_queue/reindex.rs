/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use crate::index_queue::REINDEX_CHUNK_SIZE;
// SPDX-SnippetEnd
use crate::index_queue::REINDEX_QUEUE_RATE;
use common::{Server, storage::dav::FILE_KIND_FILE};
use email::cache::MessageCacheFetch;
use groupware::cache::GroupwareCache;
use store::{
    IterateParams, U32_LEN, ValueKey,
    write::{
        BatchBuilder, CommitPriority, QueueDocumentId, SearchIndex, SearchIndexClass, ValueClass,
        key::DeserializeBigEndian,
    },
};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use store::write::TelemetryClass;
// SPDX-SnippetEnd
use std::{mem, time::Duration};
use tokio::time::{Instant, sleep_until};
use trc::AddContext;
use types::collection::SyncCollection;

const ENTRY_INTERVAL: Duration = Duration::from_nanos(1_000_000_000 / REINDEX_QUEUE_RATE);

struct PacedQueue {
    batch: BatchBuilder,
    entries: u32,
    next: Instant,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub(crate) async fn reindex_telemetry(server: &Server) -> trc::Result<()> {
    clear_tracing_queue(server).await?;

    if !server
        .core
        .email
        .index_fields
        .contains_key(&SearchIndex::Tracing)
    {
        return Ok(());
    }

    let mut from_span_id = 0;
    let mut queue = PacedQueue::new();

    loop {
        // The spans are collected in chunks, a telemetry store can hold millions of them
        let mut spans = Vec::with_capacity(REINDEX_CHUNK_SIZE);
        server
            .tracing_store()
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(from_span_id))),
                    ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(u64::MAX))),
                )
                .ascending()
                .no_values()
                .limit(REINDEX_CHUNK_SIZE),
                |key, _| {
                    spans.push(key.deserialize_be_u64(0)?);
                    Ok(spans.len() < REINDEX_CHUNK_SIZE)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let Some(last_span_id) = spans.last().copied() else {
            return Ok(());
        };

        for span_id in spans {
            queue.batch.queue_trace_index(span_id);
            queue.queued(server).await?;
        }
        queue.commit(server).await?;

        if let Some(next_span_id) = last_span_id.checked_add(1) {
            from_span_id = next_span_id;
        } else {
            return Ok(());
        }
    }
}
// SPDX-SnippetEnd

pub(crate) async fn reindex_account(server: &Server, account_id: u32) -> trc::Result<()> {
    for index in [
        SearchIndex::Email,
        SearchIndex::Calendar,
        SearchIndex::Contacts,
        SearchIndex::File,
    ] {
        clear_queued_updates(server, index, account_id).await?;
    }

    let calendars = server
        .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
        .await
        .caused_by(trc::location!())?;
    let contacts = server
        .fetch_groupware_resources(account_id, account_id, SyncCollection::AddressBook)
        .await
        .caused_by(trc::location!())?;
    let files = if server
        .core
        .email
        .index_fields
        .contains_key(&SearchIndex::File)
    {
        Some(
            server
                .fetch_groupware_resources(account_id, account_id, SyncCollection::FileNode)
                .await
                .caused_by(trc::location!())?,
        )
    } else {
        None
    };

    let mut queue = PacedQueue::new();

    for document_id in server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?
        .emails
        .iter()
        .map(|v| v.document_id())
    {
        queue
            .batch
            .queue_document_index(SearchIndex::Email, account_id, document_id);
        queue.queued(server).await?;
    }

    for (document_type, cache) in [
        (SearchIndex::Calendar, &calendars),
        (SearchIndex::Contacts, &contacts),
    ] {
        for document_id in cache.document_ids(false) {
            queue
                .batch
                .queue_document_index(document_type, account_id, document_id);
            queue.queued(server).await?;
        }
    }

    if let Some(cache) = &files {
        for document_id in cache
            .resources
            .iter()
            .filter(|resource| resource.file_kind() == Some(FILE_KIND_FILE))
            .map(|resource| resource.document_id())
        {
            queue
                .batch
                .queue_document_index(SearchIndex::File, account_id, document_id);
            queue.queued(server).await?;
        }
    }

    queue.commit(server).await
}

async fn clear_queued_updates(
    server: &Server,
    index: SearchIndex,
    partition: u32,
) -> trc::Result<()> {
    let (from_class, to_class) = SearchIndexClass::queue_range(index, partition);
    let mut batch = BatchBuilder::with_priority(CommitPriority::Background);
    batch.clear(SearchIndexClass::QueueStatus { index, partition });

    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::SearchIndex(from_class)),
                ValueKey::from(ValueClass::SearchIndex(to_class)),
            )
            .ascending(),
            |key, value| {
                if value.first().is_some_and(|action| *action != 0) {
                    batch
                        .clear(SearchIndexClass::Queue {
                            index,
                            id_prefix: key.deserialize_be_u32(1)?,
                            id_suffix: QueueDocumentId::Assigned(
                                key.deserialize_be_u32(1 + U32_LEN)?,
                            ),
                            created_at: key.deserialize_be_u64(1 + (U32_LEN * 2))?,
                        })
                        .bulk_commit_point();
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    server
        .store()
        .write_batch(&mut batch)
        .await
        .caused_by(trc::location!())?;

    Ok(())
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
async fn clear_tracing_queue(server: &Server) -> trc::Result<()> {
    server
        .store()
        .delete_range(
            ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Queue {
                index: SearchIndex::Tracing,
                id_prefix: 0,
                id_suffix: QueueDocumentId::Assigned(0),
                created_at: 0,
            })),
            ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Queue {
                index: SearchIndex::Tracing,
                id_prefix: u32::MAX,
                id_suffix: QueueDocumentId::Assigned(u32::MAX),
                created_at: u64::MAX,
            })),
        )
        .await
        .caused_by(trc::location!())?;

    server
        .store()
        .delete_range(
            ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::QueueIndex {
                index: SearchIndex::Tracing,
                partition: 0,
            })),
            ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::QueueStatus {
                index: SearchIndex::Tracing,
                partition: u32::MAX,
            })),
        )
        .await
        .caused_by(trc::location!())
}
// SPDX-SnippetEnd

impl PacedQueue {
    fn new() -> Self {
        PacedQueue {
            batch: BatchBuilder::with_priority(CommitPriority::Background),
            entries: 0,
            next: Instant::now(),
        }
    }

    async fn queued(&mut self, server: &Server) -> trc::Result<()> {
        self.entries += 1;
        if self.batch.is_large_batch() {
            self.commit(server).await
        } else {
            Ok(())
        }
    }

    async fn commit(&mut self, server: &Server) -> trc::Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        let batch = mem::replace(
            &mut self.batch,
            BatchBuilder::with_priority(CommitPriority::Background),
        );
        server.commit_batch(batch).await?;
        if let Some(deadline) = self.schedule(Instant::now()) {
            sleep_until(deadline).await;
        }
        Ok(())
    }

    fn schedule(&mut self, now: Instant) -> Option<Instant> {
        self.next += ENTRY_INTERVAL * mem::take(&mut self.entries);
        if self.next > now {
            Some(self.next)
        } else {
            self.next = now;
            None
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/services/src/index_queue/reindex/tests.rs"]
mod tests;
