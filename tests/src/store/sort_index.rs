/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use std::time::Duration;
use store::Store;

const INDEX: &str = "idx_s_email_accid_rcvd_sent";

pub async fn test(test: &TestServer) {
    let store = test.server.store();
    println!("Running PostgreSQL email sort index tests...");

    // Built in the background when the search tables are created
    wait_until_valid(store).await;

    // Built again once dropped
    exec(store, &format!("DROP INDEX {INDEX}")).await;
    test.server.search_store().create_indexes().await.unwrap();
    wait_until_valid(store).await;

    // A build cut short leaves an invalid index, which is replaced
    exec(store, &format!("DROP INDEX {INDEX}")).await;
    exec(store, "INSERT INTO s_email (accid, docid) VALUES (0, 0)").await;
    assert!(
        store
            .sql_query::<usize>(
                &format!("CREATE INDEX CONCURRENTLY {INDEX} ON s_email ((1 / (accid - accid)))"),
                vec![],
            )
            .await
            .is_err()
    );
    assert!(index_exists(store, false).await);
    test.server.search_store().create_indexes().await.unwrap();
    wait_until_valid(store).await;
    exec(store, "DELETE FROM s_email WHERE accid = 0 AND docid = 0").await;
}

async fn exec(store: &Store, query: &str) {
    store.sql_query::<usize>(query, vec![]).await.unwrap();
}

async fn index_exists(store: &Store, is_valid: bool) -> bool {
    store
        .sql_query::<bool>(
            &format!(
                "SELECT 1 FROM pg_index WHERE indexrelid = to_regclass('{INDEX}') AND indisvalid = {is_valid}"
            ),
            vec![],
        )
        .await
        .unwrap()
}

async fn wait_until_valid(store: &Store) {
    for _ in 0..300 {
        if index_exists(store, true).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{INDEX} was not built");
}
