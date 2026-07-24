/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{smtp::inbound::TestQueueEvent, utils::server::TestServerBuilder};
use registry::schema::enums::Permission;
use smtp::queue::{MessageSource, spool::SmtpSpool};
use smtp_proto::RCPT_NOTIFY_NEVER;

#[tokio::test]
async fn queued_email_send_permission() {
    let mut test = TestServerBuilder::new("smtp_queue_email_send_permission")
        .await
        .with_http_listener(19045)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let account = test
        .account("admin")
        .create_user_account(
            "readonly@example.org",
            "secret + extra safety",
            "Read-only User",
            &[],
            vec![],
        )
        .await;

    for source in [MessageSource::Authenticated, MessageSource::Sieve] {
        test.account("admin")
            .set_account_disabled_permissions(account.id(), vec![])
            .await;

        let mut message = test.server.new_message(account.name(), 0);
        message
            .expand_and_add_recipient("recipient@remote.org", &test.server)
            .await;
        for recipient in &mut message.message.recipients {
            recipient.flags |= RCPT_NOTIFY_NEVER;
        }
        assert!(
            message
                .queue(
                    None,
                    b"Subject: queued permission check\r\n\r\nTest",
                    0,
                    &test.server,
                    source
                )
                .await
        );
        let attempt = test.expect_message_then_deliver().await;

        test.account("admin")
            .set_account_disabled_permissions(account.id(), vec![Permission::EmailSend])
            .await;
        attempt.try_deliver(test.server.clone());
        test.read_event().await.assert_done();
        test.assert_queue_is_empty().await;
    }
}
