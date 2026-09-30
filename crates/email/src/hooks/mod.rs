/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod client;

use serde::{Deserialize, Serialize};

// Types copied from smtp::inbound::hooks to avoid cyclic dependency
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Address {
    pub address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Envelope {
    pub from: Address,
    pub to: Address,
    /// True when the sender authenticated over SMTP or the message passed DMARC
    #[serde(default)]
    pub sender_authenticated: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "serverHeaders")]
    #[serde(default)]
    pub server_headers: Vec<(String, String)>,
    pub contents: String,
    pub size: usize,
}

/// Filing state produced by the user's Sieve script (or the default
/// Inbox filing when no script is active) before the hook runs.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Filing {
    /// Ids of the mailboxes the message is currently set to be filed into
    pub mailbox_ids: Vec<String>,
    pub flags: Vec<String>,
    /// True when the user's Sieve script explicitly filed the message
    pub filed_by_script: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Request {
    pub user_id: String,
    pub principal_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Envelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filing: Option<Filing>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub action: Action,
    #[serde(default)]
    pub modifications: Vec<Modification>,
    /// Remove the Inbox from the filing. A message that would then be in no
    /// mailbox at all is filed into the account's Archive instead, or stays in
    /// the Inbox when the account has no Archive or the message is spam that
    /// is about to be junked. Ignored when `replace_mailboxes` takes effect,
    /// since the replaced filing contains only the hook's own targets.
    #[serde(default)]
    pub skip_inbox: bool,
    /// Replace the current filing with the hook's fileInto mailboxes
    /// instead of adding to it. When several hooks are configured, the
    /// fileInto targets of hooks that do not ask for replacement are
    /// dropped as well. Only mailbox targets are affected: flags, header
    /// modifications and preview text from every hook still apply, so a
    /// `$junk` flag from another hook still files the message into Junk.
    /// A replacing hook none of whose fileInto targets resolve is treated
    /// as additive rather than replacing the filing with nothing.
    #[serde(default)]
    pub replace_mailboxes: bool,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub preview_text: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Action {
    #[serde(rename = "accept")]
    Accept,
    #[serde(rename = "discard")]
    Discard,
    #[serde(rename = "reject")]
    Reject,
    #[serde(rename = "quarantine")]
    Quarantine,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Modification {
    #[serde(rename = "fileInto")]
    FileInto {
        #[serde(default)]
        folder: String,
        #[serde(default)]
        mailbox_id: String,
        #[serde(default)]
        special_use: Option<String>,
        #[serde(default)]
        create: bool,
    },
    #[serde(rename = "addHeader")]
    AddHeader { name: String, value: String },
    #[serde(rename = "replaceHeader")]
    ReplaceHeader {
        index: u32,
        name: String,
        value: String,
    },
}

pub enum ModificationOut {
    AddHeader { name: String, value: String },
    ReplaceHeader {
        index: u32,
        name: String,
        value: String,
    },
}

impl Request {
    pub fn new(user_id: String, principal_name: String) -> Self {
        Self {
            user_id,
            principal_name,
            envelope: None,
            message: None,
            filing: None,
        }
    }

    pub fn with_envelope(mut self, envelope: Envelope) -> Self {
        self.envelope = Some(envelope);
        self
    }

    pub fn with_message(mut self, message: Message) -> Self {
        self.message = Some(message);
        self
    }

    pub fn with_filing(mut self, filing: Filing) -> Self {
        self.filing = Some(filing);
        self
    }
}
