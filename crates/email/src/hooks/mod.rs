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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Request {
    pub user_id: String,
    pub user_id_num: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Envelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub action: Action,
    #[serde(default)]
    pub modifications: Vec<Modification>,
    #[serde(default)]
    pub skip_inbox: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Action {
    #[serde(rename = "accept")]
    Accept,
    #[serde(rename = "reject")]
    Reject,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Modification {
    #[serde(rename = "fileInto")]
    FileInto {
        folder: String,
        mailbox_id: String,
        #[serde(default)]
        flags: Vec<String>,
        #[serde(default)]
        special_use: Option<String>,
        #[serde(default)]
        create: bool,
    },
}

impl Request {
    pub fn new(user_id: String, user_id_num: u32) -> Self {
        Self {
            user_id,
            user_id_num,
            envelope: None,
            message: None,
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
}
