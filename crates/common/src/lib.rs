/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use crate::auth::{AccessTokenInner, EmailAddress};
use crate::manager::application::WebApplications;
use crate::network::asn::AsnGeoLookupData;
use crate::{
    auth::{AccountCache, DomainCache, EmailCache, MailingListCache, RoleCache, TenantCache},
    config::{
        mailstore::{
            email::EmailConfig,
            imap::ImapConfig,
            scripts::Scripting,
            spamfilter::{IpResolver, SpamClassifier, SpamFilterConfig},
        },
        smtp::auth::DkimSigner,
    },
    ipc::TrainTaskController,
    network::security::BlockedIps,
};
use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use auth::oauth::config::OAuthConfig;
use calcard::common::timezone::Tz;
use config::{
    groupware::GroupwareConfig,
    mailstore::jmap::JmapConfig,
    network::Network,
    smtp::{
        SmtpConfig,
        resolver::{Policy, Tlsa},
    },
    storage::Storage,
    telemetry::Metrics,
};
use ipc::{BroadcastEvent, PushEvent, QueueEvent, ReportingEvent};
use mail_auth::{MX, Txt};
use manager::application::Resource;
use parking_lot::{Mutex, RwLock};
use rustls::sign::CertifiedKey;
use std::sync::atomic::AtomicU64;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use store::InMemoryStore;
use tinyvec::TinyVec;
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio_rustls::TlsConnector;
use types::{acl::AclGrant, special_use::SpecialUse};
use utils::{
    cache::{Cache, CacheWithTtl},
    snowflake::SnowflakeIdGenerator,
};

pub mod auth;
pub mod cache;
pub mod config;
pub mod expr;
pub mod i18n;
pub mod ipc;
pub mod manager;
pub mod network;
pub mod scripts;
pub mod sharing;
pub mod storage;
pub mod telemetry;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL

#[cfg(feature = "enterprise")]
pub mod enterprise;

// SPDX-SnippetEnd

pub use psl;

pub static VERSION_PRIVATE: &str = env!("CARGO_PKG_VERSION");
pub static VERSION_PUBLIC: &str = "1.0.0";

pub static USER_AGENT: &str = "Stalwart/1.0.0";
pub static DAEMON_NAME: &str = concat!("Stalwart v", env!("CARGO_PKG_VERSION"),);
pub static PROD_ID: &str = "-//Stalwart Labs LLC//Stalwart Server//EN";

/*

Schema history:

1 - v0.12.0
2 - v0.12.4
3 - v0.13.0
4 - v0.14.0
5 - v0.15.0
6 - v0.16.0

*/

pub const DATABASE_SCHEMA_VERSION: u32 = 6;

pub const LONG_1D_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24);
pub const LONG_1Y_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24 * 365);

pub const IPC_CHANNEL_BUFFER: usize = 1024;

pub const KV_ACME: u8 = 0;
pub const KV_OAUTH: u8 = 1;
pub const KV_RATE_LIMIT_RCPT: u8 = 2;
pub const KV_RATE_LIMIT_SCAN: u8 = 3;
pub const KV_RATE_LIMIT_LOITER: u8 = 4;
pub const KV_RATE_LIMIT_AUTH: u8 = 5;
pub const KV_RATE_LIMIT_SMTP: u8 = 6;
pub const KV_RATE_LIMIT_CONTACT: u8 = 7;
pub const KV_RATE_LIMIT_HTTP_AUTHENTICATED: u8 = 8;
pub const KV_RATE_LIMIT_HTTP_ANONYMOUS: u8 = 9;
pub const KV_RATE_LIMIT_IMAP: u8 = 10;
pub const KV_QUOTA_BLOB: u8 = 11;
pub const KV_GREYLIST: u8 = 16;
pub const KV_LOCK_QUEUE_MESSAGE: u8 = 21;
pub const KV_LOCK_TASK: u8 = 23;
pub const KV_LOCK_DAV: u8 = 25;
pub const KV_SIEVE_ID: u8 = 26;

#[derive(Clone)]
pub struct Server {
    pub inner: Arc<Inner>,
    pub core: Arc<Core>,
}

pub struct Inner {
    pub shared_core: ArcSwap<Core>,
    pub data: Data,
    pub cache: Caches,
    pub ipc: Ipc,
}

#[allow(clippy::type_complexity)]
pub struct Data {
    pub spam_classifier: ArcSwap<SpamClassifier>,

    pub tls_certificates: ArcSwap<AHashMap<Box<str>, Arc<CertifiedKey>>>,
    pub tls_self_signed_cert: Option<Arc<CertifiedKey>>,

    pub blocked_ips: RwLock<BlockedIps>,
    pub lookup_stores: ArcSwap<AHashMap<Box<str>, InMemoryStore>>,

    pub asn_geo_data: AsnGeoLookupData,

    pub jmap_id_gen: SnowflakeIdGenerator,
    pub queue_id_gen: SnowflakeIdGenerator,
    pub span_id_gen: SnowflakeIdGenerator,
    pub registry_id_gen: SnowflakeIdGenerator,
    pub queue_status: AtomicBool,

    pub applications: WebApplications,
    pub logos: Mutex<AHashMap<Box<str>, LogoCache>>,

    pub smtp_connectors: TlsConnectors,
}

#[derive(Clone)]
pub struct LogoCache {
    domain_id: u32,
    tenant_id: Option<u32>,
    data: Option<Resource<Vec<u8>>>,
}

pub struct Caches {
    pub access_tokens: Cache<u32, Arc<AccessTokenInner>>,
    pub http_auth: Cache<Box<str>, HttpAuthCache>,

    pub messages: Cache<u32, Arc<MessageStoreCache>>,
    pub files: Cache<u32, Arc<DavResources>>,
    pub contacts: Cache<u32, Arc<DavResources>>,
    pub events: Cache<u32, Arc<DavResources>>,
    pub scheduling: Cache<u32, Arc<DavResources>>,

    pub emails: Cache<EmailAddress, EmailCache>,
    pub emails_negative: CacheWithTtl<EmailAddress, ()>,
    pub domain_names: Cache<Box<str>, u32>,
    pub domain_names_negative: CacheWithTtl<Box<str>, ()>,

    pub domains: Cache<u32, Arc<DomainCache>>,
    pub accounts: Cache<u32, Arc<AccountCache>>,
    pub roles: Cache<u32, Arc<RoleCache>>,
    pub tenants: Cache<u32, Arc<TenantCache>>,
    pub lists: Cache<u32, Arc<MailingListCache>>,

    pub dkim_signers: Cache<u32, Arc<[DkimSigner]>>,

    pub dns_txt: CacheWithTtl<Box<str>, Txt>,
    pub dns_mx: CacheWithTtl<Box<str>, Arc<[MX]>>,
    pub dns_ptr: CacheWithTtl<IpAddr, Arc<[Box<str>]>>,
    pub dns_ipv4: CacheWithTtl<Box<str>, Arc<[Ipv4Addr]>>,
    pub dns_ipv6: CacheWithTtl<Box<str>, Arc<[Ipv6Addr]>>,
    pub dns_tlsa: CacheWithTtl<Box<str>, Arc<Tlsa>>,
    pub dns_dnssec: CacheWithTtl<Box<str>, bool>,
    pub dns_mta_sts: CacheWithTtl<Box<str>, Arc<Policy>>,
    pub dns_rbl: CacheWithTtl<Box<str>, Option<Arc<IpResolver>>>,

    pub negative_cache_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct MessageStoreCache {
    pub emails: Arc<MessagesCache>,
    pub mailboxes: Arc<MailboxesCache>,
    pub update_lock: Arc<UpdateLock>,
    pub last_change_id: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MailboxesCache {
    pub change_id: u64,
    pub index: AHashMap<u32, u32>,
    pub items: Box<[MailboxCache]>,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MessagesCache {
    pub change_id: u64,
    pub items: Box<[MessageCache]>,
    pub index: AHashMap<u32, u32>,
    pub keywords: Box<[Box<str>]>,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MessageCache {
    pub document_id: u32,
    pub mailboxes: TinyVec<[MessageUidCache; 2]>,
    pub keywords: u128,
    pub thread_id: u32,
    pub change_id: u64,
    pub size: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MessageUidCache {
    pub mailbox_id: u32,
    pub uid: u32,
}

#[derive(Debug, Clone)]
pub struct MailboxCache {
    pub document_id: u32,
    pub name: String,
    pub path: String,
    pub role: SpecialUse,
    pub parent_id: u32,
    pub sort_order: u32,
    pub subscribers: TinyVec<[u32; 4]>,
    pub uid_validity: u32,
    pub acls: TinyVec<[AclGrant; 2]>,
}

#[derive(Debug, Clone)]
pub struct HttpAuthCache {
    pub account_id: u32,
    pub revision: u64,
    pub credential_id: Option<u32>,
    pub expires: Instant,
}

pub struct Ipc {
    pub push_tx: mpsc::Sender<PushEvent>,
    pub task_tx: Arc<Notify>,
    pub queue_tx: mpsc::Sender<QueueEvent>,
    pub report_tx: mpsc::Sender<ReportingEvent>,
    pub broadcast_tx: Option<mpsc::Sender<BroadcastEvent>>,
    pub train_task_controller: Arc<TrainTaskController>,
}

pub struct TlsConnectors {
    pub pki_verify: TlsConnector,
    pub dummy_verify: TlsConnector,
}

pub struct NameWrapper(pub String);

#[derive(Debug, Clone)]
pub struct DavResources {
    pub base_path: String,
    pub paths: AHashSet<DavPath>,
    pub resources: Vec<DavResource>,
    pub item_change_id: u64,
    pub container_change_id: u64,
    pub highest_change_id: u64,
    pub size: u64,
    pub update_lock: Arc<UpdateLock>,
}

#[derive(Debug)]
pub struct UpdateLock {
    pub semaphore: Semaphore,
    pub revision: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct DavPath {
    pub path: String,
    pub parent_id: Option<u32>,
    pub hierarchy_seq: u32,
    pub resource_idx: usize,
}

#[derive(Debug, Clone)]
pub struct DavResource {
    pub document_id: u32,
    pub data: DavResourceMetadata,
}

#[derive(Debug, Clone, Copy)]
pub struct DavResourcePath<'x> {
    pub path: &'x DavPath,
    pub resource: &'x DavResource,
}

#[derive(Debug, Clone)]
pub enum DavResourceMetadata {
    File {
        name: String,
        size: Option<u32>,
        parent_id: Option<u32>,
        acls: TinyVec<[AclGrant; 2]>,
    },
    Calendar {
        name: String,
        acls: TinyVec<[AclGrant; 2]>,
        preferences: TinyVec<[TinyCalendarPreferences; 2]>,
    },
    CalendarEvent {
        names: TinyVec<[DavName; 2]>,
        start: i64,
        duration: u32,
    },
    CalendarEventNotification {
        names: TinyVec<[DavName; 2]>,
    },
    AddressBook {
        name: String,
        acls: TinyVec<[AclGrant; 2]>,
    },
    ContactCard {
        names: TinyVec<[DavName; 2]>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct TinyCalendarPreferences {
    pub account_id: u32,
    pub tz: Tz,
    pub flags: u16,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct DavName {
    pub name: String,
    pub parent_id: u32,
}

#[derive(Clone)]
pub struct Core {
    pub storage: Storage,
    pub sieve: Scripting,
    pub network: Network,
    pub oauth: OAuthConfig,
    pub email: EmailConfig,
    pub jmap: JmapConfig,
    pub imap: ImapConfig,
    pub smtp: SmtpConfig,
    pub spam: SpamFilterConfig,
    pub groupware: GroupwareConfig,
    pub metrics: Metrics,

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub enterprise: Option<enterprise::Enterprise>,
    // SPDX-SnippetEnd
}

pub trait BuildServer {
    fn build_server(&self) -> Server;
}

impl BuildServer for Arc<Inner> {
    fn build_server(&self) -> Server {
        Server {
            inner: self.clone(),
            core: self.shared_core.load_full(),
        }
    }
}

pub trait IntoString: Sized {
    fn into_string(self) -> String;
}

impl IntoString for Vec<u8> {
    fn into_string(self) -> String {
        String::from_utf8(self)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

#[derive(Debug, Clone, Eq)]
pub struct ThrottleKey {
    pub hash: [u8; 32],
}

#[derive(Default)]
pub struct ThrottleKeyHasher {
    hash: u64,
}

#[derive(Clone, Default)]
pub struct ThrottleKeyHasherBuilder {}

pub const DEFAULT_LOGO_BASE64: &str =
    "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";
