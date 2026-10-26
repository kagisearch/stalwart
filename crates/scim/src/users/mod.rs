/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

pub mod get;
pub mod patch;
pub mod set;

use crate::{context::ScimContext, error::Result};
use icu_locale::{Locale as LanguageTag, LocaleExpander, subtags::Language as LanguageSubtag};
use registry::{
    schema::{
        enums::{Locale, Permission, TimeZone},
        structs::{EmailAlias, Permissions, PermissionsList, UserAccount},
    },
    types::{EnumImpl, list::List},
};
use scim_proto::{
    ResourceType,
    attributes::AttributeSelection,
    etag::weak_etag,
    message::error::Error,
    schema::{
        Meta,
        user::{Email, GroupRef, Name, USER_SCHEMA, User},
    },
};
use serde_json::Value;
use std::sync::LazyLock;
use types::id::Id;

static EXPANDER: LazyLock<LocaleExpander> = LazyLock::new(LocaleExpander::new_extended);

pub const EMAIL_TYPE_WORK: &str = "work";
pub const DEFAULT_LOCALE: Locale = Locale::EnUS;
pub const GROUP_TYPE_DIRECT: &str = "direct";

impl ScimContext<'_> {
    pub async fn user_to_scim(
        &self,
        id: Id,
        revision: u64,
        account: &UserAccount,
        selection: &AttributeSelection<'_>,
    ) -> Result<Value> {
        let user_name = self.email_address(&account.name, account.domain_id).await?;
        let mut emails = Vec::with_capacity(account.aliases.len() + 1);
        emails.push(Email {
            value: Some(user_name.clone().into()),
            r#type: Some(EMAIL_TYPE_WORK.into()),
            primary: Some(true),
            ..Default::default()
        });
        for alias in account.aliases.values() {
            emails.push(Email {
                value: Some(
                    self.email_address(&alias.name, alias.domain_id)
                        .await?
                        .into(),
                ),
                r#type: Some(EMAIL_TYPE_WORK.into()),
                ..Default::default()
            });
        }

        let groups =
            if account.member_group_ids.is_empty() || selection.excludes(&USER_SCHEMA, "groups") {
                None
            } else {
                let mut groups = Vec::with_capacity(account.member_group_ids.len());
                for group_id in account.member_group_ids.iter() {
                    let display =
                        self.server
                            .try_account(group_id.document_id())
                            .await?
                            .map(|group| {
                                group
                                    .description
                                    .as_deref()
                                    .unwrap_or_else(|| group.name.as_ref())
                                    .to_string()
                            });

                    groups.push(GroupRef {
                        value: Some(group_id.to_string().into()),
                        ref_: Some(self.location(ResourceType::Group, *group_id).into()),
                        display: display.map(Into::into),
                        r#type: Some(GROUP_TYPE_DIRECT.into()),
                    });
                }
                Some(groups)
            };

        let locale = account.locale.as_str();
        let user = User {
            id: Some(id.to_string().into()),
            external_id: account.external_id.as_deref().map(Into::into),
            user_name: Some(user_name.into()),
            name: account.description.as_deref().map(|description| Name {
                formatted: Some(description.into()),
                ..Default::default()
            }),
            display_name: account.description.as_deref().map(Into::into),
            active: if selection.excludes(&USER_SCHEMA, "active") {
                None
            } else {
                Some(self.is_active(account).await?)
            },
            emails: Some(emails),
            locale: Some(locale.into()),
            preferred_language: Some(locale.into()),
            timezone: account
                .time_zone
                .as_ref()
                .map(|time_zone| time_zone.as_str().into()),
            groups,
            meta: Some(
                Meta::new(ResourceType::User)
                    .with_created(account.created_at.to_string())
                    .with_location(self.location(ResourceType::User, id))
                    .with_version(weak_etag(revision)),
            ),
        };

        let mut value = serde_json::to_value(&user).unwrap_or(Value::Null);
        selection.apply(&USER_SCHEMA, &mut value);

        Ok(value)
    }

    pub async fn set_user_name(&self, account: &mut UserAccount, user_name: &str) -> Result<()> {
        let (local_part, domain) = self.resolve_address(user_name, "userName").await?;

        account.name = local_part;
        account.domain_id = Id::from(domain.id);
        account.member_tenant_id = match self.tenant_id() {
            Some(tenant_id) => Some(Id::from(tenant_id)),
            None => domain.id_tenant.map(Id::from),
        };

        Ok(())
    }

    pub async fn set_emails(&self, account: &mut UserAccount, emails: &[Email<'_>]) -> Result<()> {
        let primary = self.email_address(&account.name, account.domain_id).await?;
        let mut aliases = List::with_capacity(emails.len());

        for email in emails {
            let Some(value) = email.value.as_deref().filter(|value| !value.is_empty()) else {
                continue;
            };

            if value.eq_ignore_ascii_case(&primary) {
                continue;
            }

            let (local_part, domain) = self.resolve_address(value, "emails").await?;

            if domain.id_tenant.map(Id::from) != account.member_tenant_id {
                return Err(Error::invalid_value(format!(
                    "The address '{value}' belongs to a domain in a different tenant."
                ))
                .into());
            }

            let alias = EmailAlias {
                enable: true,
                name: local_part,
                domain_id: Id::from(domain.id),
                description: None,
            };

            if !aliases.iter().any(|existing| *existing == alias) {
                aliases.push(alias);
            }
        }

        account.aliases = aliases;

        Ok(())
    }
}

pub fn set_active(permissions: &mut Permissions, active: bool) {
    const AUTHENTICATE: Permission = Permission::Authenticate;

    match permissions {
        Permissions::Inherit => {
            if !active {
                let mut list = PermissionsList::default();
                list.disabled_permissions.push(AUTHENTICATE);
                *permissions = Permissions::Merge(list);
            }
        }
        Permissions::Merge(list) => {
            if active {
                list.disabled_permissions
                    .inner_mut()
                    .retain(|permission| *permission != AUTHENTICATE);
                if list.enabled_permissions.is_empty() && list.disabled_permissions.is_empty() {
                    *permissions = Permissions::Inherit;
                }
            } else {
                list.enabled_permissions
                    .inner_mut()
                    .retain(|permission| *permission != AUTHENTICATE);
                list.disabled_permissions.push(AUTHENTICATE);
            }
        }
        Permissions::Replace(list) => {
            if active {
                list.disabled_permissions
                    .inner_mut()
                    .retain(|permission| *permission != AUTHENTICATE);
                list.enabled_permissions.push(AUTHENTICATE);
            } else {
                list.enabled_permissions
                    .inner_mut()
                    .retain(|permission| *permission != AUTHENTICATE);
                list.disabled_permissions.push(AUTHENTICATE);
            }
        }
    }
}

pub fn set_locale(account: &mut UserAccount, locale: &str) -> Result<()> {
    account.locale = resolve_locale(locale).ok_or_else(|| {
        Error::invalid_value(format!(
            "The locale '{locale}' is not supported by this server."
        ))
    })?;

    Ok(())
}

fn resolve_locale(value: &str) -> Option<Locale> {
    let mut candidates = Vec::new();

    for entry in value.split(',') {
        let (tag, quality) = match entry.split_once(';') {
            Some((tag, parameters)) => (tag.trim(), quality_of(parameters)),
            None => (entry.trim(), 1000),
        };

        if !tag.is_empty() && tag != "*" && quality > 0 {
            candidates.push((tag, quality));
        }
    }

    candidates.sort_by(|(_, a), (_, b)| b.cmp(a));
    candidates.into_iter().find_map(|(tag, _)| resolve_tag(tag))
}

fn quality_of(parameters: &str) -> u16 {
    parameters
        .split(';')
        .filter_map(|parameter| {
            let parameter = parameter.trim();
            parameter
                .strip_prefix("q=")
                .or_else(|| parameter.strip_prefix("Q="))
        })
        .next()
        .map_or(1000, |quality| {
            quality
                .trim()
                .parse::<f32>()
                .ok()
                .filter(|quality| (0.0..=1.0).contains(quality))
                .map_or(1000, |quality| (quality * 1000.0).round() as u16)
        })
}

fn resolve_tag(tag: &str) -> Option<Locale> {
    let tag = tag.replace('_', "-");

    if let Some(locale) = Locale::parse(&tag).or_else(|| Locale::parse(&canonical_locale(&tag))) {
        return Some(locale);
    }

    let mut language_tag = LanguageTag::try_from_str(&tag).ok()?;
    if language_tag.id.language == LanguageSubtag::UNKNOWN {
        return None;
    }

    EXPANDER.maximize(&mut language_tag.id);
    let id = &language_tag.id;
    let language = id.language;
    let mut attempts = Vec::with_capacity(4);

    if let Some(region) = id.region {
        if let Some(script) = id.script {
            attempts.push(format!("{language}-{script}-{region}"));
        }
        attempts.push(format!("{language}-{region}"));
    }
    if let Some(script) = id.script {
        attempts.push(format!("{language}-{script}"));
    }
    attempts.push(language.to_string());

    attempts.iter().find_map(|attempt| Locale::parse(attempt))
}

fn canonical_locale(locale: &str) -> String {
    let mut canonical = String::with_capacity(locale.len());
    let mut in_extension = false;

    for (position, subtag) in locale.split('-').enumerate() {
        if position > 0 {
            canonical.push('-');
        }
        in_extension |= subtag.len() == 1;

        let is_script = subtag.len() == 4 && subtag.chars().all(|c| c.is_ascii_alphabetic());
        let is_region = subtag.len() == 2 && subtag.chars().all(|c| c.is_ascii_alphabetic())
            || subtag.len() == 3 && subtag.chars().all(|c| c.is_ascii_digit());

        if position == 0 || in_extension {
            canonical.extend(subtag.chars().flat_map(char::to_lowercase));
        } else if is_script {
            let mut chars = subtag.chars();
            canonical.extend(chars.by_ref().take(1).flat_map(char::to_uppercase));
            canonical.extend(chars.flat_map(char::to_lowercase));
        } else if is_region {
            canonical.extend(subtag.chars().flat_map(char::to_uppercase));
        } else {
            canonical.extend(subtag.chars().flat_map(char::to_lowercase));
        }
    }

    canonical
}

pub fn set_time_zone(account: &mut UserAccount, time_zone: Option<&str>) -> Result<()> {
    account.time_zone = match time_zone {
        Some(time_zone) => Some(TimeZone::parse(time_zone).ok_or_else(|| {
            Error::invalid_value(format!(
                "The time zone '{time_zone}' is not a known IANA time zone identifier."
            ))
        })?),
        None => None,
    };
    Ok(())
}

pub fn display_name(user: &User<'_>) -> Option<String> {
    user.display_name
        .as_deref()
        .filter(|display_name| !display_name.is_empty())
        .map(str::to_string)
        .or_else(|| user.name.as_ref().and_then(Name::composed))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/scim/src/users/tests.rs"]
mod tests;
