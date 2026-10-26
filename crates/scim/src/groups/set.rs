/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    auth::ScimConditional,
    context::{
        ScimContext, account_of, bounded, group_account, parse_id, revision_of, user_account,
    },
    error::{Result, no_content},
    groups,
    request::respond_with_etag,
    users::set::CLIENT_ID,
};
use compact_str::ToCompactString;
use http_proto::{HttpRequest, HttpResponse};
use hyper::{StatusCode, header};
use jmap::registry::mapping::principal::AccountUpdate;
use registry::{
    schema::{
        enums::{AccountType, Permission},
        prelude::{Object, ObjectType, Property},
        structs::{Account, GroupAccount, Roles},
    },
    types::{EnumImpl, datetime::UTCDateTime},
};
use scim_proto::{
    ResourceType,
    etag::weak_etag,
    message::{error::Error, search::SearchRequest},
    schema::group::{Group, Member},
};
use store::registry::RegistryQuery;
use trc::AddContext;
use types::id::Id;

pub const MAX_LOCAL_PART_LEN: usize = 64;
pub const MAX_UNIQUENESS_CANDIDATES: usize = 5000;
pub const MAX_NAME_ATTEMPTS: usize = 1000;
pub const FALLBACK_NAME: &str = "group";

impl ScimContext<'_> {
    pub async fn group_create(
        &self,
        body: &[u8],
        request: &SearchRequest<'_>,
    ) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountCreate)?;

        let group = Group::parse(body)?;
        let (id, object, member_ids) = self.group_insert(&group).await?;
        let resource = self.group_render(id, &object, &member_ids, request).await?;

        respond_with_etag(
            StatusCode::CREATED,
            &resource,
            weak_etag(groups::version(object.revision, &member_ids)),
        )
        .map(|response| {
            response.with_header(header::LOCATION, self.location(ResourceType::Group, id))
        })
    }

    pub async fn group_insert(&self, group: &Group<'_>) -> Result<(Id, Object, Vec<Id>)> {
        self.assert_permission(Permission::SysAccountCreate)?;

        let display_name = group
            .display_name
            .as_deref()
            .filter(|display_name| !display_name.is_empty())
            .ok_or_else(|| {
                Error::invalid_value("The 'displayName' attribute is required to create a Group.")
            })?;

        let (domain_id, domain_tenant) = self.group_domain().await?;
        self.assert_display_name_available(display_name, None)
            .await?;

        let member_ids = self
            .resolve_members(group.members.as_deref().unwrap_or_default())
            .await?;

        if !member_ids.is_empty() {
            self.assert_permission(Permission::SysAccountUpdate)?;
        }

        let mut account = Account::Group(GroupAccount {
            name: self.available_name(display_name, domain_id).await?,
            domain_id,
            description: Some(display_name.to_string()),
            created_at: UTCDateTime::now(),
            member_tenant_id: match self.tenant_id() {
                Some(tenant_id) => Some(Id::from(tenant_id)),
                None => domain_tenant,
            },
            roles: Roles::Default,
            external_id: group.external_id.as_deref().map(str::to_string),
            ..Default::default()
        });

        self.validate(&mut account, AccountUpdate::Create(CLIENT_ID))
            .await?;

        let mut object = Object::from(account);
        let id = self.insert(&object, ResourceType::Group).await?;
        object.revision = revision_of(&object);

        if let Err(error) = self.set_members(id, &member_ids, &[]).await {
            if let Err(rollback) = self.delete(id, &object).await {
                trc::event!(
                    Scim(trc::ScimEvent::RollbackFailed),
                    SpanId = self.session_id,
                    AccountId = self.access_token.account_id(),
                    Type = ResourceType::Group.as_str(),
                    Id = id.to_compact_string(),
                    Reason = bounded(&rollback.to_compact_string()),
                );
            }

            return Err(error);
        }

        trc::event!(
            Scim(trc::ScimEvent::ResourceCreated),
            SpanId = self.session_id,
            AccountId = self.access_token.account_id(),
            Type = ResourceType::Group.as_str(),
            Id = id.to_compact_string(),
            Name = bounded(display_name),
            Total = member_ids.len(),
        );

        Ok((id, object, member_ids))
    }

    pub async fn group_replace(
        &self,
        req: &HttpRequest,
        id: Id,
        body: &[u8],
        request: &SearchRequest<'_>,
    ) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountUpdate)?;

        let group = Group::parse(body)?;
        let old_object = self.account(id).await?;
        let current_members = self.group_member_ids(id).await?;

        group_account(&old_object)?;
        req.scim_assert_if_match(&weak_etag(groups::version(
            old_object.revision,
            &current_members,
        )))?;

        let (updated, member_ids) = self
            .group_update(id, &group, &old_object, current_members)
            .await?;
        let object = updated.as_ref().unwrap_or(&old_object);
        let resource = self.group_render(id, object, &member_ids, request).await?;

        respond_with_etag(
            StatusCode::OK,
            &resource,
            weak_etag(groups::version(object.revision, &member_ids)),
        )
    }

    pub async fn group_update(
        &self,
        id: Id,
        group: &Group<'_>,
        old_object: &Object,
        current_members: Vec<Id>,
    ) -> Result<(Option<Object>, Vec<Id>)> {
        self.assert_permission(Permission::SysAccountUpdate)?;

        let mut account = group_account(old_object)?.clone();
        let display_name = group
            .display_name
            .as_deref()
            .filter(|display_name| !display_name.is_empty())
            .ok_or_else(|| {
                Error::invalid_value("The 'displayName' attribute is required to replace a Group.")
            })?;

        if !groups::display_name(&account).eq_ignore_ascii_case(display_name) {
            self.assert_display_name_available(display_name, Some(id))
                .await?;
        }

        account.description = Some(display_name.to_string());
        account.external_id = group.external_id.as_deref().map(str::to_string);

        let members = self
            .resolve_members(group.members.as_deref().unwrap_or_default())
            .await?;
        let member_ids = self.set_members(id, &members, &current_members).await?;
        let object = match self.group_write(id, account, old_object).await {
            Ok(object) => object,
            Err(error) => {
                if let Err(rollback) = self.set_members(id, &current_members, &member_ids).await {
                    trc::event!(
                        Scim(trc::ScimEvent::RollbackFailed),
                        SpanId = self.session_id,
                        AccountId = self.access_token.account_id(),
                        Type = ResourceType::Group.as_str(),
                        Id = id.to_compact_string(),
                        Reason = bounded(&rollback.to_compact_string()),
                    );
                }

                return Err(error);
            }
        };

        if object.is_some() || groups::members_changed(&current_members, &member_ids) {
            trc::event!(
                Scim(trc::ScimEvent::ResourceUpdated),
                SpanId = self.session_id,
                AccountId = self.access_token.account_id(),
                Type = ResourceType::Group.as_str(),
                Id = id.to_compact_string(),
                Name = bounded(display_name),
                Total = member_ids.len(),
            );
        }

        Ok((object, member_ids))
    }

    pub async fn group_destroy(&self, req: &HttpRequest, id: Id) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountDestroy)?;

        let object = self.account(id).await?;
        group_account(&object)?;

        let member_ids = self.group_member_ids(id).await?;
        req.scim_assert_if_match(&weak_etag(groups::version(object.revision, &member_ids)))?;

        self.group_delete(id, &object).await?;

        Ok(no_content())
    }

    pub async fn group_delete(&self, id: Id, object: &Object) -> Result<()> {
        self.assert_permission(Permission::SysAccountDestroy)?;

        group_account(object)?;
        self.delete(id, object).await?;

        trc::event!(
            Scim(trc::ScimEvent::ResourceDeleted),
            SpanId = self.session_id,
            AccountId = self.access_token.account_id(),
            Type = ResourceType::Group.as_str(),
            Id = id.to_compact_string(),
        );

        Ok(())
    }

    pub async fn group_write(
        &self,
        id: Id,
        account: GroupAccount,
        old_object: &Object,
    ) -> Result<Option<Object>> {
        if group_account(old_object)? == &account {
            return Ok(None);
        }

        let mut account = Account::Group(account);
        self.validate(&mut account, AccountUpdate::Update(account_of(old_object)?))
            .await?;

        let mut object = Object::from(account);
        self.update(id, &object, old_object, ResourceType::Group)
            .await?;
        object.revision = revision_of(&object);

        Ok(Some(object))
    }

    pub async fn group_domain(&self) -> Result<(Id, Option<Id>)> {
        let object = self
            .account(Id::from(self.access_token.account_id()))
            .await
            .map_err(|_| {
                Error::invalid_value(
                    "Groups are created in the domain of the authenticated SCIM service \
                     principal, which could not be resolved.",
                )
            })?;
        let domain_id = user_account(&object)?.domain_id;
        let domain = self.domain_by_id(domain_id).await?;

        if !domain.allows_scim_provisioning() {
            return Err(Error::invalid_value(format!(
                "SCIM provisioning is not enabled for the domain '{}' of the authenticated \
                 service principal.",
                domain.name()
            ))
            .into());
        }

        Ok((domain_id, domain.id_tenant.map(Id::from)))
    }

    pub async fn resolve_members(&self, members: &[Member<'_>]) -> Result<Vec<Id>> {
        let mut member_ids = Vec::with_capacity(members.len());

        for member in members {
            if !member.is_user() {
                return Err(Error::invalid_value(
                    "Nested groups are not supported, 'members.type' must be 'User'.",
                )
                .into());
            }

            let value = member
                .value
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    Error::invalid_value("Each 'members' element requires a 'value' attribute.")
                })?;
            let id = parse_id(value).map_err(|_| {
                Error::invalid_value(format!("The member '{value}' is not a valid identifier."))
            })?;

            let object = self.account(id).await.map_err(|_| {
                Error::invalid_value(format!("The member '{value}' does not exist."))
            })?;
            user_account(&object).map_err(|_| {
                Error::invalid_value(format!("The member '{value}' is not a User."))
            })?;

            if !member_ids.contains(&id) {
                member_ids.push(id);
            }
        }

        Ok(member_ids)
    }

    pub async fn set_members(
        &self,
        group_id: Id,
        members: &[Id],
        current: &[Id],
    ) -> Result<Vec<Id>> {
        let mut applied = Vec::new();

        for member_id in current {
            if !members.contains(member_id) {
                if let Err(error) = self.remove_membership(*member_id, group_id).await {
                    self.revert_members(group_id, &applied).await;

                    return Err(error);
                }
                applied.push((*member_id, false));
            }
        }

        for member_id in members {
            if !current.contains(member_id) {
                if let Err(error) = self.add_membership(*member_id, group_id).await {
                    self.revert_members(group_id, &applied).await;

                    return Err(error);
                }
                applied.push((*member_id, true));
            }
        }

        Ok(members.to_vec())
    }

    async fn revert_members(&self, group_id: Id, applied: &[(Id, bool)]) {
        let mut failure = None;

        for (member_id, was_added) in applied.iter().rev() {
            let result = if *was_added {
                self.remove_membership(*member_id, group_id).await
            } else {
                self.add_membership(*member_id, group_id).await
            };

            if let Err(error) = result
                && failure.is_none()
            {
                failure = Some(error);
            }
        }

        if let Some(error) = failure {
            trc::event!(
                Scim(trc::ScimEvent::RollbackFailed),
                SpanId = self.session_id,
                AccountId = self.access_token.account_id(),
                Type = ResourceType::Group.as_str(),
                Id = group_id.to_compact_string(),
                Reason = bounded(&error.to_compact_string()),
            );
        }
    }

    pub async fn add_membership(&self, user_id: Id, group_id: Id) -> Result<()> {
        let object = self.account(user_id).await?;
        let account = user_account(&object)?;

        if account.member_group_ids.contains(&group_id) {
            return Ok(());
        }

        let mut account = account.clone();
        account.member_group_ids.push(group_id);

        self.user_write(user_id, account, &object).await.map(|_| ())
    }

    pub async fn remove_membership(&self, user_id: Id, group_id: Id) -> Result<()> {
        let object = self.account(user_id).await?;
        let account = user_account(&object)?;

        if !account.member_group_ids.contains(&group_id) {
            return Ok(());
        }

        let mut account = account.clone();
        account
            .member_group_ids
            .inner_mut()
            .retain(|id| *id != group_id);

        self.user_write(user_id, account, &object).await.map(|_| ())
    }

    pub async fn assert_display_name_available(
        &self,
        display_name: &str,
        exclude: Option<Id>,
    ) -> Result<()> {
        let mut query = RegistryQuery::new(ObjectType::Account)
            .with_tenant(self.tenant_id())
            .equal(Property::Type, AccountType::Group.to_id());

        if display_name
            .split(|ch: char| !ch.is_alphanumeric())
            .any(|word| word.len() > 1)
        {
            query.push_text(Property::Text, display_name);
        }

        let candidates = self
            .server
            .registry()
            .query::<Vec<Id>>(query)
            .await
            .caused_by(trc::location!())?;

        if candidates.len() > MAX_UNIQUENESS_CANDIDATES {
            return Err(Error::too_many(format!(
                "The uniqueness of the displayName '{display_name}' could not be verified \
                 against more than {MAX_UNIQUENESS_CANDIDATES} existing Groups."
            ))
            .into());
        }

        for id in candidates {
            if exclude == Some(id) {
                continue;
            }

            if self
                .try_account(id)
                .await?
                .as_ref()
                .and_then(|object| group_account(object).ok())
                .is_some_and(|account| {
                    groups::display_name(account).eq_ignore_ascii_case(display_name)
                })
            {
                return Err(Error::uniqueness(format!(
                    "A Group with the displayName '{display_name}' already exists."
                ))
                .into());
            }
        }

        Ok(())
    }

    pub async fn available_name(&self, display_name: &str, domain_id: Id) -> Result<String> {
        let slug = slugify(display_name);

        for attempt in 1..=MAX_NAME_ATTEMPTS {
            let candidate = if attempt == 1 {
                slug.clone()
            } else {
                let suffix = format!("-{attempt}");
                let mut candidate = slug.clone();
                truncate(&mut candidate, MAX_LOCAL_PART_LEN - suffix.len());
                candidate.push_str(&suffix);
                candidate
            };

            if self
                .server
                .rcpt_id_from_parts(&candidate, domain_id.document_id())
                .await
                .caused_by(trc::location!())?
                .is_none()
            {
                return Ok(candidate);
            }
        }

        Err(Error::conflict(
            "A unique mailbox name could not be derived from the supplied 'displayName'.",
        )
        .into())
    }
}

pub fn slugify(display_name: &str) -> String {
    let mut slug = String::with_capacity(display_name.len().min(MAX_LOCAL_PART_LEN));
    let mut separator = false;

    for ch in display_name.chars() {
        if ch.is_alphanumeric() {
            if separator && !slug.is_empty() {
                slug.push('-');
            }
            separator = false;

            if ch.is_uppercase() {
                slug.extend(ch.to_lowercase());
            } else {
                slug.push(ch);
            }
        } else {
            separator = true;
        }
    }

    truncate(&mut slug, MAX_LOCAL_PART_LEN);

    if slug.is_empty() {
        slug.push_str(FALLBACK_NAME);
    }

    slug
}

fn truncate(value: &mut String, max_len: usize) {
    if value.len() > max_len {
        let boundary = value
            .char_indices()
            .take_while(|(index, ch)| index + ch.len_utf8() <= max_len)
            .last()
            .map_or(0, |(index, ch)| index + ch.len_utf8());
        value.truncate(boundary);
    }

    while value.ends_with('-') {
        value.pop();
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/scim/src/groups/set/tests.rs"]
mod tests;
