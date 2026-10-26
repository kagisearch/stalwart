/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::{
    SCHEMA_USER,
    json::scim_object,
    message::error::Error,
    schema::{
        Attribute, AttributeType, EXTERNAL_ID_ATTRIBUTE, ID_ATTRIBUTE, META_ATTRIBUTE, Meta,
        Mutability, Schema, Uniqueness,
    },
};

pub const SCHEMA_ENTERPRISE_USER: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

pub const TOLERATED_USER_ATTRIBUTES: &[&str] = &[
    "password",
    "nickName",
    "profileUrl",
    "title",
    "userType",
    "phoneNumbers",
    "ims",
    "photos",
    "addresses",
    "entitlements",
    "roles",
    "x509Certificates",
    SCHEMA_ENTERPRISE_USER,
];

pub const TOLERATED_USER_SCHEMAS: &[&str] = &[SCHEMA_ENTERPRISE_USER];

pub const TOLERATED_NAME_ATTRIBUTES: &[&str] =
    &["middleName", "honorificPrefix", "honorificSuffix"];

scim_object!(pub User<'x>, Some(SCHEMA_USER), TOLERATED_USER_ATTRIBUTES, TOLERATED_USER_SCHEMAS, {
    "id" => str id: Option<Cow<'x, str>>,
    "externalId" => str external_id: Option<Cow<'x, str>>,
    "userName" => str user_name: Option<Cow<'x, str>>,
    "name" => any name: Option<Name<'x>>,
    "displayName" => str display_name: Option<Cow<'x, str>>,
    "active" => any active: Option<bool>,
    "emails" => any emails: Option<Vec<Email<'x>>>,
    "locale" => str locale: Option<Cow<'x, str>>,
    "preferredLanguage" => str preferred_language: Option<Cow<'x, str>>,
    "timezone" => str timezone: Option<Cow<'x, str>>,
    "groups" => any groups: Option<Vec<GroupRef<'x>>>,
    "meta" => any meta: Option<Meta<'x>>,
});

scim_object!(pub Name<'x>, None::<&'static str>, TOLERATED_NAME_ATTRIBUTES, &[], {
    "formatted" => str formatted: Option<Cow<'x, str>>,
    "givenName" => input given_name: Option<Cow<'x, str>>,
    "familyName" => input family_name: Option<Cow<'x, str>>,
});

impl Name<'_> {
    pub fn composed(&self) -> Option<String> {
        if let Some(formatted) = self.formatted.as_deref().filter(|value| !value.is_empty()) {
            return Some(formatted.to_string());
        }

        let mut composed = String::new();
        for part in [self.given_name.as_deref(), self.family_name.as_deref()]
            .into_iter()
            .flatten()
            .filter(|part| !part.is_empty())
        {
            if !composed.is_empty() {
                composed.push(' ');
            }
            composed.push_str(part);
        }

        Some(composed).filter(|composed| !composed.is_empty())
    }
}

scim_object!(pub Email<'x>, None::<&'static str>, {
    "value" => str value: Option<Cow<'x, str>>,
    "display" => str display: Option<Cow<'x, str>>,
    "type" => str r#type: Option<Cow<'x, str>>,
    "primary" => any primary: Option<bool>,
});

scim_object!(pub GroupRef<'x>, None::<&'static str>, {
    "value" => str value: Option<Cow<'x, str>>,
    "$ref" => str ref_: Option<Cow<'x, str>>,
    "display" => str display: Option<Cow<'x, str>>,
    "type" => str r#type: Option<Cow<'x, str>>,
});

impl<'x> User<'x> {
    pub fn parse(body: &'x [u8]) -> Result<Self, Error> {
        serde_json::from_slice(body).map_err(|err| Error::invalid_syntax(err.to_string()))
    }

    pub fn primary_email(&self) -> Option<&Email<'x>> {
        self.emails.as_ref().and_then(|emails| {
            emails
                .iter()
                .find(|email| email.primary.unwrap_or_default())
                .or_else(|| emails.first())
        })
    }
}

pub const USER_SCHEMA: Schema = Schema {
    id: SCHEMA_USER,
    name: "User",
    description: "User Account",
    attributes: &[
        ID_ATTRIBUTE,
        EXTERNAL_ID_ATTRIBUTE,
        Attribute {
            name: "userName",
            description: "Unique identifier for the User, used by the user to authenticate to \
                           the service provider. Each User MUST include a non-empty userName \
                           value.",
            required: true,
            uniqueness: Uniqueness::Server,
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "name",
            attr_type: AttributeType::Complex,
            description: "The components of the user's name.",
            sub_attributes: &[Attribute {
                name: "formatted",
                description: "The full name, formatted for display.",
                ..Attribute::DEFAULT
            }],
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "displayName",
            description: "The name of the User, suitable for display to end-users.",
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "active",
            attr_type: AttributeType::Boolean,
            description: "A Boolean value indicating the User's administrative status. A value \
                           of false suspends the account and prevents authentication.",
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "emails",
            attr_type: AttributeType::Complex,
            multi_valued: true,
            description: "Email addresses for the User. The primary email address is the \
                           address the User authenticates with.",
            sub_attributes: &[
                Attribute {
                    name: "value",
                    description: "The email address.",
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "display",
                    description: "A human-readable name, primarily used for display purposes.",
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "type",
                    description: "A label indicating the attribute's function. Every address is \
                                   of type 'work'.",
                    canonical_values: &["work"],
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "primary",
                    attr_type: AttributeType::Boolean,
                    description: "A Boolean value indicating the preferred email address. The \
                                   primary address is the User's userName and cannot be removed.",
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
            ],
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "locale",
            description: "Indicates the User's default location, used to select a localized \
                           representation, for example 'en-US'.",
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "preferredLanguage",
            description: "Indicates the User's preferred written or spoken language. Backed by \
                           the same value as locale.",
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "timezone",
            description: "The User's time zone, in IANA Time Zone database format, for example \
                           'America/Los_Angeles'.",
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "groups",
            attr_type: AttributeType::Complex,
            multi_valued: true,
            description: "A list of groups to which the user belongs. Membership is managed \
                           through the Group resource.",
            mutability: Mutability::ReadOnly,
            sub_attributes: &[
                Attribute {
                    name: "value",
                    description: "The identifier of the User's group.",
                    case_exact: true,
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "$ref",
                    attr_type: AttributeType::Reference,
                    reference_types: &["Group"],
                    description: "The URI of the corresponding Group resource.",
                    case_exact: true,
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "display",
                    description: "A human-readable name for the group.",
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "type",
                    description: "A label indicating the attribute's function.",
                    canonical_values: &["direct"],
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
            ],
            ..Attribute::DEFAULT
        },
        META_ATTRIBUTE,
    ],
};

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/scim-proto/src/schema/user/tests.rs"]
mod tests;
