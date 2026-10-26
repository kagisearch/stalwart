/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::{
    SCHEMA_GROUP,
    json::scim_object,
    message::error::Error,
    schema::{
        Attribute, AttributeType, EXTERNAL_ID_ATTRIBUTE, ID_ATTRIBUTE, META_ATTRIBUTE, Meta,
        Mutability, Schema, Uniqueness,
    },
};

pub const TOLERATED_GROUP_ATTRIBUTES: &[&str] = &["description"];

scim_object!(pub Group<'x>, Some(SCHEMA_GROUP), TOLERATED_GROUP_ATTRIBUTES, &[], {
    "id" => str id: Option<Cow<'x, str>>,
    "externalId" => str external_id: Option<Cow<'x, str>>,
    "displayName" => str display_name: Option<Cow<'x, str>>,
    "members" => any members: Option<Vec<Member<'x>>>,
    "meta" => any meta: Option<Meta<'x>>,
});

scim_object!(pub Member<'x>, None::<&'static str>, {
    "value" => str value: Option<Cow<'x, str>>,
    "$ref" => str ref_: Option<Cow<'x, str>>,
    "display" => str display: Option<Cow<'x, str>>,
    "type" => str r#type: Option<Cow<'x, str>>,
});

pub const MEMBER_TYPE_USER: &str = "User";

impl<'x> Group<'x> {
    pub fn parse(body: &'x [u8]) -> Result<Self, Error> {
        serde_json::from_slice(body).map_err(|err| Error::invalid_syntax(err.to_string()))
    }
}

impl Member<'_> {
    pub fn is_user(&self) -> bool {
        self.r#type
            .as_deref()
            .is_none_or(|value| value.eq_ignore_ascii_case(MEMBER_TYPE_USER))
    }
}

pub const GROUP_SCHEMA: Schema = Schema {
    id: SCHEMA_GROUP,
    name: "Group",
    description: "Group",
    attributes: &[
        ID_ATTRIBUTE,
        EXTERNAL_ID_ATTRIBUTE,
        Attribute {
            name: "displayName",
            description: "A human-readable name for the Group.",
            required: true,
            uniqueness: Uniqueness::Server,
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "members",
            attr_type: AttributeType::Complex,
            multi_valued: true,
            description: "A list of members of the Group. Only User members are supported.",
            sub_attributes: &[
                Attribute {
                    name: "value",
                    description: "The identifier of a member of this Group.",
                    case_exact: true,
                    mutability: Mutability::Immutable,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "$ref",
                    attr_type: AttributeType::Reference,
                    reference_types: &["User"],
                    description: "The URI corresponding to a member of this Group.",
                    case_exact: true,
                    mutability: Mutability::Immutable,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "display",
                    description: "A human-readable name for the member.",
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "type",
                    description: "A label indicating the type of resource, for example User.",
                    canonical_values: &[MEMBER_TYPE_USER],
                    mutability: Mutability::Immutable,
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
#[path = "../../../../../stalwart-tests/unit/scim-proto/src/schema/group/tests.rs"]
mod tests;
