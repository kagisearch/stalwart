/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

pub mod group;
pub mod spc;
pub mod user;

use std::borrow::Cow;

use serde::{Serialize, Serializer, ser::SerializeMap};

use crate::{
    ResourceType, SCHEMA_SCHEMA,
    filter::AttrPath,
    json::scim_object,
    message::error::{Error, ScimType},
    path::PatchPath,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schema {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub attributes: &'static [Attribute],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute {
    pub name: &'static str,
    pub attr_type: AttributeType,
    pub sub_attributes: &'static [Attribute],
    pub multi_valued: bool,
    pub description: &'static str,
    pub required: bool,
    pub canonical_values: &'static [&'static str],
    pub case_exact: bool,
    pub mutability: Mutability,
    pub returned: Returned,
    pub uniqueness: Uniqueness,
    pub reference_types: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    String,
    Boolean,
    Decimal,
    Integer,
    DateTime,
    Binary,
    Reference,
    Complex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutability {
    ReadOnly,
    ReadWrite,
    Immutable,
    WriteOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Returned {
    Always,
    Never,
    Default,
    Request,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Uniqueness {
    None,
    Server,
    Global,
}

impl Schema {
    pub fn attribute(&self, name: &str) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|attribute| attribute.name.eq_ignore_ascii_case(name))
    }

    pub fn resolve(&self, attr: &str, sub_attr: Option<&str>) -> Option<&Attribute> {
        let attribute = self.attribute(attr)?;

        match sub_attr {
            Some(sub_attr) => attribute.sub_attribute(sub_attr),
            None => Some(attribute),
        }
    }

    pub fn resolve_attr_path(&self, path: &AttrPath<'_>) -> Option<&Attribute> {
        if path.has_schema(self.id) {
            self.resolve(path.attr.as_ref(), path.sub_attr.as_deref())
        } else {
            None
        }
    }

    pub fn resolve_filter_path(&self, path: &AttrPath<'_>) -> Result<&Attribute, Error> {
        self.resolve_attr_path(path).ok_or_else(|| {
            Error::invalid_filter(format!(
                "Attribute '{path}' is not defined by schema '{}'",
                self.id
            ))
        })
    }

    pub fn resolve_patch_path(&self, path: &PatchPath<'_>) -> Result<&Attribute, Error> {
        if !path.has_schema(self.id) {
            return Err(Error::bad_request(
                ScimType::InvalidSyntax,
                format!(
                    "Unsupported schema URI '{}'",
                    path.schema.as_deref().unwrap_or_default()
                ),
            ));
        }

        match self.resolve(path.attr.as_ref(), None) {
            Some(attribute) => match path.sub_attr.as_deref() {
                Some(sub_attr) => attribute.sub_attribute(sub_attr).ok_or_else(|| {
                    Error::bad_request(
                        ScimType::InvalidSyntax,
                        format!("Unknown attribute '{path}'"),
                    )
                }),
                None => Ok(attribute),
            },
            None => Err(Error::bad_request(
                ScimType::InvalidSyntax,
                format!("Unknown attribute '{path}'"),
            )),
        }
    }

    pub fn resource<'a>(&'static self, location: Option<&'a str>) -> SchemaResource<'a> {
        SchemaResource {
            definition: self,
            location,
        }
    }
}

impl Attribute {
    pub const DEFAULT: Attribute = Attribute {
        name: "",
        attr_type: AttributeType::String,
        sub_attributes: &[],
        multi_valued: false,
        description: "",
        required: false,
        canonical_values: &[],
        case_exact: false,
        mutability: Mutability::ReadWrite,
        returned: Returned::Default,
        uniqueness: Uniqueness::None,
        reference_types: &[],
    };

    pub fn sub_attribute(&self, name: &str) -> Option<&Attribute> {
        self.sub_attributes
            .iter()
            .find(|attribute| attribute.name.eq_ignore_ascii_case(name))
    }

    pub fn is_returned_always(&self) -> bool {
        self.returned == Returned::Always
    }

    pub fn is_returned_never(&self) -> bool {
        self.returned == Returned::Never
    }

    pub fn is_writable(&self) -> bool {
        matches!(
            self.mutability,
            Mutability::ReadWrite | Mutability::WriteOnly
        )
    }
}

impl AttributeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttributeType::String => "string",
            AttributeType::Boolean => "boolean",
            AttributeType::Decimal => "decimal",
            AttributeType::Integer => "integer",
            AttributeType::DateTime => "dateTime",
            AttributeType::Binary => "binary",
            AttributeType::Reference => "reference",
            AttributeType::Complex => "complex",
        }
    }
}

impl AttributeType {
    pub fn has_case_sensitivity(&self) -> bool {
        matches!(
            self,
            AttributeType::String | AttributeType::Binary | AttributeType::Reference
        )
    }

    pub fn has_uniqueness(&self) -> bool {
        matches!(
            self,
            AttributeType::String
                | AttributeType::Decimal
                | AttributeType::Integer
                | AttributeType::Reference
        )
    }
}

impl Mutability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mutability::ReadOnly => "readOnly",
            Mutability::ReadWrite => "readWrite",
            Mutability::Immutable => "immutable",
            Mutability::WriteOnly => "writeOnly",
        }
    }
}

impl Returned {
    pub fn as_str(&self) -> &'static str {
        match self {
            Returned::Always => "always",
            Returned::Never => "never",
            Returned::Default => "default",
            Returned::Request => "request",
        }
    }
}

impl Uniqueness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Uniqueness::None => "none",
            Uniqueness::Server => "server",
            Uniqueness::Global => "global",
        }
    }
}

impl Serialize for Attribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("name", self.name)?;
        map.serialize_entry("type", self.attr_type.as_str())?;
        if self.attr_type == AttributeType::Complex {
            map.serialize_entry("subAttributes", &self.sub_attributes)?;
        }
        map.serialize_entry("multiValued", &self.multi_valued)?;
        map.serialize_entry("description", self.description)?;
        map.serialize_entry("required", &self.required)?;
        if !self.canonical_values.is_empty() {
            map.serialize_entry("canonicalValues", &self.canonical_values)?;
        }
        if self.attr_type.has_case_sensitivity() {
            map.serialize_entry("caseExact", &self.case_exact)?;
        }
        map.serialize_entry("mutability", self.mutability.as_str())?;
        map.serialize_entry("returned", self.returned.as_str())?;
        if self.attr_type.has_uniqueness() {
            map.serialize_entry("uniqueness", self.uniqueness.as_str())?;
        }
        if !self.reference_types.is_empty() {
            map.serialize_entry("referenceTypes", &self.reference_types)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SchemaResource<'a> {
    pub definition: &'static Schema,
    pub location: Option<&'a str>,
}

impl Serialize for SchemaResource<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schemas", &[SCHEMA_SCHEMA])?;
        map.serialize_entry("id", self.definition.id)?;
        map.serialize_entry("name", self.definition.name)?;
        map.serialize_entry("description", self.definition.description)?;
        map.serialize_entry("attributes", &self.definition.attributes)?;
        map.serialize_entry(
            "meta",
            &Meta {
                resource_type: Some(Cow::Borrowed("Schema")),
                location: self.location.map(Cow::Borrowed),
                ..Default::default()
            },
        )?;
        map.end()
    }
}

scim_object!(pub Meta<'x>, None::<&'static str>, {
    "resourceType" => str resource_type: Option<Cow<'x, str>>,
    "created" => str created: Option<Cow<'x, str>>,
    "location" => str location: Option<Cow<'x, str>>,
    "version" => str version: Option<Cow<'x, str>>,
    "lastModified" => input last_modified: Option<Cow<'x, str>>,
});

impl<'x> Meta<'x> {
    pub fn new(resource_type: ResourceType) -> Self {
        Meta {
            resource_type: Some(Cow::Borrowed(resource_type.as_str())),
            ..Default::default()
        }
    }

    pub fn with_created(mut self, created: impl Into<Cow<'x, str>>) -> Self {
        self.created = Some(created.into());
        self
    }

    pub fn with_location(mut self, location: impl Into<Cow<'x, str>>) -> Self {
        self.location = Some(location.into());
        self
    }

    pub fn with_version(mut self, version: impl Into<Cow<'x, str>>) -> Self {
        self.version = Some(version.into());
        self
    }
}

pub(crate) const META_ATTRIBUTE: Attribute = Attribute {
    name: "meta",
    attr_type: AttributeType::Complex,
    description: "A complex attribute containing resource metadata.",
    mutability: Mutability::ReadOnly,
    sub_attributes: &[
        Attribute {
            name: "resourceType",
            description: "The name of the resource type of the resource.",
            case_exact: true,
            mutability: Mutability::ReadOnly,
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "created",
            attr_type: AttributeType::DateTime,
            description: "The date and time the resource was added to the service provider.",
            mutability: Mutability::ReadOnly,
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "location",
            attr_type: AttributeType::Reference,
            reference_types: &["uri"],
            description: "The URI of the resource being returned.",
            case_exact: true,
            mutability: Mutability::ReadOnly,
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "version",
            description: "The version of the resource being returned, as a weak entity tag.",
            case_exact: true,
            mutability: Mutability::ReadOnly,
            ..Attribute::DEFAULT
        },
    ],
    ..Attribute::DEFAULT
};

pub(crate) const ID_ATTRIBUTE: Attribute = Attribute {
    name: "id",
    description: "The unique identifier assigned by the service provider.",
    case_exact: true,
    mutability: Mutability::ReadOnly,
    returned: Returned::Always,
    uniqueness: Uniqueness::Server,
    ..Attribute::DEFAULT
};

pub(crate) const EXTERNAL_ID_ATTRIBUTE: Attribute = Attribute {
    name: "externalId",
    description: "An identifier for the resource as defined by the provisioning client.",
    case_exact: true,
    ..Attribute::DEFAULT
};

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/scim-proto/src/schema/tests.rs"]
mod tests;
