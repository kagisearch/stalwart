/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use super::{AiBackend, AiModel, Dialect, OpenAiProfile};
use serde::{Serialize, ser::SerializeMap};
use serde_json::value::{RawValue, to_raw_value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaNode {
    String,
    Boolean,
    Number,
    Enum(Box<[Box<str>]>),
    Object(Box<[(Box<str>, SchemaNode)]>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaFlavor {
    Strict,
    Relaxed,
}

#[derive(Debug)]
pub struct PreparedFormat {
    pub raw: Box<RawValue>,
    pub instructions: Option<Box<str>>,
}

pub struct SchemaJson<'x> {
    pub node: &'x SchemaNode,
    pub flavor: SchemaFlavor,
}

struct Properties<'x> {
    fields: &'x [(Box<str>, SchemaNode)],
    flavor: SchemaFlavor,
}

struct Required<'x>(&'x [(Box<str>, SchemaNode)]);

#[derive(Serialize)]
struct OpenAiJsonSchema<'x> {
    #[serde(rename = "type")]
    typ: &'static str,
    json_schema: OpenAiJsonSchemaInner<'x>,
}

#[derive(Serialize)]
struct OpenAiJsonSchemaInner<'x> {
    name: &'x str,
    strict: bool,
    schema: SchemaJson<'x>,
}

#[derive(Serialize)]
struct TypedSchema<'x> {
    #[serde(rename = "type")]
    typ: &'static str,
    schema: SchemaJson<'x>,
}

#[derive(Serialize)]
struct JsonObject {
    #[serde(rename = "type")]
    typ: &'static str,
}

impl SchemaNode {
    pub fn object(fields: impl IntoIterator<Item = (Box<str>, SchemaNode)>) -> Self {
        SchemaNode::Object(fields.into_iter().collect())
    }

    pub fn enumeration(values: impl IntoIterator<Item = Box<str>>) -> Self {
        SchemaNode::Enum(values.into_iter().collect())
    }
}

impl Serialize for SchemaJson<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.node {
            SchemaNode::String => type_only(serializer, "string"),
            SchemaNode::Boolean => type_only(serializer, "boolean"),
            SchemaNode::Number => type_only(serializer, "number"),
            SchemaNode::Enum(values) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("type", "string")?;
                map.serialize_entry("enum", values)?;
                map.end()
            }
            SchemaNode::Object(fields) => {
                let strict = self.flavor == SchemaFlavor::Strict;
                let mut map = serializer.serialize_map(Some(3 + strict as usize))?;
                map.serialize_entry("type", "object")?;
                map.serialize_entry(
                    "properties",
                    &Properties {
                        fields,
                        flavor: self.flavor,
                    },
                )?;
                map.serialize_entry("required", &Required(fields))?;
                if strict {
                    map.serialize_entry("additionalProperties", &false)?;
                }
                map.end()
            }
        }
    }
}

fn type_only<S: serde::Serializer>(serializer: S, typ: &'static str) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry("type", typ)?;
    map.end()
}

impl Serialize for Properties<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.fields.len()))?;
        for (name, node) in self.fields {
            map.serialize_entry(
                name,
                &SchemaJson {
                    node,
                    flavor: self.flavor,
                },
            )?;
        }
        map.end()
    }
}

impl Serialize for Required<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|(name, _)| name))
    }
}

impl AiModel {
    pub fn prepare_format(
        &self,
        name: &str,
        schema: &SchemaNode,
    ) -> Result<PreparedFormat, serde_json::Error> {
        let AiBackend::Generative(model) = &self.backend else {
            return Ok(PreparedFormat {
                raw: to_raw_value(&JsonObject { typ: "json_object" })?,
                instructions: None,
            });
        };

        let strict = SchemaJson {
            node: schema,
            flavor: SchemaFlavor::Strict,
        };
        match model.dialect {
            Dialect::OpenAi(OpenAiProfile::OpenAi | OpenAiProfile::Azure | OpenAiProfile::Vllm) => {
                Ok(PreparedFormat {
                    raw: to_raw_value(&OpenAiJsonSchema {
                        typ: "json_schema",
                        json_schema: OpenAiJsonSchemaInner {
                            name,
                            strict: true,
                            schema: strict,
                        },
                    })?,
                    instructions: None,
                })
            }
            Dialect::OpenAi(OpenAiProfile::LlamaCpp) | Dialect::Anthropic => Ok(PreparedFormat {
                raw: to_raw_value(&TypedSchema {
                    typ: "json_schema",
                    schema: strict,
                })?,
                instructions: None,
            }),
            Dialect::OpenAi(OpenAiProfile::Generic) => Ok(PreparedFormat {
                raw: to_raw_value(&JsonObject { typ: "json_object" })?,
                instructions: Some(
                    format!(
                        "Respond with a single JSON object that conforms to this JSON schema:\n{}",
                        serde_json::to_string(&strict)?
                    )
                    .into_boxed_str(),
                ),
            }),
            Dialect::Gemini => Ok(PreparedFormat {
                raw: to_raw_value(&SchemaJson {
                    node: schema,
                    flavor: SchemaFlavor::Relaxed,
                })?,
                instructions: None,
            }),
            Dialect::Ollama { .. } => Ok(PreparedFormat {
                raw: to_raw_value(&strict)?,
                instructions: None,
            }),
        }
    }
}
