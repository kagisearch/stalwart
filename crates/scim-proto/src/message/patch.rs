/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::borrow::Cow;

use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::Value;

use crate::{MESSAGE_PATCH_OP, json::scim_object, message::error::Error, path::PatchPath};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct PatchRequest<'x> {
    pub operations: Vec<PatchOperation<'x>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PatchOperation<'x> {
    pub op: PatchOp,
    pub path: PatchPath<'x>,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatchOp {
    Add,
    Remove,
    Replace,
}

scim_object!(PatchBody<'x>, Some(MESSAGE_PATCH_OP), {
    "Operations" => any operations: Option<Vec<PatchOperationBody<'x>>>,
});

scim_object!(PatchOperationBody<'x>, None::<&'static str>, {
    "op" => str op: Option<Cow<'x, str>>,
    "path" => str path: Option<Cow<'x, str>>,
    "value" => any value: Option<Value>,
});

impl PatchOp {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map_ignore_case!(value.as_bytes(), PatchOp,
            "add" => PatchOp::Add,
            "remove" => PatchOp::Remove,
            "replace" => PatchOp::Replace,
        )
        .copied()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PatchOp::Add => "add",
            PatchOp::Remove => "remove",
            PatchOp::Replace => "replace",
        }
    }
}

impl<'x> PatchRequest<'x> {
    pub fn parse(body: &'x [u8]) -> Result<Self, Error> {
        let body = serde_json::from_slice::<PatchBody<'x>>(body)
            .map_err(|err| Error::invalid_syntax(err.to_string()))?;
        let operations = body
            .operations
            .ok_or_else(|| Error::invalid_syntax("Missing 'Operations' attribute"))?;

        if operations.is_empty() {
            return Err(Error::invalid_syntax(
                "The 'Operations' attribute must contain at least one operation",
            ));
        }

        let mut result = Vec::with_capacity(operations.len());

        for operation in operations {
            let op = operation
                .op
                .as_deref()
                .ok_or_else(|| Error::invalid_syntax("Missing 'op' attribute"))
                .and_then(|op| {
                    PatchOp::parse(op).ok_or_else(|| {
                        Error::invalid_syntax(format!("Unknown patch operation '{op}'"))
                    })
                })?;

            match operation.path {
                Some(Cow::Borrowed(path)) => {
                    push(op, PatchPath::parse(path)?, operation.value, &mut result)?
                }
                Some(Cow::Owned(path)) => push(
                    op,
                    PatchPath::parse(&path)?.into_owned(),
                    operation.value,
                    &mut result,
                )?,
                None => expand(op, operation.value, &mut result)?,
            }
        }

        Ok(PatchRequest { operations: result })
    }
}

fn push<'x>(
    op: PatchOp,
    path: PatchPath<'x>,
    value: Option<Value>,
    result: &mut Vec<PatchOperation<'x>>,
) -> Result<(), Error> {
    if op != PatchOp::Remove {
        if path.targets_element() {
            return Err(Error::invalid_path(format!(
                "Path '{path}' must target a sub-attribute of the matched element"
            )));
        } else if value.as_ref().is_none_or(Value::is_null) {
            return Err(Error::invalid_syntax(format!(
                "Missing 'value' attribute for operation '{}' on path '{path}'",
                op.as_str()
            )));
        }
    }

    result.push(PatchOperation { op, path, value });

    Ok(())
}

fn expand<'x>(
    op: PatchOp,
    value: Option<Value>,
    result: &mut Vec<PatchOperation<'x>>,
) -> Result<(), Error> {
    if op == PatchOp::Remove {
        return Err(Error::no_target(
            "A 'remove' operation requires a 'path' attribute",
        ));
    }

    let Some(Value::Object(value)) = value else {
        return Err(Error::invalid_syntax(
            "An operation without a 'path' requires an object 'value'",
        ));
    };

    if value.is_empty() {
        return Err(Error::invalid_syntax(
            "An operation without a 'path' requires at least one attribute",
        ));
    }

    for (name, value) in value {
        if name.contains(':') {
            let Value::Object(value) = value else {
                return Err(Error::invalid_syntax(format!(
                    "Schema extension '{name}' requires an object value"
                )));
            };

            if value.is_empty() {
                return Err(Error::invalid_syntax(format!(
                    "Schema extension '{name}' requires at least one attribute"
                )));
            }

            for (sub_name, value) in value {
                if sub_name.contains(':') {
                    return Err(Error::invalid_syntax(format!(
                        "Invalid attribute '{sub_name}' within schema extension '{name}'"
                    )));
                }

                push(
                    op,
                    PatchPath::parse(&sub_name)?
                        .into_owned()
                        .with_schema(name.clone()),
                    Some(value),
                    result,
                )?;
            }
        } else {
            push(
                op,
                PatchPath::parse(&name)?.into_owned(),
                Some(value),
                result,
            )?;
        }
    }

    Ok(())
}

impl PatchOperation<'_> {
    pub fn value_as_str(&self) -> Option<&str> {
        self.value.as_ref().and_then(Value::as_str)
    }

    pub fn value_as_bool(&self) -> Option<bool> {
        match self.value.as_ref()? {
            Value::Bool(value) => Some(*value),
            Value::String(value) if value.eq_ignore_ascii_case("true") => Some(true),
            Value::String(value) if value.eq_ignore_ascii_case("false") => Some(false),
            _ => None,
        }
    }

    pub fn value_as_array(&self) -> Option<&[Value]> {
        self.value
            .as_ref()
            .and_then(Value::as_array)
            .map(Vec::as_slice)
    }
}

impl Serialize for PatchRequest<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schemas", &[MESSAGE_PATCH_OP])?;
        map.serialize_entry("Operations", &self.operations)?;
        map.end()
    }
}

impl Serialize for PatchOperation<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("op", self.op.as_str())?;
        map.serialize_entry("path", &Displayed(&self.path))?;
        if let Some(value) = &self.value {
            map.serialize_entry("value", value)?;
        }
        map.end()
    }
}

struct Displayed<'a, T: std::fmt::Display>(&'a T);

impl<T: std::fmt::Display> Serialize for Displayed<'_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self.0)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/scim-proto/src/message/patch/tests.rs"]
mod tests;
