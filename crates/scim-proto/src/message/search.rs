/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::{borrow::Cow, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};

use crate::{
    MESSAGE_SEARCH_REQUEST, attributes::AttributeSelection, filter::Filter, json::scim_object,
    message::error::Error,
};

scim_object!(pub SearchRequest<'x>, Some(MESSAGE_SEARCH_REQUEST), {
    "attributes" => strs attributes: Option<Vec<Cow<'x, str>>>,
    "excludedAttributes" => strs excluded_attributes: Option<Vec<Cow<'x, str>>>,
    "filter" => str filter: Option<Cow<'x, str>>,
    "sortBy" => str sort_by: Option<Cow<'x, str>>,
    "sortOrder" => any sort_order: Option<SortOrder>,
    "startIndex" => any start_index: Option<i64>,
    "count" => any count: Option<i64>,
    "cursor" => str cursor: Option<Cow<'x, str>>,
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    #[default]
    Ascending,
    Descending,
}

impl SortOrder {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map_ignore_case!(value.as_bytes(), SortOrder,
            "ascending" => SortOrder::Ascending,
            "descending" => SortOrder::Descending,
        )
        .copied()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SortOrder::Ascending => "ascending",
            SortOrder::Descending => "descending",
        }
    }

    pub fn is_descending(&self) -> bool {
        *self == SortOrder::Descending
    }
}

impl<'x> SearchRequest<'x> {
    pub fn parse(body: &'x [u8]) -> Result<Self, Error> {
        serde_json::from_slice(body).map_err(|err| Error::invalid_syntax(err.to_string()))
    }

    pub fn from_query(query: &'x str) -> Result<Self, Error> {
        let mut request = SearchRequest::default();

        for parameter in query.strip_prefix('?').unwrap_or(query).split('&') {
            if parameter.is_empty() {
                continue;
            }

            let (name, value) = match parameter.split_once('=') {
                Some((name, value)) => (name, decode(value)),
                None => (parameter, Cow::Borrowed("")),
            };

            match hashify::fnc_map_ignore_case!(name.as_bytes(),
                "attributes" => Some(Parameter::Attributes),
                "excludedAttributes" => Some(Parameter::ExcludedAttributes),
                "filter" => Some(Parameter::Filter),
                "sortBy" => Some(Parameter::SortBy),
                "sortOrder" => Some(Parameter::SortOrder),
                "startIndex" => Some(Parameter::StartIndex),
                "count" => Some(Parameter::Count),
                "cursor" => Some(Parameter::Cursor),
                _ => None,
            ) {
                Some(Parameter::Attributes) => {
                    request.attributes = Some(split_list(value));
                }
                Some(Parameter::ExcludedAttributes) => {
                    request.excluded_attributes = Some(split_list(value));
                }
                Some(Parameter::Filter) => {
                    request.filter = Some(value);
                }
                Some(Parameter::SortBy) => {
                    request.sort_by = Some(value);
                }
                Some(Parameter::SortOrder) => {
                    request.sort_order = Some(SortOrder::parse(&value).ok_or_else(|| {
                        Error::invalid_value(format!("Invalid 'sortOrder' value '{value}'"))
                    })?);
                }
                Some(Parameter::StartIndex) => {
                    request.start_index = Some(parse_number(&value, "startIndex")?);
                }
                Some(Parameter::Count) => {
                    request.count = Some(parse_number(&value, "count").map_err(|_| {
                        Error::invalid_count(format!("Invalid 'count' value '{value}'"))
                    })?);
                }
                Some(Parameter::Cursor) => {
                    request.cursor = Some(value);
                }
                None => {}
            }
        }

        Ok(request)
    }

    pub fn parse_filter(&self) -> Result<Option<Filter<'_>>, Error> {
        match self.filter.as_deref() {
            Some(filter) if !filter.is_empty() => Filter::parse(filter).map(Some),
            _ => Ok(None),
        }
    }

    pub fn attribute_selection(&self) -> Result<AttributeSelection<'_>, Error> {
        AttributeSelection::from_lists(
            self.attributes.as_deref(),
            self.excluded_attributes.as_deref(),
        )
    }

    pub fn effective_start_index(&self) -> usize {
        self.start_index
            .map_or(1, |start_index| start_index.max(1) as usize)
    }

    pub fn effective_count(&self, default: usize, max: usize) -> usize {
        self.count
            .map_or(default, |count| count.max(0) as usize)
            .min(max)
    }

    pub fn is_cursor_paginated(&self) -> bool {
        self.cursor.is_some()
    }
}

fn parse_number(value: &str, name: &str) -> Result<i64, Error> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| Error::invalid_value(format!("Invalid '{name}' value '{value}'")))
}

enum Parameter {
    Attributes,
    ExcludedAttributes,
    Filter,
    SortBy,
    SortOrder,
    StartIndex,
    Count,
    Cursor,
}

fn split_list(value: Cow<'_, str>) -> Vec<Cow<'_, str>> {
    match value {
        Cow::Borrowed(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(Cow::Borrowed)
            .collect(),
        Cow::Owned(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| Cow::Owned(value.to_string()))
            .collect(),
    }
}

fn decode(value: &str) -> Cow<'_, str> {
    let bytes = value.as_bytes();

    if !bytes.iter().any(|ch| matches!(ch, b'%' | b'+')) {
        return Cow::Borrowed(value);
    }

    let mut result = Vec::with_capacity(bytes.len());
    let mut pos = 0;

    while pos < bytes.len() {
        match bytes[pos] {
            b'%' => {
                match value
                    .get(pos + 1..pos + 3)
                    .filter(|digits| digits.bytes().all(|ch| ch.is_ascii_hexdigit()))
                    .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                {
                    Some(byte) => {
                        result.push(byte);
                        pos += 3;
                    }
                    None => {
                        result.push(b'%');
                        pos += 1;
                    }
                }
            }
            b'+' => {
                result.push(b' ');
                pos += 1;
            }
            byte => {
                result.push(byte);
                pos += 1;
            }
        }
    }

    Cow::Owned(
        String::from_utf8(result)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned()),
    )
}

impl Serialize for SortOrder {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SortOrder {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SortOrderVisitor;

        impl<'de> Visitor<'de> for SortOrderVisitor {
            type Value = SortOrder;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("'ascending' or 'descending'")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                SortOrder::parse(v)
                    .ok_or_else(|| E::custom(format!("Invalid 'sortOrder' value '{v}'")))
            }
        }

        deserializer.deserialize_str(SortOrderVisitor)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/scim-proto/src/message/search/tests.rs"]
mod tests;
