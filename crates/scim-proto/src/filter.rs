/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    fmt::{self, Write},
};

use crate::message::error::Error;

pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum Filter<'x> {
    Compare {
        path: AttrPath<'x>,
        op: CompareOp,
        value: CompValue<'x>,
    },
    Present(AttrPath<'x>),
    ValuePath {
        path: AttrPath<'x>,
        filter: Box<Filter<'x>>,
    },
    And(Vec<Filter<'x>>),
    Or(Vec<Filter<'x>>),
    Not(Box<Filter<'x>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrPath<'x> {
    pub schema: Option<Cow<'x, str>>,
    pub attr: Cow<'x, str>,
    pub sub_attr: Option<Cow<'x, str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompareOp {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompValue<'x> {
    String(Cow<'x, str>),
    Bool(bool),
    Integer(i64),
    Decimal(f64),
    Null,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EqualityTerm<'x> {
    pub path: AttrPath<'x>,
    pub value: CompValue<'x>,
}

impl<'x> Filter<'x> {
    pub fn parse(input: &'x str) -> Result<Self, Error> {
        let mut parser = Parser::new(input);
        let filter = parser.parse_filter(0, false)?;
        parser.skip_ws();

        if parser.is_eof() {
            Ok(filter)
        } else {
            Err(parser.unexpected("end of filter"))
        }
    }

    pub fn into_equality_terms(self) -> Result<Vec<EqualityTerm<'x>>, Error> {
        let mut terms = Vec::with_capacity(2);
        self.collect_equality_terms(&mut terms)?;
        Ok(terms)
    }

    fn collect_equality_terms(self, terms: &mut Vec<EqualityTerm<'x>>) -> Result<(), Error> {
        match self {
            Filter::Compare {
                path,
                op: CompareOp::Eq,
                value,
            } => {
                terms.push(EqualityTerm { path, value });
                Ok(())
            }
            Filter::And(items) => {
                for item in items {
                    item.collect_equality_terms(terms)?;
                }
                Ok(())
            }
            Filter::Compare { op, .. } => Err(Error::invalid_filter(format!(
                "Unsupported operator '{}', only 'eq' and 'and' are supported",
                op.as_str()
            ))),
            Filter::Present(path) => Err(Error::invalid_filter(format!(
                "Unsupported operator 'pr' on attribute '{path}', only 'eq' and 'and' are supported"
            ))),
            Filter::Or(_) => Err(Error::invalid_filter(
                "Unsupported logical operator 'or', only 'eq' and 'and' are supported",
            )),
            Filter::Not(_) => Err(Error::invalid_filter(
                "Unsupported logical operator 'not', only 'eq' and 'and' are supported",
            )),
            Filter::ValuePath { path, .. } => Err(Error::invalid_filter(format!(
                "Value filters such as '{path}[...]' are not supported in query filters"
            ))),
        }
    }

    pub fn into_owned(self) -> Filter<'static> {
        match self {
            Filter::Compare { path, op, value } => Filter::Compare {
                path: path.into_owned(),
                op,
                value: value.into_owned(),
            },
            Filter::Present(path) => Filter::Present(path.into_owned()),
            Filter::ValuePath { path, filter } => Filter::ValuePath {
                path: path.into_owned(),
                filter: Box::new(filter.into_owned()),
            },
            Filter::And(items) => Filter::And(items.into_iter().map(Filter::into_owned).collect()),
            Filter::Or(items) => Filter::Or(items.into_iter().map(Filter::into_owned).collect()),
            Filter::Not(filter) => Filter::Not(Box::new(filter.into_owned())),
        }
    }
}

impl<'x> AttrPath<'x> {
    pub fn new(attr: impl Into<Cow<'x, str>>) -> Self {
        AttrPath {
            schema: None,
            attr: attr.into(),
            sub_attr: None,
        }
    }

    pub fn with_sub_attr(mut self, sub_attr: impl Into<Cow<'x, str>>) -> Self {
        self.sub_attr = Some(sub_attr.into());
        self
    }

    pub fn with_schema(mut self, schema: impl Into<Cow<'x, str>>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    pub fn parse(input: &'x str) -> Result<Self, Error> {
        let mut parser = Parser::new(input);
        let path = parser.parse_attr_path()?;
        parser.skip_ws();

        if parser.is_eof() {
            Ok(path)
        } else {
            Err(parser.unexpected("end of attribute path"))
        }
    }

    pub fn matches_attr(&self, attr: &str) -> bool {
        self.attr.eq_ignore_ascii_case(attr)
    }

    pub fn matches(&self, attr: &str, sub_attr: Option<&str>) -> bool {
        self.attr.eq_ignore_ascii_case(attr)
            && match (self.sub_attr.as_deref(), sub_attr) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                (None, None) => true,
                _ => false,
            }
    }

    pub fn has_schema(&self, schema: &str) -> bool {
        self.schema
            .as_deref()
            .is_none_or(|value| value.eq_ignore_ascii_case(schema))
    }

    pub fn as_ref(&self) -> AttrPath<'_> {
        AttrPath {
            schema: self.schema.as_deref().map(Cow::Borrowed),
            attr: Cow::Borrowed(self.attr.as_ref()),
            sub_attr: self.sub_attr.as_deref().map(Cow::Borrowed),
        }
    }

    pub fn into_owned(self) -> AttrPath<'static> {
        AttrPath {
            schema: self.schema.map(|value| Cow::Owned(value.into_owned())),
            attr: Cow::Owned(self.attr.into_owned()),
            sub_attr: self.sub_attr.map(|value| Cow::Owned(value.into_owned())),
        }
    }
}

impl CompareOp {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map_ignore_case!(value.as_bytes(), CompareOp,
            "eq" => CompareOp::Eq,
            "ne" => CompareOp::Ne,
            "co" => CompareOp::Co,
            "sw" => CompareOp::Sw,
            "ew" => CompareOp::Ew,
            "gt" => CompareOp::Gt,
            "ge" => CompareOp::Ge,
            "lt" => CompareOp::Lt,
            "le" => CompareOp::Le,
        )
        .copied()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CompareOp::Eq => "eq",
            CompareOp::Ne => "ne",
            CompareOp::Co => "co",
            CompareOp::Sw => "sw",
            CompareOp::Ew => "ew",
            CompareOp::Gt => "gt",
            CompareOp::Ge => "ge",
            CompareOp::Lt => "lt",
            CompareOp::Le => "le",
        }
    }

    pub fn is_ordering(&self) -> bool {
        matches!(
            self,
            CompareOp::Gt | CompareOp::Ge | CompareOp::Lt | CompareOp::Le
        )
    }
}

impl<'x> CompValue<'x> {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            CompValue::String(value) => Some(value.as_ref()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            CompValue::Bool(value) => Some(*value),
            CompValue::String(value) if value.eq_ignore_ascii_case("true") => Some(true),
            CompValue::String(value) if value.eq_ignore_ascii_case("false") => Some(false),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<i64> {
        match self {
            CompValue::Integer(value) => Some(*value),
            _ => None,
        }
    }

    pub fn into_owned(self) -> CompValue<'static> {
        match self {
            CompValue::String(value) => CompValue::String(Cow::Owned(value.into_owned())),
            CompValue::Bool(value) => CompValue::Bool(value),
            CompValue::Integer(value) => CompValue::Integer(value),
            CompValue::Decimal(value) => CompValue::Decimal(value),
            CompValue::Null => CompValue::Null,
        }
    }
}

pub(crate) struct Parser<'x> {
    input: &'x str,
    pos: usize,
}

impl<'x> Parser<'x> {
    pub(crate) fn new(input: &'x str) -> Self {
        Parser { input, pos: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    pub(crate) fn skip_ws(&mut self) {
        let bytes = self.input.as_bytes();

        while bytes.get(self.pos).is_some_and(u8::is_ascii_whitespace) {
            self.pos += 1;
        }
    }

    pub(crate) fn unexpected(&self, expected: &str) -> Error {
        Error::invalid_filter(format!("Expected {expected} at position {}", self.pos))
    }

    pub(crate) fn bump(&mut self) {
        self.pos += 1;
    }

    pub(crate) fn parse_name(&mut self) -> Result<&'x str, Error> {
        let bytes = self.input.as_bytes();
        let start = self.pos;

        while bytes
            .get(self.pos)
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_' | b'$'))
        {
            self.pos += 1;
        }

        let name = &self.input[start..self.pos];

        if is_attr_name(name) {
            Ok(name)
        } else {
            Err(Error::invalid_filter(format!(
                "Invalid attribute name '{name}' at position {start}"
            )))
        }
    }

    pub(crate) fn expect(&mut self, ch: u8) -> Result<(), Error> {
        if self.peek() == Some(ch) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.unexpected(&format!("'{}'", ch as char)))
        }
    }

    fn try_keyword(&mut self, keyword: &str) -> bool {
        let bytes = self.input.as_bytes();
        let end = self.pos + keyword.len();

        if end <= bytes.len()
            && bytes[self.pos..end].eq_ignore_ascii_case(keyword.as_bytes())
            && bytes
                .get(end)
                .is_none_or(|ch| ch.is_ascii_whitespace() || *ch == b'(')
        {
            self.pos = end;
            true
        } else {
            false
        }
    }

    pub(crate) fn parse_filter(
        &mut self,
        depth: usize,
        in_value_path: bool,
    ) -> Result<Filter<'x>, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::invalid_filter("Filter is nested too deeply"));
        }

        let mut terms = vec![self.parse_and(depth, in_value_path)?];

        loop {
            let checkpoint = self.pos;
            self.skip_ws();

            if self.try_keyword("or") {
                terms.push(self.parse_and(depth, in_value_path)?);
            } else {
                self.pos = checkpoint;
                break;
            }
        }

        Ok(if terms.len() == 1 {
            terms.pop().unwrap()
        } else {
            Filter::Or(terms)
        })
    }

    fn parse_and(&mut self, depth: usize, in_value_path: bool) -> Result<Filter<'x>, Error> {
        let mut terms = vec![self.parse_primary(depth, in_value_path)?];

        loop {
            let checkpoint = self.pos;
            self.skip_ws();

            if self.try_keyword("and") {
                terms.push(self.parse_primary(depth, in_value_path)?);
            } else {
                self.pos = checkpoint;
                break;
            }
        }

        Ok(if terms.len() == 1 {
            terms.pop().unwrap()
        } else {
            Filter::And(terms)
        })
    }

    fn parse_primary(&mut self, depth: usize, in_value_path: bool) -> Result<Filter<'x>, Error> {
        self.skip_ws();

        if self.try_keyword("not") {
            self.skip_ws();
            self.expect(b'(')?;
            let filter = self.parse_filter(depth + 1, in_value_path)?;
            self.skip_ws();
            self.expect(b')')?;

            return Ok(Filter::Not(Box::new(filter)));
        } else if self.peek() == Some(b'(') {
            self.pos += 1;
            let filter = self.parse_filter(depth + 1, in_value_path)?;
            self.skip_ws();
            self.expect(b')')?;

            return Ok(filter);
        }

        let path = self.parse_attr_path()?;

        if self.peek() == Some(b'[') {
            if in_value_path {
                return Err(Error::invalid_filter(format!(
                    "Nested value filters are not allowed at position {}",
                    self.pos
                )));
            }

            self.pos += 1;
            let filter = self.parse_filter(depth + 1, true)?;
            self.skip_ws();
            self.expect(b']')?;

            return Ok(Filter::ValuePath {
                path,
                filter: Box::new(filter),
            });
        }

        self.skip_ws();
        let operator = self.parse_word();

        if operator.is_empty() {
            return Err(self.unexpected("an operator"));
        } else if operator.eq_ignore_ascii_case("pr") {
            return Ok(Filter::Present(path));
        }

        let op = CompareOp::parse(operator).ok_or_else(|| {
            Error::invalid_filter(format!(
                "Unknown operator '{operator}' at position {}",
                self.pos - operator.len()
            ))
        })?;
        self.skip_ws();
        let value = self.parse_comp_value()?;

        Ok(Filter::Compare { path, op, value })
    }

    fn parse_word(&mut self) -> &'x str {
        let bytes = self.input.as_bytes();
        let start = self.pos;

        while bytes.get(self.pos).is_some_and(u8::is_ascii_alphabetic) {
            self.pos += 1;
        }

        &self.input[start..self.pos]
    }

    pub(crate) fn parse_attr_path(&mut self) -> Result<AttrPath<'x>, Error> {
        self.skip_ws();

        let bytes = self.input.as_bytes();
        let start = self.pos;

        while bytes.get(self.pos).copied().is_some_and(is_path_char) {
            self.pos += 1;
        }

        let token = &self.input[start..self.pos];

        if token.is_empty() {
            return Err(self.unexpected("an attribute name"));
        }

        let (schema, name) = match token.rfind(':') {
            Some(idx) if idx > 0 => (Some(&token[..idx]), &token[idx + 1..]),
            Some(_) => {
                return Err(Error::invalid_filter(format!(
                    "Invalid attribute name '{token}' at position {start}"
                )));
            }
            None => (None, token),
        };

        let (attr, sub_attr) = match name.split_once('.') {
            Some((attr, sub_attr)) => (attr, Some(sub_attr)),
            None => (name, None),
        };

        for part in [Some(attr), sub_attr].into_iter().flatten() {
            if !is_attr_name(part) {
                return Err(Error::invalid_filter(format!(
                    "Invalid attribute name '{token}' at position {start}"
                )));
            }
        }

        Ok(AttrPath {
            schema: schema.map(Cow::Borrowed),
            attr: Cow::Borrowed(attr),
            sub_attr: sub_attr.map(Cow::Borrowed),
        })
    }

    fn parse_comp_value(&mut self) -> Result<CompValue<'x>, Error> {
        match self.peek() {
            Some(b'"') => self.parse_string().map(CompValue::String),
            Some(ch) if ch == b'-' || ch.is_ascii_digit() => self.parse_number(),
            Some(_) => {
                let start = self.pos;
                let word = self.parse_word();

                hashify::fnc_map_ignore_case!(word.as_bytes(),
                    "true" => Some(CompValue::Bool(true)),
                    "false" => Some(CompValue::Bool(false)),
                    "null" => Some(CompValue::Null),
                    _ => None,
                )
                .ok_or_else(|| {
                    Error::invalid_filter(format!(
                        "Invalid comparison value '{word}' at position {start}"
                    ))
                })
            }
            None => Err(self.unexpected("a comparison value")),
        }
    }

    fn parse_number(&mut self) -> Result<CompValue<'x>, Error> {
        let bytes = self.input.as_bytes();
        let start = self.pos;

        while bytes
            .get(self.pos)
            .is_some_and(|ch| ch.is_ascii_digit() || matches!(ch, b'-' | b'+' | b'.' | b'e' | b'E'))
        {
            self.pos += 1;
        }

        let token = &self.input[start..self.pos];
        let invalid =
            || Error::invalid_filter(format!("Invalid number '{token}' at position {start}"));

        if !is_json_number(token) {
            Err(invalid())
        } else if let Ok(value) = token.parse::<i64>() {
            Ok(CompValue::Integer(value))
        } else {
            token
                .parse::<f64>()
                .ok()
                .filter(|value| value.is_finite())
                .map(CompValue::Decimal)
                .ok_or_else(invalid)
        }
    }

    fn parse_string(&mut self) -> Result<Cow<'x, str>, Error> {
        let bytes = self.input.as_bytes();
        self.pos += 1;

        let mut chunk_start = self.pos;
        let mut result: Option<String> = None;

        while self.pos < bytes.len() {
            match bytes[self.pos] {
                b'"' => {
                    let chunk = &self.input[chunk_start..self.pos];
                    self.pos += 1;

                    return Ok(match result {
                        Some(mut result) => {
                            result.push_str(chunk);
                            Cow::Owned(result)
                        }
                        None => Cow::Borrowed(chunk),
                    });
                }
                b'\\' => {
                    let result = result.get_or_insert_with(String::new);
                    result.push_str(&self.input[chunk_start..self.pos]);
                    self.pos += 1;

                    let escape = *bytes
                        .get(self.pos)
                        .ok_or_else(|| self.unexpected("an escape sequence"))?;
                    self.pos += 1;

                    match escape {
                        b'"' => result.push('"'),
                        b'\\' => result.push('\\'),
                        b'/' => result.push('/'),
                        b'b' => result.push('\u{0008}'),
                        b'f' => result.push('\u{000c}'),
                        b'n' => result.push('\n'),
                        b'r' => result.push('\r'),
                        b't' => result.push('\t'),
                        b'u' => {
                            let ch = self.parse_unicode_escape()?;
                            result.push(ch);
                        }
                        _ => {
                            return Err(Error::invalid_filter(format!(
                                "Invalid escape sequence '\\{}' at position {}",
                                escape as char,
                                self.pos - 2
                            )));
                        }
                    }

                    chunk_start = self.pos;
                }
                _ => {
                    self.pos += 1;
                }
            }
        }

        Err(self.unexpected("a closing quote"))
    }

    fn parse_unicode_escape(&mut self) -> Result<char, Error> {
        let code = self.parse_hex4()?;

        if (0xd800..0xdc00).contains(&code) {
            if self.input.as_bytes()[self.pos..].starts_with(br"\u") {
                self.pos += 2;
                let low = self.parse_hex4()?;

                if (0xdc00..0xe000).contains(&low) {
                    let code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);

                    return char::from_u32(code)
                        .ok_or_else(|| self.unexpected("a valid unicode escape"));
                }
            }

            Err(self.unexpected("a low surrogate"))
        } else {
            char::from_u32(code).ok_or_else(|| self.unexpected("a valid unicode escape"))
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, Error> {
        let end = self.pos + 4;
        let code = self
            .input
            .get(self.pos..end)
            .filter(|digits| digits.bytes().all(|ch| ch.is_ascii_hexdigit()))
            .and_then(|digits| u32::from_str_radix(digits, 16).ok())
            .ok_or_else(|| self.unexpected("four hexadecimal digits"))?;
        self.pos = end;

        Ok(code)
    }
}

fn is_json_number(token: &str) -> bool {
    let mut bytes = token.as_bytes().iter().peekable();

    if bytes.peek() == Some(&&b'-') {
        bytes.next();
    }

    let mut digits = 0;

    while bytes.peek().is_some_and(|ch| ch.is_ascii_digit()) {
        bytes.next();
        digits += 1;
    }

    if digits == 0 || (digits > 1 && token.trim_start_matches('-').starts_with('0')) {
        return false;
    }

    if bytes.peek() == Some(&&b'.') {
        bytes.next();
        digits = 0;

        while bytes.peek().is_some_and(|ch| ch.is_ascii_digit()) {
            bytes.next();
            digits += 1;
        }

        if digits == 0 {
            return false;
        }
    }

    if bytes.peek().is_some_and(|ch| matches!(ch, b'e' | b'E')) {
        bytes.next();

        if bytes.peek().is_some_and(|ch| matches!(ch, b'-' | b'+')) {
            bytes.next();
        }

        digits = 0;

        while bytes.peek().is_some_and(|ch| ch.is_ascii_digit()) {
            bytes.next();
            digits += 1;
        }

        if digits == 0 {
            return false;
        }
    }

    bytes.next().is_none()
}

fn is_path_char(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_' | b'.' | b':' | b'$')
}

fn is_attr_name(name: &str) -> bool {
    let mut chars = name.as_bytes().iter();

    chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || *ch == b'$')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_'))
}

impl fmt::Display for AttrPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(schema) = &self.schema {
            write!(f, "{schema}:")?;
        }
        f.write_str(self.attr.as_ref())?;
        if let Some(sub_attr) = &self.sub_attr {
            write!(f, ".{sub_attr}")?;
        }
        Ok(())
    }
}

impl fmt::Display for CompareOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for CompValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompValue::String(value) => write_json_string(f, value),
            CompValue::Bool(value) => write!(f, "{value}"),
            CompValue::Integer(value) => write!(f, "{value}"),
            CompValue::Decimal(value) => write!(f, "{value:?}"),
            CompValue::Null => f.write_str("null"),
        }
    }
}

impl fmt::Display for Filter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Filter::Compare { path, op, value } => write!(f, "{path} {op} {value}"),
            Filter::Present(path) => write!(f, "{path} pr"),
            Filter::ValuePath { path, filter } => write!(f, "{path}[{filter}]"),
            Filter::And(items) => write_logical(f, items, " and "),
            Filter::Or(items) => write_logical(f, items, " or "),
            Filter::Not(filter) => write!(f, "not ({filter})"),
        }
    }
}

fn write_logical(f: &mut fmt::Formatter<'_>, items: &[Filter<'_>], separator: &str) -> fmt::Result {
    for (idx, item) in items.iter().enumerate() {
        if idx > 0 {
            f.write_str(separator)?;
        }

        if matches!(item, Filter::And(_) | Filter::Or(_)) {
            write!(f, "({item})")?;
        } else {
            write!(f, "{item}")?;
        }
    }

    Ok(())
}

fn write_json_string(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    f.write_str("\"")?;

    for ch in value.chars() {
        match ch {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            '\u{0008}' => f.write_str("\\b")?,
            '\u{000c}' => f.write_str("\\f")?,
            ch if (ch as u32) < 0x20 => write!(f, "\\u{:04x}", ch as u32)?,
            ch => f.write_char(ch)?,
        }
    }

    f.write_str("\"")
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/scim-proto/src/filter/tests.rs"]
mod tests;
