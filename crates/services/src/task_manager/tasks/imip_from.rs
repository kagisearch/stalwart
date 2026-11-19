/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! FORK: display name of the `From` header on outgoing iMIP messages.
//!
//! Upstream names the sender after the account's description. An account sends
//! scheduling messages from any of its addresses, so that puts the account's
//! name next to an alias the user may be keeping apart from it.
//!
//! The name is taken from the iTIP message instead: the `CN` of the
//! `ORGANIZER` when the organizer is sending, or of the sender's own
//! `ATTENDEE` line when an attendee is replying. Both are already in the
//! attachment every recipient receives, so the header reveals nothing the
//! message does not. An organizer's `CN` is the name their client wrote for
//! them; an attendee's is the name the organizer invited them under.
//!
//! Without a usable `CN` the header carries the bare address. The account's
//! description and name are never used.

use calcard::icalendar::{ICalendar, ICalendarParameterName, ICalendarProperty};
use groupware::scheduling::Email;

const MAX_NAME_CHARS: usize = 255;

/// Returns the display name the iTIP message `ical` gives the address `from`,
/// which is sending it as the organizer or as an attendee.
pub(crate) fn imip_from_name(ical: &str, from: &str, is_from_organizer: bool) -> Option<String> {
    let ical = ICalendar::parse(ical).ok()?;
    let property = if is_from_organizer {
        ICalendarProperty::Organizer
    } else {
        ICalendarProperty::Attendee
    };

    ical.components
        .iter()
        .filter(|component| component.component_type.is_scheduling_object())
        .flat_map(|component| component.entries.iter())
        .filter(|entry| entry.name == property)
        .filter(|entry| {
            entry
                .values
                .first()
                .and_then(|value| value.as_text())
                .and_then(|address| Email::new(address, &[]))
                .is_some_and(|address| address.email.eq_ignore_ascii_case(from))
        })
        .find_map(|entry| {
            entry
                .parameter(&ICalendarParameterName::Cn)
                .and_then(|name| name.as_text())
                .and_then(|name| display_name(name, from))
        })
}

/// Cleans up a `CN` for use as a display name. Returns `None`, leaving the
/// header with the bare address, when the `CN` is empty, repeats the address
/// or is a `mailto:` URI, which is an address and not a name.
fn display_name(name: &str, from: &str) -> Option<String> {
    let name = name
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_NAME_CHARS)
        .collect::<String>();
    let name = name.trim();
    let is_mailto = name
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("mailto:"));

    (!name.is_empty() && !is_mailto && !name.eq_ignore_ascii_case(from)).then(|| name.to_string())
}
