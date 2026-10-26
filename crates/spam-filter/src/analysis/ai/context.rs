/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use common::enterprise::SpamAiWebSearch;
use serde_json::value::RawValue;

pub fn web_context(search: SpamAiWebSearch) -> Option<Box<RawValue>> {
    match search {
        SpamAiWebSearch::Disabled => None,
    }
}
