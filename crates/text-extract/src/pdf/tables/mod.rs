/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod cid;
mod cid_data;
mod cmap_data;
mod cmaps;
mod encoding;
mod encoding_data;
mod font_data;
mod fonts;
mod glyph_data;
mod glyphs;
mod names;
mod normalize;
mod presentation_data;

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/text-extract/src/pdf/tables/tests.rs"]
mod tests;
#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/text-extract/src/pdf/tables/tests_cjk.rs"]
mod tests_cjk;
#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/text-extract/src/pdf/tables/tests_normalize.rs"]
mod tests_normalize;

pub(crate) use self::cid::CidCollection;
pub(crate) use self::cmaps::{CmapDecoder, CodeRange, PredefinedCmap};
pub(crate) use self::encoding::{BaseEncoding, pdfdoc_char};
pub(crate) use self::fonts::StandardFont;
pub(crate) use self::glyphs::{
    CodeRadix, GlyphCode, glyph_name_code, glyph_unicode, zapf_dingbats_unicode,
};
pub(crate) use self::normalize::{combining_accent, presentation_form};
