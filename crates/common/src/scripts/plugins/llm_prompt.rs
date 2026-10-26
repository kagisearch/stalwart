/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use sieve::{FunctionMap, runtime::Variable};

use super::PluginContext;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use crate::enterprise::ai::{AiCallOptions, AiRequest, OutputSpec};
#[cfg(feature = "enterprise")]
use compact_str::CompactString;
#[cfg(feature = "enterprise")]
use sieve::compiler::Number;
#[cfg(feature = "enterprise")]
use std::time::Instant;
#[cfg(feature = "enterprise")]
use trc::{AiEvent, SecurityEvent};
// SPDX-SnippetEnd

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("llm_prompt", plugin_id, 3);
}

#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
pub async fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable<'static>> {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL

    #[cfg(feature = "enterprise")]
    if let (Variable::String(name), Variable::String(prompt)) =
        (&ctx.arguments[0], &ctx.arguments[1])
    {
        #[cfg(stalwart_tests)]
        if name.as_ref() == "echo-test" {
            return Ok(prompt.to_string().into());
        }
        let temperature = ctx.arguments[2].to_number_checked().map(|n| match n {
            Number::Integer(n) => (n as f64).clamp(0.0, 1.0) as f32,
            Number::Float(n) => n.clamp(0.0, 1.0) as f32,
        });

        if let Some(model) = ctx.server.core.enterprise.as_ref().and_then(|e| {
            if ctx.access_token.is_none_or(|token| {
                use registry::schema::enums::Permission;

                if token.has_permission(Permission::InteractAi) {
                    true
                } else {
                    use registry::types::EnumImpl;

                    trc::event!(
                        Security(SecurityEvent::Unauthorized),
                        AccountId = token.account_id(),
                        Details = Permission::InteractAi.as_str(),
                        SpanId = ctx.session_id,
                    );
                    false
                }
            }) {
                e.ai_model(name.as_ref())
            } else {
                None
            }
        }) {
            let time = Instant::now();
            match model
                .send(
                    &AiRequest {
                        system: None,
                        user: &[prompt.as_ref()],
                        output: OutputSpec::Text,
                        temperature,
                        max_output_tokens: None,
                        logprobs: false,
                    },
                    &AiCallOptions::new(time + model.timeout).with_span_id(ctx.session_id),
                )
                .await
            {
                Ok(response) => {
                    trc::event!(
                        Ai(AiEvent::LlmResponse),
                        Name = model.name.clone(),
                        Value = CompactString::from(prompt.as_ref()),
                        Contents = response.text.clone(),
                        Elapsed = time.elapsed(),
                        SpanId = ctx.session_id,
                    );

                    return Ok(response.text.into());
                }
                Err(err) => {
                    trc::error!(
                        err.into_trc(model)
                            .ctx(trc::Key::Elapsed, time.elapsed())
                            .span_id(ctx.session_id)
                    );
                }
            }
        }
    }

    // SPDX-SnippetEnd

    Ok(false.into())
}
