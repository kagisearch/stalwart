/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use super::facts::MessageFacts;
use crate::{
    AiGate, SpamFilterContext,
    analysis::score::ScoreAccumulator,
    modules::expression::{NO_PROBABILITY, ScoreVariables, SpamFilterResolver, StringResolver},
};
use common::{Server, config::mailstore::spamfilter::Location, enterprise::SpamAiConfig};
use std::time::Instant;

pub async fn evaluate(
    server: &Server,
    ctx: &mut SpamFilterContext<'_>,
    config: &SpamAiConfig,
    acc: &ScoreAccumulator,
) -> AiGate {
    if ctx.input.authenticated_as.is_some() {
        return AiGate::Authenticated;
    }
    if acc.decision().is_some() {
        return AiGate::Decided;
    }

    if !config.condition.is_empty() {
        let mut arena = std::mem::take(ctx.arena.get_mut());
        let matched = server
            .eval_if::<bool, _>(
                &config.condition,
                &SpamFilterResolver::new(
                    &ctx.input,
                    &ctx.output,
                    &ctx.result.tags,
                    &StringResolver(""),
                    Location::BodyText,
                )
                .with_scores(ScoreVariables {
                    score: acc.score(),
                    probability: acc.probability().unwrap_or(NO_PROBABILITY),
                    threshold: server.core.spam.scores.spam_threshold,
                }),
                &mut arena,
                ctx.input.span_id,
            )
            .await
            .unwrap_or(false);
        *ctx.arena.get_mut() = arena;
        if !matched {
            return AiGate::Condition;
        }
    }

    let now = Instant::now();
    if !config
        .tiers
        .iter()
        .any(|tier| tier.classifier.model().is_available(now))
    {
        AiGate::Unavailable
    } else if !MessageFacts::has_content(ctx) {
        AiGate::NoContent
    } else {
        AiGate::Run
    }
}
