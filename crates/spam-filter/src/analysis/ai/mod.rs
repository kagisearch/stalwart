/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

pub mod context;
pub mod facts;
pub mod gate;
pub mod verdict;

use crate::{AiGate, SpamFilterContext, analysis::score::ScoreAccumulator};
use common::{
    Server,
    config::mailstore::spamfilter::SpamFilterAction,
    enterprise::{
        AI_TAG_ERROR, SpamAiConfig, SpamAiMode,
        ai::{AiCallOptions, AiError, AiVerdict},
    },
};
use compact_str::CompactString;
use facts::MessageFacts;
use std::{
    future::Future,
    time::{Duration, Instant},
};
use trc::AiEvent;
use utils::glob::GlobMap;
use verdict::{Outcome, TierVerdict};

pub trait SpamFilterAnalyzeAi: Sync + Send {
    fn spam_filter_analyze_ai(
        &self,
        ctx: &mut SpamFilterContext<'_>,
        acc: &mut ScoreAccumulator,
    ) -> impl Future<Output = ()> + Send;
}

const TRUSTED_TAGS: [&str; 2] = ["TRUSTED_DOMAIN", "TRUSTED_REPLY"];
const UNCERTAIN_PROBABILITY_MIN: f32 = 0.15;
const UNCERTAIN_PROBABILITY_MAX: f32 = 0.85;

impl SpamFilterAnalyzeAi for Server {
    async fn spam_filter_analyze_ai(
        &self,
        ctx: &mut SpamFilterContext<'_>,
        acc: &mut ScoreAccumulator,
    ) {
        let Some(config) = self
            .core
            .enterprise
            .as_ref()
            .and_then(|enterprise| enterprise.spam_ai.as_deref())
        else {
            return;
        };

        match gate::evaluate(self, ctx, config, acc).await {
            AiGate::Run => Box::pin(classify(self, ctx, config, acc)).await,
            gate => skip(ctx, gate),
        }
    }
}

fn skip(ctx: &mut SpamFilterContext<'_>, gate: AiGate) {
    ctx.result.ai.gate = Some(gate);
    trc::event!(
        Ai(AiEvent::SpamSkipped),
        Reason = gate.as_str(),
        SpanId = ctx.input.span_id,
    );
}

async fn classify(
    server: &Server,
    ctx: &mut SpamFilterContext<'_>,
    config: &SpamAiConfig,
    acc: &mut ScoreAccumulator,
) {
    let started = Instant::now();
    let web_context = context::web_context(config.web_search);
    let facts = match MessageFacts::build(ctx, &config.input, web_context.as_deref()).serialize() {
        Ok(facts) => facts,
        Err(err) => {
            trc::event!(
                Ai(AiEvent::ApiError),
                Details = "Failed to serialize message facts",
                Reason = err.to_string(),
                SpanId = ctx.input.span_id,
            );
            return;
        }
    };

    let options = AiCallOptions::new(started + config.deadline)
        .with_breaker(config.breaker)
        .with_span_id(ctx.input.span_id);
    let mut previous: Vec<TierVerdict> = Vec::new();
    let mut current: Option<TierVerdict> = None;
    let mut failure: Option<(usize, &'static str)> = None;
    let last_tier = config.tiers.len().saturating_sub(1);
    for (tier_idx, tier) in config.tiers.iter().enumerate() {
        let model = tier.classifier.model();
        if !model.is_available(Instant::now()) {
            continue;
        }
        match tier.classifier.classify(&facts, &options).await {
            Ok(verdict) => {
                let escalate = tier_idx < last_tier && config.should_escalate(tier, &verdict);
                if let Some(earlier) = current.replace(TierVerdict {
                    tier: tier_idx,
                    verdict,
                }) {
                    previous.push(earlier);
                }
                if !escalate {
                    break;
                }
            }
            Err(AiError::CircuitOpen) => {}
            Err(err) => {
                failure = Some((tier_idx, err.description()));
                trc::error!(
                    err.into_trc(model)
                        .ctx(trc::Key::Tier, tier_idx + 1)
                        .span_id(ctx.input.span_id)
                );
            }
        }
    }

    let outcome = match (&current, failure) {
        (Some(result), _) => Outcome::Verdict(result),
        (None, Some((tier, error))) => Outcome::Error { tier, error },
        (None, None) => {
            skip(ctx, AiGate::Unavailable);
            return;
        }
    };
    ctx.result.ai.gate = Some(AiGate::Run);

    let shadow = config.mode == SpamAiMode::Shadow;
    let scores = &server.core.spam.lists.scores;
    let mut tags = Vec::new();
    match outcome {
        Outcome::Verdict(result) => {
            config.verdict_tags(&result.verdict, &mut tags);
            emit_verdict(
                config,
                result,
                &tags,
                shadow,
                started.elapsed(),
                ctx.input.span_id,
            );
            if !shadow {
                ctx.result.ai.train_spam = learn(config, scores, ctx, acc, &result.verdict, &tags);
            }
        }
        Outcome::Error { .. } => {
            tags.push(CompactString::const_new(AI_TAG_ERROR));
        }
    }

    if config.add_header {
        ctx.result.ai.header = Some(verdict::header(config, outcome, &previous, shadow));
    }

    if !shadow {
        for tag in tags {
            acc.add(&tag, scores);
            ctx.result.tags.insert(tag);
        }
    }

    ctx.result.ai.facts = Some(facts.into_inner());
}

fn emit_verdict(
    config: &SpamAiConfig,
    result: &TierVerdict,
    tags: &[CompactString],
    shadow: bool,
    elapsed: Duration,
    span_id: u64,
) {
    let verdict = &result.verdict;
    trc::event!(
        Ai(AiEvent::SpamVerdict),
        Category = CompactString::from(config.category_name(verdict.category)),
        Probability = verdict.probability,
        Confidence = verdict.confidence,
        Tier = result.tier + 1,
        Model = CompactString::from(verdict.model.as_ref()),
        Details = tags.to_vec(),
        Type = if shadow { "shadow" } else { "automatic" },
        Reason = verdict.reason.clone(),
        Elapsed = elapsed,
        SpanId = span_id,
    );
}

fn learn(
    config: &SpamAiConfig,
    scores: &GlobMap<SpamFilterAction<f32>>,
    ctx: &SpamFilterContext<'_>,
    acc: &ScoreAccumulator,
    verdict: &AiVerdict,
    tags: &[CompactString],
) -> Option<bool> {
    let learn = config.learn.as_ref()?;
    if config.is_uncertain(verdict)
        || verdict.probability < learn.min_probability
        || ctx.input.authenticated_as.is_some()
        || TRUSTED_TAGS.iter().any(|tag| ctx.result.has_tag(tag))
        || !acc.probability().is_some_and(|probability| {
            (UNCERTAIN_PROBABILITY_MIN..=UNCERTAIN_PROBABILITY_MAX).contains(&probability)
        })
    {
        return None;
    }

    let score = tags
        .first()
        .and_then(|tag| scores.get(tag).and_then(SpamFilterAction::as_score))
        .copied()?;
    let is_spam = if score > 0.0 {
        true
    } else if score < 0.0 {
        false
    } else {
        return None;
    };

    (store::rand::random::<f32>() < learn.sample_rate).then_some(is_spam)
}
