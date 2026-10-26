/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use super::{
    AI_TAG_ERROR, AI_TAG_PREFIX, AI_TAG_UNCERTAIN, AlertContent, AlertContentToken, AlertMethod,
    Enterprise, MetricAlert, SpamAiBuckets, SpamAiConfig, SpamAiInput, SpamAiLearn, SpamAiMode,
    SpamAiTier, SpamAiWebSearch,
    ai::{
        AiCategory, AiClassifier, AiModel, AiSignal, BreakerPolicy, PreparedClassifier,
        VerbalConfidence,
    },
    license::LicenseKey,
};
use crate::expr::if_block::{BootstrapExprExt, IfBlock};
use ahash::AHashSet;
use compact_str::CompactString;
use registry::schema::{
    enums,
    prelude::{ObjectType, Property},
    structs::{
        self, Alert, CalendarAlarm, CalendarScheduling, DataRetention, SecretKeyOptional,
        SecretKeyValue, SpamAi, SpamAiProperties, SystemSettings,
    },
};
use std::sync::Arc;
use store::{
    registry::{RegistryQuery, bootstrap::Bootstrap, write::RegistryWrite},
    roaring::RoaringBitmap,
};
use trc::MetricType;
use utils::template::Template;

impl Enterprise {
    pub async fn parse(bp: &mut Bootstrap) -> Option<Self> {
        let server_hostname = bp
            .setting_infallible::<SystemSettings>()
            .await
            .default_hostname;
        let mut update_license = None;
        let mut enterprise = bp.setting_infallible::<structs::Enterprise>().await;

        // WARNING: TAMPERING WITH THIS FUNCTION IS STRICTLY PROHIBITED
        // Any attempt to modify, bypass, or disable this license validation mechanism
        // constitutes a severe violation of the Stalwart Enterprise License Agreement.
        // Such actions may result in immediate termination of your license, legal action,
        // and substantial financial penalties. Stalwart Labs LLC actively monitors for
        // unauthorized modifications and will pursue all available legal remedies against
        // violators to the fullest extent of the law, including but not limited to claims
        // for copyright infringement, breach of contract, and fraud.

        let license_result = match (
            enterprise.license_key.secret().await,
            enterprise.api_key.secret().await,
        ) {
            (Ok(Some(license_key)), Ok(maybe_api_key)) => {
                match (
                    LicenseKey::new(license_key, &server_hostname),
                    maybe_api_key,
                ) {
                    (Ok(license), Some(api_key)) if license.is_near_expiration() => Ok(license
                        .try_renew(api_key.as_ref())
                        .await
                        .map(|result| {
                            update_license = Some(result.encoded_key);
                            result.key
                        })
                        .unwrap_or(license)),
                    (Ok(license), None) => Ok(license),
                    (Err(_), Some(api_key)) => LicenseKey::invalid(&server_hostname)
                        .try_renew(api_key.as_ref())
                        .await
                        .map(|result| {
                            update_license = Some(result.encoded_key);
                            result.key
                        }),
                    (maybe_license, _) => maybe_license,
                }
            }
            (Ok(None), Ok(Some(api_key))) => LicenseKey::invalid(&server_hostname)
                .try_renew(api_key.as_ref())
                .await
                .map(|result| {
                    update_license = Some(result.encoded_key);
                    result.key
                }),
            (Ok(None), Ok(None)) => {
                #[cfg(not(stalwart_tests))]
                return None;

                #[cfg(stalwart_tests)]
                Ok(LicenseKey {
                    valid_to: store::write::now() + (86400 * 365),
                    valid_from: store::write::now() - 3600,
                    domain: server_hostname.to_string(),
                    accounts: 100,
                })
            }
            (Err(err), _) => {
                bp.build_error(ObjectType::Enterprise.singleton(), err);
                return None;
            }
            (_, Err(err)) => {
                bp.build_error(ObjectType::Enterprise.singleton(), err);
                return None;
            }
        };

        // Report error
        let license = match license_result {
            Ok(license) => license,
            Err(err) => {
                bp.build_warning(ObjectType::Enterprise.singleton(), err.to_string());
                return None;
            }
        };

        // Update the license if a new one was obtained
        let logo = enterprise.logo.clone();
        if let Some(license) = update_license {
            enterprise.license_key = SecretKeyOptional::Value(SecretKeyValue { secret: license });
            if let Err(err) = bp
                .registry
                .write(RegistryWrite::insert(&enterprise.into()))
                .await
            {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to update license key")
                );
            }
        }

        match bp
            .registry
            .query::<RoaringBitmap>(RegistryQuery::new(ObjectType::Account))
            .await
        {
            Ok(total) if total.len() > license.accounts as u64 => {
                bp.build_warning(
                    ObjectType::Enterprise.singleton(),
                    format!(
                        "License key is valid but only allows {} accounts, found {}.",
                        license.accounts,
                        total.len()
                    ),
                );
                return None;
            }
            Err(e) => {
                trc::error!(
                    e.caused_by(trc::location!())
                        .details("Failed to count total individual principals")
                );
                return None;
            }
            _ => (),
        }

        let dr = bp.setting_infallible::<DataRetention>().await;

        let mut ai_models = Vec::new();
        for model in bp.list_infallible::<structs::AiModel>().await {
            if let Some(model) = AiModel::build(bp, model.id, model.object).await {
                ai_models.push(Arc::new(model));
            }
        }

        let spam_ai = match bp.setting_infallible::<SpamAi>().await {
            SpamAi::Enable(properties) => {
                SpamAiConfig::parse(bp, &ai_models, properties).map(Arc::new)
            }
            SpamAi::Disable => None,
        };

        // Build the enterprise configuration
        let mut enterprise = Enterprise {
            license,
            deleted_items_retention: dr
                .archive_deleted_items_for
                .map(|retention| retention.into_inner()),
            deleted_accounts_retention: dr
                .archive_deleted_accounts_for
                .map(|retention| retention.into_inner()),
            logo,
            metrics_alerts: Default::default(),
            ai_models,
            spam_ai,
            template_calendar_alarm: None,
            template_scheduling_email: None,
            template_scheduling_web: None,
            trace_retention: dr.hold_traces_for.map(|d| d.into_inner()),
            metrics_retention: dr.hold_metrics_for.map(|d| d.into_inner()),
            metrics_interval: dr.metrics_collection_interval.into(),
        };

        // Parse metric alerts
        for alert in bp.list_infallible::<Alert>().await {
            let id = alert.id;
            let alert = alert.object;

            if !alert.enable {
                continue;
            }
            let condition = bp.compile_expr(id, &alert.ctx_condition());
            let condition = IfBlock::new(
                condition.id,
                condition.property,
                Box::default(),
                condition.default,
            );
            let mut method = Vec::with_capacity(1);
            if let structs::AlertEmail::Enabled(alert) = alert.email_alert {
                method.push(AlertMethod::Email {
                    from_name: alert.from_name,
                    from_addr: alert.from_address,
                    to: alert.to.into_inner(),
                    subject: AlertContent::new(&alert.subject),
                    body: AlertContent::new(&alert.body),
                });
            }
            if let structs::AlertEvent::Enabled(alert) = alert.event_alert {
                method.push(AlertMethod::Event {
                    message: alert.event_message.as_deref().map(AlertContent::new),
                });
            }

            enterprise.metrics_alerts.push(MetricAlert {
                id,
                condition,
                method,
            });
        }

        // Parse templates
        let sched = bp.setting_infallible::<CalendarScheduling>().await;
        let alarm = bp.setting_infallible::<CalendarAlarm>().await;

        for (template, value, object, property) in [
            (
                alarm.template,
                &mut enterprise.template_calendar_alarm,
                ObjectType::CalendarAlarm.singleton(),
                Property::Template,
            ),
            (
                sched.email_template,
                &mut enterprise.template_scheduling_email,
                ObjectType::CalendarScheduling.singleton(),
                Property::EmailTemplate,
            ),
        ] {
            if let Some(template) = template {
                match Template::parse(&template) {
                    Ok(template) => *value = Some(template),
                    Err(err) => {
                        bp.invalid_property(object, property, format!("Invalid template: {err}"));
                    }
                }
            }
        }

        enterprise.template_scheduling_web = sched
            .http_rsvp_template
            .as_deref()
            .map(|page| page.trim())
            .filter(|page| !page.is_empty())
            .map(Arc::from);

        Some(enterprise)
    }
}

impl SpamAiConfig {
    pub fn parse(
        bp: &mut Bootstrap,
        models: &[Arc<AiModel>],
        properties: SpamAiProperties,
    ) -> Option<Self> {
        let id = ObjectType::SpamAi.singleton();
        let condition = bp.compile_expr(id, &properties.ctx_condition());
        let classifier = Arc::new(AiClassifier {
            instructions: properties.instructions.into_boxed_str(),
            categories: properties
                .categories
                .iter()
                .map(|category| AiCategory {
                    name: category.name.as_str().into(),
                    description: category.description.as_str().into(),
                    includes: category
                        .includes
                        .iter()
                        .map(|include| include.as_str().into())
                        .collect(),
                })
                .collect(),
            signals: properties
                .signals
                .iter()
                .map(|signal| AiSignal {
                    name: signal.name.as_str().into(),
                    question: signal.question.as_str().into(),
                })
                .collect(),
            explanation: properties.explanation,
            verbal: VerbalConfidence {
                high: properties.verbal_high.into_inner() as f32,
                medium: properties.verbal_medium.into_inner() as f32,
                low: properties.verbal_low.into_inner() as f32,
            },
        });
        if let Err(err) = classifier.validate() {
            bp.build_error(id, format!("Invalid AI classifier definition: {err:?}"));
            return None;
        }
        let category_tags = classifier
            .categories
            .iter()
            .map(|category| {
                ["_HIGH", "_MEDIUM", "_LOW"].map(|suffix| ai_tag(&category.name, suffix))
            })
            .collect::<Box<[_]>>();
        let signal_tags = classifier
            .signals
            .iter()
            .map(|signal| ai_tag(&signal.name, ""))
            .collect::<Box<[_]>>();
        if let Some(tag) = duplicate_tag(&category_tags, &signal_tags) {
            bp.build_error(
                id,
                format!("AI classifier names produce the tag {tag} more than once"),
            );
            return None;
        }

        let mut tiers = Vec::with_capacity(properties.tiers.len());
        for tier in properties.tiers.iter() {
            let Some(model) = models
                .iter()
                .find(|model| model.id == tier.model_id.id())
                .cloned()
            else {
                bp.build_error(id, format!("AI model {:?} not found", tier.model_id.id()));
                return None;
            };
            let mut escalate_on = Vec::with_capacity(tier.escalate_on.len());
            for name in tier.escalate_on.iter() {
                match classifier.category_index(name) {
                    Some(category) => escalate_on.push(category),
                    None => bp
                        .build_warning(id, format!("Unknown escalation category {name:?} ignored")),
                }
            }
            let classifier = match PreparedClassifier::new(model, classifier.clone()) {
                Ok(classifier) => classifier,
                Err(err) => {
                    bp.build_error(id, format!("Unable to prepare AI classifier: {err}"));
                    return None;
                }
            };
            tiers.push(SpamAiTier {
                classifier,
                escalate_below: tier.escalate_below.into_inner() as f32,
                escalate_on: escalate_on.into_boxed_slice(),
            });
        }
        if tiers.is_empty() {
            bp.build_error(id, "The AI classifier requires at least one model tier");
            return None;
        }

        Some(SpamAiConfig {
            mode: match properties.mode {
                enums::SpamAiMode::Automatic => SpamAiMode::Automatic,
                enums::SpamAiMode::Shadow => SpamAiMode::Shadow,
            },
            condition,
            tiers: tiers.into_boxed_slice(),
            category_tags,
            signal_tags,
            classifier,
            buckets: SpamAiBuckets {
                high: properties.bucket_high.into_inner() as f32,
                medium: properties.bucket_medium.into_inner() as f32,
                uncertain_below: properties.uncertain_below.into_inner() as f32,
            },
            add_header: properties.add_header,
            input: SpamAiInput {
                max_input_chars: usize::try_from(properties.max_input_chars).unwrap_or(usize::MAX),
                max_links: usize::try_from(properties.max_links).unwrap_or(usize::MAX),
                max_attachments: usize::try_from(properties.max_attachments).unwrap_or(usize::MAX),
                trim_quotes: properties.trim_quotes,
                include_auth: properties.include_auth,
                include_links: properties.include_links,
                include_attachments: properties.include_attachments,
            },
            deadline: properties.deadline.into_inner(),
            breaker: BreakerPolicy {
                threshold: u32::try_from(properties.breaker_threshold).unwrap_or(u32::MAX),
                cooldown: properties.breaker_cooldown.into_inner(),
            },
            learn: match properties.learn {
                structs::SpamAiLearn::Enable(learn) => Some(SpamAiLearn {
                    min_probability: learn.min_probability.into_inner() as f32,
                    sample_rate: learn.sample_rate.into_inner() as f32,
                }),
                structs::SpamAiLearn::Disable => None,
            },
            web_search: match properties.web_search {
                structs::SpamAiWebSearch::Disable => SpamAiWebSearch::Disabled,
            },
        })
    }
}

fn duplicate_tag<'x>(
    category_tags: &'x [[CompactString; 3]],
    signal_tags: &'x [CompactString],
) -> Option<&'x str> {
    let mut seen = AHashSet::with_capacity(category_tags.len() * 3 + signal_tags.len() + 2);
    seen.insert(AI_TAG_UNCERTAIN);
    seen.insert(AI_TAG_ERROR);
    category_tags
        .iter()
        .flatten()
        .chain(signal_tags)
        .map(CompactString::as_str)
        .find(|tag| !seen.insert(*tag))
}

fn ai_tag(name: &str, suffix: &str) -> CompactString {
    let mut tag = CompactString::with_capacity(AI_TAG_PREFIX.len() + name.len() + suffix.len());
    tag.push_str(AI_TAG_PREFIX);
    tag.extend(name.chars().map(|ch| {
        if ch.is_ascii_alphanumeric() {
            ch.to_ascii_uppercase()
        } else {
            '_'
        }
    }));
    tag.push_str(suffix);
    tag
}

impl AlertContent {
    fn new(value: &str) -> Self {
        let mut tokens = Vec::new();
        let mut value = value.chars().peekable();
        let mut buf = String::new();

        while let Some(ch) = value.next() {
            if ch == '%' && value.peek() == Some(&'{') {
                value.next();

                let mut var_name = String::new();
                let mut found_curly = false;

                for ch in value.by_ref() {
                    if ch == '}' {
                        found_curly = true;
                        break;
                    }
                    var_name.push(ch);
                }

                if found_curly && value.peek() == Some(&'%') {
                    value.next();
                    if let Some(event_type) =
                        MetricType::parse(&var_name).map(AlertContentToken::Metric)
                    {
                        if !buf.is_empty() {
                            tokens.push(AlertContentToken::Text(std::mem::take(&mut buf)));
                        }
                        tokens.push(event_type);
                    } else {
                        buf.push('%');
                        buf.push('{');
                        buf.push_str(&var_name);
                        buf.push('}');
                        buf.push('%');
                    }
                } else {
                    buf.push('%');
                    buf.push('{');
                    buf.push_str(&var_name);
                }
            } else {
                buf.push(ch);
            }
        }

        if !buf.is_empty() {
            tokens.push(AlertContentToken::Text(buf));
        }

        AlertContent(tokens)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/enterprise/config/tests.rs"]
mod tests;
