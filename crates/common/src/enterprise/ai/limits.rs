/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use registry::schema::structs::Rate;
use std::{
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

pub struct AiLimits {
    pub semaphore: Semaphore,
    pub rate: Option<RateLimiter>,
    pub breaker: CircuitBreaker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerPolicy {
    pub threshold: u32,
    pub cooldown: Duration,
}

pub struct RateLimiter {
    origin: Instant,
    interval: u64,
    next: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Closed,
    Probe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateSlot {
    Now,
    At(Instant),
    Exceeded,
}

pub struct CircuitBreaker {
    origin: Instant,
    failures: AtomicU32,
    open_until: AtomicU64,
}

const DEFAULT_BREAKER_THRESHOLD: u32 = 5;
const DEFAULT_BREAKER_COOLDOWN: Duration = Duration::from_secs(60);

impl Default for BreakerPolicy {
    fn default() -> Self {
        BreakerPolicy {
            threshold: DEFAULT_BREAKER_THRESHOLD,
            cooldown: DEFAULT_BREAKER_COOLDOWN,
        }
    }
}

impl AiLimits {
    pub fn new(max_concurrent_requests: usize, rate_limit: Option<Rate>) -> Self {
        let origin = Instant::now();
        AiLimits {
            semaphore: Semaphore::new(max_concurrent_requests.clamp(1, Semaphore::MAX_PERMITS)),
            rate: rate_limit.and_then(|rate| RateLimiter::new(origin, rate)),
            breaker: CircuitBreaker {
                origin,
                failures: AtomicU32::new(0),
                open_until: AtomicU64::new(0),
            },
        }
    }
}

impl RateLimiter {
    fn new(origin: Instant, rate: Rate) -> Option<Self> {
        let period = duration_nanos(rate.period.into_inner());
        (rate.count > 0 && period > 0).then(|| RateLimiter {
            origin,
            interval: (period / rate.count).max(1),
            next: AtomicU64::new(0),
        })
    }

    pub fn reserve(&self, now: Instant, deadline: Instant) -> RateSlot {
        let now_nanos = nanos_since(self.origin, now);
        let deadline_nanos = nanos_since(self.origin, deadline);
        let mut next = self.next.load(Ordering::Relaxed);
        loop {
            let slot = next.max(now_nanos);
            if slot > deadline_nanos {
                return RateSlot::Exceeded;
            }
            match self.next.compare_exchange_weak(
                next,
                slot.saturating_add(self.interval),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) if slot > now_nanos => {
                    return RateSlot::At(self.origin + Duration::from_nanos(slot));
                }
                Ok(_) => return RateSlot::Now,
                Err(current) => next = current,
            }
        }
    }
}

impl CircuitBreaker {
    pub fn is_open(&self, now: Instant) -> bool {
        let open_until = self.open_until.load(Ordering::Acquire);
        open_until != 0 && nanos_since(self.origin, now) < open_until
    }

    pub fn admit(&self, now: Instant, cooldown: Duration) -> Option<Admission> {
        let open_until = self.open_until.load(Ordering::Acquire);
        if open_until == 0 {
            return Some(Admission::Closed);
        }
        let now_nanos = nanos_since(self.origin, now);
        if now_nanos < open_until {
            return None;
        }
        self.open_until
            .compare_exchange(
                open_until,
                reopen_at(now_nanos, cooldown),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()
            .map(|_| Admission::Probe)
    }

    pub fn record_success(&self) {
        if self.open_until.load(Ordering::Relaxed) != 0 {
            self.open_until.store(0, Ordering::Release);
        }
        if self.failures.load(Ordering::Relaxed) != 0 {
            self.failures.store(0, Ordering::Relaxed);
        }
    }

    pub fn record_failure(
        &self,
        policy: &BreakerPolicy,
        now: Instant,
        trip: bool,
        admission: Admission,
    ) -> bool {
        let failures = self
            .failures
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if admission == Admission::Probe || trip || failures >= policy.threshold.max(1) {
            let now_nanos = nanos_since(self.origin, now);
            let previous = self
                .open_until
                .swap(reopen_at(now_nanos, policy.cooldown), Ordering::AcqRel);
            admission == Admission::Probe || previous == 0 || previous <= now_nanos
        } else {
            false
        }
    }
}

fn reopen_at(now_nanos: u64, cooldown: Duration) -> u64 {
    now_nanos.saturating_add(duration_nanos(cooldown)).max(1)
}

fn nanos_since(origin: Instant, instant: Instant) -> u64 {
    duration_nanos(instant.saturating_duration_since(origin))
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/enterprise/ai/limits/tests.rs"]
mod tests;
