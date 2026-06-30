/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::NextHop;
use crate::outbound::dane::dnssec::DnssecStatus;
use crate::queue::{Error, ErrorDetails, HostResponse, Status};
use common::{
    Server,
    config::smtp::queue::{ConnectionStrategy, HostOrIp, IpAndHost, MxConfig},
    expr::functions::ResolveVariable,
};
use mail_auth::{
    IpLookupStrategy, MX,
    common::resolver::ToFqdn,
    hickory_resolver::proto::rr::{Name, RData, RecordType},
};
use rand::{Rng, seq::SliceRandom};
use registry::schema::enums::ExpressionVariable;
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Instant,
};

pub struct IpLookupResult {
    pub remote_ips: Vec<IpAddr>,
    pub dnssec_status: DnssecStatus,
}

pub trait DnsLookup: Sync + Send {
    fn ip_lookup(
        &self,
        key: &str,
        strategy: IpLookupStrategy,
        max_results: usize,
    ) -> impl Future<Output = mail_auth::Result<Vec<IpAddr>>> + Send;

    fn dnssec_ip_lookup(
        &self,
        key: &str,
        strategy: IpLookupStrategy,
        max_results: usize,
    ) -> impl Future<Output = mail_auth::Result<(Vec<IpAddr>, DnssecStatus)>> + Send;

    fn resolve_host(
        &self,
        remote_host: &NextHop<'_>,
        envelope: &impl ResolveVariable,
        use_dnssec: bool,
    ) -> impl Future<Output = Result<IpLookupResult, Status<HostResponse<Box<str>>, ErrorDetails>>> + Send;
}

impl DnsLookup for Server {
    async fn ip_lookup(
        &self,
        key: &str,
        strategy: IpLookupStrategy,
        max_results: usize,
    ) -> mail_auth::Result<Vec<IpAddr>> {
        let (has_ipv4, has_ipv6, v4_first) = match strategy {
            IpLookupStrategy::Ipv4Only => (true, false, false),
            IpLookupStrategy::Ipv6Only => (false, true, false),
            IpLookupStrategy::Ipv4thenIpv6 => (true, true, true),
            IpLookupStrategy::Ipv6thenIpv4 => (true, true, false),
        };
        let ipv4_addrs = if has_ipv4 {
            match self
                .core
                .smtp
                .resolvers
                .dns
                .ipv4_lookup(key, Some(&self.inner.cache.dns_ipv4))
                .await
            {
                Ok(addrs) => addrs,
                Err(_) if has_ipv6 => Arc::new([]),
                Err(err) => return Err(err),
            }
        } else {
            Arc::new([])
        };

        if has_ipv6 {
            let ipv6_addrs = match self
                .core
                .smtp
                .resolvers
                .dns
                .ipv6_lookup(key, Some(&self.inner.cache.dns_ipv6))
                .await
            {
                Ok(addrs) => addrs,
                Err(_) if !ipv4_addrs.is_empty() => Arc::new([]),
                Err(err) => return Err(err),
            };
            if v4_first {
                Ok(ipv4_addrs
                    .iter()
                    .copied()
                    .map(IpAddr::from)
                    .chain(ipv6_addrs.iter().copied().map(IpAddr::from))
                    .take(max_results)
                    .collect())
            } else {
                Ok(ipv6_addrs
                    .iter()
                    .copied()
                    .map(IpAddr::from)
                    .chain(ipv4_addrs.iter().copied().map(IpAddr::from))
                    .take(max_results)
                    .collect())
            }
        } else {
            Ok(ipv4_addrs
                .iter()
                .take(max_results)
                .copied()
                .map(IpAddr::from)
                .collect())
        }
    }

    async fn dnssec_ip_lookup(
        &self,
        key: &str,
        strategy: IpLookupStrategy,
        max_results: usize,
    ) -> mail_auth::Result<(Vec<IpAddr>, DnssecStatus)> {
        let fqdn = key.to_fqdn();
        if let Some(secure) = self.inner.cache.dns_dnssec.get(fqdn.as_ref()) {
            return Ok((
                self.ip_lookup(key, strategy, max_results).await?,
                if secure {
                    DnssecStatus::Secure
                } else {
                    DnssecStatus::Insecure
                },
            ));
        }

        #[cfg(any(test, feature = "test_mode"))]
        if true {
            return Ok((
                self.ip_lookup(key, strategy, max_results).await?,
                DnssecStatus::Secure,
            ));
        }

        let (query_v4, query_v6, v4_first) = match strategy {
            IpLookupStrategy::Ipv4Only => (true, false, true),
            IpLookupStrategy::Ipv6Only => (false, true, false),
            IpLookupStrategy::Ipv4thenIpv6 => (true, true, true),
            IpLookupStrategy::Ipv6thenIpv4 => (true, true, false),
        };
        let resolver = &self.core.smtp.resolvers.dnssec.resolver;
        let name = Name::from_str_relaxed(fqdn.as_ref())?;

        let mut ipv4: Vec<Ipv4Addr> = Vec::new();
        let mut ipv6: Vec<Ipv6Addr> = Vec::new();
        let mut all_secure = true;
        let mut v4_valid_until: Option<Instant> = None;
        let mut v6_valid_until: Option<Instant> = None;
        let mut not_found: Option<mail_auth::Error> = None;

        let mut record_types = Vec::with_capacity(2);
        if query_v4 {
            record_types.push(RecordType::A);
        }
        if query_v6 {
            record_types.push(RecordType::AAAA);
        }

        for record_type in record_types {
            match resolver.lookup(name.clone(), record_type).await {
                Ok(lookup) => {
                    let valid_until = lookup.valid_until();
                    let mut found = false;
                    for record in lookup.answers() {
                        if !record.proof.is_secure() {
                            all_secure = false;
                        }
                        match &record.data {
                            RData::A(a) => {
                                ipv4.push(a.0);
                                found = true;
                            }
                            RData::AAAA(aaaa) => {
                                ipv6.push(aaaa.0);
                                found = true;
                            }
                            _ => {}
                        }
                    }
                    if found {
                        if record_type == RecordType::A {
                            v4_valid_until = Some(valid_until);
                        } else {
                            v6_valid_until = Some(valid_until);
                        }
                    }
                }
                Err(err) => {
                    let err: mail_auth::Error = err.into();
                    if matches!(err, mail_auth::Error::DnsRecordNotFound(_)) {
                        not_found = Some(err);
                    } else {
                        return Err(err);
                    }
                }
            }
        }

        if ipv4.is_empty() && ipv6.is_empty() {
            return Err(not_found.unwrap_or(mail_auth::Error::DnsRecordNotFound(
                mail_auth::hickory_resolver::proto::op::ResponseCode::NXDomain,
            )));
        }

        if let Some(valid_until) = v4_valid_until {
            self.inner.cache.dns_ipv4.insert_with_expiry(
                fqdn.clone(),
                Arc::from(ipv4.as_slice()),
                valid_until,
            );
        }
        if let Some(valid_until) = v6_valid_until {
            self.inner.cache.dns_ipv6.insert_with_expiry(
                fqdn.clone(),
                Arc::from(ipv6.as_slice()),
                valid_until,
            );
        }
        if let Some(valid_until) = v4_valid_until.into_iter().chain(v6_valid_until).min() {
            self.inner
                .cache
                .dns_dnssec
                .insert_with_expiry(fqdn, all_secure, valid_until);
        }

        let remote_ips: Vec<IpAddr> = if v4_first {
            ipv4.into_iter()
                .map(IpAddr::from)
                .chain(ipv6.into_iter().map(IpAddr::from))
                .take(max_results)
                .collect()
        } else {
            ipv6.into_iter()
                .map(IpAddr::from)
                .chain(ipv4.into_iter().map(IpAddr::from))
                .take(max_results)
                .collect()
        };

        Ok((
            remote_ips,
            if all_secure {
                DnssecStatus::Secure
            } else {
                DnssecStatus::Insecure
            },
        ))
    }

    #[allow(unused_mut)]
    async fn resolve_host(
        &self,
        remote_host: &NextHop<'_>,
        envelope: &impl ResolveVariable,
        use_dnssec: bool,
    ) -> Result<IpLookupResult, Status<HostResponse<Box<str>>, ErrorDetails>> {
        let (mut remote_ips, dnssec_status) = match remote_host.fqdn_hostname() {
            HostOrIp::Host(hostname) => {
                let lookup = if use_dnssec {
                    self.dnssec_ip_lookup(
                        hostname.as_ref(),
                        remote_host.ip_lookup_strategy(),
                        remote_host.max_multi_homed(),
                    )
                    .await
                } else {
                    self.ip_lookup(
                        hostname.as_ref(),
                        remote_host.ip_lookup_strategy(),
                        remote_host.max_multi_homed(),
                    )
                    .await
                    .map(|ips| (ips, DnssecStatus::Insecure))
                };

                lookup.map_err(|err| {
                    if let mail_auth::Error::DnsRecordNotFound(_) = &err {
                        if matches!(
                            remote_host,
                            NextHop::MX {
                                is_implicit: true,
                                ..
                            }
                        ) {
                            Status::PermanentFailure(ErrorDetails {
                                entity: remote_host.hostname().into(),
                                details: Error::DnsError("no MX record found.".into()),
                            })
                        } else {
                            Status::PermanentFailure(ErrorDetails {
                                entity: remote_host.hostname().into(),
                                details: Error::ConnectionError("record not found for MX".into()),
                            })
                        }
                    } else {
                        Status::TemporaryFailure(ErrorDetails {
                            entity: remote_host.hostname().into(),
                            details: Error::ConnectionError(
                                format!("lookup error: {err}").into_boxed_str(),
                            ),
                        })
                    }
                })?
            }
            HostOrIp::Ip(ip) => (vec![ip], DnssecStatus::Insecure),
        };

        if !remote_ips.is_empty() {
            #[cfg(not(feature = "test_mode"))]
            if remote_ips.iter().any(|ip| ip.is_loopback()) {
                remote_ips.retain(|ip| !ip.is_loopback());
                if remote_ips.is_empty() {
                    return Err(Status::PermanentFailure(ErrorDetails {
                        entity: remote_host.hostname().into(),
                        details: Error::ConnectionError("host resolves loopback address".into()),
                    }));
                }
            }

            Ok(IpLookupResult {
                remote_ips,
                dnssec_status,
            })
        } else {
            Err(Status::TemporaryFailure(ErrorDetails {
                entity: remote_host.hostname().into(),
                details: Error::DnsError(
                    format!(
                        "No IP addresses found for {:?}.",
                        envelope
                            .resolve_variable(ExpressionVariable::Mx)
                            .to_string()
                    )
                    .into_boxed_str(),
                ),
            }))
        }
    }
}

pub trait SourceIp {
    fn source_ip(&self, is_v4: bool) -> Option<&IpAndHost>;
}

impl SourceIp for ConnectionStrategy {
    fn source_ip(&self, is_v4: bool) -> Option<&IpAndHost> {
        let ips = if is_v4 {
            &self.source_ipv4
        } else {
            &self.source_ipv6
        };
        match ips.len().cmp(&1) {
            std::cmp::Ordering::Equal => ips.first(),
            std::cmp::Ordering::Greater => Some(&ips[rand::rng().random_range(0..ips.len())]),
            std::cmp::Ordering::Less => None,
        }
    }
}

pub trait ToNextHop {
    fn to_remote_hosts<'x, 'y: 'x>(
        &'x self,
        domain: &'y str,
        config: &'x MxConfig,
    ) -> Option<Vec<NextHop<'x>>>;
}

impl ToNextHop for Arc<[MX]> {
    fn to_remote_hosts<'x, 'y: 'x>(
        &'x self,
        domain: &'y str,
        config: &'x MxConfig,
    ) -> Option<Vec<NextHop<'x>>> {
        if !self.is_empty() {
            // Obtain max number of MX hosts to process
            let mut remote_hosts = Vec::with_capacity(config.max_mx);

            'outer: for mx in self.iter() {
                if mx.exchanges.len() > 1 {
                    let mut slice = mx.exchanges.iter().collect::<Vec<_>>();
                    slice.shuffle(&mut rand::rng());
                    for remote_host in slice {
                        remote_hosts.push(NextHop::MX {
                            host: remote_host.as_ref(),
                            is_implicit: false,
                            config,
                        });
                        if remote_hosts.len() == config.max_mx {
                            break 'outer;
                        }
                    }
                } else if let Some(remote_host) = mx.exchanges.first() {
                    // Check for Null MX
                    if mx.preference == 0 && remote_host.as_ref() == "." {
                        return None;
                    }
                    remote_hosts.push(NextHop::MX {
                        host: remote_host.as_ref(),
                        is_implicit: false,
                        config,
                    });
                    if remote_hosts.len() == config.max_mx {
                        break;
                    }
                }
            }
            remote_hosts.into()
        } else {
            // If an empty list of MXs is returned, the address is treated as if it was
            // associated with an implicit MX RR with a preference of 0, pointing to that host.
            vec![NextHop::MX {
                host: domain,
                is_implicit: true,
                config,
            }]
            .into()
        }
    }
}
