// crates/rnmdb-common/src/metrics.rs - RNovModularDB source module.
// Copyright (C) 2026 czxieddan
// This file is part of RNovModularDB and is provided under version 1.1 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also
// subject to the AHCL provisions concerning Continuous AHCL Licensing Segments
// and migration to later official versions. After a reasonable opportunity to
// read AHCL, all applicable Additional Restrictions, and all version notices,
// use, copying, modification, building, dependency use, deployment,
// distribution, or network operation constitutes acceptance to the extent
// permitted by applicable law.
// License notice updated: September 17, 2026.
// Official AHCL text and public notices: https://ahcl.aperip.com
// AHCL Materials Directory: .ahcl/
// Repository official or recognized AHCL copy: .ahcl/AHCL-1.1.md
// Canonical repository: https://github.com/czxieddan/RNovModularDB
// Project notice: .ahcl/AHCL-PROJECT-NOTICE.md
// Version records: .ahcl/AHCL-VERSION-ADOPTION.md
// Source and history: .ahcl/AHCL-SOURCE.md
// Dependencies and licenses: .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions: None.
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::{ErrorKind, Result, RnovError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetricValue {
    Counter(u64),
    Gauge(i64),
    Histogram {
        count: u64,
        sum: i128,
        min: i64,
        max: i64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricSample {
    name: String,
    value: MetricValue,
}

impl MetricSample {
    pub fn new(name: impl Into<String>, value: MetricValue) -> Result<Self> {
        let name = name.into();
        validate_metric_name(&name)?;
        Ok(Self { name, value })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &MetricValue {
        &self.value
    }
}

pub trait MetricsExporter {
    fn export(&self, samples: &[MetricSample]) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
pub struct MetricsRegistry {
    metrics: Arc<RwLock<BTreeMap<String, MetricValue>>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_counter(&self, name: impl AsRef<str>, delta: u64) -> Result<u64> {
        let name = validate_metric_name(name.as_ref())?;
        let mut metrics = self.write_metrics()?;
        let next = match metrics.get(name) {
            Some(MetricValue::Counter(current)) => current.saturating_add(delta),
            Some(_) => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("metric '{name}' already exists with a different kind"),
                ));
            }
            None => delta,
        };
        metrics.insert(name.to_string(), MetricValue::Counter(next));
        Ok(next)
    }

    pub fn set_gauge(&self, name: impl AsRef<str>, value: i64) -> Result<()> {
        let name = validate_metric_name(name.as_ref())?;
        let mut metrics = self.write_metrics()?;
        match metrics.get(name) {
            Some(MetricValue::Gauge(_)) | None => {
                metrics.insert(name.to_string(), MetricValue::Gauge(value));
                Ok(())
            }
            Some(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("metric '{name}' already exists with a different kind"),
            )),
        }
    }

    pub fn record_histogram(&self, name: impl AsRef<str>, value: i64) -> Result<()> {
        let name = validate_metric_name(name.as_ref())?;
        let mut metrics = self.write_metrics()?;
        match metrics.get_mut(name) {
            Some(MetricValue::Histogram {
                count,
                sum,
                min,
                max,
            }) => {
                *count = count.saturating_add(1);
                *sum = sum.saturating_add(value as i128);
                *min = (*min).min(value);
                *max = (*max).max(value);
                Ok(())
            }
            Some(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("metric '{name}' already exists with a different kind"),
            )),
            None => {
                metrics.insert(
                    name.to_string(),
                    MetricValue::Histogram {
                        count: 1,
                        sum: value as i128,
                        min: value,
                        max: value,
                    },
                );
                Ok(())
            }
        }
    }

    pub fn snapshot(&self) -> Result<Vec<MetricSample>> {
        let metrics = self.read_metrics()?;
        metrics
            .iter()
            .map(|(name, value)| MetricSample::new(name.clone(), value.clone()))
            .collect()
    }

    pub fn export(&self, exporter: &impl MetricsExporter) -> Result<()> {
        exporter.export(&self.snapshot()?)
    }

    fn read_metrics(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, BTreeMap<String, MetricValue>>> {
        self.metrics
            .read()
            .map_err(|_| RnovError::new(ErrorKind::Internal, "metrics registry lock poisoned"))
    }

    fn write_metrics(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, BTreeMap<String, MetricValue>>> {
        self.metrics
            .write()
            .map_err(|_| RnovError::new(ErrorKind::Internal, "metrics registry lock poisoned"))
    }
}

pub fn format_metrics_text(samples: &[MetricSample]) -> String {
    samples
        .iter()
        .map(|sample| match sample.value() {
            MetricValue::Counter(value) => format!("{} counter {}", sample.name(), value),
            MetricValue::Gauge(value) => format!("{} gauge {}", sample.name(), value),
            MetricValue::Histogram {
                count,
                sum,
                min,
                max,
            } => format!(
                "{} histogram count={} sum={} min={} max={}",
                sample.name(),
                count,
                sum,
                min,
                max
            ),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn validate_metric_name(name: &str) -> Result<&str> {
    if name.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "metric name cannot be empty",
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'.' | b'-'))
    {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "metric name contains unsupported characters",
        ));
    }
    Ok(name)
}
