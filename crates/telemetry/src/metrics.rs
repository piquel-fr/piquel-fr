//! Instruments declared as `static`s, bound to the meter provider on first use.
//!
//! ```
//! use piquel_telemetry::{Counter, Label, Labels};
//!
//! /// Why a request was throttled.
//! struct Throttled {
//!     /// Its rate category, from a closed vocabulary.
//!     category: &'static str,
//! }
//!
//! impl Labels for Throttled {
//!     fn labels(&self) -> impl IntoIterator<Item = Label> {
//!         [("category", self.category)]
//!     }
//! }
//!
//! /// Requests refused for exceeding their budget.
//! static THROTTLED: Counter<Throttled> =
//!     Counter::new("piquel.auth.throttled", "{request}", "Requests refused by rate limits.");
//!
//! THROTTLED.add(1, &Throttled { category: "login" });
//! ```

use crate::SCOPE;
use opentelemetry::{KeyValue, global, metrics};
use std::{marker::PhantomData, sync::OnceLock};

/// One metric attribute. Its value is a `&'static str`, so only a closed
/// vocabulary, never an ID, name or address, can label a metric.
pub type Label = (&'static str, &'static str);

/// The attributes of an instrument's measurements: one type per instrument, so
/// every measurement has the same keys.
pub trait Labels {
    /// The attributes, as `(key, value)` pairs.
    fn labels(&self) -> impl IntoIterator<Item = Label>;

    /// The attributes as OpenTelemetry records them.
    fn attributes(&self) -> Vec<KeyValue> {
        self.labels()
            .into_iter()
            .map(|(key, value)| KeyValue::new(key, value))
            .collect()
    }
}

impl Labels for () {
    /// No attributes.
    fn labels(&self) -> impl IntoIterator<Item = Label> {
        []
    }
}

impl<const N: usize> Labels for [Label; N] {
    /// The pairs themselves.
    fn labels(&self) -> impl IntoIterator<Item = Label> {
        *self
    }
}

/// What every instrument declares: its semantic-convention name, its UCUM unit
/// (e.g. `s`, or `{request}` for a count of requests) and a description.
struct Descriptor {
    /// e.g. `piquel.auth.sign_ins`.
    name: &'static str,
    /// e.g. `{sign_in}`.
    unit: &'static str,
    /// One sentence.
    description: &'static str,
}

/// A monotonic count, e.g. of sign-ins.
pub struct Counter<L = ()> {
    /// Name, unit and description.
    descriptor: Descriptor,
    /// Created on first use, from the provider installed by then.
    instrument: OnceLock<metrics::Counter<u64>>,
    /// The attributes each increment carries.
    labels: PhantomData<fn(L)>,
}

impl<L: Labels> Counter<L> {
    /// Declares a counter.
    #[must_use]
    pub const fn new(name: &'static str, unit: &'static str, description: &'static str) -> Self {
        Self {
            descriptor: Descriptor {
                name,
                unit,
                description,
            },
            instrument: OnceLock::new(),
            labels: PhantomData,
        }
    }

    /// Adds `value` to the count with `labels`.
    pub fn add(&self, value: u64, labels: &L) {
        self.instrument
            .get_or_init(|| {
                let Descriptor {
                    name,
                    unit,
                    description,
                } = self.descriptor;
                global::meter(SCOPE)
                    .u64_counter(name)
                    .with_unit(unit)
                    .with_description(description)
                    .build()
            })
            .add(value, &labels.attributes());
    }
}

/// A distribution of measurements, e.g. of durations in seconds.
pub struct Histogram<L = ()> {
    /// Name, unit and description.
    descriptor: Descriptor,
    /// Upper bounds of the buckets.
    boundaries: &'static [f64],
    /// Created on first use, from the provider installed by then.
    instrument: OnceLock<metrics::Histogram<f64>>,
    /// The attributes each measurement carries.
    labels: PhantomData<fn(L)>,
}

impl<L: Labels> Histogram<L> {
    /// Declares a histogram with explicit bucket `boundaries`.
    #[must_use]
    pub const fn new(
        name: &'static str,
        unit: &'static str,
        description: &'static str,
        boundaries: &'static [f64],
    ) -> Self {
        Self {
            descriptor: Descriptor {
                name,
                unit,
                description,
            },
            boundaries,
            instrument: OnceLock::new(),
            labels: PhantomData,
        }
    }

    /// Records `value` with `labels`.
    pub fn record(&self, value: f64, labels: &L) {
        self.record_attributes(value, &labels.attributes());
    }

    /// Records `value` with attributes this crate bounded itself, such as route templates.
    pub(crate) fn record_attributes(&self, value: f64, attributes: &[KeyValue]) {
        self.instrument
            .get_or_init(|| {
                let Descriptor {
                    name,
                    unit,
                    description,
                } = self.descriptor;
                global::meter(SCOPE)
                    .f64_histogram(name)
                    .with_unit(unit)
                    .with_description(description)
                    .with_boundaries(self.boundaries.to_vec())
                    .build()
            })
            .record(value, attributes);
    }
}

/// A value read when metrics are collected, e.g. the connections a pool holds.
pub struct Gauge<L = ()> {
    /// Name, unit and description.
    descriptor: Descriptor,
    /// Registered by [`Self::observe`]; kept so its callback stays registered.
    instrument: OnceLock<metrics::ObservableGauge<u64>>,
    /// The attributes each observation carries.
    labels: PhantomData<fn(L)>,
}

impl<L: Labels + 'static> Gauge<L> {
    /// Declares a gauge.
    #[must_use]
    pub const fn new(name: &'static str, unit: &'static str, description: &'static str) -> Self {
        Self {
            descriptor: Descriptor {
                name,
                unit,
                description,
            },
            instrument: OnceLock::new(),
            labels: PhantomData,
        }
    }

    /// Reports the values `observe` returns at every collection. Only the first
    /// call registers; later ones do nothing.
    pub fn observe<I>(&'static self, observe: impl Fn() -> I + Send + Sync + 'static)
    where
        I: IntoIterator<Item = (u64, L)>,
    {
        self.instrument.get_or_init(|| {
            let Descriptor {
                name,
                unit,
                description,
            } = self.descriptor;
            global::meter(SCOPE)
                .u64_observable_gauge(name)
                .with_unit(unit)
                .with_description(description)
                .with_callback(move |observer| {
                    for (value, labels) in observe() {
                        observer.observe(value, &labels.attributes());
                    }
                })
                .build()
        });
    }
}
