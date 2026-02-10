//! A Rust library for representing and deserializing CVSS data.
//!
//! This crate provides Rust types that map directly to the official
//! JSON schema representations for CVSS versions 2.0, 3.0, 3.1, and 4.0.
//!
//! # Example
//!
//! Deserializing a CVSS v3.1 JSON object:
//!
//! ```
//! use cvss_rs::v3::AttackVector;
//! use cvss_rs::{Cvss, Severity, Version};
//!
//! let json_data = r#"{
//!   "version": "3.1",
//!   "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
//!   "attackVector": "NETWORK",
//!   "attackComplexity": "LOW",
//!   "privilegesRequired": "NONE",
//!   "userInteraction": "NONE",
//!   "scope": "UNCHANGED",
//!   "confidentialityImpact": "HIGH",
//!   "integrityImpact": "HIGH",
//!   "availabilityImpact": "HIGH",
//!   "baseScore": 9.8,
//!   "baseSeverity": "CRITICAL"
//! }"#;
//!
//! let cvss: Cvss = serde_json::from_str(json_data).unwrap();
//!
//! assert_eq!(cvss.version(), Version::V3_1);
//! assert_eq!(cvss.base_score(), 9.8);
//! assert_eq!(cvss.base_severity().unwrap(), Severity::Critical);
//!
//! // We can also get the inner struct and access some of its fields
//! if let Cvss::V3_1(cvss_v3) = cvss {
//!     assert_eq!(cvss_v3.attack_vector, Some(AttackVector::Network));
//! } else {
//!     // The example should panic if the if let fails
//!     panic!("Expected Cvss::V3_1 variant");
//! }
//! ```

use serde::Deserialize;
use std::fmt::{self, Display, Formatter};
use strum::{Display, EnumDiscriminants, EnumString};

pub mod helper;
pub mod v2_0;
pub mod v3;
pub mod v4_0;
pub mod version;

/// An enum to hold any version of a CVSS object.
#[derive(Debug, Deserialize, EnumDiscriminants)]
#[serde(tag = "version")]
#[strum_discriminants(name(Version))]
#[strum_discriminants(vis(pub))]
#[strum_discriminants(derive(Display, EnumString))]
pub enum Cvss {
    #[serde(rename = "2.0")]
    V2(v2_0::CvssV2),
    #[serde(rename = "3.0")]
    V3_0(v3::CvssV3),
    #[serde(rename = "3.1")]
    V3_1(v3::CvssV3),
    #[serde(rename = "4.0")]
    V4(v4_0::CvssV4),
}

impl Display for Cvss {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.vector_string())
    }
}

impl Cvss {
    /// Returns the version of the CVSS standard.
    pub fn version(&self) -> Version {
        self.into()
    }

    /// Returns the CVSS vector string.
    pub fn vector_string(&self) -> &str {
        match self {
            Cvss::V2(c) => c.vector_string(),
            Cvss::V3_0(c) => c.vector_string(),
            Cvss::V3_1(c) => c.vector_string(),
            Cvss::V4(c) => c.vector_string(),
        }
    }

    /// Returns the base score.
    pub fn base_score(&self) -> f64 {
        match self {
            Cvss::V2(c) => c.base_score(),
            Cvss::V3_0(c) => c.base_score(),
            Cvss::V3_1(c) => c.base_score(),
            Cvss::V4(c) => c.base_score(),
        }
    }

    /// Returns the base severity.
    pub fn base_severity(&self) -> Option<Severity> {
        match self {
            Cvss::V2(c) => c.base_severity(),
            Cvss::V3_0(c) => c.base_severity(),
            Cvss::V3_1(c) => c.base_severity(),
            Cvss::V4(c) => c.base_severity(),
        }
    }
}

/// Represents the qualitative severity rating of a vulnerability.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Errors that can occur when parsing CVSS vector strings.
#[derive(Clone, Debug, PartialEq)]
pub enum ParseError {
    /// Vector string doesn't start with "CVSS" or expected prefix
    InvalidPrefix { found: String },
    /// Unsupported or invalid CVSS version
    InvalidVersion { version: String },
    /// Component is malformed (not in key:value format)
    InvalidComponent { component: String },
    /// Metric abbreviation not recognized
    UnknownMetric { metric: String },
    /// Metric value parsing failed
    InvalidMetricValue { metric: String, value: String },
    /// Required base metric is missing
    MissingRequiredMetric { metric: String },
    /// Same metric appears multiple times
    DuplicateMetric { metric: String },
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidPrefix { found } => {
                write!(
                    f,
                    "invalid vector prefix: expected 'CVSS', found '{}'",
                    found
                )
            }
            ParseError::InvalidVersion { version } => {
                write!(f, "invalid or unsupported CVSS version: '{}'", version)
            }
            ParseError::InvalidComponent { component } => {
                write!(
                    f,
                    "invalid component format: '{}' (expected 'KEY:VALUE')",
                    component
                )
            }
            ParseError::UnknownMetric { metric } => {
                write!(f, "unknown metric abbreviation: '{}'", metric)
            }
            ParseError::InvalidMetricValue { metric, value } => {
                write!(f, "invalid value '{}' for metric '{}'", value, metric)
            }
            ParseError::MissingRequiredMetric { metric } => {
                write!(f, "missing required metric: '{}'", metric)
            }
            ParseError::DuplicateMetric { metric } => {
                write!(f, "duplicate metric: '{}'", metric)
            }
        }
    }
}

impl std::error::Error for ParseError {}
