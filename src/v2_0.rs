//! Represents the CVSS v2.0 specification.

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::Severity as UnifiedSeverity;

/// Represents a CVSS v2.0 score object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV2 {
    /// The CVSS vector string.
    pub vector_string: String,
    /// The qualitative severity rating.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// The base score, a value between 0.0 and 10.0.
    pub base_score: f64,
    /// The temporal score, a value between 0.0 and 10.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal_score: Option<f64>,
    /// The environmental score, a value between 0.0 and 10.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environmental_score: Option<f64>,
    /// The access vector metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_vector: Option<AccessVector>,
    /// The access complexity metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_complexity: Option<AccessComplexity>,
    /// The authentication metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Authentication>,
    /// The confidentiality impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_impact: Option<Impact>,
    /// The integrity impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_impact: Option<Impact>,
    /// The availability impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_impact: Option<Impact>,
}

/// Represents the qualitative severity rating of a vulnerability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

/// Represents the access vector metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessVector {
    #[strum(serialize = "N")]
    Network,
    #[strum(serialize = "A")]
    AdjacentNetwork,
    #[strum(serialize = "L")]
    Local,
}

impl AccessVector {
    /// Returns the numeric score for this metric per CVSS v2.0 specification.
    pub fn score(&self) -> f64 {
        match self {
            AccessVector::Network => 1.0,
            AccessVector::AdjacentNetwork => 0.646,
            AccessVector::Local => 0.395,
        }
    }
}

/// Represents the access complexity metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum AccessComplexity {
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "M")]
    Medium,
    #[strum(serialize = "L")]
    Low,
}

impl AccessComplexity {
    /// Returns the numeric score for this metric per CVSS v2.0 specification.
    pub fn score(&self) -> f64 {
        match self {
            AccessComplexity::High => 0.35,
            AccessComplexity::Medium => 0.61,
            AccessComplexity::Low => 0.71,
        }
    }
}

/// Represents the authentication metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum Authentication {
    #[strum(serialize = "M")]
    Multiple,
    #[strum(serialize = "S")]
    Single,
    #[strum(serialize = "N")]
    None,
}

impl Authentication {
    /// Returns the numeric score for this metric per CVSS v2.0 specification.
    pub fn score(&self) -> f64 {
        match self {
            Authentication::Multiple => 0.45,
            Authentication::Single => 0.56,
            Authentication::None => 0.704,
        }
    }
}

/// Represents the impact metrics (confidentiality, integrity, availability).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum Impact {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "P")]
    Partial,
    #[strum(serialize = "C")]
    Complete,
}

impl Impact {
    /// Returns the numeric score for this metric per CVSS v2.0 specification.
    pub fn score(&self) -> f64 {
        match self {
            Impact::None => 0.0,
            Impact::Partial => 0.275,
            Impact::Complete => 0.660,
        }
    }
}

impl CvssV2 {
    pub fn vector_string(&self) -> &str {
        &self.vector_string
    }

    pub fn base_score(&self) -> f64 {
        self.base_score
    }

    pub fn base_severity(&self) -> Option<UnifiedSeverity> {
        self.severity.as_ref().map(|s| match s {
            Severity::Low => UnifiedSeverity::Low,
            Severity::Medium => UnifiedSeverity::Medium,
            Severity::High => UnifiedSeverity::High,
        })
    }
}
