//! Represents the CVSS v2.0 specification.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use strum::{Display, EnumString};

use crate::{ParseError, Severity as UnifiedSeverity};

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

impl FromStr for CvssV2 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components_str = s;

        // CVSS v2 vectors may or may not have "CVSS:2.0/" prefix
        // Examples: "AV:N/AC:L/Au:N/C:C/I:C/A:C" or "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C"
        let components_str =
            if components_str.starts_with("CVSS:2.0/") || components_str.starts_with("cvss:2.0/") {
                &components_str[9..] // Skip "CVSS:2.0/"
            } else {
                components_str
            };

        let mut cvss = CvssV2 {
            vector_string: s.to_string(),
            severity: None,
            base_score: 0.0,
            temporal_score: None,
            environmental_score: None,
            access_vector: None,
            access_complexity: None,
            authentication: None,
            confidentiality_impact: None,
            integrity_impact: None,
            availability_impact: None,
        };

        // Parse metrics
        for component in components_str.split('/') {
            if component.is_empty() {
                continue;
            }

            let mut parts = component.split(':');
            let key = parts
                .next()
                .ok_or_else(|| ParseError::InvalidComponent {
                    component: component.to_string(),
                })?
                .to_ascii_uppercase();
            let value = parts
                .next()
                .ok_or_else(|| ParseError::InvalidComponent {
                    component: component.to_string(),
                })?
                .to_ascii_uppercase();

            // Check for extra colons
            if parts.next().is_some() {
                return Err(ParseError::InvalidComponent {
                    component: component.to_string(),
                });
            }

            match key.as_str() {
                "AV" => {
                    cvss.access_vector =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "AC" => {
                    cvss.access_complexity =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "AU" => {
                    cvss.authentication =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "C" => {
                    cvss.confidentiality_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "I" => {
                    cvss.integrity_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "A" => {
                    cvss.availability_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                _ => {
                    return Err(ParseError::UnknownMetric { metric: key });
                }
            }
        }

        Ok(cvss)
    }
}

impl fmt::Display for CvssV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // CVSS v2 typically doesn't include version prefix, but we'll include it for consistency
        write!(f, "AV:")?;
        if let Some(av) = &self.access_vector {
            write!(f, "{}", av)?;
        }
        if let Some(ac) = &self.access_complexity {
            write!(f, "/AC:{}", ac)?;
        }
        if let Some(au) = &self.authentication {
            write!(f, "/Au:{}", au)?;
        }
        if let Some(c) = &self.confidentiality_impact {
            write!(f, "/C:{}", c)?;
        }
        if let Some(i) = &self.integrity_impact {
            write!(f, "/I:{}", i)?;
        }
        if let Some(a) = &self.availability_impact {
            write!(f, "/A:{}", a)?;
        }

        Ok(())
    }
}
