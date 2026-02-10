//! Represents the CVSS v2.0 specification.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use strum::{Display, EnumString};

use crate::helper::round_to_first_decimal;
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
    /// The exploitability metric (temporal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exploitability: Option<Exploitability>,
    /// The remediation level metric (temporal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_level: Option<RemediationLevel>,
    /// The report confidence metric (temporal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_confidence: Option<ReportConfidence>,
    /// The collateral damage potential metric (environmental).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collateral_damage_potential: Option<CollateralDamagePotential>,
    /// The target distribution metric (environmental).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_distribution: Option<TargetDistribution>,
    /// The confidentiality requirement metric (environmental).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_requirement: Option<SecurityRequirement>,
    /// The integrity requirement metric (environmental).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_requirement: Option<SecurityRequirement>,
    /// The availability requirement metric (environmental).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_requirement: Option<SecurityRequirement>,
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

/// Exploitability (E) - Temporal metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Exploitability {
    #[strum(serialize = "U")]
    Unproven,
    #[strum(serialize = "POC")]
    ProofOfConcept,
    #[strum(serialize = "F")]
    Functional,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "ND")]
    NotDefined,
}

impl Exploitability {
    /// Returns the numeric score for this metric per CVSS v2.0 specification.
    pub fn score(&self) -> f64 {
        match self {
            Exploitability::Unproven => 0.85,
            Exploitability::ProofOfConcept => 0.9,
            Exploitability::Functional => 0.95,
            Exploitability::High => 1.0,
            Exploitability::NotDefined => 1.0,
        }
    }
}

/// Remediation Level (RL) - Temporal metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemediationLevel {
    #[strum(serialize = "OF")]
    OfficialFix,
    #[strum(serialize = "TF")]
    TemporaryFix,
    #[strum(serialize = "W")]
    Workaround,
    #[strum(serialize = "U")]
    Unavailable,
    #[strum(serialize = "ND")]
    NotDefined,
}

impl RemediationLevel {
    /// Returns the numeric score for this metric per CVSS v2.0 specification.
    pub fn score(&self) -> f64 {
        match self {
            RemediationLevel::OfficialFix => 0.87,
            RemediationLevel::TemporaryFix => 0.90,
            RemediationLevel::Workaround => 0.95,
            RemediationLevel::Unavailable => 1.0,
            RemediationLevel::NotDefined => 1.0,
        }
    }
}

/// Report Confidence (RC) - Temporal metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportConfidence {
    #[strum(serialize = "UC")]
    Unconfirmed,
    #[strum(serialize = "UR")]
    Uncorroborated,
    #[strum(serialize = "C")]
    Confirmed,
    #[strum(serialize = "ND")]
    NotDefined,
}

impl ReportConfidence {
    /// Returns the numeric score for this metric per CVSS v2.0 specification.
    pub fn score(&self) -> f64 {
        match self {
            ReportConfidence::Unconfirmed => 0.90,
            ReportConfidence::Uncorroborated => 0.95,
            ReportConfidence::Confirmed => 1.0,
            ReportConfidence::NotDefined => 1.0,
        }
    }
}

/// Collateral Damage Potential (CDP) - Environmental metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CollateralDamagePotential {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "LM")]
    LowMedium,
    #[strum(serialize = "MH")]
    MediumHigh,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "ND")]
    NotDefined,
}

impl CollateralDamagePotential {
    /// Returns the numeric score for this metric per CVSS v2.0 specification.
    pub fn score(&self) -> f64 {
        match self {
            CollateralDamagePotential::None => 0.0,
            CollateralDamagePotential::Low => 0.1,
            CollateralDamagePotential::LowMedium => 0.3,
            CollateralDamagePotential::MediumHigh => 0.4,
            CollateralDamagePotential::High => 0.5,
            CollateralDamagePotential::NotDefined => 0.0,
        }
    }
}

/// Target Distribution (TD) - Environmental metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetDistribution {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "M")]
    Medium,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "ND")]
    NotDefined,
}

impl TargetDistribution {
    /// Returns the numeric score for this metric per CVSS v2.0 specification.
    pub fn score(&self) -> f64 {
        match self {
            TargetDistribution::None => 0.0,
            TargetDistribution::Low => 0.25,
            TargetDistribution::Medium => 0.75,
            TargetDistribution::High => 1.0,
            TargetDistribution::NotDefined => 1.0,
        }
    }
}

/// Security Requirement (CR, IR, AR) - Environmental metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityRequirement {
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "M")]
    Medium,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "ND")]
    NotDefined,
}

impl SecurityRequirement {
    /// Returns the numeric score for this metric per CVSS v2.0 specification.
    pub fn score(&self) -> f64 {
        match self {
            SecurityRequirement::Low => 0.5,
            SecurityRequirement::Medium => 1.0,
            SecurityRequirement::High => 1.51,
            SecurityRequirement::NotDefined => 1.0,
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

    /// Calculates the base score from the base metrics.
    /// Returns None if required base metrics are missing.
    pub fn calculated_base_score(&self) -> Option<f64> {
        self.calculate_base_score(self.calculate_impact()?)
    }

    fn calculate_base_score(&self, impact: f64) -> Option<f64> {
        // All base metrics are required
        let av = self.access_vector.as_ref()?;
        let ac = self.access_complexity.as_ref()?;
        let au = self.authentication.as_ref()?;

        // Calculate exploitability
        let exploitability = 20.0 * av.score() * ac.score() * au.score();

        // f(impact) = 0 if impact = 0, else 1.176
        let f_impact = if impact == 0.0 { 0.0 } else { 1.176 };

        // Calculate base score
        let score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact;

        // Round to 1 decimal place
        Some(round_to_first_decimal(score))
    }

    /// Calculates the impact score from the impact metrics.
    pub fn calculate_impact(&self) -> Option<f64> {
        let c = self.confidentiality_impact.as_ref()?;
        let i = self.integrity_impact.as_ref()?;
        let a = self.availability_impact.as_ref()?;

        Some(10.41 * (1.0 - (1.0 - c.score()) * (1.0 - i.score()) * (1.0 - a.score())))
    }

    /// Calculates the temporal score from base and temporal metrics.
    /// Returns None if required base metrics are missing.
    ///
    /// Note: CVSS v2.0 temporal metrics are not commonly used in this library's schema,
    /// but the calculation is provided for completeness.
    pub fn calculated_temporal_score(&self) -> Option<f64> {
        self.calculate_temporal_score(self.calculate_base_score(self.calculate_impact()?)?)
    }

    fn calculate_temporal_score(&self, base_score: f64) -> Option<f64> {
        let exploitability = self.exploitability.as_ref()?;
        let remediation_level = self.remediation_level.as_ref()?;
        let report_confidence = self.report_confidence.as_ref()?;

        let temporal_score = base_score
            * exploitability.score()
            * remediation_level.score()
            * report_confidence.score();

        Some(round_to_first_decimal(temporal_score))
    }

    /// Calculates the environmental score from base, temporal, and environmental metrics.
    /// Returns None if required base metrics are missing.
    ///
    /// Note: CVSS v2.0 environmental metrics are not commonly used in this library's schema,
    /// but the calculation is provided for completeness.
    pub fn calculated_environmental_score(&self) -> Option<f64> {
        let collateral_damage_potential = self.collateral_damage_potential.as_ref()?;
        let target_distribution = self.target_distribution.as_ref()?;

        let adjusted_temporal = self.calculate_temporal_score(
            self.calculate_base_score(self.calculate_adjusted_impact()?)?,
        );
        let environmental_score = (adjusted_temporal?
            + (10.0 - adjusted_temporal?) * collateral_damage_potential.score())
            * target_distribution.score();

        Some(round_to_first_decimal(environmental_score))
    }

    /// Calculates the adjusted impact score from the impact and requirement metrics.
    pub fn calculate_adjusted_impact(&self) -> Option<f64> {
        let cr = self.confidentiality_requirement.as_ref()?;
        let ci = self.confidentiality_impact.as_ref()?;
        let ir = self.integrity_requirement.as_ref()?;
        let ii = self.integrity_impact.as_ref()?;
        let ar = self.availability_requirement.as_ref()?;
        let ai = self.availability_impact.as_ref()?;

        Some(
            (10.41
                * (1.0
                    - (1.0 - ci.score() * cr.score())
                        * (1.0 - ii.score() * ir.score())
                        * (1.0 - ai.score() * ar.score())))
            .min(10.0),
        )
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
            exploitability: None,
            remediation_level: None,
            report_confidence: None,
            collateral_damage_potential: None,
            target_distribution: None,
            confidentiality_requirement: None,
            integrity_requirement: None,
            availability_requirement: None,
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
                // Temporal metrics
                "E" => {
                    cvss.exploitability =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "RL" => {
                    cvss.remediation_level =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "RC" => {
                    cvss.report_confidence =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                // Environmental metrics
                "CDP" => {
                    cvss.collateral_damage_potential =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "TD" => {
                    cvss.target_distribution =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "CR" => {
                    cvss.confidentiality_requirement =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "IR" => {
                    cvss.integrity_requirement =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "AR" => {
                    cvss.availability_requirement =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                _ => {
                    // Silently ignore unknown metrics to be lenient with parsing
                    // This allows us to parse vectors even if they have metrics we don't recognize
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
