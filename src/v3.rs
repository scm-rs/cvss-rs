//! Represents the CVSS v3.0 and v3.1 specifications.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use strum::{Display, EnumString};

use crate::{ParseError, Severity as UnifiedSeverity};

/// Represents a CVSS v3.0 or v3.1 score object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV3 {
    /// The CVSS vector string.
    pub vector_string: String,
    /// The base score, a value between 0.0 and 10.0.
    pub base_score: f64,
    /// The qualitative severity rating for the base score.
    pub base_severity: Severity,
    /// The attack vector metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_vector: Option<AttackVector>,
    /// The attack complexity metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_complexity: Option<AttackComplexity>,
    /// The privileges required metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges_required: Option<PrivilegesRequired>,
    /// The user interaction metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_interaction: Option<UserInteraction>,
    /// The scope metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// The confidentiality impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_impact: Option<Impact>,
    /// The integrity impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_impact: Option<Impact>,
    /// The availability impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_impact: Option<Impact>,

    // Temporal Metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal_severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exploit_code_maturity: Option<ExploitCodeMaturity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_level: Option<RemediationLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_confidence: Option<ReportConfidence>,

    // Environmental Metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environmental_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environmental_severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_requirement: Option<SecurityRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_requirement: Option<SecurityRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_requirement: Option<SecurityRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_vector: Option<AttackVector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_complexity: Option<AttackComplexity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_privileges_required: Option<PrivilegesRequired>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_user_interaction: Option<UserInteraction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_scope: Option<Scope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_confidentiality_impact: Option<Impact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_integrity_impact: Option<Impact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_availability_impact: Option<Impact>,
}

/// Represents the qualitative severity rating of a vulnerability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Represents the attack vector metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackVector {
    #[strum(serialize = "N")]
    Network,
    #[strum(serialize = "A")]
    AdjacentNetwork,
    #[strum(serialize = "L")]
    Local,
    #[strum(serialize = "P")]
    Physical,
    #[strum(serialize = "X")]
    NotDefined,
}

impl AttackVector {
    /// Returns the numeric score for this metric per CVSS v3.x specification.
    pub fn score(&self) -> f64 {
        match self {
            AttackVector::Network => 0.85,
            AttackVector::AdjacentNetwork => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.20,
            AttackVector::NotDefined => 0.85, // Defaults to worst case (Network)
        }
    }
}

/// Represents the attack complexity metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackComplexity {
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "X")]
    NotDefined,
}

impl AttackComplexity {
    /// Returns the numeric score for this metric per CVSS v3.x specification.
    pub fn score(&self) -> f64 {
        match self {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
            AttackComplexity::NotDefined => 0.77, // Defaults to worst case (Low)
        }
    }
}

/// Represents the privileges required metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivilegesRequired {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Represents the user interaction metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserInteraction {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "R")]
    Required,
    #[strum(serialize = "X")]
    NotDefined,
}

impl UserInteraction {
    /// Returns the numeric score for this metric per CVSS v3.x specification.
    pub fn score(&self) -> f64 {
        match self {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
            UserInteraction::NotDefined => 0.85, // Defaults to worst case (None)
        }
    }
}

/// Represents the scope metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Scope {
    #[strum(serialize = "U")]
    Unchanged,
    #[strum(serialize = "C")]
    Changed,
    #[strum(serialize = "X")]
    NotDefined,
}

impl Scope {
    /// Returns whether the scope is changed (for use in score calculation).
    pub fn is_changed(&self) -> bool {
        matches!(self, Scope::Changed)
    }
}

/// Represents the impact metrics (confidentiality, integrity, availability).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Impact {
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "X")]
    NotDefined,
}

impl Impact {
    /// Returns the numeric score for this metric per CVSS v3.x specification.
    pub fn score(&self) -> f64 {
        match self {
            Impact::High => 0.56,
            Impact::Low => 0.22,
            Impact::None => 0.0,
            Impact::NotDefined => 0.56, // Defaults to worst case (High)
        }
    }
}

/// Represents the exploit code maturity metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExploitCodeMaturity {
    #[strum(serialize = "U")]
    Unproven,
    #[strum(serialize = "P")]
    ProofOfConcept,
    #[strum(serialize = "F")]
    Functional,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "X")]
    NotDefined,
}

impl ExploitCodeMaturity {
    /// Returns the temporal score multiplier for this metric per CVSS v3.x specification.
    pub fn score(&self) -> f64 {
        match self {
            ExploitCodeMaturity::Unproven => 0.91,
            ExploitCodeMaturity::ProofOfConcept => 0.94,
            ExploitCodeMaturity::Functional => 0.97,
            ExploitCodeMaturity::High => 1.0,
            ExploitCodeMaturity::NotDefined => 1.0,
        }
    }
}

/// Represents the remediation level metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemediationLevel {
    #[strum(serialize = "O")]
    OfficialFix,
    #[strum(serialize = "T")]
    TemporaryFix,
    #[strum(serialize = "W")]
    Workaround,
    #[strum(serialize = "U")]
    Unavailable,
    #[strum(serialize = "X")]
    NotDefined,
}

impl RemediationLevel {
    /// Returns the temporal score multiplier for this metric per CVSS v3.x specification.
    pub fn score(&self) -> f64 {
        match self {
            RemediationLevel::OfficialFix => 0.95,
            RemediationLevel::TemporaryFix => 0.96,
            RemediationLevel::Workaround => 0.97,
            RemediationLevel::Unavailable => 1.0,
            RemediationLevel::NotDefined => 1.0,
        }
    }
}

/// Represents the report confidence metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportConfidence {
    #[strum(serialize = "U")]
    Unknown,
    #[strum(serialize = "R")]
    Reasonable,
    #[strum(serialize = "C")]
    Confirmed,
    #[strum(serialize = "X")]
    NotDefined,
}

impl ReportConfidence {
    /// Returns the temporal score multiplier for this metric per CVSS v3.x specification.
    pub fn score(&self) -> f64 {
        match self {
            ReportConfidence::Unknown => 0.92,
            ReportConfidence::Reasonable => 0.96,
            ReportConfidence::Confirmed => 1.0,
            ReportConfidence::NotDefined => 1.0,
        }
    }
}

/// Represents the security requirement metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityRequirement {
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "M")]
    Medium,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "X")]
    NotDefined,
}

impl SecurityRequirement {
    /// Returns the environmental score multiplier for this metric per CVSS v3.x specification.
    pub fn score(&self) -> f64 {
        match self {
            SecurityRequirement::Low => 0.5,
            SecurityRequirement::Medium => 1.0,
            SecurityRequirement::High => 1.5,
            SecurityRequirement::NotDefined => 1.0,
        }
    }
}

impl CvssV3 {
    pub fn vector_string(&self) -> &str {
        &self.vector_string
    }

    pub fn base_score(&self) -> f64 {
        self.base_score
    }

    pub fn base_severity(&self) -> Option<UnifiedSeverity> {
        Some(match self.base_severity {
            Severity::None => UnifiedSeverity::None,
            Severity::Low => UnifiedSeverity::Low,
            Severity::Medium => UnifiedSeverity::Medium,
            Severity::High => UnifiedSeverity::High,
            Severity::Critical => UnifiedSeverity::Critical,
        })
    }
}

impl FromStr for CvssV3 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut components = s.split('/');

        // Parse version prefix (e.g., "CVSS:3.1")
        let version_component = components.next().ok_or_else(|| ParseError::InvalidPrefix {
            found: String::new(),
        })?;

        let mut version_parts = version_component.split(':');
        let prefix = version_parts
            .next()
            .ok_or_else(|| ParseError::InvalidPrefix {
                found: version_component.to_string(),
            })?;

        if !prefix.eq_ignore_ascii_case("CVSS") {
            return Err(ParseError::InvalidPrefix {
                found: prefix.to_string(),
            });
        }

        let version = version_parts
            .next()
            .ok_or_else(|| ParseError::InvalidVersion {
                version: version_component.to_string(),
            })?;

        if version != "3.0" && version != "3.1" {
            return Err(ParseError::InvalidVersion {
                version: version.to_string(),
            });
        }

        // Initialize a CvssV3 with empty fields
        let mut cvss = CvssV3 {
            vector_string: s.to_string(),
            base_score: 0.0,
            base_severity: Severity::None,
            attack_vector: None,
            attack_complexity: None,
            privileges_required: None,
            user_interaction: None,
            scope: None,
            confidentiality_impact: None,
            integrity_impact: None,
            availability_impact: None,
            temporal_score: None,
            temporal_severity: None,
            exploit_code_maturity: None,
            remediation_level: None,
            report_confidence: None,
            environmental_score: None,
            environmental_severity: None,
            confidentiality_requirement: None,
            integrity_requirement: None,
            availability_requirement: None,
            modified_attack_vector: None,
            modified_attack_complexity: None,
            modified_privileges_required: None,
            modified_user_interaction: None,
            modified_scope: None,
            modified_confidentiality_impact: None,
            modified_integrity_impact: None,
            modified_availability_impact: None,
        };

        // Parse metrics
        for component in components {
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
                // Base metrics
                "AV" => {
                    cvss.attack_vector =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "AC" => {
                    cvss.attack_complexity =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "PR" => {
                    cvss.privileges_required =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "UI" => {
                    cvss.user_interaction =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "S" => {
                    cvss.scope =
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
                    cvss.exploit_code_maturity =
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
                "MAV" => {
                    cvss.modified_attack_vector =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MAC" => {
                    cvss.modified_attack_complexity =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MPR" => {
                    cvss.modified_privileges_required =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MUI" => {
                    cvss.modified_user_interaction =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MS" => {
                    cvss.modified_scope =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MC" => {
                    cvss.modified_confidentiality_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MI" => {
                    cvss.modified_integrity_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MA" => {
                    cvss.modified_availability_impact =
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

impl fmt::Display for CvssV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Determine version from the stored vector_string if possible, default to 3.1
        let version = if self.vector_string.starts_with("CVSS:3.0") {
            "3.0"
        } else {
            "3.1"
        };

        write!(f, "CVSS:{}", version)?;

        // Base metrics
        if let Some(av) = &self.attack_vector {
            write!(f, "/AV:{}", av)?;
        }
        if let Some(ac) = &self.attack_complexity {
            write!(f, "/AC:{}", ac)?;
        }
        if let Some(pr) = &self.privileges_required {
            write!(f, "/PR:{}", pr)?;
        }
        if let Some(ui) = &self.user_interaction {
            write!(f, "/UI:{}", ui)?;
        }
        if let Some(s) = &self.scope {
            write!(f, "/S:{}", s)?;
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

        // Temporal metrics
        if let Some(e) = &self.exploit_code_maturity {
            write!(f, "/E:{}", e)?;
        }
        if let Some(rl) = &self.remediation_level {
            write!(f, "/RL:{}", rl)?;
        }
        if let Some(rc) = &self.report_confidence {
            write!(f, "/RC:{}", rc)?;
        }

        // Environmental metrics
        if let Some(cr) = &self.confidentiality_requirement {
            write!(f, "/CR:{}", cr)?;
        }
        if let Some(ir) = &self.integrity_requirement {
            write!(f, "/IR:{}", ir)?;
        }
        if let Some(ar) = &self.availability_requirement {
            write!(f, "/AR:{}", ar)?;
        }
        if let Some(mav) = &self.modified_attack_vector {
            write!(f, "/MAV:{}", mav)?;
        }
        if let Some(mac) = &self.modified_attack_complexity {
            write!(f, "/MAC:{}", mac)?;
        }
        if let Some(mpr) = &self.modified_privileges_required {
            write!(f, "/MPR:{}", mpr)?;
        }
        if let Some(mui) = &self.modified_user_interaction {
            write!(f, "/MUI:{}", mui)?;
        }
        if let Some(ms) = &self.modified_scope {
            write!(f, "/MS:{}", ms)?;
        }
        if let Some(mc) = &self.modified_confidentiality_impact {
            write!(f, "/MC:{}", mc)?;
        }
        if let Some(mi) = &self.modified_integrity_impact {
            write!(f, "/MI:{}", mi)?;
        }
        if let Some(ma) = &self.modified_availability_impact {
            write!(f, "/MA:{}", ma)?;
        }

        Ok(())
    }
}
