//! Represents the CVSS v4.0 specification.

mod lookup;
mod score;
mod scoring;

pub use score::Nomenclature;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use strum::{Display, EnumString};

use crate::{ParseError, Severity as UnifiedSeverity};

/// Represents a CVSS v4.0 score object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV4 {
    /// The CVSS vector string.
    pub vector_string: String,
    /// The base score, a value between 0.0 and 10.0.
    pub base_score: f64,
    /// The qualitative severity rating for the base score.
    pub base_severity: Severity,

    // --- Base Metrics ---
    /// Attack Vector (AV).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_vector: Option<AttackVector>,
    /// Attack Complexity (AC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_complexity: Option<AttackComplexity>,
    /// Attack Requirements (AT).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_requirements: Option<AttackRequirements>,
    /// Privileges Required (PR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges_required: Option<PrivilegesRequired>,
    /// User Interaction (UI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_interaction: Option<UserInteraction>,
    /// Vulnerable System Confidentiality Impact (VC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vuln_confidentiality_impact: Option<Impact>,
    /// Vulnerable System Integrity Impact (VI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vuln_integrity_impact: Option<Impact>,
    /// Vulnerable System Availability Impact (VA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vuln_availability_impact: Option<Impact>,
    /// Subsequent System Confidentiality Impact (SC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_confidentiality_impact: Option<Impact>,
    /// Subsequent System Integrity Impact (SI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_integrity_impact: Option<Impact>,
    /// Subsequent System Availability Impact (SA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_availability_impact: Option<Impact>,

    // --- Threat Metrics ---
    /// Exploit Maturity (E).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exploit_maturity: Option<ExploitMaturity>,

    // --- Environmental Metrics ---
    /// Confidentiality Requirement (CR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_requirement: Option<Requirement>,
    /// Integrity Requirement (IR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_requirement: Option<Requirement>,
    /// Availability Requirement (AR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_requirement: Option<Requirement>,
    /// Modified Attack Vector (MAV).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_vector: Option<AttackVector>,
    /// Modified Attack Complexity (MAC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_complexity: Option<AttackComplexity>,
    /// Modified Attack Requirements (MAT).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_requirements: Option<AttackRequirements>,
    /// Modified Privileges Required (MPR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_privileges_required: Option<PrivilegesRequired>,
    /// Modified User Interaction (MUI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_user_interaction: Option<UserInteraction>,
    /// Modified Vulnerable System Confidentiality Impact (MVC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_vuln_confidentiality_impact: Option<Impact>,
    /// Modified Vulnerable System Integrity Impact (MVI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_vuln_integrity_impact: Option<Impact>,
    /// Modified Vulnerable System Availability Impact (MVA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_vuln_availability_impact: Option<Impact>,
    /// Modified Subsequent System Confidentiality Impact (MSC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_sub_confidentiality_impact: Option<Impact>,
    /// Modified Subsequent System Integrity Impact (MSI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_sub_integrity_impact: Option<Impact>,
    /// Modified Subsequent System Availability Impact (MSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_sub_availability_impact: Option<Impact>,

    // --- Supplemental Metrics ---
    #[serde(rename = "Safety")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety: Option<Safety>,
    #[serde(rename = "Automatable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automatable: Option<Automatable>,
    #[serde(rename = "Recovery")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<Recovery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_density: Option<ValueDensity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerability_response_effort: Option<VulnerabilityResponseEffort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_urgency: Option<ProviderUrgency>,
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

/// Attack Vector (AV) / Modified Attack Vector (MAV).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackVector {
    #[strum(serialize = "N")]
    Network,
    #[strum(serialize = "A")]
    Adjacent,
    #[strum(serialize = "L")]
    Local,
    #[strum(serialize = "P")]
    Physical,
}

impl AttackVector {
    pub fn level(&self) -> f64 {
        match self {
            AttackVector::Network => 0.0,
            AttackVector::Adjacent => 1.0,
            AttackVector::Local => 2.0,
            AttackVector::Physical => 3.0,
        }
    }
}

/// Attack Complexity (AC) / Modified Attack Complexity (MAC).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackComplexity {
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "H")]
    High,
}

impl AttackComplexity {
    pub fn level(&self) -> f64 {
        match self {
            AttackComplexity::Low => 0.0,
            AttackComplexity::High => 1.0,
        }
    }
}

/// Attack Requirements (AT) / Modified Attack Requirements (MAT).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackRequirements {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "P")]
    Present,
}

impl AttackRequirements {
    pub fn level(&self) -> f64 {
        match self {
            AttackRequirements::None => 0.0,
            AttackRequirements::Present => 1.0,
        }
    }
}

/// Privileges Required (PR) / Modified Privileges Required (MPR).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivilegesRequired {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "H")]
    High,
}

impl PrivilegesRequired {
    pub fn level(&self) -> f64 {
        match self {
            PrivilegesRequired::None => 0.0,
            PrivilegesRequired::Low => 1.0,
            PrivilegesRequired::High => 2.0,
        }
    }
}

/// User Interaction (UI) / Modified User Interaction (MUI).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum UserInteraction {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "P")]
    Passive,
    #[strum(serialize = "A")]
    Active,
}

impl UserInteraction {
    pub fn level(&self) -> f64 {
        match self {
            UserInteraction::None => 0.0,
            UserInteraction::Passive => 1.0,
            UserInteraction::Active => 2.0,
        }
    }
}

/// Impact metrics (VC, VI, VA, SC, SI, SA and their modified versions).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum Impact {
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "N")]
    None,
}

impl Impact {
    pub fn level(&self) -> f64 {
        match self {
            Impact::High => 0.0,
            Impact::Low => 1.0,
            Impact::None => 2.0,
        }
    }
}

/// Exploit Maturity (E).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExploitMaturity {
    #[strum(serialize = "A")]
    Attacked,
    #[strum(serialize = "P")]
    ProofOfConcept,
    #[strum(serialize = "U")]
    Unreported,
    #[strum(serialize = "X")]
    NotDefined,
}

impl ExploitMaturity {
    pub fn level(&self) -> f64 {
        match self {
            ExploitMaturity::Attacked => 0.0,
            ExploitMaturity::ProofOfConcept => 1.0,
            ExploitMaturity::Unreported => 2.0,
            ExploitMaturity::NotDefined => 2.0, // NotDefined defaults to Unreported
        }
    }
}

/// Requirement metrics (CR, IR, AR).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum Requirement {
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "M")]
    Medium,
    #[strum(serialize = "L")]
    Low,
}

impl Requirement {
    pub fn level(&self) -> f64 {
        match self {
            Requirement::High => 0.0,
            Requirement::Medium => 1.0,
            Requirement::Low => 2.0,
        }
    }
}

/// Safety (S).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Safety {
    #[strum(serialize = "N")]
    Negligible,
    #[strum(serialize = "P")]
    Present,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Automatable (AU).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Automatable {
    #[strum(serialize = "N")]
    No,
    #[strum(serialize = "Y")]
    Yes,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Recovery (R).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Recovery {
    #[strum(serialize = "A")]
    Automatic,
    #[strum(serialize = "U")]
    User,
    #[strum(serialize = "I")]
    Irrecoverable,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Value Density (V).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValueDensity {
    #[strum(serialize = "D")]
    Diffuse,
    #[strum(serialize = "C")]
    Concentrated,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Vulnerability Response Effort (RE).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VulnerabilityResponseEffort {
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "M")]
    Moderate,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Provider Urgency (U).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderUrgency {
    #[strum(serialize = "Clear")]
    Clear,
    #[strum(serialize = "Green")]
    Green,
    #[strum(serialize = "Amber")]
    Amber,
    #[strum(serialize = "Red")]
    Red,
    #[strum(serialize = "X")]
    NotDefined,
}

impl CvssV4 {
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

    /// Calculates the base score from the base metrics.
    /// Returns None if required base metrics are missing.
    ///
    /// TODO: CVSS v4.0 score calculation is not yet implemented.
    /// CVSS v4.0 uses a complex lookup-table based algorithm (MacroVector)
    /// and nomenclature system (CVSS-B, CVSS-BT, CVSS-BE, CVSS-BTE).
    /// This requires implementing the full specification from:
    /// https://www.first.org/cvss/v4.0/specification-document
    pub fn calculated_base_score(&self) -> Option<f64> {
        // TODO: Implement CVSS v4.0 base score calculation
        None
    }
}

impl FromStr for CvssV4 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut components = s.split('/');

        // Parse version prefix (e.g., "CVSS:4.0")
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

        if version != "4.0" {
            return Err(ParseError::InvalidVersion {
                version: version.to_string(),
            });
        }

        // Initialize a CvssV4 with empty fields
        let mut cvss = CvssV4 {
            vector_string: s.to_string(),
            base_score: 0.0,
            base_severity: Severity::None,
            attack_vector: None,
            attack_complexity: None,
            attack_requirements: None,
            privileges_required: None,
            user_interaction: None,
            vuln_confidentiality_impact: None,
            vuln_integrity_impact: None,
            vuln_availability_impact: None,
            sub_confidentiality_impact: None,
            sub_integrity_impact: None,
            sub_availability_impact: None,
            exploit_maturity: None,
            confidentiality_requirement: None,
            integrity_requirement: None,
            availability_requirement: None,
            modified_attack_vector: None,
            modified_attack_complexity: None,
            modified_attack_requirements: None,
            modified_privileges_required: None,
            modified_user_interaction: None,
            modified_vuln_confidentiality_impact: None,
            modified_vuln_integrity_impact: None,
            modified_vuln_availability_impact: None,
            modified_sub_confidentiality_impact: None,
            modified_sub_integrity_impact: None,
            modified_sub_availability_impact: None,
            safety: None,
            automatable: None,
            recovery: None,
            value_density: None,
            vulnerability_response_effort: None,
            provider_urgency: None,
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
                "AT" => {
                    cvss.attack_requirements =
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
                "VC" => {
                    cvss.vuln_confidentiality_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "VI" => {
                    cvss.vuln_integrity_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "VA" => {
                    cvss.vuln_availability_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "SC" => {
                    cvss.sub_confidentiality_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "SI" => {
                    cvss.sub_integrity_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "SA" => {
                    cvss.sub_availability_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                // Threat metrics
                "E" => {
                    cvss.exploit_maturity =
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
                "MAT" => {
                    cvss.modified_attack_requirements =
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
                "MVC" => {
                    cvss.modified_vuln_confidentiality_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MVI" => {
                    cvss.modified_vuln_integrity_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MVA" => {
                    cvss.modified_vuln_availability_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MSC" => {
                    cvss.modified_sub_confidentiality_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MSI" => {
                    cvss.modified_sub_integrity_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "MSA" => {
                    cvss.modified_sub_availability_impact =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                // Supplemental metrics
                "S" => {
                    cvss.safety =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "AU" => {
                    cvss.automatable =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "R" => {
                    cvss.recovery =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "V" => {
                    cvss.value_density =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "RE" => {
                    cvss.vulnerability_response_effort =
                        Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
                            metric: key.clone(),
                            value: value.clone(),
                        })?);
                }
                "U" => {
                    cvss.provider_urgency =
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

impl fmt::Display for CvssV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CVSS:4.0")?;

        // Base metrics
        if let Some(av) = &self.attack_vector {
            write!(f, "/AV:{}", av)?;
        }
        if let Some(ac) = &self.attack_complexity {
            write!(f, "/AC:{}", ac)?;
        }
        if let Some(at) = &self.attack_requirements {
            write!(f, "/AT:{}", at)?;
        }
        if let Some(pr) = &self.privileges_required {
            write!(f, "/PR:{}", pr)?;
        }
        if let Some(ui) = &self.user_interaction {
            write!(f, "/UI:{}", ui)?;
        }
        if let Some(vc) = &self.vuln_confidentiality_impact {
            write!(f, "/VC:{}", vc)?;
        }
        if let Some(vi) = &self.vuln_integrity_impact {
            write!(f, "/VI:{}", vi)?;
        }
        if let Some(va) = &self.vuln_availability_impact {
            write!(f, "/VA:{}", va)?;
        }
        if let Some(sc) = &self.sub_confidentiality_impact {
            write!(f, "/SC:{}", sc)?;
        }
        if let Some(si) = &self.sub_integrity_impact {
            write!(f, "/SI:{}", si)?;
        }
        if let Some(sa) = &self.sub_availability_impact {
            write!(f, "/SA:{}", sa)?;
        }

        // Threat metrics
        if let Some(e) = &self.exploit_maturity {
            write!(f, "/E:{}", e)?;
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
        if let Some(mat) = &self.modified_attack_requirements {
            write!(f, "/MAT:{}", mat)?;
        }
        if let Some(mpr) = &self.modified_privileges_required {
            write!(f, "/MPR:{}", mpr)?;
        }
        if let Some(mui) = &self.modified_user_interaction {
            write!(f, "/MUI:{}", mui)?;
        }
        if let Some(mvc) = &self.modified_vuln_confidentiality_impact {
            write!(f, "/MVC:{}", mvc)?;
        }
        if let Some(mvi) = &self.modified_vuln_integrity_impact {
            write!(f, "/MVI:{}", mvi)?;
        }
        if let Some(mva) = &self.modified_vuln_availability_impact {
            write!(f, "/MVA:{}", mva)?;
        }
        if let Some(msc) = &self.modified_sub_confidentiality_impact {
            write!(f, "/MSC:{}", msc)?;
        }
        if let Some(msi) = &self.modified_sub_integrity_impact {
            write!(f, "/MSI:{}", msi)?;
        }
        if let Some(msa) = &self.modified_sub_availability_impact {
            write!(f, "/MSA:{}", msa)?;
        }

        // Supplemental metrics
        if let Some(s) = &self.safety {
            write!(f, "/S:{}", s)?;
        }
        if let Some(au) = &self.automatable {
            write!(f, "/AU:{}", au)?;
        }
        if let Some(r) = &self.recovery {
            write!(f, "/R:{}", r)?;
        }
        if let Some(v) = &self.value_density {
            write!(f, "/V:{}", v)?;
        }
        if let Some(re) = &self.vulnerability_response_effort {
            write!(f, "/RE:{}", re)?;
        }
        if let Some(u) = &self.provider_urgency {
            write!(f, "/U:{}", u)?;
        }

        Ok(())
    }
}
