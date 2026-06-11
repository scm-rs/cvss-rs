//! Represents the CVSS v4.0 specification.

mod lookup;
mod score;
mod scoring;

pub use score::Nomenclature;

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::utils::{parse_metrics::parse_metric, prefix};
use crate::{ParseError, Severity as UnifiedSeverity, Version};

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
    pub sub_confidentiality_impact: Option<SubsequentImpact>,
    /// Subsequent System Integrity Impact (SI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_integrity_impact: Option<SubsequentImpact>,
    /// Subsequent System Availability Impact (SA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_availability_impact: Option<SubsequentImpact>,

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
    pub modified_attack_vector: Option<ModifiedAttackVector>,
    /// Modified Attack Complexity (MAC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_complexity: Option<ModifiedAttackComplexity>,
    /// Modified Attack Requirements (MAT).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_requirements: Option<ModifiedAttackRequirements>,
    /// Modified Privileges Required (MPR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_privileges_required: Option<ModifiedPrivilegesRequired>,
    /// Modified User Interaction (MUI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_user_interaction: Option<ModifiedUserInteraction>,
    /// Modified Vulnerable System Confidentiality Impact (MVC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_vuln_confidentiality_impact: Option<ModifiedImpact>,
    /// Modified Vulnerable System Integrity Impact (MVI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_vuln_integrity_impact: Option<ModifiedImpact>,
    /// Modified Vulnerable System Availability Impact (MVA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_vuln_availability_impact: Option<ModifiedImpact>,
    /// Modified Subsequent System Confidentiality Impact (MSC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_sub_confidentiality_impact: Option<ModifiedSubsequentImpact>,
    /// Modified Subsequent System Integrity Impact (MSI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_sub_integrity_impact: Option<ModifiedSubsequentImpact>,
    /// Modified Subsequent System Availability Impact (MSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_sub_availability_impact: Option<ModifiedSubsequentImpact>,

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

/// Attack Vector (AV).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
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
            AttackVector::Adjacent => 0.1,
            AttackVector::Local => 0.2,
            AttackVector::Physical => 0.3,
        }
    }
}

/// Modified Attack Vector (MAV). Extends AttackVector with NotDefined (X).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModifiedAttackVector {
    #[strum(serialize = "N")]
    Network,
    #[strum(serialize = "A")]
    Adjacent,
    #[strum(serialize = "L")]
    Local,
    #[strum(serialize = "P")]
    Physical,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Attack Complexity (AC).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
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
            AttackComplexity::High => 0.1,
        }
    }
}

/// Modified Attack Complexity (MAC). Extends AttackComplexity with NotDefined (X).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum ModifiedAttackComplexity {
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Attack Requirements (AT).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
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
            AttackRequirements::Present => 0.1,
        }
    }
}

/// Modified Attack Requirements (MAT). Extends AttackRequirements with NotDefined (X).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum ModifiedAttackRequirements {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "P")]
    Present,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Privileges Required (PR).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
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
            PrivilegesRequired::Low => 0.1,
            PrivilegesRequired::High => 0.2,
        }
    }
}

/// Modified Privileges Required (MPR). Extends PrivilegesRequired with NotDefined (X).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum ModifiedPrivilegesRequired {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "X")]
    NotDefined,
}

/// User Interaction (UI).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
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
            UserInteraction::Passive => 0.1,
            UserInteraction::Active => 0.2,
        }
    }
}

/// Modified User Interaction (MUI). Extends UserInteraction with NotDefined (X).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum ModifiedUserInteraction {
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "P")]
    Passive,
    #[strum(serialize = "A")]
    Active,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Impact metrics for vulnerable system (VC, VI, VA).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
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
            Impact::Low => 0.1,
            Impact::None => 0.2,
        }
    }
}

/// Modified impact metrics for vulnerable system (MVC, MVI, MVA). Extends Impact with NotDefined (X).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum ModifiedImpact {
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "N")]
    None,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Impact metrics for subsequent system (SC, SI, SA).
/// Includes Safety variant which is unique to subsequent system impacts.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum SubsequentImpact {
    #[strum(serialize = "S")]
    Safety,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "N")]
    None,
}

impl SubsequentImpact {
    pub fn level(&self) -> f64 {
        match self {
            SubsequentImpact::Safety => 0.0,
            SubsequentImpact::High => 0.1,
            SubsequentImpact::Low => 0.2,
            SubsequentImpact::None => 0.3,
        }
    }
}

/// Modified impact metrics for subsequent system (MSC, MSI, MSA). Extends SubsequentImpact with NotDefined (X).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum ModifiedSubsequentImpact {
    #[strum(serialize = "S")]
    Safety,
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "N")]
    Negligible,
    #[strum(serialize = "X")]
    NotDefined,
}

/// Exploit Maturity (E).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
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
            ExploitMaturity::ProofOfConcept => 0.1,
            ExploitMaturity::Unreported => 0.2,
            ExploitMaturity::NotDefined => 0.2, // NotDefined defaults to Unreported
        }
    }
}

/// Requirement metrics (CR, IR, AR).
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum Requirement {
    #[strum(serialize = "H")]
    High,
    #[strum(serialize = "M")]
    Medium,
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "X")]
    NotDefined,
}

impl Requirement {
    pub fn level(&self) -> f64 {
        match self {
            Requirement::High | Requirement::NotDefined => 0.0,
            Requirement::Medium => 0.1,
            Requirement::Low => 0.2,
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
#[strum(ascii_case_insensitive)]
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
    /// This uses the CVSS v4.0 MacroVector-based scoring algorithm as specified in:
    /// <https://www.first.org/cvss/v4.0/specification-document>
    ///
    /// The score is rounded to one decimal place as required by the specification.
    ///
    /// Note: In CVSS v4.0, the "base score" excludes threat metrics (like E) for
    /// backwards compatibility with the CVSS v3.x schema, even though CVSS v4.0
    /// conceptually has a unified score. Use `calculated_full_score()` if you need
    /// the full score including threat metrics.
    pub fn calculated_base_score(&self) -> Option<f64> {
        let score = scoring::calculate_base_score(self)?;
        Some(score::round_v4(score))
    }

    /// Calculates the full CVSS v4.0 score including threat metrics (E).
    /// Returns None if required base metrics are missing.
    ///
    /// This includes the Exploit Maturity (E) metric in the score calculation.
    /// For base score only (excluding E), use `calculated_base_score()`.
    pub fn calculated_full_score(&self) -> Option<f64> {
        let score = scoring::calculate_score(self)?;
        Some(score::round_v4(score))
    }

    /// Calculates the CVSS v4.0 score and returns it along with the appropriate nomenclature.
    ///
    /// Returns a tuple of (score, nomenclature) where:
    /// - score: The calculated CVSS v4.0 score (0.0-10.0), rounded to one decimal place
    /// - nomenclature: The appropriate nomenclature based on which metrics are present:
    ///   - CVSS-B: Base metrics only
    ///   - CVSS-BT: Base + Threat metrics
    ///   - CVSS-BE: Base + Environmental metrics
    ///   - CVSS-BTE: Base + Threat + Environmental metrics
    ///
    /// Returns None if required base metrics are missing.
    pub fn calculated_score(&self) -> Option<(f64, Nomenclature)> {
        let score = scoring::calculate_score(self)?;
        let rounded_score = score::round_v4(score);
        let nomenclature = Nomenclature::from(self);
        Some((rounded_score, nomenclature))
    }
}

impl FromStr for CvssV4 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Extract and validate version prefix
        let (version, components_str) = prefix::extract_version_from_required_prefix(s)?;

        // Must be 4.0
        prefix::validate_allowed_prefix_version(&version, &[Version::V4])?;

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
                // Base metrics
                "AV" => parse_metric(&mut cvss.attack_vector, &value, &key)?,
                "AC" => parse_metric(&mut cvss.attack_complexity, &value, &key)?,
                "AT" => parse_metric(&mut cvss.attack_requirements, &value, &key)?,
                "PR" => parse_metric(&mut cvss.privileges_required, &value, &key)?,
                "UI" => parse_metric(&mut cvss.user_interaction, &value, &key)?,
                "VC" => parse_metric(&mut cvss.vuln_confidentiality_impact, &value, &key)?,
                "VI" => parse_metric(&mut cvss.vuln_integrity_impact, &value, &key)?,
                "VA" => parse_metric(&mut cvss.vuln_availability_impact, &value, &key)?,
                "SC" => parse_metric(&mut cvss.sub_confidentiality_impact, &value, &key)?,
                "SI" => parse_metric(&mut cvss.sub_integrity_impact, &value, &key)?,
                "SA" => parse_metric(&mut cvss.sub_availability_impact, &value, &key)?,
                // Threat metrics
                "E" => parse_metric(&mut cvss.exploit_maturity, &value, &key)?,
                // Environmental metrics
                "CR" => parse_metric(&mut cvss.confidentiality_requirement, &value, &key)?,
                "IR" => parse_metric(&mut cvss.integrity_requirement, &value, &key)?,
                "AR" => parse_metric(&mut cvss.availability_requirement, &value, &key)?,
                // Modified base metrics
                "MAV" => parse_metric(&mut cvss.modified_attack_vector, &value, &key)?,
                "MAC" => parse_metric(&mut cvss.modified_attack_complexity, &value, &key)?,
                "MAT" => parse_metric(&mut cvss.modified_attack_requirements, &value, &key)?,
                "MPR" => parse_metric(&mut cvss.modified_privileges_required, &value, &key)?,
                "MUI" => parse_metric(&mut cvss.modified_user_interaction, &value, &key)?,
                "MVC" => {
                    parse_metric(&mut cvss.modified_vuln_confidentiality_impact, &value, &key)?
                }
                "MVI" => parse_metric(&mut cvss.modified_vuln_integrity_impact, &value, &key)?,
                "MVA" => parse_metric(&mut cvss.modified_vuln_availability_impact, &value, &key)?,
                "MSC" => parse_metric(&mut cvss.modified_sub_confidentiality_impact, &value, &key)?,
                "MSI" => parse_metric(&mut cvss.modified_sub_integrity_impact, &value, &key)?,
                "MSA" => parse_metric(&mut cvss.modified_sub_availability_impact, &value, &key)?,
                // Supplemental metrics
                "S" => parse_metric(&mut cvss.safety, &value, &key)?,
                "AU" => parse_metric(&mut cvss.automatable, &value, &key)?,
                "R" => parse_metric(&mut cvss.recovery, &value, &key)?,
                "V" => parse_metric(&mut cvss.value_density, &value, &key)?,
                "RE" => parse_metric(&mut cvss.vulnerability_response_effort, &value, &key)?,
                "U" => parse_metric(&mut cvss.provider_urgency, &value, &key)?,
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
