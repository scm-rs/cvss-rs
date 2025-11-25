//! Represents the CVSS v4.0 specification.

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::Severity as UnifiedSeverity;

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

/// Attack Complexity (AC) / Modified Attack Complexity (MAC).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackComplexity {
    #[strum(serialize = "L")]
    Low,
    #[strum(serialize = "H")]
    High,
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
}
