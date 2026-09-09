//! Represents the CVSS v3.0 and v3.1 specifications.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::utils::{format_vector::write_metric, parse_metrics::parse_metric, prefix};
use crate::{
    Defined, ParseError, Severity as UnifiedSeverity, Version, impl_defined, version::VersionV3,
};

/// Represents a CVSS v3.0 or v3.1 score object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CvssV3 {
    /// The CVSS vector string.
    pub vector_string: String,
    /// The specific CVSS v3 version (3.0 or 3.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<VersionV3>,
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

impl PrivilegesRequired {
    /// Returns the numeric score for this metric, accounting for scope.
    /// Per CVSS v3.x specification, the PR score depends on whether scope is changed.
    pub fn score(&self, scope_changed: bool) -> f64 {
        match self {
            PrivilegesRequired::None => 0.85,
            PrivilegesRequired::Low => {
                if scope_changed {
                    0.68
                } else {
                    0.62
                }
            }
            PrivilegesRequired::High => {
                if scope_changed {
                    0.50
                } else {
                    0.27
                }
            }
            PrivilegesRequired::NotDefined => 0.85, // Defaults to worst case (None)
        }
    }
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

impl_defined!(
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Impact,
    ExploitCodeMaturity,
    RemediationLevel,
    ReportConfidence,
    SecurityRequirement,
);

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

    /// Calculates the base score from the base metrics.
    ///
    /// There is no difference in the base score calculation between CVSS v3.0 and v3.1.
    ///
    /// See the [CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations).
    ///
    /// Returns `None` if any required base metric is missing.
    pub fn calculated_base_score(&self) -> Option<f64> {
        let av = self.attack_vector.as_ref()?;
        let ac = self.attack_complexity.as_ref()?;
        let pr = self.privileges_required.as_ref()?;
        let ui = self.user_interaction.as_ref()?;
        let scope = self.scope.as_ref()?;
        let c = self.confidentiality_impact.as_ref()?;
        let i = self.integrity_impact.as_ref()?;
        let a = self.availability_impact.as_ref()?;

        let scope_changed = scope.is_changed();

        // ISS (Impact Sub Score)
        let iss = 1.0 - ((1.0 - c.score()) * (1.0 - i.score()) * (1.0 - a.score()));

        let impact = if scope_changed {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
        } else {
            6.42 * iss
        };

        let exploitability = 8.22 * av.score() * ac.score() * pr.score(scope_changed) * ui.score();

        let score = if impact <= 0.0 {
            0.0
        } else if scope_changed {
            roundup(f64::min(1.08 * (impact + exploitability), 10.0))
        } else {
            roundup(f64::min(impact + exploitability, 10.0))
        };

        Some(score)
    }

    /// Calculates the temporal score from base and temporal metrics.
    ///
    /// Temporal metrics default to 1.0 (NotDefined) when absent.
    /// There is no difference in the temporal score calculation between CVSS v3.0 and v3.1.
    ///
    /// See the [CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document#7-2-Temporal-Metrics-Equations).
    ///
    /// Returns `None` if any required base metric is missing.
    pub fn calculated_temporal_score(&self) -> Option<f64> {
        let base_score = self.calculated_base_score()?;

        let e = self
            .exploit_code_maturity
            .as_ref()
            .map_or(1.0, |m| m.score());
        let rl = self.remediation_level.as_ref().map_or(1.0, |m| m.score());
        let rc = self.report_confidence.as_ref().map_or(1.0, |m| m.score());

        Some(roundup(base_score * e * rl * rc))
    }

    /// Calculates the environmental score from base, temporal, and environmental metrics.
    ///
    /// Modified base metrics default to the corresponding base metric when absent or NotDefined.
    /// The modified impact formula differs between CVSS v3.0 and v3.1.
    ///
    /// See the [CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations)
    /// and the [CVSS v3.0 specification](https://www.first.org/cvss/v3.0/specification-document#8-3-Environmental).
    ///
    /// Returns `None` if any required base metric is missing.
    pub fn calculated_environmental_score(&self) -> Option<f64> {
        let av = self.attack_vector.as_ref()?;
        let ac = self.attack_complexity.as_ref()?;
        let pr = self.privileges_required.as_ref()?;
        let ui = self.user_interaction.as_ref()?;
        let scope = self.scope.as_ref()?;
        let c = self.confidentiality_impact.as_ref()?;
        let i = self.integrity_impact.as_ref()?;
        let a = self.availability_impact.as_ref()?;

        // Modified metrics: if not present or set to NotDefined (X), fall back to base metric
        let mav = self
            .modified_attack_vector
            .as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(av);
        let mac = self
            .modified_attack_complexity
            .as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(ac);
        let mpr = self
            .modified_privileges_required
            .as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(pr);
        let mui = self
            .modified_user_interaction
            .as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(ui);
        let ms = self
            .modified_scope
            .as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(scope);
        let mc = self
            .modified_confidentiality_impact
            .as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(c);
        let mi = self
            .modified_integrity_impact
            .as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(i);
        let ma = self
            .modified_availability_impact
            .as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(a);

        let cr = self
            .confidentiality_requirement
            .as_ref()
            .map_or(1.0, |m| m.score());
        let ir = self
            .integrity_requirement
            .as_ref()
            .map_or(1.0, |m| m.score());
        let ar = self
            .availability_requirement
            .as_ref()
            .map_or(1.0, |m| m.score());

        let scope_changed = ms.is_changed();

        let m_exploitability =
            8.22 * mav.score() * mac.score() * mpr.score(scope_changed) * mui.score();

        // Modified ISS (MISS)
        let m_iss = f64::min(
            1.0 - ((1.0 - cr * mc.score()) * (1.0 - ir * mi.score()) * (1.0 - ar * ma.score())),
            0.915,
        );

        // Modified impact — v3.1 uses a different formula than v3.0
        let m_impact = if scope_changed {
            match self.version {
                Some(VersionV3::V3_1) => {
                    7.52 * (m_iss - 0.029) - 3.25 * (m_iss * 0.9731 - 0.02).powf(13.0)
                }
                _ => 7.52 * (m_iss - 0.029) - 3.25 * (m_iss - 0.02).powf(15.0),
            }
        } else {
            6.42 * m_iss
        };

        let score = if m_impact <= 0.0 {
            0.0
        } else {
            let e = self
                .exploit_code_maturity
                .as_ref()
                .map_or(1.0, |m| m.score());
            let rl = self.remediation_level.as_ref().map_or(1.0, |m| m.score());
            let rc = self.report_confidence.as_ref().map_or(1.0, |m| m.score());

            if scope_changed {
                roundup(roundup(f64::min(1.08 * (m_exploitability + m_impact), 10.0)) * e * rl * rc)
            } else {
                roundup(roundup(f64::min(m_exploitability + m_impact, 10.0)) * e * rl * rc)
            }
        };

        Some(score)
    }
}

/// Rounds up to 1 decimal place as required by the CVSS v3 specification.
///
/// Applying `ceil` directly to a floating-point value can incorrectly round an
/// intended exact tenth because earlier calculations may leave a tiny positive
/// error. The specification avoids that by first normalizing the value to five
/// decimal places and then performing the round-up decision with integer
/// arithmetic.
///
/// See <https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding>.
fn roundup(value: f64) -> f64 {
    // Discard insignificant floating-point noise at the precision prescribed
    // by the specification.
    let int_input = (value * 100000.0).round() as i64;

    // Keep the round-up decision in integer arithmetic. Converting back to a
    // float and calling `ceil` here would reintroduce the precision problem the
    // normalization step is intended to avoid.
    if int_input % 10000 == 0 {
        int_input as f64 / 100000.0
    } else {
        (int_input / 10000 + 1) as f64 / 10.0
    }
}

impl FromStr for CvssV3 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // extract and validate version prefix
        let (version, components_str) = prefix::extract_version_from_required_prefix(s)?;

        // validate that the prefix version is either 3.0 or 3.1
        prefix::validate_allowed_prefix_version(&version, &[Version::V3_0, Version::V3_1])?;

        // map to tightened version enum
        let parsed_version = match version {
            Version::V3_0 => VersionV3::V3_0,
            Version::V3_1 => VersionV3::V3_1,
            _ => unreachable!("validated above"),
        };

        // Initialize a CvssV3 with empty fields
        let mut cvss = CvssV3 {
            vector_string: s.to_string(),
            version: Some(parsed_version),
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
                "PR" => parse_metric(&mut cvss.privileges_required, &value, &key)?,
                "UI" => parse_metric(&mut cvss.user_interaction, &value, &key)?,
                "S" => parse_metric(&mut cvss.scope, &value, &key)?,
                "C" => parse_metric(&mut cvss.confidentiality_impact, &value, &key)?,
                "I" => parse_metric(&mut cvss.integrity_impact, &value, &key)?,
                "A" => parse_metric(&mut cvss.availability_impact, &value, &key)?,
                // Temporal metrics
                "E" => parse_metric(&mut cvss.exploit_code_maturity, &value, &key)?,
                "RL" => parse_metric(&mut cvss.remediation_level, &value, &key)?,
                "RC" => parse_metric(&mut cvss.report_confidence, &value, &key)?,
                // Environmental metrics
                "CR" => parse_metric(&mut cvss.confidentiality_requirement, &value, &key)?,
                "IR" => parse_metric(&mut cvss.integrity_requirement, &value, &key)?,
                "AR" => parse_metric(&mut cvss.availability_requirement, &value, &key)?,
                // Modified metrics
                "MAV" => parse_metric(&mut cvss.modified_attack_vector, &value, &key)?,
                "MAC" => parse_metric(&mut cvss.modified_attack_complexity, &value, &key)?,
                "MPR" => parse_metric(&mut cvss.modified_privileges_required, &value, &key)?,
                "MUI" => parse_metric(&mut cvss.modified_user_interaction, &value, &key)?,
                "MS" => parse_metric(&mut cvss.modified_scope, &value, &key)?,
                "MC" => parse_metric(&mut cvss.modified_confidentiality_impact, &value, &key)?,
                "MI" => parse_metric(&mut cvss.modified_integrity_impact, &value, &key)?,
                "MA" => parse_metric(&mut cvss.modified_availability_impact, &value, &key)?,
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

        write!(f, "CVSS:{version}")?;

        // Base metrics
        write_metric(f, "AV", &self.attack_vector)?;
        write_metric(f, "AC", &self.attack_complexity)?;
        write_metric(f, "PR", &self.privileges_required)?;
        write_metric(f, "UI", &self.user_interaction)?;
        write_metric(f, "S", &self.scope)?;
        write_metric(f, "C", &self.confidentiality_impact)?;
        write_metric(f, "I", &self.integrity_impact)?;
        write_metric(f, "A", &self.availability_impact)?;

        // Temporal metrics
        write_metric(f, "E", &self.exploit_code_maturity)?;
        write_metric(f, "RL", &self.remediation_level)?;
        write_metric(f, "RC", &self.report_confidence)?;

        // Environmental metrics
        write_metric(f, "CR", &self.confidentiality_requirement)?;
        write_metric(f, "IR", &self.integrity_requirement)?;
        write_metric(f, "AR", &self.availability_requirement)?;
        write_metric(f, "MAV", &self.modified_attack_vector)?;
        write_metric(f, "MAC", &self.modified_attack_complexity)?;
        write_metric(f, "MPR", &self.modified_privileges_required)?;
        write_metric(f, "MUI", &self.modified_user_interaction)?;
        write_metric(f, "MS", &self.modified_scope)?;
        write_metric(f, "MC", &self.modified_confidentiality_impact)?;
        write_metric(f, "MI", &self.modified_integrity_impact)?;
        write_metric(f, "MA", &self.modified_availability_impact)?;

        Ok(())
    }
}

#[cfg(test)]
mod roundup_tests {
    use super::roundup;

    #[test]
    fn follows_cvss_v3_integer_rounding_algorithm() {
        for (input, expected) in [
            (0.0, 0.0),
            (4.0, 4.0),
            (4.02, 4.1),
            (10.0, 10.0),
            (1.2000000000000002, 1.2),
            (4.000001, 4.0),
            (4.000006, 4.1),
        ] {
            assert_eq!(roundup(input), expected, "input: {input}");
        }
    }
}
