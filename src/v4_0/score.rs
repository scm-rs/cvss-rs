//! CVSS v4.0 score and nomenclature types.

use super::*;
use std::fmt;

/// CVSS v4.0 Nomenclature indicates the type of metrics used to calculate the score.
///
/// From the CVSS v4.0 specification:
/// "Numerical CVSS Scores have very different meanings based on the metrics used to calculate them.
/// Therefore, numerical CVSS scores should be labeled using nomenclature that communicates
/// the metrics used in its generation."
#[derive(Clone, Debug, PartialEq)]
pub enum Nomenclature {
    /// CVSS-B: Base metrics only
    CvssB,
    /// CVSS-BE: Base and Environmental metrics
    CvssBE,
    /// CVSS-BT: Base and Threat metrics
    CvssBT,
    /// CVSS-BTE: Base, Threat, and Environmental metrics
    CvssBTE,
}

impl fmt::Display for Nomenclature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Nomenclature::CvssB => write!(f, "CVSS-B"),
            Nomenclature::CvssBE => write!(f, "CVSS-BE"),
            Nomenclature::CvssBT => write!(f, "CVSS-BT"),
            Nomenclature::CvssBTE => write!(f, "CVSS-BTE"),
        }
    }
}

impl From<&CvssV4> for Nomenclature {
    /// Detects the appropriate nomenclature based on which metrics are present in the vector.
    fn from(cvss: &CvssV4) -> Self {
        let has_threat = cvss.exploit_maturity.is_some();

        let has_environmental = cvss.confidentiality_requirement.is_some()
            || cvss.integrity_requirement.is_some()
            || cvss.availability_requirement.is_some()
            || cvss.modified_attack_vector.is_some()
            || cvss.modified_attack_complexity.is_some()
            || cvss.modified_attack_requirements.is_some()
            || cvss.modified_privileges_required.is_some()
            || cvss.modified_user_interaction.is_some()
            || cvss.modified_vuln_confidentiality_impact.is_some()
            || cvss.modified_vuln_integrity_impact.is_some()
            || cvss.modified_vuln_availability_impact.is_some()
            || cvss.modified_sub_confidentiality_impact.is_some()
            || cvss.modified_sub_integrity_impact.is_some()
            || cvss.modified_sub_availability_impact.is_some();

        match (has_threat, has_environmental) {
            (true, true) => Nomenclature::CvssBTE,
            (true, false) => Nomenclature::CvssBT,
            (false, true) => Nomenclature::CvssBE,
            (false, false) => Nomenclature::CvssB,
        }
    }
}

/// Rounds a CVSS v4.0 score to one decimal place using the specification's rounding method.
///
/// The specification requires rounding to one decimal place. To stay compatible with
/// existing implementations (including Red Hat's test suite), this uses the same method:
///
/// ```python
/// from decimal import Decimal as D, ROUND_HALF_UP
/// EPSILON = 10**-6
/// return float(D(x + EPSILON).quantize(D("0.1"), rounding=ROUND_HALF_UP))
/// ```
///
/// This adds a small epsilon before rounding to handle floating point precision issues.
pub(crate) fn round_v4(value: f64) -> f64 {
    let value = f64::clamp(value, 0.0, 10.0);
    const EPSILON: f64 = 10e-6;
    ((value + EPSILON) * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_v4() {
        // Test floating point precision handling
        // 8.6 - 7.15 = 1.4499999999999993 (float) => should round to 1.5
        assert_eq!(round_v4(8.6 - 7.15), 1.5);
        assert_eq!(round_v4(5.12345), 5.1);
        assert_eq!(round_v4(5.15), 5.2);
        assert_eq!(round_v4(5.14), 5.1);

        // Test clamping
        assert_eq!(round_v4(-1.0), 0.0);
        assert_eq!(round_v4(11.0), 10.0);
    }

    #[test]
    fn test_nomenclature_display() {
        assert_eq!(Nomenclature::CvssB.to_string(), "CVSS-B");
        assert_eq!(Nomenclature::CvssBE.to_string(), "CVSS-BE");
        assert_eq!(Nomenclature::CvssBT.to_string(), "CVSS-BT");
        assert_eq!(Nomenclature::CvssBTE.to_string(), "CVSS-BTE");
    }
}
