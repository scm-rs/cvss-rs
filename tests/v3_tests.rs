use cvss::v3::AttackVector;
use cvss_rs as cvss;
use cvss_rs::v3::CvssV3;
use std::str::FromStr;

#[test]
fn test_v3_1_rounding_examples() {
    // CVE-2023-35161: Tests CVSS v3.1 environmental formula changes
    //
    // CVSS v3.1 changed the ENVIRONMENTAL Impact formula (Modified Impact Sub Score):
    // - v3.0: 7.52 × (MISS - 0.029) - 3.25 × (MISS - 0.02)^15
    // - v3.1: 7.52 × (MISS - 0.029) - 3.25 × (MISS × 0.9731 - 0.02)^13
    //
    // The base score formula remained unchanged (still uses exponent 15).
    //
    // References:
    // - https://www.first.org/cvss/v3-1/specification-document#7-3-Environmental-Metrics-Equations
    // - https://www.first.org/cvss/v3-1/user-guide#2-6-Formula-Changes
    //
    // This produces different scores:
    // - Base: 9.6 (same formula for both v3.0 and v3.1)
    // - Temporal: 9.6 (based on base score)
    // - Environmental: 9.7 (v3.1 formula with exponent 13 produces higher score)
    let vector1 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H";
    let cvss1 = CvssV3::from_str(vector1).unwrap();

    let base_score = cvss1.calculated_base_score().unwrap();
    let temporal_score = cvss1.calculated_temporal_score().unwrap();
    let env_score = cvss1.calculated_environmental_score().unwrap();

    assert_eq!(base_score, 9.6, "Base score should be 9.6");
    assert_eq!(
        temporal_score, 9.6,
        "Temporal score should be 9.6 (with E/RL/RC = NotDefined)"
    );
    assert_eq!(env_score, 9.7, "Environmental score should be 9.7 per CVSS v3.1 formula (with all env metrics = NotDefined)");
}

#[test]
fn test_v3_1_critical() {
    let input_json = include_str!("data/v3_1_critical.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V3_1);
    assert_eq!(cvss.base_score(), 9.8);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Critical);
}

#[test]
fn test_v3_0_critical() {
    let input_json = include_str!("data/v3_0_critical.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V3_0);
    assert_eq!(cvss.base_score(), 9.8);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Critical);
}

#[test]
fn test_v3_1_medium() {
    let input_json = include_str!("data/v3_1_medium.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V3_1);
    assert_eq!(cvss.base_score(), 5.8);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Medium);

    // Custom assertion for v3_1_medium
    if let cvss::Cvss::V3_1(c) = cvss {
        assert_eq!(c.attack_vector, Some(AttackVector::Local));
    } else {
        panic!("Wrong enum variant");
    }
}

#[test]
fn test_v3_environmental() {
    let input_json = include_str!("data/v3_environmental.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V3_1);
    assert_eq!(cvss.base_score(), 9.6);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Critical);
}
