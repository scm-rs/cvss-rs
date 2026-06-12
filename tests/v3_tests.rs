use cvss_rs::{
    v3::{AttackVector, CvssV3},
    Cvss, ParseError, Severity, Version,
};
use rstest::rstest;
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
    let cvss: Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), Version::V3_1);
    assert_eq!(cvss.base_score(), 9.8);
    assert_eq!(cvss.base_severity().unwrap(), Severity::Critical);
}

#[test]
fn test_v3_0_critical() {
    let input_json = include_str!("data/v3_0_critical.json");
    let cvss: Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), Version::V3_0);
    assert_eq!(cvss.base_score(), 9.8);
    assert_eq!(cvss.base_severity().unwrap(), Severity::Critical);
}

#[test]
fn test_v3_1_medium() {
    let input_json = include_str!("data/v3_1_medium.json");
    let cvss: Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), Version::V3_1);
    assert_eq!(cvss.base_score(), 5.8);
    assert_eq!(cvss.base_severity().unwrap(), Severity::Medium);

    // Custom assertion for v3_1_medium
    if let Cvss::V3_1(c) = cvss {
        assert_eq!(c.attack_vector, Some(AttackVector::Local));
    } else {
        panic!("Wrong enum variant");
    }
}

#[test]
fn test_v3_environmental() {
    let input_json = include_str!("data/v3_environmental.json");
    let cvss: Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), Version::V3_1);
    assert_eq!(cvss.base_score(), 9.6);
    assert_eq!(cvss.base_severity().unwrap(), Severity::Critical);
}

#[test]
fn test_v3_1_display_round_trip() {
    // Create a v3.1 vector with all metrics defined
    let vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:T/RC:C/CR:H/IR:H/AR:H/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:L/MA:L";

    // Parse the vector string
    let o = CvssV3::from_str(vector_string).expect("Failed to parse vector string");

    // Convert to string using Display
    let display_string = o.to_string();

    // Verify round-trip
    assert_eq!(
        display_string, vector_string,
        "Round-trip failed for: {}",
        vector_string
    );
}

#[test]
fn test_v3_1_unknown_metric_should_error() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:H";

    assert!(matches!(
        CvssV3::from_str(vector),
        Err(ParseError::UnknownMetric { metric }) if metric == "XX"
    ));
}

#[test]
fn test_v3_1_multiple_unknown_metric_should_error_first() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:H/YY:H";

    assert!(matches!(
        CvssV3::from_str(vector),
        Err(ParseError::UnknownMetric { metric }) if metric == "XX"
    ));
}

#[rstest]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L", "AV")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AC:H", "AC")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/PR:H", "PR")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/UI:R", "UI")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/S:C", "S")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/C:L", "C")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/I:L", "I")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:L", "A")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/E:P", "E")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/RL:W/RL:OF", "RL")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/RC:C/RC:UC", "RC")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/CR:M", "CR")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/IR:H/IR:M", "IR")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AR:H/AR:M", "AR")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L/MAV:A", "MAV")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAC:H/MAC:L", "MAC")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L/MPR:N", "MPR")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MUI:R/MUI:N", "MUI")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MS:C/MS:U", "MS")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:L/MC:H", "MC")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MI:L/MI:H", "MI")]
#[case("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MA:L/MA:H", "MA")]
fn test_v3_1_duplicate_metrics_should_error(#[case] vector: &str, #[case] expected_metric: &str) {
    let result = vector.parse::<CvssV3>();
    assert!(
        matches!(result, Err(ParseError::DuplicateMetric { ref metric }) if metric == expected_metric),
        "Expected DuplicateMetric error for metric '{}', but got: {:?}",
        expected_metric,
        result
    );
}
