use cvss_rs as cvss;
use cvss_rs::{v2_0::CvssV2, ParseError};
use rstest::rstest;
use std::str::FromStr;

#[test]
fn test_v2_0_example() {
    let input_json = include_str!("data/v2_0_example.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V2);
    assert_eq!(cvss.base_score(), 7.5);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::High);
}

#[test]
fn test_v2_0_minimal() {
    let input_json = include_str!("data/v2_0_minimal.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V2);
    assert_eq!(cvss.base_score(), 7.5);
}

#[test]
fn test_v2_0_unknown_metric_should_error() {
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/XX:H";

    assert!(matches!(
        CvssV2::from_str(vector),
        Err(cvss::ParseError::UnknownMetric { metric }) if metric == "XX"
    ));
}

#[test]
fn test_v2_0_multiple_unknown_metric_should_error_first() {
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/XX:H/YY:H";

    assert!(matches!(
        CvssV2::from_str(vector),
        Err(cvss::ParseError::UnknownMetric { metric }) if metric == "XX"
    ));
}

#[rstest]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/AV:L", "AV")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/AC:H", "AC")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/Au:S", "AU")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/C:P", "C")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/I:P", "I")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/A:P", "A")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/E:POC", "E")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/RL:OF/RL:TF", "RL")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/RC:C/RC:UC", "RC")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:H/CDP:LM", "CDP")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:H/TD:L", "TD")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:H/CR:M", "CR")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/IR:H/IR:M", "IR")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/AR:H/AR:M", "AR")]
fn test_v2_0_duplicate_metrics_should_error(#[case] vector: &str, #[case] expected_metric: &str) {
    let result = vector.parse::<CvssV2>();
    assert!(
        matches!(result, Err(ParseError::DuplicateMetric { ref metric }) if metric == expected_metric),
        "Expected DuplicateMetric error for metric '{}', but got: {:?}",
        expected_metric,
        result
    );
}

#[test]
fn test_v2_0_display_round_trip() {
    // Create a v2 vector with all metrics defined
    let vector_str = "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H";

    // Parse the vector string
    let o = cvss::v2_0::CvssV2::from_str(vector_str).expect("Failed to parse vector string");

    // Convert to string using Display
    let display_string = o.to_string();

    // Parse the display string back
    let r = cvss::v2_0::CvssV2::from_str(&display_string).expect("Failed to parse Display output");

    // Verify all base metrics
    assert_eq!(o.access_vector, r.access_vector);
    assert_eq!(o.access_complexity, r.access_complexity);
    assert_eq!(o.authentication, r.authentication);
    assert_eq!(o.confidentiality_impact, r.confidentiality_impact);
    assert_eq!(o.integrity_impact, r.integrity_impact);
    assert_eq!(o.availability_impact, r.availability_impact);

    // Verify all temporal metrics
    assert_eq!(o.exploitability, r.exploitability);
    assert_eq!(o.remediation_level, r.remediation_level);
    assert_eq!(o.report_confidence, r.report_confidence);

    // Verify all environmental metrics
    assert_eq!(o.collateral_damage_potential, r.collateral_damage_potential);
    assert_eq!(o.target_distribution, r.target_distribution);
    assert_eq!(o.confidentiality_requirement, r.confidentiality_requirement);
    assert_eq!(o.integrity_requirement, r.integrity_requirement);
    assert_eq!(o.availability_requirement, r.availability_requirement);
}
