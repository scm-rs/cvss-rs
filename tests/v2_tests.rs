use cvss_rs as cvss;
use cvss_rs::{ParseError, v2_0::CvssV2};
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
        "Expected DuplicateMetric error for metric '{expected_metric}', but got: {result:?}"
    );
}

#[rstest]
#[case("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H")]
fn test_v2_0_display_round_trip(#[case] vector_str: &str) {
    let parsed = CvssV2::from_str(vector_str).expect("Failed to parse vector string");
    let display_str = parsed.to_string();
    assert_eq!(
        display_str, vector_str,
        "Round-trip failed for: {vector_str}"
    );
}

#[test]
fn test_v2_0_display_round_trip_through_json() {
    let vector_str = "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H";
    let parsed = CvssV2::from_str(vector_str).expect("Failed to parse vector string");

    let json = serde_json::to_string(&parsed).expect("Failed to serialize CVSS v2");
    let deserialized: CvssV2 = serde_json::from_str(&json).expect("Failed to deserialize CVSS v2");

    assert_eq!(deserialized, parsed, "Serde round-trip changed CVSS v2");
    assert_eq!(
        deserialized.to_string(),
        vector_str,
        "Serde round-trip lost the CVSS v2 prefix"
    );
}
