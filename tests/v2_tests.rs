use cvss_rs::{v2_0::CvssV2, Cvss, ParseError, Severity, Version};
use rstest::rstest;
use std::str::FromStr;

#[test]
fn test_v2_0_example() {
    let input_json = include_str!("data/v2_0_example.json");
    let cvss: Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), Version::V2);
    assert_eq!(cvss.base_score(), 7.5);
    assert_eq!(cvss.base_severity().unwrap(), Severity::High);
}

#[test]
fn test_v2_0_minimal() {
    let input_json = include_str!("data/v2_0_minimal.json");
    let cvss: Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), Version::V2);
    assert_eq!(cvss.base_score(), 7.5);
}

#[test]
fn test_v2_0_unknown_metric_should_error() {
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/XX:H";

    assert!(matches!(
        CvssV2::from_str(vector),
        Err(ParseError::UnknownMetric { metric }) if metric == "XX"
    ));
}

#[test]
fn test_v2_0_multiple_unknown_metric_should_error_first() {
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/XX:H/YY:H";

    assert!(matches!(
        CvssV2::from_str(vector),
        Err(ParseError::UnknownMetric { metric }) if metric == "XX"
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

#[rstest]
#[case("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H")]
#[case("AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H")]
fn test_v2_0_display_round_trip(#[case] vector_str: &str) {
    // Parse the vector string
    let parsed = CvssV2::from_str(vector_str).expect("Failed to parse vector string");

    // Convert to string using Display
    let parsed_str = parsed.to_string();

    // Verify round-trip
    assert_eq!(
        parsed_str, vector_str,
        "Round-trip failed for: {}",
        vector_str
    );
}
