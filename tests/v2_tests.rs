use cvss_rs as cvss;
use cvss_rs::v2_0::CvssV2;
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
    // Test that unknown metrics are rejected, not silently ignored
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/XX:H";
    let result = CvssV2::from_str(vector);

    assert!(result.is_err(), "Should reject unknown metric XX");
    if let Err(cvss::ParseError::UnknownMetric { metric }) = result {
        assert_eq!(metric, "XX");
    } else {
        panic!("Expected UnknownMetric error");
    }
}
