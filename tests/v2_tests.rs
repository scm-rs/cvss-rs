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
