use cvss_rs as cvss;
use cvss_rs::helper::round_to_first_decimal;
use cvss_rs::Cvss;

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
