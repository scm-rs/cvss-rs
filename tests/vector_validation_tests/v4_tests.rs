use cvss_rs as cvss;
use std::str::FromStr;

#[test]
fn test_v4_0_valid_prefix() {
    let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H";
    let cvss = cvss::v4_0::CvssV4::from_str(vector)
        .expect("should parse valid v4.0 vector with CVSS:4.0 prefix");

    assert_eq!(cvss.vector_string, vector);
    assert_eq!(cvss.attack_vector, Some(cvss::v4_0::AttackVector::Network));
}

#[test]
fn test_v4_0_missing_prefix() {
    let vector = "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H";
    let result = cvss::v4_0::CvssV4::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixLabel { .. })
    ));
}

#[test]
fn test_v4_0_invalid_lowercase_prefix() {
    let vector = "cvss:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H";
    let result = cvss::v4_0::CvssV4::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixLabel { .. })
    ));
}

#[test]
fn test_v4_0_invalid_mixed_case_prefix() {
    let vector = "CvSs:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H";
    let result = cvss::v4_0::CvssV4::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixLabel { .. })
    ));
}

#[test]
fn test_v4_0_invalid_prefix_version() {
    let vector = "CVSS:4.9/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H";
    let result = cvss::v4_0::CvssV4::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixVersion { .. })
    ));
}

#[test]
fn test_v4_0_invalid_malformed_prefix_version() {
    let vector = "CVSS:4/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H";
    let result = cvss::v4_0::CvssV4::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::MalformedPrefixVersion { .. })
    ));
}

#[test]
fn test_v4_0_parser_fails_on_v_3_1_vector() {
    let vector = "CVSS:3.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H";
    let result = cvss::v4_0::CvssV4::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixVersion { .. })
    ));
}

#[test]
fn test_v4_0_invalid_malformed_vector() {
    let vector = "THIS:JUSTISNTACVSSVECTOR";
    let result = cvss::v4_0::CvssV4::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::MalformedVectorString)
    ));
}
