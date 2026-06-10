use cvss_rs as cvss;
use std::str::FromStr;

#[test]
fn test_v3_1_valid_prefix() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let cvss = cvss::v3::CvssV3::from_str(vector)
        .expect("should parse valid v3.1 vector with CVSS:3.1 prefix");

    assert_eq!(cvss.vector_string, vector);
    assert_eq!(cvss.attack_vector, Some(cvss::v3::AttackVector::Network));
}

#[test]
fn test_v3_missing_prefix() {
    let vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let result = cvss::v3::CvssV3::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixLabel { .. })
    ));
}

#[test]
fn test_v3_1_invalid_lowercase_prefix() {
    let vector = "cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let result = cvss::v3::CvssV3::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixLabel { .. })
    ));
}

#[test]
fn test_v3_1_invalid_mixed_case_prefix() {
    let vector = "CvSs:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let result = cvss::v3::CvssV3::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixLabel { .. })
    ));
}

#[test]
fn test_v3_invalid_prefix_version() {
    let vector = "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let result = cvss::v3::CvssV3::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixVersion { .. })
    ));
}

#[test]
fn test_v3_invalid_malformed_prefix_version() {
    let vector = "CVSS:3/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let result = cvss::v3::CvssV3::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::MalformedPrefixVersion { .. })
    ));
}

#[test]
fn test_v3_parser_fails_on_v_2_0_vector() {
    let vector = "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let result = cvss::v3::CvssV3::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixVersion { .. })
    ));
}

#[test]
fn test_v3_invalid_malformed_vector() {
    let vector = "THIS:JUSTISNTACVSSVECTOR";
    let result = cvss::v3::CvssV3::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::MalformedVectorString)
    ));
}
