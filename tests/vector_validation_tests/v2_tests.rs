use cvss_rs as cvss;
use std::str::FromStr;

#[test]
fn test_v2_0_valid_with_prefix() {
    let vector = "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let cvss = cvss::v2_0::CvssV2::from_str(vector)
        .expect("should parse valid v2.0 vector with CVSS:2.0 prefix");

    assert_eq!(cvss.vector_string, vector);
    assert_eq!(cvss.access_vector, Some(cvss::v2_0::AccessVector::Network));
}

#[test]
fn test_v2_0_valid_without_prefix() {
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let cvss = cvss::v2_0::CvssV2::from_str(vector)
        .expect("should parse valid v2.0 vector without prefix");

    assert_eq!(cvss.vector_string, vector);
    assert_eq!(cvss.access_vector, Some(cvss::v2_0::AccessVector::Network));
}

#[test]
fn test_v2_0_invalid_lowercase_prefix() {
    let vector = "cvss:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let result = cvss::v2_0::CvssV2::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixLabel { .. })
    ));
}

#[test]
fn test_v2_0_invalid_mixed_case_prefix() {
    let vector = "CvSs:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let result = cvss::v2_0::CvssV2::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixLabel { .. })
    ));
}

#[test]
fn test_v2_0_invalid_prefix_version() {
    let vector = "CVSS:2.9/AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let result = cvss::v2_0::CvssV2::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixVersion { .. })
    ));
}

#[test]
fn test_v2_0_invalid_malformed_prefix_version() {
    let vector = "CVSS:2/AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let result = cvss::v2_0::CvssV2::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::MalformedPrefixVersion { .. })
    ));
}

#[test]
fn test_v2_0_parser_fails_on_v_3_1_vector() {
    let vector = "CVSS:3.1/AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let result = cvss::v2_0::CvssV2::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::InvalidPrefixVersion { .. })
    ));
}

#[test]
fn test_v2_0_invalid_malformed_vector() {
    let vector = "THIS:JUSTISNTACVSSVECTOR";
    let result = cvss::v2_0::CvssV2::from_str(vector);

    assert!(matches!(
        result,
        Err(cvss::ParseError::MalformedVectorString)
    ));
}
