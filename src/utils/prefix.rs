//! Utilities for validating and parsing CVSS vector prefixes.

use crate::{ParseError, Version};
use std::str::FromStr;

/// Validates and parses a CVSS vector prefix into a [`Version`].
///
/// This is a shared internal function used by the CVSS v2, v3, and v4 parsers.
///
/// # Arguments
/// * `prefix_component` - A string expected to be in the format `CVSS:X.Y`, where:
///   - The label `CVSS` must be in uppercase
///   - `X.Y` is a version number (one of: `2.0`, `3.0`, `3.1`, or `4.0`)
///
/// # Returns
/// * `Ok(`[`Version`]`)` - The validated CVSS version
/// * `Err(`[`ParseError::InvalidPrefixLabel`]`)` - The prefix label is not exactly `CVSS` or the prefix is missing
/// * `Err(`[`ParseError::MalformedPrefixVersion`]`)` - The version component doesn't match `X.Y` format
/// * `Err(`[`ParseError::InvalidPrefixVersion`]`)` - The version `X.Y` is not a recognized CVSS version
fn validate_prefix(prefix_component: &str) -> Result<Version, ParseError> {
    // split the input on the first ':' into prefix and version string
    // if there is no ':', return an InvalidPrefixLabel error
    let (label_str, version_str) =
        prefix_component
            .split_once(':')
            .ok_or_else(|| ParseError::InvalidPrefixLabel {
                found: prefix_component.to_string(),
            })?;

    // the prefix must be exactly 'CVSS' in uppercase, else return an InvalidPrefixLabel error
    if label_str != "CVSS" {
        return Err(ParseError::InvalidPrefixLabel {
            found: prefix_component.to_string(),
        });
    }

    // version string must have 'X.Y' structure where X and Y are ASCII digits
    let version_bytes = version_str.as_bytes();
    let version_has_valid_structure = version_bytes.len() == 3
        && version_bytes[0].is_ascii_digit()
        && version_bytes[1] == b'.'
        && version_bytes[2].is_ascii_digit();
    if !version_has_valid_structure {
        return Err(ParseError::MalformedPrefixVersion {
            version: prefix_component.to_string(),
        });
    }

    // version string must be one of the known versions
    Version::from_str(version_str).map_err(|_| ParseError::InvalidPrefixVersion {
        version: version_str.to_string(),
    })
}

/// Splits a CVSS vector string on the first `'/'` separator.
///
/// # Returns
/// * `Ok((first_component, remaining_components))`
/// * `Err(`[`ParseError::MalformedVectorString`]`)` - No `'/'` separator was found in the vector
#[inline]
fn split_vector(vector: &str) -> Result<(&str, &str), ParseError> {
    vector
        .split_once('/')
        .ok_or(ParseError::MalformedVectorString)
}

/// Extracts and validates a CVSS version prefix from a vector string.
///
/// Used by CVSS v3 and v4 parsers where the prefix is required.
///
/// # Arguments
/// * `vector` - A CVSS vector
///
/// # Returns
/// * `Ok((`[`Version`]`, remaining_metrics))` - The prefix was valid; `remaining_metrics` contains the metric key-value pairs
/// * `Err(`[`ParseError::MalformedVectorString`]`)` - The vector has no `'/'` separator
/// * `Err(`[`ParseError::InvalidPrefixLabel`]`)` - The first component is not a valid CVSS prefix
/// * `Err(`[`ParseError::MalformedPrefixVersion`]`)` - The prefix exists but the version format is invalid
/// * `Err(`[`ParseError::InvalidPrefixVersion`]`)` - The prefix version is not a supported CVSS version
pub(crate) fn extract_version_from_required_prefix(
    vector: &str,
) -> Result<(Version, &str), ParseError> {
    let (first_component, remaining_components) = split_vector(vector)?;

    // if the version prefix is missing, first_component contains some metric KVP, which will
    // result in an InvalidPrefixLabel error
    let version = validate_prefix(first_component)?;

    Ok((version, remaining_components))
}

/// Tries to extract a CVSS version prefix from a vector string, allowing for an optional prefix.
///
/// Used by the CVSS v2 parser, where the prefix is optional. If a prefix-like
/// component is detected (starts with `cvss:` case-insensitively), it is validated. Otherwise, the entire
/// vector is returned as metrics.
///
/// # Arguments
/// * `vector` - A CVSS vector
///
/// # Returns
/// * `Ok((Some(`[`Version`]`), remaining_metrics))` - A valid CVSS prefix was found and parsed
/// * `Ok((None, vector))` - No prefix was detected; the vector is returned as-is for metric parsing
/// * `Err(`[`ParseError::MalformedVectorString`]`)` - The vector has no `'/'` separator
/// * `Err(`[`ParseError::InvalidPrefixLabel`]`)` - A prefix-like component exists but fails validation
/// * `Err(`[`ParseError::MalformedPrefixVersion`]`)` - A prefix exists but the version format is invalid
/// * `Err(`[`ParseError::InvalidPrefixVersion`]`)` - A prefix exists but the version is not supported
pub(crate) fn extract_version_from_optional_prefix(
    vector: &str,
) -> Result<(Option<Version>, &str), ParseError> {
    let (first_component, remaining_components) = split_vector(vector)?;

    // check if the first component key is case-insensitive `cvss:`
    // if so, we assume the first element to be a cvss prefix, and validate it
    let is_prefix_like = first_component
        .get(..5)
        .is_some_and(|s| s.eq_ignore_ascii_case("cvss:"));
    if is_prefix_like {
        let version = validate_prefix(first_component)?;
        Ok((Some(version), remaining_components))
    } else {
        Ok((None, vector))
    }
}

/// Validates that a parsed CVSS version is supported in the current parser context.
///
/// # Arguments
/// * `version` - The [`Version`] to validate
/// * `allowed_versions` - A slice of allowed [`Version`] values for the current context
///
/// # Returns
/// * `Ok(())` - The version is in the allowed list
/// * `Err(`[`ParseError::InvalidPrefixVersion`]`)` - The version is not allowed in this context
pub(crate) fn validate_allowed_prefix_version(
    version: &Version,
    allowed_versions: &[Version],
) -> Result<(), ParseError> {
    if allowed_versions.contains(version) {
        Ok(())
    } else {
        Err(ParseError::InvalidPrefixVersion {
            version: version.to_string(),
        })
    }
}

#[cfg(test)]
mod split_vector_tests {
    use super::*;

    #[test]
    fn test_split_vector_valid() {
        let (first, rest) = split_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert_eq!(first, "CVSS:3.1");
        assert_eq!(rest, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    }

    #[test]
    fn test_split_vector_invalid_only_prefix() {
        let result = split_vector("CVSS:3.1");
        assert!(matches!(result, Err(ParseError::MalformedVectorString)));
    }

    #[test]
    fn test_split_vector_invalid_empty() {
        let result = split_vector("");
        assert!(matches!(result, Err(ParseError::MalformedVectorString)));
    }

    #[test]
    fn test_split_vector_valid_v2_vector_no_prefix() {
        let (first, rest) = split_vector("AV:N/AC:L/Au:N/C:N/I:N/A:N").unwrap();
        assert_eq!(first, "AV:N");
        assert_eq!(rest, "AC:L/Au:N/C:N/I:N/A:N");
    }
}

#[cfg(test)]
mod validate_prefix_tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("CVSS:2.0", Version::V2)]
    #[case("CVSS:3.0", Version::V3_0)]
    #[case("CVSS:3.1", Version::V3_1)]
    #[case("CVSS:4.0", Version::V4)]
    fn test_valid_prefixes(#[case] input: &str, #[case] expected: Version) {
        assert_eq!(validate_prefix(input).unwrap(), expected);
    }

    #[rstest]
    #[case("cvss:2.0")]
    #[case("CvSs:2.0")]
    #[case("CVSS2.0")]
    #[case("CVSS-2.0")]
    fn test_invalid_prefix_cases(#[case] input: &str) {
        let result = validate_prefix(input);
        assert!(matches!(result, Err(ParseError::InvalidPrefixLabel { .. })));
    }

    #[rstest]
    #[case("CVSS:")]
    #[case("CVSS:3")]
    #[case("CVSS:2.0:extra")]
    fn test_malformed_version_cases(#[case] input: &str) {
        let result = validate_prefix(input);
        assert!(matches!(
            result,
            Err(ParseError::MalformedPrefixVersion { .. })
        ));
    }

    #[rstest]
    #[case("CVSS:2.9")]
    #[case("CVSS:3.2")]
    #[case("CVSS:4.9")]
    #[case("CVSS:5.0")]
    fn test_invalid_version_cases(#[case] input: &str) {
        let result = validate_prefix(input);
        assert!(matches!(
            result,
            Err(ParseError::InvalidPrefixVersion { .. })
        ));
    }
}

#[cfg(test)]
mod extract_required_version_component_tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        Version::V3_0,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )]
    #[case(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        Version::V3_1,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )]
    #[case(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
        Version::V4,
        "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"
    )]
    fn test_valid_vectors(
        #[case] input: &str,
        #[case] expected_version: Version,
        #[case] expected_remaining: &str,
    ) {
        let (version, remaining) = extract_version_from_required_prefix(input).unwrap();
        assert_eq!(version, expected_version);
        assert_eq!(remaining, expected_remaining);
    }

    #[test]
    fn test_invalid_only_prefix() {
        let result = extract_version_from_required_prefix("CVSS:3.1");
        assert!(matches!(result, Err(ParseError::MalformedVectorString)));
    }

    #[test]
    fn test_invalid_missing_prefix() {
        let result = extract_version_from_required_prefix("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert!(matches!(result, Err(ParseError::InvalidPrefixLabel { .. })));
    }

    #[test]
    fn test_invalid_invalid_prefix_label() {
        let result =
            extract_version_from_required_prefix("cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert!(matches!(result, Err(ParseError::InvalidPrefixLabel { .. })));
    }

    #[test]
    fn test_malformed_prefix_version() {
        let result =
            extract_version_from_required_prefix("CVSS:3/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert!(matches!(
            result,
            Err(ParseError::MalformedPrefixVersion { .. })
        ));
    }

    #[test]
    fn test_invalid_invalid_prefix_version() {
        let result =
            extract_version_from_required_prefix("CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert!(matches!(
            result,
            Err(ParseError::InvalidPrefixVersion { .. })
        ));
    }
}

#[cfg(test)]
mod extract_version_from_optional_prefix_tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(
        "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
        Some(Version::V2),
        "AV:N/AC:L/Au:N/C:C/I:C/A:C"
    )]
    #[case("AV:N/AC:L/Au:N/C:C/I:C/A:C", None, "AV:N/AC:L/Au:N/C:C/I:C/A:C")]
    fn test_valid_vectors_with_prefix(
        #[case] input: &str,
        #[case] expected_version: Option<Version>,
        #[case] expected_remaining: &str,
    ) {
        let (version, remaining) = extract_version_from_optional_prefix(input).unwrap();
        assert_eq!(version, expected_version);
        assert_eq!(remaining, expected_remaining);
    }

    #[test]
    fn test_only_prefix_no_slash() {
        let result = extract_version_from_optional_prefix("CVSS:2.0");
        assert!(matches!(result, Err(ParseError::MalformedVectorString)));
    }

    #[test]
    fn test_lowercase_prefix_label() {
        let result = extract_version_from_optional_prefix("cvss:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C");
        assert!(matches!(result, Err(ParseError::InvalidPrefixLabel { .. })));
    }

    #[test]
    fn test_invalid_prefix_version() {
        let result = extract_version_from_optional_prefix("CVSS:2.9/AV:N/AC:L/Au:N/C:C/I:C/A:C");
        assert!(matches!(
            result,
            Err(ParseError::InvalidPrefixVersion { .. })
        ));
    }

    #[test]
    fn test_malformed_prefix_version() {
        let result = extract_version_from_optional_prefix("CVSS:2/AV:N/AC:L/Au:N/C:C/I:C/A:C");
        assert!(matches!(
            result,
            Err(ParseError::MalformedPrefixVersion { .. })
        ));
    }
}

#[cfg(test)]
mod validate_allowed_prefix_version_tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(&Version::V3_1, &[Version::V3_1], true)]
    #[case(&Version::V3_1, &[Version::V4], false)]
    #[case(&Version::V3_1, &[Version::V3_1, Version::V4], true)]
    #[case(&Version::V3_1, &[Version::V3_0, Version::V4], false)]
    fn test_validate_allowed_prefix_version(
        #[case] version: &Version,
        #[case] allowed_versions: &[Version],
        #[case] should_be_ok: bool,
    ) {
        let result = validate_allowed_prefix_version(version, allowed_versions);

        if should_be_ok {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(ParseError::InvalidPrefixVersion { .. })
            ));
        }
    }
}
