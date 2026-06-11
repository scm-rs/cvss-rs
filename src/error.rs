use thiserror::Error;

/// Errors that can occur when parsing CVSS vector strings.
#[derive(Clone, Debug, PartialEq, Error)]
pub enum ParseError {
    /// Vector string is malformed (e.g., missing '/' separators)
    #[error("malformed vector string: no '/' separator found")]
    MalformedVectorString,
    /// Vector string doesn't start with "CVSS:"
    #[error("invalid vector prefix: expected prefix to start with 'CVSS:', found '{found}'")]
    InvalidPrefixLabel { found: String },
    /// CVSS version has unexpected format
    #[error("malformed CVSS version format: '{version}' (expected 'X.Y')")]
    MalformedPrefixVersion { version: String },
    /// Unsupported or invalid CVSS version
    #[error("invalid or unsupported CVSS version: '{version}'")]
    InvalidPrefixVersion { version: String },
    /// Component is malformed (not in key:value format)
    #[error("invalid component format: '{component}' (expected 'KEY:VALUE')")]
    InvalidComponent { component: String },
    /// Metric abbreviation not recognized
    #[error("unknown metric abbreviation: '{metric}'")]
    UnknownMetric { metric: String },
    /// Metric value parsing failed
    #[error("invalid value '{value}' for metric '{metric}'")]
    InvalidMetricValue { metric: String, value: String },
    /// Required base metric is missing
    #[error("missing required metric: '{metric}'")]
    MissingRequiredMetric { metric: String },
    /// Same metric appears multiple times
    #[error("duplicate metric: '{metric}'")]
    DuplicateMetric { metric: String },
}
