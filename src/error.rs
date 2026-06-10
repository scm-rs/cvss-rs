use thiserror::Error;

/// Errors that can occur when parsing CVSS vector strings.
#[derive(Clone, Debug, PartialEq, Error)]
pub enum ParseError {
    /// Vector string doesn't start with "CVSS" or expected prefix
    #[error("invalid vector prefix: expected 'CVSS', found '{found}'")]
    InvalidPrefix { found: String },
    /// Unsupported or invalid CVSS version
    #[error("invalid or unsupported CVSS version: '{version}'")]
    InvalidVersion { version: String },
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
