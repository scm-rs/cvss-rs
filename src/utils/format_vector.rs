use std::fmt;

/// Writes a CVSS metric from an optional reference
///
/// This function writes a metric to the formatter with the pattern `/KEY:VALUE`.
/// If the value is None, nothing is written.
///
/// # Arguments
/// * `f` - formatter
/// * `name` - metric name (e.g., "AV")
/// * `value` - optional metric value
pub fn write_metric<T: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    key: &str,
    value: Option<&T>,
) -> fmt::Result {
    if let Some(val) = value {
        write!(f, "/{}:{}", key, val)?;
    }
    Ok(())
}
