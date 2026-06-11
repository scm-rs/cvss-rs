use crate::ParseError;
use std::str::FromStr;

/// Generic helper function for parsing and setting metrics. It checks for duplicate metrics
/// and invalid metric values.
///
/// # Arguments
///
/// * `field` - mutable reference to an Option field to be populated
/// * `value` - input value
/// * `key` - metric key used for error reporting
///
/// # Returns
///
/// * `Ok(())` if the metric was successfully parsed and set
/// * `Err(ParseError)` if the metric is a duplicate or if parsing fails
pub(crate) fn parse_metric<T: FromStr>(
    field: &mut Option<T>,
    value: &str,
    key: &str,
) -> Result<(), ParseError> {
    // check if the metric is already populated, i.e. if there is a duplicate metric
    if field.is_some() {
        return Err(ParseError::DuplicateMetric {
            metric: key.to_string(),
        });
    }
    // check metric value validity -> either set value or throw invalid value error
    *field = Some(value.parse().map_err(|_| ParseError::InvalidMetricValue {
        metric: key.to_string(),
        value: value.to_string(),
    })?);
    Ok(())
}
