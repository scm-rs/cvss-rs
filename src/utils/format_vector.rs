use std::fmt;

pub fn write_metric<T: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    key: &str,
    value: &Option<T>,
) -> fmt::Result {
    if let Some(val) = value {
        write!(f, "/{key}:{val}")?;
    }
    Ok(())
}
