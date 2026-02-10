pub fn round_to_first_decimal(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}
