# cvss-rs

**Rust library for handling CVSS scores**

[![Crates.io](https://img.shields.io/crates/v/cvss-rs.svg)](https://crates.io/crates/cvss-rs)
[![Documentation](https://docs.rs/cvss-rs/badge.svg)](https://docs.rs/cvss-rs)
[![License](https://img.shields.io/crates/l/cvss-rs.svg)](LICENSE)

---

## About

`cvss-rs` is a Rust library that provides tools for working with the **Common Vulnerability Scoring System (CVSS)** data. With this crate, you can parse, validate, manipulate, and serialize CVSS JSON representation of scores in a type-safe way.

## Features

- Full support for CVSS versions 2.0, 3.0, 3.1, and 4.0
- Type-safe representations of all CVSS metrics
- JSON deserialization compatible with official CVSS schemas
- Score calculation for all supported versions
- Vector string parsing via `FromStr` implementation
- Unified API across all CVSS versions

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
cvss-rs = "0.2"
```

## Usage

### Deserializing CVSS from JSON

The library automatically detects the CVSS version from JSON data:

```rust
use cvss_rs::{Cvss, Severity, Version};

let json_data = r#"{
  "version": "3.1",
  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "attackVector": "NETWORK",
  "attackComplexity": "LOW",
  "privilegesRequired": "NONE",
  "userInteraction": "NONE",
  "scope": "UNCHANGED",
  "confidentialityImpact": "HIGH",
  "integrityImpact": "HIGH",
  "availabilityImpact": "HIGH",
  "baseScore": 9.8,
  "baseSeverity": "CRITICAL"
}"#;

let cvss: Cvss = serde_json::from_str(json_data).unwrap();

assert_eq!(cvss.version(), Version::V3_1);
assert_eq!(cvss.base_score(), 9.8);
assert_eq!(cvss.base_severity().unwrap(), Severity::Critical);
```

### Parsing Vector Strings

You can parse CVSS vector strings directly:

```rust
use cvss_rs::v3::CvssV3;
use std::str::FromStr;

let cvss = CvssV3::from_str("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H").unwrap();
let score = cvss.calculated_base_score().unwrap();
assert_eq!(score, 9.6);
```

### Working with CVSS v2.0

```rust
use cvss_rs::{Cvss, Version};

let json = r#"{
  "version": "2.0",
  "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
  "baseScore": 7.5,
  "accessVector": "NETWORK",
  "accessComplexity": "LOW",
  "authentication": "NONE",
  "confidentialityImpact": "PARTIAL",
  "integrityImpact": "PARTIAL",
  "availabilityImpact": "PARTIAL"
}"#;

let cvss: Cvss = serde_json::from_str(json).unwrap();
assert_eq!(cvss.version(), Version::V2);
assert_eq!(cvss.base_score(), 7.5);
```

### Working with CVSS v4.0

```rust
use cvss_rs::{Cvss, Version};

let json = r#"{
  "version": "4.0",
  "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  "baseScore": 9.3,
  "baseSeverity": "CRITICAL",
  "attackVector": "NETWORK",
  "attackComplexity": "LOW",
  "attackRequirements": "NONE",
  "privilegesRequired": "NONE",
  "userInteraction": "NONE",
  "vulnConfidentialityImpact": "HIGH",
  "vulnIntegrityImpact": "HIGH",
  "vulnAvailabilityImpact": "HIGH",
  "subConfidentialityImpact": "NONE",
  "subIntegrityImpact": "NONE",
  "subAvailabilityImpact": "NONE"
}"#;

let cvss: Cvss = serde_json::from_str(json).unwrap();
assert_eq!(cvss.version(), Version::V4);
assert_eq!(cvss.base_score(), 9.3);
```

### Accessing Version-Specific Fields

You can access version-specific fields by matching on the `Cvss` enum:

```rust
use cvss_rs::{Cvss, v3::AttackVector};

let json = r#"{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"NONE","userInteraction":"NONE","scope":"UNCHANGED","confidentialityImpact":"HIGH","integrityImpact":"HIGH","availabilityImpact":"HIGH","baseScore":9.8,"baseSeverity":"CRITICAL"}"#;

let cvss: Cvss = serde_json::from_str(json).unwrap();

if let Cvss::V3_1(cvss_v3) = cvss {
    assert_eq!(cvss_v3.attack_vector, Some(AttackVector::Network));
}
```

## Supported CVSS Versions

| Version | Parsing | Score Calculation | Environmental |
|---------|---------|-------------------|---------------|
| 2.0     | Yes     | Yes               | Yes           |
| 3.0     | Yes     | Yes               | Yes           |
| 3.1     | Yes     | Yes               | Yes           |
| 4.0     | Yes     | Yes               | Yes           |

## Documentation

Full API documentation is available at [docs.rs/cvss-rs](https://docs.rs/cvss-rs).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
