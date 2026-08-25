//! The FIRST schemas require the `version` key on every CVSS object.
//! These tests pin that the typed models always emit it, and that
//! documents omitting the key keep deserializing with the default
//! filled, so readers of older data see no breakage.

use cvss_rs as cvss;
use cvss_rs::{
    v2_0::CvssV2,
    v3::CvssV3,
    v4_0::CvssV4,
    version::{VersionV2, VersionV4},
};
use std::str::FromStr;

#[test]
fn v2_serializes_the_required_version() {
    let cvss = CvssV2::from_str("AV:N/AC:L/Au:N/C:C/I:C/A:C").unwrap();
    assert_eq!(cvss.version, VersionV2::V2_0);
    let json = serde_json::to_value(&cvss).unwrap();
    assert_eq!(json["version"], serde_json::json!("2.0"));
}

#[test]
fn v2_deserialization_defaults_the_version() {
    let json = serde_json::json!({
        "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "baseScore": 10.0
    });
    let cvss: CvssV2 = serde_json::from_value(json).unwrap();
    assert_eq!(cvss.version, VersionV2::V2_0);
    // Re-serialization emits the key the schema requires.
    let json = serde_json::to_value(&cvss).unwrap();
    assert_eq!(json["version"], serde_json::json!("2.0"));
}

#[test]
fn v4_serializes_the_required_version() {
    let cvss = CvssV4::from_str("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        .unwrap();
    assert_eq!(cvss.version, VersionV4::V4_0);
    let json = serde_json::to_value(&cvss).unwrap();
    assert_eq!(json["version"], serde_json::json!("4.0"));
}

#[test]
fn v4_deserialization_defaults_the_version() {
    let json = serde_json::json!({
        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "baseScore": 9.3,
        "baseSeverity": "CRITICAL"
    });
    let cvss: CvssV4 = serde_json::from_value(json).unwrap();
    assert_eq!(cvss.version, VersionV4::V4_0);
    let json = serde_json::to_value(&cvss).unwrap();
    assert_eq!(json["version"], serde_json::json!("4.0"));
}

#[test]
fn the_cvss_enum_still_routes_on_the_version_tag() {
    // The internally tagged enum picks its variant by the version key;
    // with the structs carrying the field themselves, both agree.
    let json = serde_json::json!({
        "version": "2.0",
        "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "baseScore": 10.0
    });
    let parsed: cvss::Cvss = serde_json::from_value(json).unwrap();
    assert_eq!(parsed.version(), cvss::Version::V2);
    match parsed {
        cvss::Cvss::V2(v2) => assert_eq!(v2.version, VersionV2::V2_0),
        other => panic!("expected the v2 variant, got {other:?}"),
    }
}

#[test]
fn v3_vector_path_records_its_version() {
    let cvss = CvssV3::from_str("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
    let json = serde_json::to_value(&cvss).unwrap();
    assert_eq!(json["version"], serde_json::json!("3.1"));
}
