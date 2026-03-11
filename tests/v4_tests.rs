use cvss_rs as cvss;
use cvss_rs::v4_0::CvssV4;
use std::str::FromStr;

#[test]
fn test_v4_0_debug_mismatch() {
    // CVE-2024-7657: This vector should calculate to 5.3
    let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N";
    let cvss = CvssV4::from_str(vector).unwrap();

    let score = cvss.calculated_base_score().unwrap();
    assert_eq!(score, 5.3);
}

#[test]
fn test_v4_0_exploit_maturity_notdefined() {
    // CVE-2025-6829: Vector with E:X (NotDefined) should still calculate to 5.3
    // Previously calculated 1.3 due to bug in merge_exploit_maturity
    let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:X";
    let cvss = CvssV4::from_str(vector).unwrap();

    let score = cvss.calculated_base_score().unwrap();
    assert_eq!(
        score, 5.3,
        "E:X (NotDefined) should be treated as E:A (Attacked)"
    );

    // CVE-2025-6166: Another E:X case that should calculate to 5.1
    let vector2 = "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:X";
    let cvss2 = CvssV4::from_str(vector2).unwrap();

    let score2 = cvss2.calculated_base_score().unwrap();
    assert_eq!(score2, 5.1, "E:X should be treated as E:A");
}

#[test]
fn test_v4_0_example() {
    let input_json = include_str!("data/v4_0_example.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V4);
    assert_eq!(cvss.base_score(), 9.3);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Critical);
}

#[test]
fn test_v4_0_cve_example() {
    let input_json = include_str!("data/v4_0_cve_example.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V4);
    assert_eq!(cvss.base_score(), 5.9);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Medium);
}

#[test]
fn test_v4_0_minimal() {
    let input_json = include_str!("data/v4_0_minimal.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V4);
    assert_eq!(cvss.base_score(), 9.9);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Critical);
}

#[test]
fn test_v4_0_cve_2020_36855() {
    // CVE-2020-36855: Base score should be 4.8 regardless of E metric
    // In CVSS v4.0, base score excludes threat metrics (E) for backwards compatibility
    let vector = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P";
    let cvss = CvssV4::from_str(vector).unwrap();

    let score = cvss.calculated_base_score().unwrap();
    assert_eq!(score, 4.8);
}

#[test]
fn test_v4_0_all_metrics_not_defined() {
    // Test vector from trustify that was failing due to "X" (NotDefined) values
    // All optional metrics are set to X (NotDefined) per CVSS v4.0 spec
    let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X";
    let cvss = CvssV4::from_str(vector).expect("Should parse vector with X (NotDefined) values");

    // Verify that the parsed CVSS object can calculate a score
    let score = cvss
        .calculated_base_score()
        .expect("Should calculate base score");
    assert!(score > 0.0, "Score should be positive");

    // CR:X, IR:X, AR:X default to High per CVSS v4.0 spec, which affects EQ6
    // The score with all modified metrics as NotDefined (defaulting to base values)
    // and requirements as High produces 8.6
    assert_eq!(score, 8.6);
}
