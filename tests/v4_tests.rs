use cvss_rs as cvss;
use cvss_rs::{v4_0::CvssV4, ParseError};
use rstest::rstest;
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

#[test]
fn test_v4_0_provider_urgency_values() {
    // Test that ProviderUrgency values parse correctly despite the parser uppercasing values.
    // The spec defines these as mixed-case: Clear, Green, Amber, Red.
    let base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L";
    for urgency in &["Clear", "Green", "Amber", "Red", "X"] {
        let vector = format!("{base}/U:{urgency}");
        CvssV4::from_str(&vector).unwrap_or_else(|e| panic!("Should parse U:{urgency}: {e}"));
    }
}

#[test]
fn test_v4_0_unknown_metric_should_error() {
    let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/XX:H";

    assert!(matches!(
        CvssV4::from_str(vector),
        Err(cvss::ParseError::UnknownMetric { metric }) if metric == "XX"
    ));
}

#[test]
fn test_v4_0_multiple_unknown_metric_should_error_first() {
    let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/XX:H/YY:H";

    assert!(matches!(
        CvssV4::from_str(vector),
        Err(cvss::ParseError::UnknownMetric { metric }) if metric == "XX"
    ));
}

#[rstest]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/AV:L", "AV")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/AC:H", "AC")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/AT:R", "AT")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/PR:H", "PR")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/UI:R", "UI")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/VC:L", "VC")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/VI:L", "VI")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/VA:L", "VA")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SC:H", "SC")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SI:L/SI:H", "SI")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SA:L/SA:H", "SA")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/E:U/E:P", "E")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/CR:H/CR:M", "CR")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/IR:H/IR:M", "IR")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/AR:H/AR:M", "AR")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/S:P/S:N", "S")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/AU:Y/AU:N", "AU")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/R:A/R:U", "R")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/V:D/V:C", "V")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/RE:L/RE:M", "RE")]
#[case("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/U:Clear/U:Red", "U")]
fn test_v4_0_duplicate_metrics_should_error(#[case] vector: &str, #[case] expected_metric: &str) {
    let result = vector.parse::<CvssV4>();
    assert!(
        matches!(result, Err(ParseError::DuplicateMetric { ref metric }) if metric == expected_metric),
        "Expected DuplicateMetric error for metric '{}', but got: {:?}",
        expected_metric,
        result
    );
}

#[test]
fn test_v4_0_display_round_trip() {
    // Create a v4.0 vector with all metrics defined
    let vector_string = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:L/MAC:H/MAT:P/MPR:L/MUI:P/MVC:L/MVI:L/MVA:L/MSC:L/MSI:L/MSA:L/S:P/AU:Y/R:A/V:D/RE:M/U:Green";

    // Parse the vector string
    let o = CvssV4::from_str(vector_string).expect("Failed to parse vector string");

    // Convert to string using Display
    let display_string = o.to_string();

    // Parse the display string back
    let r = CvssV4::from_str(&display_string).expect("Failed to parse Display output");

    // Verify all base metrics
    assert_eq!(o.attack_vector, r.attack_vector);
    assert_eq!(o.attack_complexity, r.attack_complexity);
    assert_eq!(o.attack_requirements, r.attack_requirements);
    assert_eq!(o.privileges_required, r.privileges_required);
    assert_eq!(o.user_interaction, r.user_interaction);
    assert_eq!(o.vuln_confidentiality_impact, r.vuln_confidentiality_impact);
    assert_eq!(o.vuln_integrity_impact, r.vuln_integrity_impact);
    assert_eq!(o.vuln_availability_impact, r.vuln_availability_impact);
    assert_eq!(o.sub_confidentiality_impact, r.sub_confidentiality_impact);
    assert_eq!(o.sub_integrity_impact, r.sub_integrity_impact);
    assert_eq!(o.sub_availability_impact, r.sub_availability_impact);

    // Verify threat metrics
    assert_eq!(o.exploit_maturity, r.exploit_maturity);

    // Verify environmental metrics
    assert_eq!(o.confidentiality_requirement, r.confidentiality_requirement);
    assert_eq!(o.integrity_requirement, r.integrity_requirement);
    assert_eq!(o.availability_requirement, r.availability_requirement);
    assert_eq!(o.modified_attack_vector, r.modified_attack_vector);
    assert_eq!(o.modified_attack_complexity, r.modified_attack_complexity);
    assert_eq!(
        o.modified_attack_requirements,
        r.modified_attack_requirements
    );
    assert_eq!(
        o.modified_privileges_required,
        r.modified_privileges_required
    );
    assert_eq!(o.modified_user_interaction, r.modified_user_interaction);
    assert_eq!(
        o.modified_vuln_confidentiality_impact,
        r.modified_vuln_confidentiality_impact
    );
    assert_eq!(
        o.modified_vuln_integrity_impact,
        r.modified_vuln_integrity_impact
    );
    assert_eq!(
        o.modified_vuln_availability_impact,
        r.modified_vuln_availability_impact
    );
    assert_eq!(
        o.modified_sub_confidentiality_impact,
        r.modified_sub_confidentiality_impact
    );
    assert_eq!(
        o.modified_sub_integrity_impact,
        r.modified_sub_integrity_impact
    );
    assert_eq!(
        o.modified_sub_availability_impact,
        r.modified_sub_availability_impact
    );

    // Verify supplemental metrics
    assert_eq!(o.safety, r.safety);
    assert_eq!(o.automatable, r.automatable);
    assert_eq!(o.recovery, r.recovery);
    assert_eq!(o.value_density, r.value_density);
    assert_eq!(
        o.vulnerability_response_effort,
        r.vulnerability_response_effort
    );
    assert_eq!(o.provider_urgency, r.provider_urgency);
}
