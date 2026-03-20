use cvss_rs::v3::CvssV3;
use rstest::rstest;
use std::str::FromStr;

/// Helper function to parse a CVSS v3 vector and verify base, temporal, and environmental scores
///
/// This function parses the provided CVSS v3 vector string and checks for each of the expected scores
/// provided (base, temporal, environmental) if the calculated score matches the expected score.
///
/// Arguments:
/// - `vector`: The CVSS v3 vector string to parse and evaluate
/// - `expected_base`: The expected base score
/// - `expected_temporal`: Optional expected temporal score
/// - `expected_environmental`: Optional expected environmental score
fn assert_v3_scores(
    vector: &str,
    expected_base: f64,
    expected_temporal: Option<f64>,
    expected_environmental: Option<f64>,
) {
    let cvss = CvssV3::from_str(vector)
        .unwrap_or_else(|_| panic!("Failed to parse CVSS v3 vector: {}", vector));

    let calculated_base = cvss
        .calculated_base_score()
        .expect("Failed to calculate base score");
    assert_eq!(
        calculated_base, expected_base,
        "Base score mismatch for vector: {}. Expected: {}, Calculated: {}",
        vector, expected_base, calculated_base
    );

    if let Some(expected_temporal) = expected_temporal {
        let calculated_temporal = cvss
            .calculated_temporal_score()
            .expect("Failed to calculate temporal score");
        assert_eq!(
            calculated_temporal, expected_temporal,
            "Temporal score mismatch for vector: {}. Expected: {}, Calculated: {}",
            vector, expected_temporal, calculated_temporal
        );
    }

    if let Some(expected_environmental) = expected_environmental {
        let calculated_environmental = cvss
            .calculated_environmental_score()
            .expect("Failed to calculate environmental score");
        assert_eq!(
            calculated_environmental, expected_environmental,
            "Environmental score mismatch for vector: {}. Expected: {}, Calculated: {}",
            vector, expected_environmental, calculated_environmental
        );
    }
}

/// Helper function to parse a CVSS v3 vector and verify only the base score
fn assert_v3_base_score(vector: &str, expected_base: f64) {
    assert_v3_scores(vector, expected_base, None, None);
}

#[test]
fn test_v3_score_calculation() {
    // This is a critical vulnerability with base score 9.8
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    assert_v3_scores(vector, 9.8, Some(9.8), Some(9.8));
}

#[test]
fn test_v3_scope_changed_calculation() {
    // Scope changed (S:C) with low privileges required
    let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
    // With scope changed, PR:L uses 0.68 instead of 0.62
    assert_v3_base_score(vector, 9.9);
}

#[test]
fn test_v3_temporal_score_calculation() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C";
    // Base (9.8) * E(0.94) * RL(0.95) * RC(1.0) = 8.75... -> roundup to 8.8
    assert_v3_scores(vector, 9.8, Some(8.8), None);
}

#[test]
fn test_v3_environmental_score_calculation() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H";
    // With all security requirements set to High (1.5), modified impact is capped at 0.915
    // but the final roundup still results in 9.8
    assert_v3_scores(vector, 9.8, None, Some(9.8));
}

#[test]
fn test_v3_zero_impact_score() {
    // No impact should result in score 0.0
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
    assert_v3_base_score(vector, 0.0);
}

#[test]
fn test_v3_cve_with_some_not_defined() {
    // This vector is based on an issue brought up here: https://github.com/scm-rs/cvss-rs/issues/9
    // This tests that explicit `NotDefined` / `X` values in the modified metrics used in the
    // environmental score calculation are handled correctly / like implicit
    // "NotDefined" values caused by absence in the vector string.
    let vector_explicit =
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/MAV:A/MAC:L/MPR:N/MUI:X/MS:U/CR:L/IR:H/AR:X";
    assert_v3_scores(vector_explicit, 7.8, Some(7.8), Some(8.0));
    let vector_implicit =
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/MAV:A/MAC:L/MPR:N/MS:U/CR:L/IR:H";
    assert_v3_scores(vector_implicit, 7.8, Some(7.8), Some(8.0));
}

/// These are real CVEs with the metrics taken from the official first.org CVSS examples.
/// Tests for CVEs with base score only.
#[rstest]
// This test only exists in the v3.0 examples.
// https://www.first.org/cvss/v3.0/examples#phpMyAdmin-Reflected-Cross-site-Scripting-Vulnerability-CVE-2013-1937
#[case::cve_2013_1937_v3_0("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1)]
// This test only exists in the v3.0 examples.
// https://www.first.org/cvss/v3.0/examples#DokuWiki-Reflected-Cross-site-Scripting-Attack-CVE-2014-9253
#[case::cve_2014_9253_v3_0("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4)]
// This was re-scored in CVSS v3.1.
// https://www.first.org/cvss/v3.0/examples#Cisco-IOS-Arbitrary-Command-Execution-Vulnerability-CVE-2012-0384
#[case::cve_2012_0384_v3_0("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8)]
// https://www.first.org/cvss/v3.1/examples#MySQL-Stored-SQL-Injection-CVE-2013-0375
#[case::cve_2013_0375_v3_1("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4)]
// https://www.first.org/cvss/v3.1/examples#SSLv3-POODLE-Vulnerability-CVE-2014-3566
#[case::cve_2014_3566_v3_1("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1)]
// https://www.first.org/cvss/v3.1/examples#Apache-Tomcat-XML-Parser-Vulnerability-CVE-2009-0783
#[case::cve_2009_0783_v3_1("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2)]
// v3.1 re-scored PR:L -> PR:H, resulting in score 7.2 instead of 8.8.
// https://www.first.org/cvss/v3.1/examples#Cisco-IOS-Arbitrary-Command-Execution-Vulnerability-CVE-2012-0384
#[case::cve_2012_0384_v3_1("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2)]
// https://www.first.org/cvss/v3.1/examples#Apple-iWork-Denial-of-Service-Vulnerability-CVE-2015-1098
#[case::cve_2015_1098_v3_1("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8)]
// https://www.first.org/cvss/v3.1/examples#OpenSSL-Heartbleed-Vulnerability-CVE-2014-0160
#[case::cve_2014_0160_v3_1("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5)]
// https://www.first.org/cvss/v3.1/examples#DNS-Kaminsky-Bug-CVE-2008-1447
#[case::cve_2008_1447_v3_1("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", 6.8)]
// https://www.first.org/cvss/v3.1/examples#Sophos-Login-Screen-Bypass-Vulnerability-CVE-2014-2005
#[case::cve_2014_2005_v3_1("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8)]
// https://www.first.org/cvss/v3.1/examples#Joomla-Directory-Traversal-Vulnerability-CVE-2010-0467
#[case::cve_2010_0467_v3_1("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", 5.8)]
// https://www.first.org/cvss/v3.1/examples#Cisco-Access-Control-Bypass-Vulnerability-CVE-2012-1342
#[case::cve_2012_1342_v3_1("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8)]
// https://www.first.org/cvss/v3.1/examples#Juniper-Proxy-ARP-Denial-of-Service-Vulnerability-CVE-2013-6014
#[case::cve_2013_6014_v3_1("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", 9.3)]
// https://www.first.org/cvss/v3.1/examples#Microsoft-Windows-Bluetooth-Remote-Code-Execution-Vulnerability-CVE-2011-1265
#[case::cve_2011_1265_v3_1("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8)]
// https://www.first.org/cvss/v3.1/examples#Apple-iOS-Security-Control-Bypass-Vulnerability-CVE-2014-2019
#[case::cve_2014_2019_v3_1("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 4.6)]
// https://www.first.org/cvss/v3.1/examples#SearchBlox-Cross-Site-Request-Forgery-Vulnerability-CVE-2015-0970
#[case::cve_2015_0970_v3_1("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8)]
// https://www.first.org/cvss/v3.1/examples#SSL-TLS-MITM-Vulnerability-CVE-2014-0224
#[case::cve_2014_0224_v3_1("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4)]
// https://www.first.org/cvss/v3.1/examples#Google-Chrome-Sandbox-Bypass-vulnerability-CVE-2012-5376
#[case::cve_2012_5376_v3_1("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6)]
// https://www.first.org/cvss/v3.1/examples#SAMR-LSAD-Privilege-Escalation-via-Protocol-Downgrade-Vulnerability-Badlock-CVE-2016-0128-and-CVE-2016-2118
#[case::cve_2016_0128_v3_1("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8)]
// https://www.first.org/cvss/v3.1/examples#SAMR-LSAD-Privilege-Escalation-via-Protocol-Downgrade-Vulnerability-Badlock-CVE-2016-0128-and-CVE-2016-2118
#[case::cve_2016_2118_v3_1("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.5)]
// https://www.first.org/cvss/v3.1/examples#Cantemo-Portal-Stored-Cross-site-Scripting-Vulnerability-CVE-2019-7551
#[case::cve_2019_7551_v3_1("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 9.0)]
// https://www.first.org/cvss/v3.1/examples#WordPress-Mail-Plugin-Reflected-Cross-site-Scripting-Vulnerability-CVE-2017-5942
#[case::cve_2017_5942_v3_1("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1)]
// https://www.first.org/cvss/v3.1/examples#Remote-Code-Execution-in-Oracle-Outside-in-Technology-CVE-2016-5558
#[case::cve_2016_5558_v3_1("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", 8.6)]
// https://www.first.org/cvss/v3.1/examples#Lenovo-ThinkPwn-Exploit-CVE-2016-5729
#[case::cve_2016_5729_v3_1("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.2)]
// https://www.first.org/cvss/v3.1/examples#Failure-to-Lock-Flash-on-Resume-from-sleep-CVE-2015-2890
#[case::cve_2015_2890_v3_1("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", 6.0)]
// https://www.first.org/cvss/v3.1/examples#Intel-DCI-Issue-CVE-2018-3652
#[case::cve_2018_3652_v3_1("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 7.6)]
// https://www.first.org/cvss/v3.1/examples#Scripting-Engine-Memory-Corruption-Vulnerability-CVE-2019-0884
#[case::cve_2019_0884_v3_1("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2)]
fn test_real_cve_base_only(#[case] vector: &str, #[case] expected_base: f64) {
    assert_v3_base_score(vector, expected_base);
}
