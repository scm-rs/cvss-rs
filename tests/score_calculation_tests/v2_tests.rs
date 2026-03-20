use cvss_rs::v2_0::CvssV2;
use rstest::rstest;
use std::str::FromStr;

/// Helper function to parse a CVSS v2.0 vector and verify base, temporal, and environmental scores
///
/// This function parses the provided CVSS v2.0 vector string and checks for each of the expected scores
/// provided (base, temporal, environmental) if the calculated score matches the expected score.
///
/// Arguments:
/// - `vector`: The CVSS v2.0 vector string to parse and evaluate
/// - `expected_base`: The expected base score
/// - `expected_temporal`: Optional expected temporal score
/// - `expected_environmental`: Optional expected environmental score
fn assert_v2_scores(
    vector: &str,
    expected_base: f64,
    expected_temporal: Option<f64>,
    expected_environmental: Option<f64>,
) {
    let cvss =
        CvssV2::from_str(vector).expect(&format!("Failed to parse CVSS v2 vector: {}", vector));

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

/// Helper function to parse a CVSS v2.0 vector and verify only the base score
fn assert_v2_base_score(vector: &str, expected_base: f64) {
    assert_v2_scores(vector, expected_base, None, None);
}

#[test]
fn test_v2_base_score_with_missing_temporal_and_environmental_metrics() {
    // This is a high severity vulnerability
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
    // With all temporal and environmental metrics missing, the metrics should default to NotDefined,
    // so the temporal and environmental scores should be the same as the base score
    assert_v2_scores(vector, 10.0, Some(10.0), Some(10.0));
}

#[test]
fn test_v2_base_score_with_not_defined_temporal_and_environmental_metrics() {
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND";
    // With all temporal and environmental metrics set to NotDefined,
    // the temporal and environmental scores should be the same as the base score
    assert_v2_scores(vector, 10.0, Some(10.0), Some(10.0));
}

#[test]
fn test_v2_partial_impact_calculation() {
    let vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P";
    // Impact = 10.41 * (1 - (1-0.275)^3) = 6.443...
    // Exploitability = 20 * 1.0 * 0.71 * 0.704 = 10.0
    // Score = ((0.6*6.443) + (0.4*10.0) - 1.5) * 1.176 = 7.459... -> round to 7.5
    assert_v2_base_score(vector, 7.5);
}

#[test]
fn test_v2_zero_impact_score() {
    let vector = "AV:N/AC:L/Au:N/C:N/I:N/A:N";
    // Impact = 10.41 * (1 - (1-0)^3) = 0.0
    // Exploitability = 20 * 1.0 * 0.71 * 0.704 = 10.0
    // Score = ((0.6*0.0) + (0.4*10.0) - 1.5) * 0 = 0 (since impact is 0, f_impact is 0, so score should be 0)
    assert_v2_base_score(vector, 0.0);
}

/// These are real CVEs with the metrics taken from the official first.org CVSS examples.
/// Tests for CVEs with full scores (base, temporal, environmental).
#[rstest]
// https://www.first.org/cvss/v2/guide#3-3-1-CVE-2002-0392
#[case::cve_2002_0392(
    "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H",
    7.8,
    6.4,
    9.2
)]
// https://www.first.org/cvss/v2/guide#3-3-3-CVE-2003-0062
#[case::cve_2003_0062(
    "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M",
    6.2,
    4.9,
    7.5
)]
// https://www.first.org/cvss/v2/guide#3-3-2-CVE-2003-0818
#[case::cve_2003_0818(
    "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L",
    10.0,
    8.3,
    9.0
)]
fn test_real_cve_full(
    #[case] vector: &str,
    #[case] expected_base: f64,
    #[case] expected_temporal: f64,
    #[case] expected_environmental: f64,
) {
    assert_v2_scores(
        vector,
        expected_base,
        Some(expected_temporal),
        Some(expected_environmental),
    );
}

/// These are real CVEs with the metrics taken from the official first.org CVSS examples.
/// Tests for CVEs with base score only.
#[rstest]
// https://www.first.org/cvss/v3.0/examples#phpMyAdmin-Reflected-Cross-site-Scripting-Vulnerability-CVE-2013-1937
#[case::cve_2013_1937("AV:N/AC:L/Au:S/C:P/I:P/A:N", 5.5)]
// https://www.first.org/cvss/v3.0/examples#SSLv3-POODLE-Vulnerability-CVE-2014-3566
#[case::cve_2014_3566("AV:N/AC:M/Au:N/C:P/I:N/A:N", 4.3)]
// https://www.first.org/cvss/v3.0/examples#VMware-Guest-to-Host-Escape-Vulnerability-CVE-2012-1516
#[case::cve_2012_1516("AV:N/AC:L/Au:S/C:C/I:C/A:C", 9.0)]
// https://www.first.org/cvss/v3.0/examples#Apache-Tomcat-XML-Parser-Vulnerability-CVE-2009-0783
#[case::cve_2009_0783("AV:L/AC:L/Au:N/C:P/I:P/A:P", 4.6)]
// https://www.first.org/cvss/v3.0/examples#Cisco-IOS-Arbitrary-Command-Execution-Vulnerability-CVE-2012-0384
#[case::cve_2012_0384("AV:N/AC:M/Au:S/C:C/I:C/A:C", 8.5)]
// https://www.first.org/cvss/v3.0/examples#Apple-iWork-Denial-of-Service-Vulnerability-CVE-2015-1098
#[case::cve_2015_1098("AV:N/AC:M/Au:N/C:P/I:P/A:P", 6.8)]
// https://www.first.org/cvss/v3.0/examples#OpenSSL-Heartbleed-Vulnerability-CVE-2014-0160
#[case::cve_2014_0160("AV:N/AC:L/Au:N/C:P/I:N/A:N", 5.0)]
// https://www.first.org/cvss/v3.0/examples#DNS-Kaminsky-Bug-CVE-2008-1447
#[case::cve_2008_1447("AV:N/AC:L/Au:N/C:N/I:P/A:N", 5.0)]
// https://www.first.org/cvss/v3.0/examples#Sophos-Login-Screen-Bypass-Vulnerability-CVE-2014-2005
#[case::cve_2014_2005("AV:L/AC:M/Au:N/C:C/I:C/A:C", 6.9)]
// https://www.first.org/cvss/v3.0/examples#Juniper-Proxy-ARP-Denial-of-Service-Vulnerability-CVE-2013-6014
#[case::cve_2013_6014("AV:A/AC:L/Au:N/C:N/I:C/A:N", 6.1)]
// https://www.first.org/cvss/v3.0/examples#DokuWiki-Reflected-Cross-site-Scripting-Attack-CVE-2014-9253
#[case::cve_2014_9253("AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3)]
// https://www.first.org/cvss/v3.0/examples#Adobe-Acrobat-Buffer-Overflow-Vulnerability-CVE-2009-0658
#[case::cve_2009_0658("AV:N/AC:M/Au:N/C:C/I:C/A:C", 9.3)]
// https://www.first.org/cvss/v3.0/examples#Microsoft-Windows-Bluetooth-Remote-Code-Execution-Vulnerability-CVE-2011-1265
#[case::cve_2011_1265("AV:A/AC:L/Au:N/C:C/I:C/A:C", 8.3)]
// https://www.first.org/cvss/v3.0/examples#Apple-iOS-Security-Control-Bypass-Vulnerability-CVE-2014-2019
#[case::cve_2014_2019("AV:L/AC:L/Au:N/C:N/I:C/A:N", 4.9)]
// https://www.first.org/cvss/v3.0/examples#SAMR-LSAD-Privilege-Escalation-via-Protocol-Downgrade-Vulnerability-Badlock-CVE-2016-0128-and-CVE-2016-2118
#[case::cve_2016_0128("AV:N/AC:M/Au:N/C:P/I:P/A:N", 5.8)]
// https://www.first.org/cvss/v3.1/examples#Cantemo-Portal-Stored-Cross-site-Scripting-Vulnerability-CVE-2019-7551
#[case::cve_2019_7551("AV:N/AC:M/Au:S/C:P/I:P/A:P", 6.0)]
// https://www.first.org/cvss/v3.1/examples#Lenovo-ThinkPwn-Exploit-CVE-2016-5729
#[case::cve_2016_5729("AV:L/AC:L/Au:S/C:C/I:C/A:C", 6.8)]
// https://www.first.org/cvss/v3.1/examples#Failure-to-Lock-Flash-on-Resume-from-sleep-CVE-2015-2890
#[case::cve_2015_2890("AV:L/AC:L/Au:N/C:C/I:C/A:C", 7.2)]
// https://www.first.org/cvss/v3.1/examples#Scripting-Engine-Memory-Corruption-Vulnerability-CVE-2019-0884
#[case::cve_2019_0884("AV:N/AC:H/Au:N/C:C/I:C/A:C", 7.6)]
fn test_real_cve_base_only(#[case] vector: &str, #[case] expected_base: f64) {
    assert_v2_scores(vector, expected_base, None, None);
}
