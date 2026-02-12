use cvss_rs::v2_0::CvssV2;
use std::str::FromStr;

#[test]
fn test_v2_score_calculation() {
    // AV:N/AC:L/Au:N/C:C/I:C/A:C
    // This is a high severity vulnerability
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    assert_eq!(calculated_score, 10.0);
}

#[test]
fn test_v2_partial_impact_calculation() {
    // AV:N/AC:L/Au:N/C:P/I:P/A:P
    let vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    // Impact = 10.41 * (1 - (1-0.275)^3) = 6.443...
    // Exploitability = 20 * 1.0 * 0.71 * 0.704 = 10.0
    // Score = ((0.6*6.443) + (0.4*10.0) - 1.5) * 1.176 = 7.459... -> round to 7.5
    assert_eq!(calculated_score, 7.5);
}

#[test]
fn test_v2_zero_impact_score() {
    // AV:N/AC:L/Au:N/C:N/I:N/A:N
    let vector = "AV:N/AC:L/Au:N/C:N/I:N/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    // Impact = 10.41 * (1 - (1-0)^3) = 0.0
    // Exploitability = 20 * 1.0 * 0.71 * 0.704 = 10.0
    // Score = ((0.6*0.0) + (0.4*10.0) - 1.5) * 0 = 0 (since impact is 0, f_impact is 0, so score should be 0)
    assert_eq!(calculated_score, 0.0);
}

#[test]
fn test_v2_undefined_temporal_and_environmental_metrics() {
    // AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    let calculated_temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    let calculated_environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    // With all temporal and environmental metrics set to NotDefined,
    // the temporal and environmental scores should be the same as the base score
    assert_eq!(calculated_score, 10.0);
    assert_eq!(calculated_temporal_score, 10.0);
    assert_eq!(calculated_environmental_score, 10.0);
}

#[test]
fn test_v2_missing_temporal_and_environmental_metrics() {
    // AV:N/AC:L/Au:N/C:C/I:C/A:C
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    let calculated_temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    let calculated_environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    // With all temporal and environmental metrics missing, the metrics should default to NotDefined,
    // so the temporal and environmental scores should be the same as the base score
    assert_eq!(calculated_score, 10.0);
    assert_eq!(calculated_temporal_score, 10.0);
    assert_eq!(calculated_environmental_score, 10.0);
}

#[test]
fn test_v2_real_cve_2002_0392() {
    // This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
    // https://www.first.org/cvss/v2/guide#3-3-1-CVE-2002-0392
    let vector = "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    let calculated_temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    let calculated_environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    assert_eq!(calculated_score, 7.8);
    assert_eq!(calculated_temporal_score, 6.4);
    assert_eq!(calculated_environmental_score, 9.2);
}

#[test]
fn test_v2_real_cve_2003_0062() {
    // This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
    // https://www.first.org/cvss/v2/guide#3-3-3-CVE-2003-0062
    let vector = "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    let calculated_temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    let calculated_environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    assert_eq!(calculated_score, 6.2);
    assert_eq!(calculated_temporal_score, 4.9);
    assert_eq!(calculated_environmental_score, 7.5);
}

#[test]
fn test_v2_real_cve_2003_0818() {
    // This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
    // https://www.first.org/cvss/v2/guide#3-3-2-CVE-2003-0818
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    let calculated_temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    let calculated_environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    assert_eq!(calculated_score, 10.0);
    assert_eq!(calculated_temporal_score, 8.3);
    assert_eq!(calculated_environmental_score, 9.0);
}
