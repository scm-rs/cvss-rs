use cvss_rs::v2_0::CvssV2;
use cvss_rs::v3::CvssV3;
use std::str::FromStr;

#[test]
fn test_v3_score_calculation() {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    // This is a critical vulnerability with base score 9.8
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    assert_eq!(calculated_score, 9.8);
}

#[test]
fn test_v3_scope_changed_calculation() {
    // CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
    // Scope changed (S:C) with low privileges required
    let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    // With scope changed, PR:L uses 0.68 instead of 0.62
    assert_eq!(calculated_score, 9.9);
}

#[test]
fn test_v3_temporal_score_calculation() {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let base_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate base score");
    assert_eq!(base_score, 9.8);

    let temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    // Base (9.8) * E(0.94) * RL(0.95) * RC(1.0) = 8.75... -> roundup to 8.8
    assert_eq!(temporal_score, 8.8);
}

#[test]
fn test_v3_environmental_score_calculation() {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let base_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate base score");
    assert_eq!(base_score, 9.8);

    let environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");
    // With all security requirements set to High (1.5), modified impact is capped at 0.915
    // but the final roundup still results in 9.8
    assert_eq!(environmental_score, 9.8);
}

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
fn test_v3_zero_impact_score() {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
    // No impact should result in score 0.0
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    assert_eq!(calculated_score, 0.0);
}

#[test]
fn test_v2_zero_impact_score() {
    // AV:N/AC:L/Au:N/C:N/I:N/A:N
    // No impact should result in score 0.0
    let vector = "AV:N/AC:L/Au:N/C:N/I:N/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    assert_eq!(calculated_score, 0.0);
}
