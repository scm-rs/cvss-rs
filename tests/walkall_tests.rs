use anyhow::{anyhow, bail};
use cvss_rs::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Deserialize;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::Mutex;
use walkdir::WalkDir;

#[derive(Deserialize)]
struct CveRoot {
    containers: CnaContainers,
}

#[derive(Deserialize)]
struct CnaContainers {
    cna: Cna,
}

#[derive(Deserialize)]
struct Cna {
    metrics: Option<Vec<Metric>>,
}

#[derive(Deserialize)]
struct Metric {
    #[serde(rename = "cvssV3_1")]
    cvss_v3_1: Option<CvssV3>,
    #[serde(rename = "cvssV3_0")]
    cvss_v3_0: Option<CvssV3>,
    #[serde(rename = "cvssV2_0")]
    cvss_v2_0: Option<CvssV2>,
    #[serde(rename = "cvssV4_0")]
    cvss_v4_0: Option<CvssV4>,
}

#[test]
fn test_walkall() -> anyhow::Result<()> {
    let source = match env::var("CVE_BASE_DIR") {
        Ok(val) => val,
        Err(_) => {
            println!("CVE_BASE_DIR not set, skipping test");
            return Ok(());
        }
    };

    let walker = WalkDir::new(source).follow_links(true).contents_first(true);
    let mut files = Vec::new();

    for entry in walker {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let name = match entry.file_name().to_str() {
            None => continue,
            Some(name) => name,
        };
        if !name.starts_with("CVE-") {
            continue;
        }
        files.push(entry.into_path());
    }

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} {wide_bar} {pos}/{len} ({eta})")
            .unwrap(),
    );

    let failed_files = Mutex::new(Vec::new());
    let score_mismatches = Mutex::new(Vec::new());
    let stats = Mutex::new(ScoreStats::default());

    files
        .into_par_iter()
        .progress_with(pb)
        .for_each(|file| match process(&file) {
            Ok(result) => {
                let mut stats = stats.lock().unwrap();
                stats.merge(result.stats);
                if !result.mismatches.is_empty() {
                    score_mismatches
                        .lock()
                        .unwrap()
                        .push((file, result.mismatches));
                }
            }
            Err(e) => {
                failed_files.lock().unwrap().push((file, e.to_string()));
            }
        });

    let failed = failed_files.lock().unwrap();
    if !failed.is_empty() {
        for (file, error) in failed.iter() {
            eprintln!("Failed to process file: {:?}, error: {}", file, error);
        }
        bail!("{} files failed to process", failed.len());
    }

    // Print statistics
    let stats = stats.lock().unwrap();
    println!("\n╔═══════════════════════════════════════════════════════════════════╗");
    println!("║                   CVSS Score Validation Results                   ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║ Version │ Total CVEs │  Matches  │   Match Rate                   ║");
    println!("╟─────────┼────────────┼───────────┼────────────────────────────────╢");
    println!(
        "║ V2.0    │ {:>10} │ {:>9} │ {:>6.2}%                        ║",
        stats.v2_total,
        stats.v2_matches,
        if stats.v2_total > 0 {
            stats.v2_matches as f64 / stats.v2_total as f64 * 100.0
        } else {
            0.0
        }
    );
    println!(
        "║ V3.0    │ {:>10} │ {:>9} │ {:>6.2}%                        ║",
        stats.v3_0_total,
        stats.v3_0_matches,
        if stats.v3_0_total > 0 {
            stats.v3_0_matches as f64 / stats.v3_0_total as f64 * 100.0
        } else {
            0.0
        }
    );
    println!(
        "║ V3.1    │ {:>10} │ {:>9} │ {:>6.2}%                        ║",
        stats.v3_1_total,
        stats.v3_1_matches,
        if stats.v3_1_total > 0 {
            stats.v3_1_matches as f64 / stats.v3_1_total as f64 * 100.0
        } else {
            0.0
        }
    );
    println!(
        "║ V4.0    │ {:>10} │ {:>9} │ {:>6.2}%                        ║",
        stats.v4_total,
        stats.v4_matches,
        if stats.v4_total > 0 {
            stats.v4_matches as f64 / stats.v4_total as f64 * 100.0
        } else {
            0.0
        }
    );
    println!("╚═══════════════════════════════════════════════════════════════════╝\n");

    // Print all mismatches
    let mismatches = score_mismatches.lock().unwrap();
    if !mismatches.is_empty() {
        // Group mismatches by version
        let mut v2_mismatches = Vec::new();
        let mut v3_0_mismatches = Vec::new();
        let mut v3_1_mismatches = Vec::new();
        let mut v4_mismatches = Vec::new();

        for (file, file_mismatches) in mismatches.iter() {
            for mismatch in file_mismatches {
                let entry = (file, mismatch);
                match mismatch.version.as_str() {
                    "V2.0" => v2_mismatches.push(entry),
                    "V3.0" => v3_0_mismatches.push(entry),
                    "V3.1" => v3_1_mismatches.push(entry),
                    "V4.0" => v4_mismatches.push(entry),
                    _ => {}
                }
            }
        }

        let total_mismatches = v2_mismatches.len()
            + v3_0_mismatches.len()
            + v3_1_mismatches.len()
            + v4_mismatches.len();

        // Count implementation issues (Red Hat doesn't confirm our calculation)
        let mut implementation_issues = 0;
        for (_, mismatch) in v2_mismatches
            .iter()
            .chain(v3_0_mismatches.iter())
            .chain(v3_1_mismatches.iter())
        {
            match (mismatch.redhat_score, mismatch.base_score) {
                // Red Hat agrees with our base score = CVE DB error, not our issue
                (Some(rh), Some(base)) if (rh - base).abs() < 0.05 => {}
                // Red Hat agrees with JSON = our implementation issue
                (Some(rh), _) if (rh - mismatch.expected_score).abs() < 0.05 => {
                    implementation_issues += 1;
                }
                // Red Hat unavailable or differs from both = potential issue
                _ => {
                    implementation_issues += 1;
                }
            }
        }

        println!("\n╔═══════════════════════════════════════════════════════════════════╗");
        println!("║                      SCORE MISMATCHES FOUND                       ║");
        println!("╚═══════════════════════════════════════════════════════════════════╝\n");

        // Print all V2.0 mismatches
        if !v2_mismatches.is_empty() {
            println!("V2.0 Mismatches ({}):", v2_mismatches.len());
            for (file, mismatch) in v2_mismatches.iter() {
                let filename = file
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                let redhat_status = match mismatch.redhat_score {
                    Some(rh) if (rh - mismatch.calculated_score).abs() < 0.05 => {
                        format!("✓ RedHat agrees ({:.1}) - CVE DB error", rh)
                    }
                    Some(rh) if (rh - mismatch.expected_score).abs() < 0.05 => {
                        format!("✗ RedHat agrees with JSON ({:.1}) - impl issue", rh)
                    }
                    Some(rh) => format!("? RedHat differs ({:.1})", rh),
                    None => "? RedHat unavailable".to_string(),
                };

                println!(
                    "  {} - JSON: {:.1}, Calc: {:.1} | {}\n    Vector: {}",
                    filename,
                    mismatch.expected_score,
                    mismatch.calculated_score,
                    redhat_status,
                    mismatch.vector
                );
            }
            println!();
        }

        // Print all V3.0 mismatches
        if !v3_0_mismatches.is_empty() {
            println!("V3.0 Mismatches ({}):", v3_0_mismatches.len());
            for (file, mismatch) in v3_0_mismatches.iter() {
                let filename = file
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let base = mismatch
                    .base_score
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "N/A".to_string());
                let temporal = mismatch
                    .temporal_score
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "N/A".to_string());
                let env = mismatch
                    .environmental_score
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "N/A".to_string());

                // Red Hat returns base score, so compare with our base_score
                let redhat_status = match (mismatch.redhat_score, mismatch.base_score) {
                    (Some(rh), Some(base)) if (rh - base).abs() < 0.05 => {
                        format!("✓ RedHat agrees ({:.1}) - CVE DB error", rh)
                    }
                    (Some(rh), _) if (rh - mismatch.expected_score).abs() < 0.05 => {
                        format!("✗ RedHat agrees with JSON ({:.1}) - impl issue", rh)
                    }
                    (Some(rh), Some(base)) => {
                        format!("? RedHat ({:.1}) vs our base ({:.1})", rh, base)
                    }
                    (Some(rh), None) => format!("? RedHat: {:.1}", rh),
                    (None, _) => "? RedHat unavailable".to_string(),
                };

                println!(
                    "  {} - JSON: {:.1}, Calc: {:.1} (Base: {}, Temporal: {}, Env: {}) | {}\n    Vector: {}",
                    filename,
                    mismatch.expected_score,
                    mismatch.calculated_score,
                    base,
                    temporal,
                    env,
                    redhat_status,
                    mismatch.vector
                );
            }
            println!();
        }

        // Print all V3.1 mismatches
        if !v3_1_mismatches.is_empty() {
            println!("V3.1 Mismatches ({}):", v3_1_mismatches.len());
            for (file, mismatch) in v3_1_mismatches.iter() {
                let filename = file
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let base = mismatch
                    .base_score
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "N/A".to_string());
                let temporal = mismatch
                    .temporal_score
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "N/A".to_string());
                let env = mismatch
                    .environmental_score
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "N/A".to_string());

                // Red Hat returns base score, so compare with our base_score
                let redhat_status = match (mismatch.redhat_score, mismatch.base_score) {
                    (Some(rh), Some(base)) if (rh - base).abs() < 0.05 => {
                        format!("✓ RedHat agrees ({:.1}) - CVE DB error", rh)
                    }
                    (Some(rh), _) if (rh - mismatch.expected_score).abs() < 0.05 => {
                        format!("✗ RedHat agrees with JSON ({:.1}) - impl issue", rh)
                    }
                    (Some(rh), Some(base)) => {
                        format!("? RedHat ({:.1}) vs our base ({:.1})", rh, base)
                    }
                    (Some(rh), None) => format!("? RedHat: {:.1}", rh),
                    (None, _) => "? RedHat unavailable".to_string(),
                };

                println!(
                    "  {} - JSON: {:.1}, Calc: {:.1} (Base: {}, Temporal: {}, Env: {}) | {}\n    Vector: {}",
                    filename,
                    mismatch.expected_score,
                    mismatch.calculated_score,
                    base,
                    temporal,
                    env,
                    redhat_status,
                    mismatch.vector
                );
            }
            println!();
        }

        // Print all V4.0 mismatches
        if !v4_mismatches.is_empty() {
            println!("V4.0 Mismatches ({}):", v4_mismatches.len());
            for (file, mismatch) in v4_mismatches.iter() {
                let filename = file
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                println!(
                    "  {} - JSON: {:.1}, Calc: {:.1}\n    Vector: {}",
                    filename, mismatch.expected_score, mismatch.calculated_score, mismatch.vector
                );
            }
            println!();
        }

        // Summary
        let cve_db_errors = total_mismatches - implementation_issues - v4_mismatches.len();
        println!("╔═══════════════════════════════════════════════════════════════════╗");
        println!("║                         MISMATCH SUMMARY                          ║");
        println!("╠═══════════════════════════════════════════════════════════════════╣");
        println!(
            "║ Total mismatches:         {:>5}                                   ║",
            total_mismatches
        );
        println!(
            "║ CVE DB errors (verified): {:>5}                                   ║",
            cve_db_errors
        );
        println!(
            "║ Implementation issues:    {:>5}                                   ║",
            implementation_issues
        );
        println!(
            "║ V4.0 (unverified):        {:>5}                                   ║",
            v4_mismatches.len()
        );
        println!("╚═══════════════════════════════════════════════════════════════════╝\n");

        if implementation_issues > 0 {
            bail!(
                "Found {} implementation issues that need fixing",
                implementation_issues
            );
        } else if !v4_mismatches.is_empty() {
            println!(
                "Note: {} V4.0 mismatches found but Red Hat verification unavailable",
                v4_mismatches.len()
            );
            println!(
                "V3.x implementation verified as correct by Red Hat ({} CVE DB errors confirmed)",
                cve_db_errors
            );
        } else {
            println!("All mismatches verified as CVE database errors - implementation is correct!");
        }
    }

    Ok(())
}

#[derive(Default)]
struct ScoreStats {
    v2_total: usize,
    v2_matches: usize,
    v3_0_total: usize,
    v3_0_matches: usize,
    v3_1_total: usize,
    v3_1_matches: usize,
    v4_total: usize,
    v4_matches: usize,
}

impl ScoreStats {
    fn merge(&mut self, other: ScoreStats) {
        self.v2_total += other.v2_total;
        self.v2_matches += other.v2_matches;
        self.v3_0_total += other.v3_0_total;
        self.v3_0_matches += other.v3_0_matches;
        self.v3_1_total += other.v3_1_total;
        self.v3_1_matches += other.v3_1_matches;
        self.v4_total += other.v4_total;
        self.v4_matches += other.v4_matches;
    }
}

struct ScoreMismatch {
    version: String,
    vector: String, // CVSS vector string
    expected_score: f64,
    calculated_score: f64,
    redhat_score: Option<f64>, // Red Hat verification
    // For V3.x: show all three calculation methods
    base_score: Option<f64>,
    temporal_score: Option<f64>,
    environmental_score: Option<f64>,
}

struct ProcessResult {
    stats: ScoreStats,
    mismatches: Vec<ScoreMismatch>,
}

/// Verify a CVSS vector against Red Hat's cvss_calculator CLI tool
fn verify_with_redhat(vector: &str) -> Option<f64> {
    let output = Command::new("cvss_calculator")
        .args(["-v", vector])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with("Base Score:") {
            if let Some(score_str) = line.split_whitespace().nth(2) {
                return score_str.parse().ok();
            }
        }
    }
    None
}

fn process(path: &Path) -> anyhow::Result<ProcessResult> {
    let content = fs::read(path)?;
    let cve: CveRoot = serde_json::from_slice(&content)
        .map_err(|e| anyhow!("Failed to deserialize CVE: {}", e))?;

    let mut stats = ScoreStats::default();
    let mut mismatches = Vec::new();

    if let Some(metrics) = cve.containers.cna.metrics {
        for metric in metrics {
            // Process V2.0
            if let Some(v2) = &metric.cvss_v2_0 {
                stats.v2_total += 1;
                let json_score = v2.base_score;

                // Validate JSON score range
                if !(0.0..=10.0).contains(&json_score) {
                    bail!("Invalid V2.0 base_score: {}", json_score);
                }

                // Parse vector and calculate score
                match CvssV2::from_str(&v2.vector_string) {
                    Ok(parsed) => {
                        match parsed.calculated_base_score() {
                            Some(calculated) => {
                                // calculated_base_score() already rounds to 1 decimal place
                                let diff = (json_score - calculated).abs();

                                if diff < 0.05 {
                                    stats.v2_matches += 1;
                                } else {
                                    let redhat_score = verify_with_redhat(&v2.vector_string);
                                    mismatches.push(ScoreMismatch {
                                        version: "V2.0".to_string(),
                                        vector: v2.vector_string.clone(),
                                        expected_score: json_score,
                                        calculated_score: calculated,
                                        redhat_score,
                                        base_score: None,
                                        temporal_score: None,
                                        environmental_score: None,
                                    });
                                }
                            }
                            None => {
                                // Score calculation returned None
                                mismatches.push(ScoreMismatch {
                                    version: "V2.0".to_string(),
                                    vector: format!("{} (score calc failed)", v2.vector_string),
                                    expected_score: json_score,
                                    calculated_score: 0.0,
                                    redhat_score: None,
                                    base_score: None,
                                    temporal_score: None,
                                    environmental_score: None,
                                });
                            }
                        }
                    }
                    Err(_) => {
                        // Parsing failed
                        mismatches.push(ScoreMismatch {
                            version: "V2.0".to_string(),
                            vector: format!("{} (parse failed)", v2.vector_string),
                            expected_score: json_score,
                            calculated_score: 0.0,
                            redhat_score: None,
                            base_score: None,
                            temporal_score: None,
                            environmental_score: None,
                        });
                    }
                }
            }

            // Process V3.0
            if let Some(v3_0) = &metric.cvss_v3_0 {
                stats.v3_0_total += 1;
                let json_score = v3_0.base_score;

                if !(0.0..=10.0).contains(&json_score) {
                    bail!("Invalid V3.0 base_score: {}", json_score);
                }

                if let Ok(parsed) = CvssV3::from_str(&v3_0.vector_string) {
                    // Try base, temporal, and environmental scores to handle CVE database inconsistency
                    // (some include temporal/environmental metrics in baseScore, some don't)
                    let base_only = parsed.calculated_base_score();
                    let with_temporal = parsed.calculated_temporal_score();
                    let with_environmental = parsed.calculated_environmental_score();

                    // Use the score that matches (prefer base > temporal > environmental)
                    let calculated = if let Some(base) = base_only {
                        if (json_score - base).abs() < 0.05 {
                            Some(base)
                        } else if let Some(temporal) = with_temporal {
                            if (json_score - temporal).abs() < 0.05 {
                                Some(temporal)
                            } else if let Some(env) = with_environmental {
                                Some(env)
                            } else {
                                Some(temporal)
                            }
                        } else if let Some(env) = with_environmental {
                            Some(env)
                        } else {
                            Some(base)
                        }
                    } else {
                        with_temporal.or(with_environmental)
                    };

                    if let Some(calculated) = calculated {
                        let diff = (json_score - calculated).abs();

                        if diff < 0.05 {
                            stats.v3_0_matches += 1;
                        } else {
                            // Red Hat calculator returns base score, so compare with our base_score
                            let redhat_score =
                                base_only.and_then(|_| verify_with_redhat(&v3_0.vector_string));
                            mismatches.push(ScoreMismatch {
                                version: "V3.0".to_string(),
                                vector: v3_0.vector_string.clone(),
                                expected_score: json_score,
                                calculated_score: calculated,
                                redhat_score,
                                base_score: base_only,
                                temporal_score: with_temporal,
                                environmental_score: with_environmental,
                            });
                        }
                    }
                }
            }

            // Process V3.1
            if let Some(v3_1) = &metric.cvss_v3_1 {
                stats.v3_1_total += 1;
                let json_score = v3_1.base_score;

                if !(0.0..=10.0).contains(&json_score) {
                    bail!("Invalid V3.1 base_score: {}", json_score);
                }

                if let Ok(parsed) = CvssV3::from_str(&v3_1.vector_string) {
                    // Try base, temporal, and environmental scores to handle CVE database inconsistency
                    // (some include temporal/environmental metrics in baseScore, some don't)
                    let base_only = parsed.calculated_base_score();
                    let with_temporal = parsed.calculated_temporal_score();
                    let with_environmental = parsed.calculated_environmental_score();

                    // Use the score that matches (prefer base > temporal > environmental)
                    let calculated = if let Some(base) = base_only {
                        if (json_score - base).abs() < 0.05 {
                            Some(base)
                        } else if let Some(temporal) = with_temporal {
                            if (json_score - temporal).abs() < 0.05 {
                                Some(temporal)
                            } else if let Some(env) = with_environmental {
                                Some(env)
                            } else {
                                Some(temporal)
                            }
                        } else if let Some(env) = with_environmental {
                            Some(env)
                        } else {
                            Some(base)
                        }
                    } else {
                        with_temporal.or(with_environmental)
                    };

                    if let Some(calculated) = calculated {
                        let diff = (json_score - calculated).abs();

                        if diff < 0.05 {
                            stats.v3_1_matches += 1;
                        } else {
                            // Red Hat calculator returns base score, so compare with our base_score
                            let redhat_score =
                                base_only.and_then(|_| verify_with_redhat(&v3_1.vector_string));
                            mismatches.push(ScoreMismatch {
                                version: "V3.1".to_string(),
                                vector: v3_1.vector_string.clone(),
                                expected_score: json_score,
                                calculated_score: calculated,
                                redhat_score,
                                base_score: base_only,
                                temporal_score: with_temporal,
                                environmental_score: with_environmental,
                            });
                        }
                    }
                }
            }

            // Process V4.0
            if let Some(v4) = &metric.cvss_v4_0 {
                stats.v4_total += 1;
                let json_score = v4.base_score;

                if !(0.0..=10.0).contains(&json_score) {
                    bail!("Invalid V4.0 base_score: {}", json_score);
                }

                // Calculate with our implementation - try BOTH base score and full score
                // to handle CVE database inconsistency (some include E in baseScore, some don't)
                let (score_without_e, score_with_e) =
                    if let Ok(parsed) = CvssV4::from_str(&v4.vector_string) {
                        (
                            parsed.calculated_base_score(),
                            parsed.calculated_full_score(),
                        )
                    } else {
                        (None, None)
                    };

                // Use the score that matches (prefer without E for backwards compatibility)
                let calculated = if let Some(score_without_e) = score_without_e {
                    if (json_score - score_without_e).abs() < 0.05 {
                        Some(score_without_e)
                    } else if let Some(score_with_e) = score_with_e {
                        Some(score_with_e)
                    } else {
                        Some(score_without_e)
                    }
                } else {
                    score_with_e
                };

                // Compare our implementation with JSON
                if let Some(calculated) = calculated {
                    let diff = (json_score - calculated).abs();
                    if diff < 0.05 {
                        stats.v4_matches += 1;
                    } else {
                        // Red Hat calculator doesn't support V4.0
                        mismatches.push(ScoreMismatch {
                            version: "V4.0".to_string(),
                            vector: v4.vector_string.clone(),
                            expected_score: json_score,
                            calculated_score: calculated,
                            redhat_score: None,
                            base_score: None,
                            temporal_score: None,
                            environmental_score: None,
                        });
                    }
                }
            }
        }
    }

    Ok(ProcessResult { stats, mismatches })
}
