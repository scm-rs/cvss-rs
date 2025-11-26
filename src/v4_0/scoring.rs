//! CVSS v4.0 scoring algorithm implementation.
//!
//! Implements the MacroVector-based scoring algorithm as specified in:
//! https://www.first.org/cvss/v4.0/specification-document

use super::*;
use crate::v4_0::lookup::lookup_global;
use crate::v4_0::lookup::{max_composed, max_severity};

/// Represents the Equivalence groups (EQ) used in CVSS v4.0 scoring.
#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub(crate) enum VectorEq {
    Eq1(u8),
    Eq2(u8),
    Eq3Eq6(u8, u8),
    Eq4(u8),
    Eq5(u8),
}

/// Represents a MacroVector tuple (EQ1-EQ6) used for score lookup.
#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub(crate) struct MacroVector {
    pub eq1: u8,
    pub eq2: u8,
    pub eq3: u8,
    pub eq4: u8,
    pub eq5: u8,
    pub eq6: u8,
}

impl MacroVector {
    pub fn new(eq1: u8, eq2: u8, eq3: u8, eq4: u8, eq5: u8, eq6: u8) -> Self {
        MacroVector {
            eq1,
            eq2,
            eq3,
            eq4,
            eq5,
            eq6,
        }
    }

    pub fn as_tuple(&self) -> (u8, u8, u8, u8, u8, u8) {
        (self.eq1, self.eq2, self.eq3, self.eq4, self.eq5, self.eq6)
    }

    pub fn incr_eq1(&self) -> Self {
        Self {
            eq1: self.eq1 + 1,
            ..*self
        }
    }

    pub fn incr_eq2(&self) -> Self {
        Self {
            eq2: self.eq2 + 1,
            ..*self
        }
    }

    pub fn incr_eq3(&self) -> Self {
        Self {
            eq3: self.eq3 + 1,
            ..*self
        }
    }

    pub fn incr_eq4(&self) -> Self {
        Self {
            eq4: self.eq4 + 1,
            ..*self
        }
    }

    pub fn incr_eq5(&self) -> Self {
        Self {
            eq5: self.eq5 + 1,
            ..*self
        }
    }

    pub fn incr_eq6(&self) -> Self {
        Self {
            eq6: self.eq6 + 1,
            ..*self
        }
    }
}

// Helper functions to merge base metrics with modified/environmental metrics
// Modified metrics override base metrics if present

fn merge_av(base: AttackVector, modified: Option<AttackVector>) -> AttackVector {
    modified.unwrap_or(base)
}

fn merge_ac(base: AttackComplexity, modified: Option<AttackComplexity>) -> AttackComplexity {
    modified.unwrap_or(base)
}

fn merge_at(base: AttackRequirements, modified: Option<AttackRequirements>) -> AttackRequirements {
    modified.unwrap_or(base)
}

fn merge_pr(base: PrivilegesRequired, modified: Option<PrivilegesRequired>) -> PrivilegesRequired {
    modified.unwrap_or(base)
}

fn merge_ui(base: UserInteraction, modified: Option<UserInteraction>) -> UserInteraction {
    modified.unwrap_or(base)
}

fn merge_impact(base: Impact, modified: Option<Impact>) -> Impact {
    modified.unwrap_or(base)
}

fn merge_subsequent_impact(
    base: SubsequentImpact,
    modified: Option<SubsequentImpact>,
) -> SubsequentImpact {
    modified.unwrap_or(base)
}

fn merge_exploit_maturity(e: Option<ExploitMaturity>) -> ExploitMaturity {
    match e {
        Some(ExploitMaturity::NotDefined) | None => ExploitMaturity::Attacked,
        Some(other) => other,
    }
}

fn merge_requirement(r: Option<Requirement>) -> Requirement {
    r.unwrap_or(Requirement::High)
}

/// Calculate EQ1: Exploitation complexity (AV, PR, UI)
/// - 0: AV:N and PR:N and UI:N
/// - 1: (AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
/// - 2: not(AV:N or PR:N or UI:N) or AV:P
fn eq1(av: AttackVector, pr: PrivilegesRequired, ui: UserInteraction) -> u8 {
    if av == AttackVector::Network && pr == PrivilegesRequired::None && ui == UserInteraction::None
    {
        0
    } else if (av == AttackVector::Network
        || pr == PrivilegesRequired::None
        || ui == UserInteraction::None)
        && av != AttackVector::Physical
    {
        1
    } else {
        2
    }
}

/// Calculate EQ2: Attack requirements (AC, AT)
/// - 0: AC:L and AT:N
/// - 1: not(AC:L and AT:N)
fn eq2(ac: AttackComplexity, at: AttackRequirements) -> u8 {
    if ac == AttackComplexity::Low && at == AttackRequirements::None {
        0
    } else {
        1
    }
}

/// Calculate EQ3: Vulnerable system impact (VC, VI, VA)
/// - 0: VC:H and VI:H
/// - 1: not(VC:H and VI:H) and (VC:H or VI:H or VA:H)
/// - 2: not (VC:H or VI:H or VA:H)
fn eq3(vc: Impact, vi: Impact, va: Impact) -> u8 {
    if vc == Impact::High && vi == Impact::High {
        0
    } else if vc == Impact::High || vi == Impact::High || va == Impact::High {
        1
    } else {
        2
    }
}

/// Calculate EQ4: Subsequent System impacts (SC, SI, SA)
/// - 0: SC:S or SI:S or SA:S (Safety impact)
/// - 1: not (SC:S or SI:S or SA:S) and (SC:H or SI:H or SA:H)
/// - 2: not (SC:S or SI:S or SA:S) and not (SC:H or SI:H or SA:H)
fn eq4(sc: SubsequentImpact, si: SubsequentImpact, sa: SubsequentImpact) -> u8 {
    // Check for Safety impact first (EQ4 = 0)
    if sc == SubsequentImpact::Safety
        || si == SubsequentImpact::Safety
        || sa == SubsequentImpact::Safety
    {
        0
    } else if sc == SubsequentImpact::High
        || si == SubsequentImpact::High
        || sa == SubsequentImpact::High
    {
        1
    } else {
        2
    }
}

/// Calculate EQ5: Exploit maturity (E)
/// - 0: E:A (Attacked)
/// - 1: E:P (ProofOfConcept)
/// - 2: E:U (Unreported) or E:X (NotDefined)
fn eq5(e: ExploitMaturity) -> u8 {
    match e {
        ExploitMaturity::Attacked => 0,
        ExploitMaturity::ProofOfConcept => 1,
        ExploitMaturity::Unreported | ExploitMaturity::NotDefined => 2,
    }
}

/// Calculate EQ6: Security requirements (CR, IR, AR) combined with impacts
/// - 0: (CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
/// - 1: not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]
fn eq6(
    cr: Requirement,
    vc: Impact,
    ir: Requirement,
    vi: Impact,
    ar: Requirement,
    va: Impact,
) -> u8 {
    if (cr == Requirement::High && vc == Impact::High)
        || (ir == Requirement::High && vi == Impact::High)
        || (ar == Requirement::High && va == Impact::High)
    {
        0
    } else {
        1
    }
}

/// Main scoring function that calculates the CVSS v4.0 score.
/// Returns None if required base metrics are missing.
///
/// If `include_threat_metrics` is false, the E metric will be fixed to Attacked (EQ5=0)
/// regardless of its actual value. This is used for calculating the "base score" which
/// excludes threat metrics for backwards compatibility with CVSS v3.x.
pub fn calculate_score_internal(cvss: &CvssV4, include_threat_metrics: bool) -> Option<f64> {
    // Get base metrics - all are required for scoring
    let base_av = cvss.attack_vector.as_ref()?;
    let base_ac = cvss.attack_complexity.as_ref()?;
    let base_at = cvss.attack_requirements.as_ref()?;
    let base_pr = cvss.privileges_required.as_ref()?;
    let base_ui = cvss.user_interaction.as_ref()?;
    let base_vc = cvss.vuln_confidentiality_impact.as_ref()?;
    let base_vi = cvss.vuln_integrity_impact.as_ref()?;
    let base_va = cvss.vuln_availability_impact.as_ref()?;
    let base_sc = cvss.sub_confidentiality_impact.as_ref()?;
    let base_si = cvss.sub_integrity_impact.as_ref()?;
    let base_sa = cvss.sub_availability_impact.as_ref()?;

    // Merge base metrics with modified/environmental metrics
    let av = merge_av(*base_av, cvss.modified_attack_vector);
    let ac = merge_ac(*base_ac, cvss.modified_attack_complexity);
    let at = merge_at(*base_at, cvss.modified_attack_requirements);
    let pr = merge_pr(*base_pr, cvss.modified_privileges_required);
    let ui = merge_ui(*base_ui, cvss.modified_user_interaction);
    let vc = merge_impact(*base_vc, cvss.modified_vuln_confidentiality_impact);
    let vi = merge_impact(*base_vi, cvss.modified_vuln_integrity_impact);
    let va = merge_impact(*base_va, cvss.modified_vuln_availability_impact);
    let sc = merge_subsequent_impact(*base_sc, cvss.modified_sub_confidentiality_impact);
    let si = merge_subsequent_impact(*base_si, cvss.modified_sub_integrity_impact);
    let sa = merge_subsequent_impact(*base_sa, cvss.modified_sub_availability_impact);

    // Merge threat and environmental metrics
    // For base score calculation, always use E:A (Attacked) regardless of actual value
    let e = if include_threat_metrics {
        merge_exploit_maturity(cvss.exploit_maturity)
    } else {
        ExploitMaturity::Attacked // Base score always uses E:A (EQ5=0)
    };
    let cr = merge_requirement(cvss.confidentiality_requirement);
    let ir = merge_requirement(cvss.integrity_requirement);
    let ar = merge_requirement(cvss.availability_requirement);

    // Exception for no impact on system (shortcut to 0.0)
    if vc == Impact::None
        && vi == Impact::None
        && va == Impact::None
        && sc == SubsequentImpact::None
        && si == SubsequentImpact::None
        && sa == SubsequentImpact::None
    {
        return Some(0.0);
    }

    // Calculate MacroVector
    let macro_vector = MacroVector::new(
        eq1(av, pr, ui),
        eq2(ac, at),
        eq3(vc, vi, va),
        eq4(sc, si, sa),
        eq5(e),
        eq6(cr, vc, ir, vi, ar, va),
    );

    // Lookup base score from MacroVector
    let value = lookup_global(&macro_vector)?;

    // Calculate next lower macro scores
    let score_eq1_next_lower = lookup_global(&macro_vector.incr_eq1());
    let score_eq2_next_lower = lookup_global(&macro_vector.incr_eq2());

    // EQ3 and EQ6 are related
    let score_eq3eq6_next_lower =
        if (macro_vector.eq3 == 0 || macro_vector.eq3 == 1) && macro_vector.eq6 == 1 {
            // 11 --> 21 or 01 --> 11
            lookup_global(&macro_vector.incr_eq3())
        } else if macro_vector.eq3 == 1 && macro_vector.eq6 == 0 {
            // 10 --> 11
            lookup_global(&macro_vector.incr_eq6())
        } else if macro_vector.eq3 == 0 && macro_vector.eq6 == 0 {
            // 00 --> 01 or 00 --> 10 (take the higher score)
            let left = lookup_global(&macro_vector.incr_eq6());
            let right = lookup_global(&macro_vector.incr_eq3());
            if left > right {
                left
            } else {
                right
            }
        } else {
            // 21 --> 32 (does not exist)
            lookup_global(&macro_vector.incr_eq3())
        };

    let score_eq4_next_lower = lookup_global(&macro_vector.incr_eq4());
    let score_eq5_next_lower = lookup_global(&macro_vector.incr_eq5());

    // Get max severity vectors for each EQ
    let eq1_maxes = max_composed(VectorEq::Eq1(macro_vector.eq1));
    let eq2_maxes = max_composed(VectorEq::Eq2(macro_vector.eq2));
    let eq3_eq6_maxes = max_composed(VectorEq::Eq3Eq6(macro_vector.eq3, macro_vector.eq6));
    let eq4_maxes = max_composed(VectorEq::Eq4(macro_vector.eq4));
    let eq5_maxes = max_composed(VectorEq::Eq5(macro_vector.eq5));

    // Compose all max vectors
    let mut max_vectors = Vec::new();
    for eq1_max in &eq1_maxes {
        for eq2_max in &eq2_maxes {
            for eq3_eq6_max in &eq3_eq6_maxes {
                for eq4_max in &eq4_maxes {
                    for eq5_max in &eq5_maxes {
                        max_vectors.push(format!(
                            "{}{}{}{}{}",
                            eq1_max, eq2_max, eq3_eq6_max, eq4_max, eq5_max
                        ));
                    }
                }
            }
        }
    }

    // Calculate severity distances
    let mut severity_distance_av = 0.0;
    let mut severity_distance_pr = 0.0;
    let mut severity_distance_ui = 0.0;
    let mut severity_distance_ac = 0.0;
    let mut severity_distance_at = 0.0;
    let mut severity_distance_vc = 0.0;
    let mut severity_distance_vi = 0.0;
    let mut severity_distance_va = 0.0;
    let mut severity_distance_sc = 0.0;
    let mut severity_distance_si = 0.0;
    let mut severity_distance_sa = 0.0;
    let mut severity_distance_cr = 0.0;
    let mut severity_distance_ir = 0.0;
    let mut severity_distance_ar = 0.0;

    // Find the appropriate max vector
    for max_vector_str in &max_vectors {
        let max_vector_metrics = parse_max_vector(max_vector_str)?;

        severity_distance_av = av.level() - max_vector_metrics.av.level();
        severity_distance_pr = pr.level() - max_vector_metrics.pr.level();
        severity_distance_ui = ui.level() - max_vector_metrics.ui.level();
        severity_distance_ac = ac.level() - max_vector_metrics.ac.level();
        severity_distance_at = at.level() - max_vector_metrics.at.level();
        severity_distance_vc = vc.level() - max_vector_metrics.vc.level();
        severity_distance_vi = vi.level() - max_vector_metrics.vi.level();
        severity_distance_va = va.level() - max_vector_metrics.va.level();
        severity_distance_sc = sc.level() - max_vector_metrics.sc.level();
        severity_distance_si = si.level() - max_vector_metrics.si.level();
        severity_distance_sa = sa.level() - max_vector_metrics.sa.level();
        severity_distance_cr = cr.level() - max_vector_metrics.cr.level();
        severity_distance_ir = ir.level() - max_vector_metrics.ir.level();
        severity_distance_ar = ar.level() - max_vector_metrics.ar.level();

        // If any distance is negative, this isn't the right max vector
        if severity_distance_av < 0.0
            || severity_distance_pr < 0.0
            || severity_distance_ui < 0.0
            || severity_distance_ac < 0.0
            || severity_distance_at < 0.0
            || severity_distance_vc < 0.0
            || severity_distance_vi < 0.0
            || severity_distance_va < 0.0
            || severity_distance_sc < 0.0
            || severity_distance_si < 0.0
            || severity_distance_sa < 0.0
            || severity_distance_cr < 0.0
            || severity_distance_ir < 0.0
            || severity_distance_ar < 0.0
        {
            continue;
        } else {
            // Found the right max vector
            break;
        }
    }

    // Calculate current severity distances for each EQ
    let current_severity_distance_eq1 =
        severity_distance_av + severity_distance_pr + severity_distance_ui;
    let current_severity_distance_eq2 = severity_distance_ac + severity_distance_at;
    let current_severity_distance_eq3eq6 = severity_distance_vc
        + severity_distance_vi
        + severity_distance_va
        + severity_distance_cr
        + severity_distance_ir
        + severity_distance_ar;
    let current_severity_distance_eq4 =
        severity_distance_sc + severity_distance_si + severity_distance_sa;

    let step = 0.1;

    // Calculate available distances
    let available_distance_eq1 = score_eq1_next_lower.map(|v| value - v);
    let available_distance_eq2 = score_eq2_next_lower.map(|v| value - v);
    let available_distance_eq3eq6 = score_eq3eq6_next_lower.map(|v| value - v);
    let available_distance_eq4 = score_eq4_next_lower.map(|v| value - v);
    let available_distance_eq5 = score_eq5_next_lower.map(|v| value - v);

    let mut n_existing_lower = 0;

    // Get max severity values
    let max_severity_eq1 = max_severity(VectorEq::Eq1(macro_vector.eq1)) as f64 * step;
    let max_severity_eq2 = max_severity(VectorEq::Eq2(macro_vector.eq2)) as f64 * step;
    let max_severity_eq3eq6 =
        max_severity(VectorEq::Eq3Eq6(macro_vector.eq3, macro_vector.eq6)) as f64 * step;
    let max_severity_eq4 = max_severity(VectorEq::Eq4(macro_vector.eq4)) as f64 * step;

    // Calculate normalized severities
    let normalized_severity_eq1 = if let Some(a) = available_distance_eq1 {
        n_existing_lower += 1;
        let percent = current_severity_distance_eq1 / max_severity_eq1;
        a * percent
    } else {
        0.0
    };

    let normalized_severity_eq2 = if let Some(a) = available_distance_eq2 {
        n_existing_lower += 1;
        let percent = current_severity_distance_eq2 / max_severity_eq2;
        a * percent
    } else {
        0.0
    };

    let normalized_severity_eq3eq6 = if let Some(a) = available_distance_eq3eq6 {
        n_existing_lower += 1;
        let percent = current_severity_distance_eq3eq6 / max_severity_eq3eq6;
        a * percent
    } else {
        0.0
    };

    let normalized_severity_eq4 = if let Some(a) = available_distance_eq4 {
        n_existing_lower += 1;
        let percent = current_severity_distance_eq4 / max_severity_eq4;
        a * percent
    } else {
        0.0
    };

    let normalized_severity_eq5 = if available_distance_eq5.is_some() {
        n_existing_lower += 1;
        // EQ5 percentage is always 0
        0.0
    } else {
        0.0
    };

    // Calculate mean distance
    let mean_distance = if n_existing_lower == 0 {
        0.0
    } else {
        (normalized_severity_eq1
            + normalized_severity_eq2
            + normalized_severity_eq3eq6
            + normalized_severity_eq4
            + normalized_severity_eq5)
            / n_existing_lower as f64
    };

    // Final score is base score minus mean distance
    Some(value - mean_distance)
}

/// Temporary struct to hold parsed max vector metrics
struct MaxVectorMetrics {
    av: AttackVector,
    ac: AttackComplexity,
    at: AttackRequirements,
    pr: PrivilegesRequired,
    ui: UserInteraction,
    vc: Impact,
    vi: Impact,
    va: Impact,
    sc: SubsequentImpact,
    si: SubsequentImpact,
    sa: SubsequentImpact,
    cr: Requirement,
    ir: Requirement,
    ar: Requirement,
}

/// Parse a max vector string into metrics
fn parse_max_vector(s: &str) -> Option<MaxVectorMetrics> {
    // Initialize with defaults
    let mut av = AttackVector::Network;
    let mut ac = AttackComplexity::Low;
    let mut at = AttackRequirements::None;
    let mut pr = PrivilegesRequired::None;
    let mut ui = UserInteraction::None;
    let mut vc = Impact::None;
    let mut vi = Impact::None;
    let mut va = Impact::None;
    let mut sc = SubsequentImpact::None;
    let mut si = SubsequentImpact::None;
    let mut sa = SubsequentImpact::None;
    let mut cr = Requirement::Medium;
    let mut ir = Requirement::Medium;
    let mut ar = Requirement::Medium;

    let s = s.trim_end_matches('/');
    for component in s.split('/') {
        let mut parts = component.split(':');
        let key = parts.next()?.to_ascii_uppercase();
        let value = parts.next()?.to_ascii_uppercase();

        match key.as_str() {
            "AV" => av = value.parse().ok()?,
            "AC" => ac = value.parse().ok()?,
            "AT" => at = value.parse().ok()?,
            "PR" => pr = value.parse().ok()?,
            "UI" => ui = value.parse().ok()?,
            "VC" => vc = value.parse().ok()?,
            "VI" => vi = value.parse().ok()?,
            "VA" => va = value.parse().ok()?,
            "SC" => sc = value.parse().ok()?,
            "SI" => si = value.parse().ok()?,
            "SA" => sa = value.parse().ok()?,
            "CR" => cr = value.parse().ok()?,
            "IR" => ir = value.parse().ok()?,
            "AR" => ar = value.parse().ok()?,
            _ => {}
        }
    }

    Some(MaxVectorMetrics {
        av,
        ac,
        at,
        pr,
        ui,
        vc,
        vi,
        va,
        sc,
        si,
        sa,
        cr,
        ir,
        ar,
    })
}

/// Calculate the full CVSS v4.0 score including all metrics (base, threat, environmental).
pub fn calculate_score(cvss: &CvssV4) -> Option<f64> {
    calculate_score_internal(cvss, true)
}

/// Calculate the base score only (excludes threat metrics like E).
/// This is used for the "baseScore" field which excludes threat metrics
/// for backwards compatibility with CVSS v3.x schema.
pub fn calculate_base_score(cvss: &CvssV4) -> Option<f64> {
    calculate_score_internal(cvss, false)
}
