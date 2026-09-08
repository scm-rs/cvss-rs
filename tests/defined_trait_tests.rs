use cvss_rs::Defined;
use cvss_rs::v3;
use cvss_rs::v4_0;

#[test]
fn test_v3_defined_trait() {
    assert!(v3::AttackVector::Network.is_defined());
    assert!(!v3::AttackVector::NotDefined.is_defined());

    assert_eq!(
        v3::AttackVector::Network.as_defined(),
        Some(&v3::AttackVector::Network)
    );
    assert_eq!(v3::AttackVector::NotDefined.as_defined(), None);
}

#[test]
fn test_v3_all_enums_have_defined() {
    assert!(!v3::AttackComplexity::NotDefined.is_defined());
    assert!(!v3::PrivilegesRequired::NotDefined.is_defined());
    assert!(!v3::UserInteraction::NotDefined.is_defined());
    assert!(!v3::Scope::NotDefined.is_defined());
    assert!(!v3::Impact::NotDefined.is_defined());
    assert!(!v3::ExploitCodeMaturity::NotDefined.is_defined());
    assert!(!v3::RemediationLevel::NotDefined.is_defined());
    assert!(!v3::ReportConfidence::NotDefined.is_defined());
    assert!(!v3::SecurityRequirement::NotDefined.is_defined());
}

#[test]
fn test_v4_defined_trait() {
    assert!(v4_0::ExploitMaturity::Attacked.is_defined());
    assert!(!v4_0::ExploitMaturity::NotDefined.is_defined());

    assert_eq!(
        v4_0::ExploitMaturity::Attacked.as_defined(),
        Some(&v4_0::ExploitMaturity::Attacked)
    );
    assert_eq!(v4_0::ExploitMaturity::NotDefined.as_defined(), None);
}

#[test]
fn test_v4_all_enums_have_defined() {
    assert!(!v4_0::ModifiedAttackVector::NotDefined.is_defined());
    assert!(!v4_0::ModifiedAttackComplexity::NotDefined.is_defined());
    assert!(!v4_0::ModifiedAttackRequirements::NotDefined.is_defined());
    assert!(!v4_0::ModifiedPrivilegesRequired::NotDefined.is_defined());
    assert!(!v4_0::ModifiedUserInteraction::NotDefined.is_defined());
    assert!(!v4_0::ModifiedImpact::NotDefined.is_defined());
    assert!(!v4_0::ModifiedSubsequentImpact::NotDefined.is_defined());
    assert!(!v4_0::Requirement::NotDefined.is_defined());
    assert!(!v4_0::Safety::NotDefined.is_defined());
    assert!(!v4_0::Automatable::NotDefined.is_defined());
    assert!(!v4_0::Recovery::NotDefined.is_defined());
    assert!(!v4_0::ValueDensity::NotDefined.is_defined());
    assert!(!v4_0::VulnerabilityResponseEffort::NotDefined.is_defined());
    assert!(!v4_0::ProviderUrgency::NotDefined.is_defined());
}

#[test]
fn test_defined_with_option_and_then() {
    let some_defined: Option<v3::AttackVector> = Some(v3::AttackVector::Network);
    let some_not_defined: Option<v3::AttackVector> = Some(v3::AttackVector::NotDefined);
    let none: Option<v3::AttackVector> = None;

    let fallback = v3::AttackVector::Local;

    assert_eq!(
        some_defined
            .as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(&fallback),
        &v3::AttackVector::Network
    );
    assert_eq!(
        some_not_defined
            .as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(&fallback),
        &v3::AttackVector::Local
    );
    assert_eq!(
        none.as_ref()
            .and_then(|v| v.as_defined())
            .unwrap_or(&fallback),
        &v3::AttackVector::Local
    );
}
