use hlock::lockfile::{self, Lockfile, Source};
use hlock::policy::{Advisory, AdvisorySeverity};

#[test]
fn test_advisory_roundtrip() {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        advisories: vec![
            Advisory {
                package: "lodash".to_string(),
                advisory_id: "GHSA-jf85-cq4p-4qr8".to_string(),
                severity: AdvisorySeverity::High,
                url: "https://github.com/advisories/GHSA-jf85-cq4p-4qr8".to_string(),
                affected_versions: "<4.17.21".to_string(),
            },
            Advisory {
                package: "express".to_string(),
                advisory_id: "CVE-2024-43999".to_string(),
                severity: AdvisorySeverity::Medium,
                url: "".to_string(),
                affected_versions: ">=4.0.0 <4.21.0".to_string(),
            },
        ],
        ..Lockfile::default()
    };

    let serialized = lockfile::serialize(&mut lockfile).unwrap();
    let deserialized = lockfile::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.advisories.len(), 2);
    assert_eq!(deserialized.advisories[0].package, "lodash");
    assert_eq!(deserialized.advisories[0].severity, AdvisorySeverity::High);
    assert_eq!(deserialized.advisories[1].package, "express");
}

#[test]
fn test_advisory_parse_in_header() {
    let content = "@source 0 https://registry.npmjs.org/\n\n@advisory lodash GHSA-jf85-cq4p-4qr8 high https://github.com/advisories/GHSA-jf85-cq4p-4qr8 <4.17.21\n";
    let lockfile = lockfile::deserialize(content).unwrap();
    assert_eq!(lockfile.advisories.len(), 1);
    assert_eq!(lockfile.advisories[0].package, "lodash");
    assert_eq!(lockfile.advisories[0].severity, AdvisorySeverity::High);
}

#[test]
fn test_advisory_audit_report() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        advisories: vec![
            Advisory {
                package: "critical-pkg".to_string(),
                advisory_id: "CVE-2024-1".to_string(),
                severity: AdvisorySeverity::Critical,
                url: "".to_string(),
                affected_versions: "*".to_string(),
            },
            Advisory {
                package: "high-pkg".to_string(),
                advisory_id: "CVE-2024-2".to_string(),
                severity: AdvisorySeverity::High,
                url: "".to_string(),
                affected_versions: "*".to_string(),
            },
            Advisory {
                package: "low-pkg".to_string(),
                advisory_id: "CVE-2024-3".to_string(),
                severity: AdvisorySeverity::Low,
                url: "".to_string(),
                affected_versions: "*".to_string(),
            },
        ],
        ..Lockfile::default()
    };

    let report = lockfile.audit();
    assert_eq!(report.critical.len(), 1);
    assert_eq!(report.high.len(), 1);
    assert_eq!(report.low.len(), 1);
    assert!(report.has_vulnerabilities());
    assert!(report.has_critical_or_high());
    assert_eq!(report.total_count(), 3);
}

#[test]
fn test_invalid_vex_status() {
    let content = "@source 0 https://registry.npmjs.org/\n\n@vex lodash CVE-2024-12345 invalid_status reason impact\n";
    let result = hlock::lockfile::deserialize(content);
    assert!(result.is_err(), "expected error for invalid VEX status");
    match result.unwrap_err() {
        hlock::Error::InvalidVexStatus { status, .. } => {
            assert_eq!(status, "invalid_status");
        }
        other => panic!("expected InvalidVexStatus, got {:?}", other),
    }
}
