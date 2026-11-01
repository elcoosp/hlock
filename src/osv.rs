//! OSV (osv.dev) API client for live vulnerability queries

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct OsvQuery {
    pub package: OsvPackage,
    pub version: String,
}

#[derive(Serialize)]
pub struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvResponse {
    #[serde(default)]
    pub vulns: Vec<OsvVulnerability>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvVulnerability {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvAffected {
    pub package: Option<OsvAffectedPackage>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvAffectedPackage {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<OsvRangeEvent>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OsvRangeEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

///
/// # Errors
///
/// Returns `Err` if input validation fails.
/// Query the OSV API for vulnerabilities affecting a package at a given version.
pub fn query_osv(name: &str, version: &str, timeout_secs: u64) -> Result<OsvResponse, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let query = OsvQuery {
        package: OsvPackage {
            name: name.to_string(),
            ecosystem: "npm".to_string(),
        },
        version: version.to_string(),
    };

    let response = client
        .post("https://api.osv.dev/v1/query")
        .json(&query)
        .send()
        .map_err(|e| format!("OSV query failed for {name}@{version}: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("OSV API returned status {}", response.status()));
    }

    response
        .json::<OsvResponse>()
        .map_err(|e| format!("Failed to parse OSV response for {name}@{version}: {e}"))
}

/// Extract the first fixed version from an OSV vulnerability entry.
#[must_use]
pub fn find_fixed_version(vuln: &OsvVulnerability) -> Option<String> {
    for affected in &vuln.affected {
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(ref fixed) = event.fixed {
                    return Some(fixed.clone());
                }
            }
        }
    }
    None
}

/// Determine the effective severity of an OSV vulnerability.
#[must_use]
pub fn osv_severity(vuln: &OsvVulnerability) -> crate::policy::AdvisorySeverity {
    for sev in &vuln.severity {
        if sev.severity_type == "CVSS_V3"
            && let Ok(score) = sev.score.parse::<f64>()
        {
            if score >= 9.0 {
                return crate::policy::AdvisorySeverity::Critical;
            } else if score >= 7.0 {
                return crate::policy::AdvisorySeverity::High;
            } else if score >= 4.0 {
                return crate::policy::AdvisorySeverity::Medium;
            } else if score > 0.0 {
                return crate::policy::AdvisorySeverity::Low;
            }
        }
    }
    crate::policy::AdvisorySeverity::Info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osv_severity_critical() {
        let vuln = OsvVulnerability {
            id: "test".to_string(),
            summary: String::new(),
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "9.8".to_string(),
            }],
            references: vec![],
            affected: vec![],
        };
        assert_eq!(
            osv_severity(&vuln),
            crate::policy::AdvisorySeverity::Critical
        );
    }

    #[test]
    fn test_osv_severity_high() {
        let vuln = OsvVulnerability {
            id: "test".to_string(),
            summary: String::new(),
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "7.5".to_string(),
            }],
            references: vec![],
            affected: vec![],
        };
        assert_eq!(osv_severity(&vuln), crate::policy::AdvisorySeverity::High);
    }

    #[test]
    fn test_osv_severity_medium() {
        let vuln = OsvVulnerability {
            id: "test".to_string(),
            summary: String::new(),
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "5.5".to_string(),
            }],
            references: vec![],
            affected: vec![],
        };
        assert_eq!(osv_severity(&vuln), crate::policy::AdvisorySeverity::Medium);
    }

    #[test]
    fn test_osv_severity_no_cvss() {
        let vuln = OsvVulnerability {
            id: "test".to_string(),
            summary: String::new(),
            severity: vec![],
            references: vec![],
            affected: vec![],
        };
        assert_eq!(osv_severity(&vuln), crate::policy::AdvisorySeverity::Info);
    }

    #[test]
    fn test_find_fixed_version() {
        let vuln = OsvVulnerability {
            id: "test".to_string(),
            summary: String::new(),
            severity: vec![],
            references: vec![],
            affected: vec![OsvAffected {
                package: None,
                ranges: vec![OsvRange {
                    range_type: "SEMVER".to_string(),
                    events: vec![
                        OsvRangeEvent {
                            introduced: Some("0".to_string()),
                            fixed: None,
                        },
                        OsvRangeEvent {
                            introduced: None,
                            fixed: Some("4.17.22".to_string()),
                        },
                    ],
                }],
            }],
        };
        assert_eq!(find_fixed_version(&vuln), Some("4.17.22".to_string()));
    }

    #[test]
    fn test_find_fixed_version_none() {
        let vuln = OsvVulnerability {
            id: "test".to_string(),
            summary: String::new(),
            severity: vec![],
            references: vec![],
            affected: vec![],
        };
        assert_eq!(find_fixed_version(&vuln), None);
    }

    #[test]
    fn test_osv_severity_low() {
        let vuln = OsvVulnerability {
            id: "test".to_string(),
            summary: String::new(),
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "3.1".to_string(),
            }],
            references: vec![],
            affected: vec![],
        };
        assert_eq!(osv_severity(&vuln), crate::policy::AdvisorySeverity::Low);
    }

    #[test]
    fn test_osv_severity_boundaries() {
        let make = |score: &str| OsvVulnerability {
            id: "t".to_string(),
            summary: String::new(),
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: score.to_string(),
            }],
            references: vec![],
            affected: vec![],
        };
        assert_eq!(
            osv_severity(&make("9.0")),
            crate::policy::AdvisorySeverity::Critical
        );
        assert_eq!(
            osv_severity(&make("7.0")),
            crate::policy::AdvisorySeverity::High
        );
        assert_eq!(
            osv_severity(&make("4.0")),
            crate::policy::AdvisorySeverity::Medium
        );
        assert_eq!(
            osv_severity(&make("0.1")),
            crate::policy::AdvisorySeverity::Low
        );
        // Zero and negative scores fall through to Info.
        assert_eq!(
            osv_severity(&make("0.0")),
            crate::policy::AdvisorySeverity::Info
        );
        assert_eq!(
            osv_severity(&make("-2")),
            crate::policy::AdvisorySeverity::Info
        );
    }

    #[test]
    fn test_osv_severity_ignores_non_cvss_and_bad_scores() {
        let vuln = OsvVulnerability {
            id: "t".to_string(),
            summary: String::new(),
            severity: vec![
                OsvSeverity {
                    severity_type: "GHSA".to_string(),
                    score: "9.9".to_string(),
                },
                OsvSeverity {
                    severity_type: "CVSS_V3".to_string(),
                    score: "not-a-number".to_string(),
                },
            ],
            references: vec![],
            affected: vec![],
        };
        assert_eq!(osv_severity(&vuln), crate::policy::AdvisorySeverity::Info);
    }

    #[test]
    fn test_find_fixed_version_scans_all_ranges_and_skips_introduced_only() {
        let vuln = OsvVulnerability {
            id: "t".to_string(),
            summary: String::new(),
            severity: vec![],
            references: vec![],
            affected: vec![
                OsvAffected {
                    package: Some(OsvAffectedPackage {
                        name: "npm".to_string(),
                        ecosystem: "lodash".to_string(),
                    }),
                    ranges: vec![OsvRange {
                        range_type: "SEMVER".to_string(),
                        events: vec![OsvRangeEvent {
                            introduced: Some("0".to_string()),
                            fixed: None,
                        }],
                    }],
                },
                OsvAffected {
                    package: None,
                    ranges: vec![OsvRange {
                        range_type: "ECOSYSTEM".to_string(),
                        events: vec![OsvRangeEvent {
                            introduced: None,
                            fixed: Some("2.0.0".to_string()),
                        }],
                    }],
                },
            ],
        };
        assert_eq!(find_fixed_version(&vuln), Some("2.0.0".to_string()));
    }

    #[test]
    fn test_osv_response_deserializes_realistic_payload() {
        let payload = r#"{
            "vulns": [
                {
                    "id": "GHSA-xxxx",
                    "summary": "Prototype pollution",
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                    "references": [{"type": "WEB", "url": "https://osv.dev/vulnerability/GHSA-xxxx"}],
                    "affected": [
                        {
                            "package": {"name": "lodash", "ecosystem": "npm"},
                            "ranges": [
                                {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                            ]
                        }
                    ]
                }
            ]
        }"#;
        let response: OsvResponse = serde_json::from_str(payload).unwrap();
        assert_eq!(response.vulns.len(), 1);
        let vuln = &response.vulns[0];
        assert_eq!(vuln.id, "GHSA-xxxx");
        assert_eq!(vuln.summary, "Prototype pollution");
        assert_eq!(
            osv_severity(vuln),
            crate::policy::AdvisorySeverity::Critical
        );
        assert_eq!(find_fixed_version(vuln).as_deref(), Some("4.17.21"));
        assert_eq!(vuln.references[0].ref_type, "WEB");
        assert_eq!(vuln.affected[0].package.as_ref().unwrap().name, "lodash");
    }

    #[test]
    fn test_osv_response_defaults_are_tolerant() {
        let response: OsvResponse = serde_json::from_str("{}").unwrap();
        assert!(response.vulns.is_empty());
    }
}
