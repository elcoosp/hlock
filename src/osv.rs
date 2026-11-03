//! OSV (osv.dev) API client for live vulnerability queries
//!
//! v1.0.1: one shared pooled client, per-request timeouts, bounded response
//! buffering (a hostile endpoint cannot OOM the gate), and the batch
//! endpoint `/v1/querybatch` for `audit --online` (spec §7).

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Cap on response bodies read from OSV (10 MiB): vulnerability documents
/// are far smaller, so anything bigger is treated as hostile.
const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

#[derive(Serialize, Clone)]
pub struct OsvQuery {
    pub package: OsvPackage,
    pub version: String,
}

#[derive(Serialize, Clone)]
pub struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Serialize)]
pub struct OsvBatchQuery {
    pub queries: Vec<OsvQuery>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct OsvBatchResponse {
    #[serde(default)]
    pub results: Vec<OsvResponse>,
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

/// The shared pooled HTTP client for OSV queries.
fn shared_client() -> Result<&'static reqwest::blocking::Client, String> {
    static CLIENT: OnceLock<Option<reqwest::blocking::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::limited(3))
                .build()
                .ok()
        })
        .as_ref()
        .ok_or_else(|| "Failed to create HTTP client".to_string())
}

/// Reads a response body with a hard size cap.
fn read_body_capped(response: reqwest::blocking::Response, what: &str) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut body = Vec::new();
    let mut reader = response.take(MAX_RESPONSE_BYTES as u64 + 1);
    reader
        .read_to_end(&mut body)
        .map_err(|e| format!("{what}: failed to read response body: {e}"))?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(format!(
            "{what}: response exceeds the {MAX_RESPONSE_BYTES}-byte safety cap"
        ));
    }
    Ok(body)
}

/// Sends one OSV request with retry + exponential backoff on 5xx/timeouts
/// (2 attempts total, spec §7).
fn post_osv<T: serde::Serialize>(
    url: &str,
    payload: &T,
    timeout_secs: u64,
    what: &str,
) -> Result<Vec<u8>, String> {
    let client = shared_client()?;
    let mut last_err = String::new();
    for attempt in 0u64..2 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(300 * attempt));
        }
        let result = client
            .post(url)
            .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
            .json(payload)
            .send();
        match result {
            Ok(response) => {
                let status = response.status();
                if status.is_server_error() {
                    last_err = format!("{what}: OSV API returned HTTP {status}");
                    continue;
                }
                if !status.is_success() {
                    return Err(format!("{what}: OSV API returned HTTP {status}"));
                }
                return read_body_capped(response, what);
            }
            Err(e) => {
                last_err = format!("{what}: OSV request failed: {e}");
            }
        }
    }
    Err(last_err)
}

///
/// # Errors
///
/// Returns `Err` if input validation fails.
/// Query the OSV API for vulnerabilities affecting a package at a given version.
pub fn query_osv(name: &str, version: &str, timeout_secs: u64) -> Result<OsvResponse, String> {
    let query = OsvQuery {
        package: OsvPackage {
            name: name.to_string(),
            ecosystem: "npm".to_string(),
        },
        version: version.to_string(),
    };
    let body = post_osv(
        "https://api.osv.dev/v1/query",
        &query,
        timeout_secs,
        &format!("{name}@{version}"),
    )?;
    serde_json::from_slice::<OsvResponse>(&body)
        .map_err(|e| format!("Failed to parse OSV response for {name}@{version}: {e}"))
}

/// Batch query: one round-trip for the whole graph (spec §7).
/// The returned vector is index-aligned with the input queries.
///
/// # Errors
/// Returns `Err` when the batch request itself fails; per-query failures
/// surface as an empty `OsvResponse` in the result vector.
pub fn query_osv_batch(
    queries: &[OsvQuery],
    timeout_secs: u64,
) -> Result<Vec<OsvResponse>, String> {
    if queries.is_empty() {
        return Ok(Vec::new());
    }
    let body = post_osv(
        "https://api.osv.dev/v1/querybatch",
        &OsvBatchQuery {
            queries: queries.to_vec(),
        },
        timeout_secs,
        "batch",
    )?;
    let batch: OsvBatchResponse = serde_json::from_slice(&body)
        .map_err(|e| format!("Failed to parse OSV batch response: {e}"))?;
    if batch.results.len() != queries.len() {
        return Err(format!(
            "OSV batch response has {} results for {} queries",
            batch.results.len(),
            queries.len()
        ));
    }
    Ok(batch.results)
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
