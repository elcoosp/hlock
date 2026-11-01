//! OSSF Scorecard integration (G08)
//! Fetches the scorecard score for a GitHub repository.

use serde::Deserialize;
use std::fmt::Write as _;

#[derive(Deserialize, Debug, Clone)]
pub struct ScorecardResult {
    pub repo: String,
    pub date: String,
    pub score: f64,
    pub checks: Vec<ScorecardCheck>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ScorecardCheck {
    pub name: String,
    pub score: i32,
    pub reason: String,
    pub details: Vec<String>,
    pub documentation: ScorecardDoc,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ScorecardDoc {
    pub short: String,
    pub url: String,
}

///
/// # Errors
///
/// Returns `Err` if input validation fails.
/// Fetch the OSSF Scorecard v4 JSON result for a GitHub repository.
/// repo must be in the form "owner/name" (e.g. "browserify/browserify").
pub fn fetch_scorecard(repo: &str) -> Result<ScorecardResult, String> {
    let url = format!("https://api.securityscorecards.dev/projects/github.com/{repo}");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| format!("Scorecard query failed for {repo}: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("Scorecard API returned HTTP {}", response.status()));
    }

    response
        .json::<ScorecardResult>()
        .map_err(|e| format!("Failed to parse Scorecard response: {e}"))
}

/// Produce a human-readable summary of the scorecard result.
#[must_use]
pub fn format_scorecard(result: &ScorecardResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Repository: {}", result.repo);
    let _ = writeln!(out, "Date: {}", result.date);
    let _ = writeln!(out, "Overall Score: {:.1}/10", result.score);
    out.push('\n');
    out.push_str("Checks:\n");
    for check in &result.checks {
        let icon = match check.score {
            s if s >= 8 => "✓",
            s if s >= 5 => "~",
            _ => "✗",
        };
        let _ = writeln!(
            out,
            "  {} {} ({}/10): {}",
            icon, check.name, check.score, check.reason
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_scorecard() {
        let result = ScorecardResult {
            repo: "owner/repo".to_string(),
            date: "2025-01-01".to_string(),
            score: 7.5,
            checks: vec![
                ScorecardCheck {
                    name: "Binary-Artifacts".to_string(),
                    score: 10,
                    reason: "no binaries found in the repo".to_string(),
                    details: vec![],
                    documentation: ScorecardDoc {
                        short: "description".to_string(),
                        url: "https://...".to_string(),
                    },
                },
                ScorecardCheck {
                    name: "Code-Review".to_string(),
                    score: 0,
                    reason: "0 out of 1 merged PRs reviewed".to_string(),
                    details: vec![],
                    documentation: ScorecardDoc {
                        short: "description".to_string(),
                        url: "https://...".to_string(),
                    },
                },
            ],
        };
        let formatted = format_scorecard(&result);
        assert!(formatted.contains("Binary-Artifacts"));
        assert!(formatted.contains("Code-Review"));
    }

    #[test]
    fn test_format_scorecard_icons_cover_all_bands() {
        let check = |name: &str, score: i32| ScorecardCheck {
            name: name.to_string(),
            score,
            reason: "r".to_string(),
            details: vec![],
            documentation: ScorecardDoc {
                short: "d".to_string(),
                url: "https://d".to_string(),
            },
        };
        let result = ScorecardResult {
            repo: "o/r".to_string(),
            date: "2025-06-01".to_string(),
            score: 5.555,
            checks: vec![
                check("Maintained", 10),
                check("Security-Policy", 6),
                check("Dangerous-Workflow", 2),
            ],
        };
        let formatted = format_scorecard(&result);
        assert!(
            formatted.contains("✓ Maintained (10/10)"),
            "high band: {formatted}"
        );
        assert!(
            formatted.contains("~ Security-Policy (6/10)"),
            "middle band: {formatted}"
        );
        assert!(
            formatted.contains("✗ Dangerous-Workflow (2/10)"),
            "low band: {formatted}"
        );
        assert!(formatted.contains("Repository: o/r"));
        assert!(formatted.contains("Overall Score: 5.6/10"));
        assert!(formatted.starts_with("Checks:\n") || formatted.contains("\nChecks:\n"));
    }
}
