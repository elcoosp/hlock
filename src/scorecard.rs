//! OSSF Scorecard integration (G08)
//! Fetches the scorecard score for a GitHub repository.

use serde::Deserialize;

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

/// Fetch the OSSF Scorecard v4 JSON result for a GitHub repository.
/// repo must be in the form "owner/name" (e.g. "browserify/browserify").
pub fn fetch_scorecard(repo: &str) -> Result<ScorecardResult, String> {
    let url = format!("https://api.securityscorecards.dev/projects/github.com/{}", repo);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| format!("Scorecard query failed for {}: {}", repo, e))?;

    if !response.status().is_success() {
        return Err(format!("Scorecard API returned HTTP {}", response.status()));
    }

    response
        .json::<ScorecardResult>()
        .map_err(|e| format!("Failed to parse Scorecard response: {}", e))
}

/// Produce a human-readable summary of the scorecard result.
pub fn format_scorecard(result: &ScorecardResult) -> String {
    let mut out = String::new();
    out.push_str(&format!("Repository: {}\n", result.repo));
    out.push_str(&format!("Date: {}\n", result.date));
    out.push_str(&format!("Overall Score: {:.1}/10\n", result.score));
    out.push('\n');
    out.push_str("Checks:\n");
    for check in &result.checks {
        let icon = match check.score {
            s if s >= 8 => "✓",
            s if s >= 5 => "~",
            _ => "✗",
        };
        out.push_str(&format!("  {} {} ({}/10): {}\n",
            icon, check.name, check.score, check.reason));
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
                    documentation: ScorecardDoc { short: "description".to_string(), url: "https://...".to_string() },
                },
                ScorecardCheck {
                    name: "Code-Review".to_string(),
                    score: 0,
                    reason: "0 out of 1 merged PRs reviewed".to_string(),
                    details: vec![],
                    documentation: ScorecardDoc { short: "description".to_string(), url: "https://...".to_string() },
                },
            ],
        };
        let formatted = format_scorecard(&result);
        assert!(formatted.contains("Binary-Artifacts"));
        assert!(formatted.contains("Code-Review"));
    }
}
