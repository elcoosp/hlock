//! Terminal output helpers.
//!
//! Two guarantees (v1.0.1):
//! 1. **Color policy** honors the documented environment variables —
//!    `NO_COLOR`, `FORCE_COLOR`, `CLICOLOR_FORCE` — in addition to the CLI
//!    flags (spec §9). CLI flags win; env vars fill the gaps.
//! 2. **Output hygiene**: strings that originate from untrusted lockfiles
//!    (package names, URLs, metadata) can carry ANSI escape sequences that
//!    spoof terminal UIs. Every style wrapper passes the payload through
//!    [`sanitize_control`] so raw C0/C1 bytes never reach the terminal.
use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorWhen {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

pub struct ColorConfig {
    when: ColorWhen,
    pub enabled: bool,
}

impl ColorConfig {
    pub fn from_cli_args(color_flag: &str, no_color: bool, format: OutputFormat) -> Self {
        let env = EnvColor::from_env();
        let when = if no_color {
            ColorWhen::Never
        } else {
            match color_flag {
                "always" => ColorWhen::Always,
                "never" => ColorWhen::Never,
                _ => env.cli_default(),
            }
        };
        // An explicit NO_COLOR in the environment always wins over `auto`.
        let when = match (when, env) {
            (ColorWhen::Auto, EnvColor::NoColor) => ColorWhen::Never,
            (ColorWhen::Auto, EnvColor::Force) => ColorWhen::Always,
            (when, _) => when,
        };
        let when = if format == OutputFormat::Json {
            ColorWhen::Never
        } else {
            when
        };
        let enabled = match when {
            ColorWhen::Always => true,
            ColorWhen::Never => false,
            ColorWhen::Auto => std::io::stdout().is_terminal(),
        };
        let cfg = Self { when, enabled };
        cfg.apply_override();
        cfg
    }

    pub fn should_color(&self) -> bool {
        self.enabled
    }

    fn apply_override(&self) {
        match self.when {
            ColorWhen::Always => owo_colors::set_override(true),
            ColorWhen::Never => owo_colors::set_override(false),
            ColorWhen::Auto => {}
        }
    }
}

/// The color-relevant environment state, resolved once per call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvColor {
    Neutral,
    NoColor,
    Force,
}

impl EnvColor {
    /// `true` when the env forces color (`FORCE_COLOR` / `CLICOLOR_FORCE`).
    fn force() -> bool {
        let force_color =
            std::env::var("FORCE_COLOR").is_ok_and(|v| !v.is_empty() && v != "0" && v != "false");
        let clicolor_force =
            std::env::var("CLICOLOR_FORCE").is_ok_and(|v| !v.is_empty() && v != "0");
        force_color || clicolor_force
    }

    /// `true` when the env suppresses color (`NO_COLOR`, per no-color.org).
    fn no_color() -> bool {
        std::env::var("NO_COLOR").is_ok_and(|v| !v.is_empty())
    }

    fn from_env() -> Self {
        if Self::no_color() {
            Self::NoColor
        } else if Self::force() {
            Self::Force
        } else {
            Self::Neutral
        }
    }

    /// The default `when` for an unspecified CLI flag.
    fn cli_default(self) -> ColorWhen {
        match self {
            Self::NoColor => ColorWhen::Never,
            Self::Force => ColorWhen::Always,
            Self::Neutral => ColorWhen::Auto,
        }
    }
}

pub fn parse_format(format: &str) -> OutputFormat {
    match format {
        "json" => OutputFormat::Json,
        _ => OutputFormat::Text,
    }
}

/// Strips C0/C1 control characters (keeping tab and newline, which the
/// line-oriented renderers rely on) so lockfile-sourced strings can never
/// carry terminal escape sequences into output.
pub fn sanitize_control(s: &str) -> String {
    let needs_work = s
        .chars()
        .any(|c| (c.is_control() && c != '\t' && c != '\n') || c == '\u{7f}');
    if !needs_work {
        return s.to_string();
    }
    s.chars()
        .filter(|c| !(*c != '\t' && *c != '\n' && (*c).is_control()) && *c != '\u{7f}')
        .collect()
}

/// Text styles available for terminal output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Bold,
    Cyan,
    Green,
    Yellow,
    Red,
    Blue,
}

/// Returns a styler closure applying `style` to text only when colors are on.
///
/// This is the single source of truth for conditional styling: every command
/// renders plain text when colors are disabled instead of leaking ANSI codes
/// into pipes and files.
pub fn styler(on: bool, style: Style) -> impl Fn(&str) -> String {
    move |s: &str| {
        let s = sanitize_control(s);
        if on {
            use owo_colors::OwoColorize as _;
            match style {
                Style::Bold => s.bold().to_string(),
                Style::Cyan => s.cyan().to_string(),
                Style::Green => s.green().to_string(),
                Style::Yellow => s.yellow().to_string(),
                Style::Red => s.red().to_string(),
                Style::Blue => s.blue().to_string(),
            }
        } else {
            s
        }
    }
}

pub struct C<'a> {
    pub text: &'a str,
    pub on: bool,
}

impl C<'_> {
    fn sanitized(&self) -> String {
        sanitize_control(self.text)
    }
    pub fn gb(&self) -> String {
        if self.on {
            use owo_colors::OwoColorize;
            self.sanitized().green().bold().to_string()
        } else {
            self.sanitized()
        }
    }
    pub fn rb(&self) -> String {
        if self.on {
            use owo_colors::OwoColorize;
            self.sanitized().red().bold().to_string()
        } else {
            self.sanitized()
        }
    }
    pub fn yb(&self) -> String {
        if self.on {
            use owo_colors::OwoColorize;
            self.sanitized().yellow().bold().to_string()
        } else {
            self.sanitized()
        }
    }
    pub fn bl(&self) -> String {
        if self.on {
            use owo_colors::OwoColorize;
            self.sanitized().blue().to_string()
        } else {
            self.sanitized()
        }
    }
    #[allow(dead_code)]
    pub fn b(&self) -> String {
        if self.on {
            use owo_colors::OwoColorize;
            self.sanitized().bold().to_string()
        } else {
            self.sanitized()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_keeps_printable_and_tabs() {
        assert_eq!(sanitize_control("hello\tworld\n"), "hello\tworld\n");
    }

    #[test]
    fn sanitize_strips_ansi_escapes() {
        assert_eq!(sanitize_control("evil\u{1b}[31mname"), "evil[31mname");
        assert_eq!(sanitize_control("a\u{7f}b"), "ab");
    }

    #[test]
    fn c_wrapper_neutralizes_escapes_when_off() {
        let out = C {
            text: "p\u{1b}[31mq",
            on: false,
        }
        .gb();
        assert!(!out.contains('\u{1b}'));
    }

    #[test]
    fn env_color_defaults() {
        // Pure resolution logic — no environment mutation needed.
        assert_eq!(EnvColor::Neutral.cli_default(), ColorWhen::Auto);
        assert_eq!(EnvColor::NoColor.cli_default(), ColorWhen::Never);
        assert_eq!(EnvColor::Force.cli_default(), ColorWhen::Always);
    }
}
