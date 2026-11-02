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
        let when = if no_color {
            ColorWhen::Never
        } else {
            match color_flag {
                "always" => ColorWhen::Always,
                "never" => ColorWhen::Never,
                _ => ColorWhen::Auto,
            }
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

pub fn parse_format(format: &str) -> OutputFormat {
    match format {
        "json" => OutputFormat::Json,
        _ => OutputFormat::Text,
    }
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
            s.to_string()
        }
    }
}

pub struct C<'a> {
    pub text: &'a str,
    pub on: bool,
}

impl C<'_> {
    pub fn gb(&self) -> String {
        if self.on {
            use owo_colors::OwoColorize;
            self.text.green().bold().to_string()
        } else {
            self.text.to_string()
        }
    }
    pub fn rb(&self) -> String {
        if self.on {
            use owo_colors::OwoColorize;
            self.text.red().bold().to_string()
        } else {
            self.text.to_string()
        }
    }
    pub fn yb(&self) -> String {
        if self.on {
            use owo_colors::OwoColorize;
            self.text.yellow().bold().to_string()
        } else {
            self.text.to_string()
        }
    }
    pub fn bl(&self) -> String {
        if self.on {
            use owo_colors::OwoColorize;
            self.text.blue().to_string()
        } else {
            self.text.to_string()
        }
    }
    #[allow(dead_code)]
    pub fn b(&self) -> String {
        if self.on {
            use owo_colors::OwoColorize;
            self.text.bold().to_string()
        } else {
            self.text.to_string()
        }
    }
}
