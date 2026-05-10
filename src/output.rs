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

#[allow(dead_code)]
pub struct ColorConfig {
    when: ColorWhen,
    pub enabled: bool,
}

impl ColorConfig {
    #[allow(dead_code)]
    pub fn new(when: ColorWhen) -> Self {
        let cfg = Self { when, enabled: true };
        cfg.apply_override();
        cfg
    }

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

    #[allow(dead_code)]
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

pub struct C<'a> {
    pub text: &'a str,
    pub on: bool,
}

impl<'a> C<'a> {
    pub fn gb(&self) -> String { if self.on { use owo_colors::OwoColorize; self.text.green().bold().to_string() } else { self.text.to_string() } }
    pub fn rb(&self) -> String { if self.on { use owo_colors::OwoColorize; self.text.red().bold().to_string() } else { self.text.to_string() } }
    pub fn yb(&self) -> String { if self.on { use owo_colors::OwoColorize; self.text.yellow().bold().to_string() } else { self.text.to_string() } }
    pub fn bl(&self) -> String { if self.on { use owo_colors::OwoColorize; self.text.blue().to_string() } else { self.text.to_string() } }
    pub fn b(&self) -> String { if self.on { use owo_colors::OwoColorize; self.text.bold().to_string() } else { self.text.to_string() } }
    #[allow(dead_code)]
    pub fn g(&self) -> String { if self.on { use owo_colors::OwoColorize; self.text.green().to_string() } else { self.text.to_string() } }
    #[allow(dead_code)]
    pub fn y(&self) -> String { if self.on { use owo_colors::OwoColorize; self.text.yellow().to_string() } else { self.text.to_string() } }
    #[allow(dead_code)]
    pub fn r(&self) -> String { if self.on { use owo_colors::OwoColorize; self.text.red().to_string() } else { self.text.to_string() } }
}
