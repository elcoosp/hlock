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
}

impl ColorConfig {
    pub fn new(when: ColorWhen) -> Self {
        let cfg = Self { when };
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
        let cfg = Self { when };
        cfg.apply_override();
        cfg
    }

    pub fn should_color(&self) -> bool {
        match self.when {
            ColorWhen::Always => true,
            ColorWhen::Never => false,
            ColorWhen::Auto => std::io::stdout().is_terminal(),
        }
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
