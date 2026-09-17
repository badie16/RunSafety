use std::path::PathBuf;

use anyhow::Result;
use runsafety_shared::config::CliPattern;
use runsafety_shared::types::CliType;

pub struct DiscoveredProcess {
    pub pid: u32,
    pub cmdline_args: Vec<String>,
    pub cwd: PathBuf,
}

pub trait ProcessScanner {
    fn scan(&self) -> Result<Vec<DiscoveredProcess>>;
}

/// Match a process cmdline against configured CLI patterns.
/// Returns the matched CliType, or None if no pattern matches.
pub fn match_cli_type(cmdline_args: &[String], patterns: &[CliPattern]) -> Option<CliType> {
    for arg in cmdline_args {
        let arg_lower = arg.to_lowercase();
        for pattern in patterns {
            for pat in &pattern.patterns {
                if word_boundary_match(&arg_lower, &pat.to_lowercase()) {
                    return Some(CliType::from_config_str(&pattern.cli_type));
                }
            }
        }
    }
    None
}

/// Check if `needle` appears in `haystack` at a word boundary.
/// Characters before and after the match must be non-alphanumeric/underscore
/// (or at string start/end). Prevents "cursor" matching "CursorUIViewService".
fn word_boundary_match(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    for (pos, _) in haystack.match_indices(needle) {
        let before_ok = pos == 0 || !h[pos - 1].is_ascii_alphanumeric() && h[pos - 1] != b'_';
        let after = pos + needle.len();
        let after_ok = after >= h.len() || !h[after].is_ascii_alphanumeric() && h[after] != b'_';
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxScanner;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosScanner;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsScanner;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_patterns() -> Vec<CliPattern> {
        vec![
            CliPattern {
                name: "claude".into(),
                cli_type: "ClaudeCode".into(),
                patterns: vec![
                    "claude".into(),
                    "claude-code".into(),
                    "@anthropic/claude-code".into(),
                ],
                memory_limit: None,
            },
            CliPattern {
                name: "codex".into(),
                cli_type: "Codex".into(),
                patterns: vec!["codex".into(), "openai-codex".into()],
                memory_limit: None,
            },
            CliPattern {
                name: "gemini".into(),
                cli_type: "GeminiCli".into(),
                patterns: vec!["gemini".into(), "gemini-cli".into()],
                memory_limit: None,
            },
            CliPattern {
                name: "cursor".into(),
                cli_type: "Cursor".into(),
                patterns: vec!["cursor-agent".into(), "cursor".into()],
                memory_limit: None,
            },
            CliPattern {
                name: "aider".into(),
                cli_type: "Aider".into(),
                patterns: vec!["aider".into()],
                memory_limit: None,
            },
        ]
    }

    #[test]
    fn matches_claude_code_binary() {
        let args = vec![
            "/usr/bin/node".into(),
            "/home/user/.nvm/versions/node/v22/bin/claude".into(),
        ];
        assert_eq!(
            match_cli_type(&args, &test_patterns()),
            Some(CliType::ClaudeCode)
        );
    }

    #[test]
    fn matches_claude_code_npm_global() {
        let args = vec![
            "node".into(),
            "/usr/lib/node_modules/@anthropic/claude-code/cli.js".into(),
        ];
        assert_eq!(
            match_cli_type(&args, &test_patterns()),
            Some(CliType::ClaudeCode)
        );
    }

    #[test]
    fn matches_codex() {
        let args = vec!["codex".into(), "--help".into()];
        assert_eq!(
            match_cli_type(&args, &test_patterns()),
            Some(CliType::Codex)
        );
    }

    #[test]
    fn matches_gemini_cli() {
        let args = vec!["/usr/local/bin/gemini-cli".into(), "chat".into()];
        assert_eq!(
            match_cli_type(&args, &test_patterns()),
            Some(CliType::GeminiCli)
        );
    }

    #[test]
    fn matches_cursor_agent() {
        let args = vec!["cursor-agent".into(), "--background".into()];
        assert_eq!(
            match_cli_type(&args, &test_patterns()),
            Some(CliType::Cursor)
        );
    }

    #[test]
    fn matches_aider() {
        let args = vec![
            "/home/user/.local/bin/aider".into(),
            "--model".into(),
            "gpt-4".into(),
        ];
        assert_eq!(
            match_cli_type(&args, &test_patterns()),
            Some(CliType::Aider)
        );
    }

    #[test]
    fn no_match_for_unrelated_process() {
        let args = vec!["/usr/bin/vim".into(), "file.rs".into()];
        assert_eq!(match_cli_type(&args, &test_patterns()), None);
    }

    #[test]
    fn no_match_for_empty_cmdline() {
        let args: Vec<String> = vec![];
        assert_eq!(match_cli_type(&args, &test_patterns()), None);
    }

    #[test]
    fn case_insensitive_match() {
        let args = vec!["Claude-Code".into()];
        assert_eq!(
            match_cli_type(&args, &test_patterns()),
            Some(CliType::ClaudeCode)
        );
    }

    #[test]
    fn no_match_for_macos_cursor_ui_service() {
        let args = vec![
            "/System/Library/PrivateFrameworks/TextInputUIMacHelper.framework/Versions/A/XPCServices/CursorUIViewService.xpc/Contents/MacOS/CursorUIViewService".into(),
        ];
        assert_eq!(match_cli_type(&args, &test_patterns()), None);
    }

    #[test]
    fn matches_cursor_binary_directly() {
        let args = vec!["/usr/local/bin/cursor".into()];
        assert_eq!(
            match_cli_type(&args, &test_patterns()),
            Some(CliType::Cursor)
        );
    }

    #[test]
    fn word_boundary_allows_path_separators() {
        let args = vec!["/usr/lib/node_modules/@anthropic/claude-code/cli.js".into()];
        assert_eq!(
            match_cli_type(&args, &test_patterns()),
            Some(CliType::ClaudeCode)
        );
    }
}
