//! nd7's own configuration: one TOML file, read from two places.
//!
//! `~/.nd7/config.toml` applies to every session; `~/.nd7/sessions/<pid>/config.toml`
//! to one. Both have the same shape, and both live under `~/.nd7`, which no
//! profile makes writable, so nothing inside a session can change them.
//!
//! ```toml
//! [ssh]
//! hosts = [
//!   "github.com",
//! ]
//! ```
//!
//! This module only parses; what the fields mean is decided where they are used.

use std::{fs, io, path::Path, str::FromStr};

use serde::Deserialize;

/// The whole file. Every section is optional, so an empty file and a
/// missing one mean the same thing: nothing allowed beyond the defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub ssh: Ssh,
}

/// The `[ssh]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    /// Host names, as they appear in `~/.ssh/known_hosts`, that a session
    /// may authenticate to through the ssh-agent proxy.
    #[serde(default)]
    pub hosts: Vec<String>,
}

impl FromStr for Config {
    type Err = toml::de::Error;

    fn from_str(text: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(text)
    }
}

/// The configuration in the file at a path. A file that is not there is an
/// empty configuration; a file that is there but does not parse is an
/// error, never silently empty, because a typo must not open or close
/// anything without being seen.
impl TryFrom<&Path> for Config {
    type Error = io::Error;

    fn try_from(path: &Path) -> io::Result<Config> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => return Err(e),
        };
        text.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nd7-config-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_missing_file_is_an_empty_config() {
        let dir = scratch("missing");
        assert_eq!(
            Config::try_from(dir.join("config.toml").as_path()).unwrap(),
            Config::default()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_empty_file_is_an_empty_config() {
        let dir = scratch("empty");
        let path = dir.join("config.toml");
        fs::write(&path, "").unwrap();
        assert_eq!(Config::try_from(path.as_path()).unwrap(), Config::default());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hosts_are_read_across_lines() {
        let dir = scratch("hosts");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            r#"[ssh]
hosts = [
  "github.com",
  "staging.internal",
]
"#,
        )
        .unwrap();
        assert_eq!(
            Config::try_from(path.as_path()).unwrap().ssh.hosts,
            ["github.com", "staging.internal"]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_string_parses_without_a_file() {
        let config: Config = r#"[ssh]
hosts = ["github.com"]
"#
        .parse()
        .unwrap();
        assert_eq!(config.ssh.hosts, ["github.com"]);
        assert!(
            r#"[ssh]
hosts = 1
"#
            .parse::<Config>()
            .is_err()
        );
    }

    #[test]
    fn a_file_that_does_not_parse_is_an_error_that_names_it() {
        let dir = scratch("broken");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            r#"[ssh]
hosts = "github.com"
"#,
        )
        .unwrap();
        let err = Config::try_from(path.as_path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("config.toml"), "{err}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unknown_key_is_an_error() {
        let dir = scratch("unknown");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            r#"[ssh]
host = ["github.com"]
"#,
        )
        .unwrap();
        assert_eq!(
            Config::try_from(path.as_path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
