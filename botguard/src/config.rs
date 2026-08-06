use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub blocked_fingerprints: HashSet<String>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let raw = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&raw)?;
        Ok(config)
    }
}
