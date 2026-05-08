use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub tunnel: TunnelConfig,
    pub service: std::collections::HashMap<String, ServiceConfig>,
}

#[derive(Debug, Deserialize)]
pub struct TunnelConfig {
    pub r#type: String,
    pub region: String,
    pub instance_type: String,
}

#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    pub port: u16,
    pub build_command: Option<String>,
    pub run_command: String,
    pub health_check_path: Option<String>,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let content = fs::read_to_string("ephemwork.toml")
            .or_else(|_| fs::read_to_string("ephemwork.toml.example"))?
            ;
        toml::from_str(&content).map_err(Into::into)
    }
}
