use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub output_json: Option<String>,
    pub sqlite_path: Option<String>,
    pub plugin_dir: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self { output_json: Some("out.json".into()), sqlite_path: None, plugin_dir: None }
    }
}
