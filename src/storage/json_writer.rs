use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use serde_json::json;
use crate::dispatcher::Storage;

pub struct JsonWriter {
    path: PathBuf,
}

impl JsonWriter {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        Ok(Self { path })
    }
}

impl Storage for JsonWriter {
    fn store(&self, name: &str, data: &[u8]) {
        let event = json!({
            "analyzer": name,
            "length": data.len(),
            "data": base64::encode(data),
        });

        if let Ok(json_str) = serde_json::to_string(&event) {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                let _ = writeln!(file, "{}", json_str);
            }
        }
    }
}
