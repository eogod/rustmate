use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::PathBuf,
};

use anyhow::Context;

use crate::{event::Event, output::EventSink};

pub struct JsonlWriter {
    writer: BufWriter<File>,
}

impl JsonlWriter {
    pub fn create(path: PathBuf) -> anyhow::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("failed to open JSONL output {}", path.display()))?;

        Ok(Self {
            writer: BufWriter::new(file),
        })
    }
}

impl EventSink for JsonlWriter {
    fn write(&mut self, event: &Event) -> anyhow::Result<()> {
        serde_json::to_writer(&mut self.writer, event)?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    fn write_batch(&mut self, events: &[Event]) -> anyhow::Result<()> {
        for event in events {
            serde_json::to_writer(&mut self.writer, event)?;
            self.writer.write_all(b"\n")?;
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}
