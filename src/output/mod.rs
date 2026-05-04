pub mod jsonl;

use anyhow::Result;

use crate::event::Event;

pub trait EventSink: Send {
    fn write(&mut self, event: &Event) -> Result<()>;

    fn write_batch(&mut self, events: &[Event]) -> Result<()> {
        for event in events {
            self.write(event)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
