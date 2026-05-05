pub mod dns;
pub mod http;
pub mod tls_meta;

use crate::{
    event::Event,
    flow::{FlowObservation, StreamChunk},
    packet::DecodedPacket,
};

pub trait Analyzer: Send {
    fn name(&self) -> &'static str;
    fn analyze(&mut self, packet: &DecodedPacket<'_>, events: &mut Vec<Event>);

    fn analyze_stream(
        &mut self,
        _packet: &DecodedPacket<'_>,
        _flow: &FlowObservation<'_>,
        _chunk: &StreamChunk<'_>,
        _events: &mut Vec<Event>,
    ) {
    }
}
