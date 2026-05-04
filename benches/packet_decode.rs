use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use etherparse::PacketBuilder;
use pcap::Linktype;
use rustmate::packet::{DecodedPacket, LinkLayer, PacketTimestamp, RawPacket};

fn ethernet_tcp_http_packet() -> RawPacket {
    let payload = b"GET /flag HTTP/1.1\r\nHost: ctf.local\r\n\r\n";
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 20)
        .tcp(31337, 80, 1, 4096);
    let mut data = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut data, payload).unwrap();

    RawPacket {
        timestamp: PacketTimestamp { sec: 1, usec: 0 },
        link_layer: LinkLayer::Ethernet,
        linktype: Linktype::ETHERNET.0,
        data,
    }
}

fn decode_tcp_payload(c: &mut Criterion) {
    let packet = ethernet_tcp_http_packet();

    c.bench_function("decode_tcp_payload", |b| {
        b.iter(|| {
            let decoded = DecodedPacket::from_raw(black_box(&packet));
            black_box(decoded.transport_payload());
        })
    });
}

criterion_group!(benches, decode_tcp_payload);
criterion_main!(benches);
