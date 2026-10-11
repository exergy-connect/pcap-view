import {test} from 'node:test';
import assert from 'node:assert/strict';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {parsePcapng} from '../parser.js';
import {fixture} from './fixtures.js';

function frame(text = 'GET /tunnel HTTP/1.1\r\n\r\n', sequence = 0, vlan = false) {
  const payload = new TextEncoder().encode(text), p = vlan ? 18 : 14;
  const bytes = new Uint8Array(p + 40 + payload.length), v = new DataView(bytes.buffer);
  bytes.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  v.setUint16(12, vlan ? 0x8100 : 0x0800);
  if (vlan) {v.setUint16(14, 100); v.setUint16(16, 0x0800);}
  bytes[p] = 0x45; v.setUint16(p + 2, 40 + payload.length); bytes[p + 9] = 6;
  bytes.set([192, 0, 2, 1, 192, 0, 2, 2], p + 12);
  v.setUint16(p + 20, 50000); v.setUint16(p + 22, 80); v.setUint32(p + 24, sequence);
  bytes[p + 32] = 0x50; bytes[p + 33] = 16; bytes.set(payload, p + 40);
  return bytes;
}
function ip(payload, proto = 143, ipv6 = false) {
  const p = ipv6 ? 40 : 20, bytes = new Uint8Array(p + payload.length), v = new DataView(bytes.buffer);
  bytes[0] = ipv6 ? 0x60 : 0x45;
  v.setUint16(ipv6 ? 4 : 2, ipv6 ? payload.length : bytes.length);
  bytes[ipv6 ? 6 : 9] = proto;
  if (!ipv6) bytes.set([198, 51, 100, 1, 198, 51, 100, 2], 12);
  bytes.set(payload, p); return bytes;
}
function dissect(bytes, names = 'all', contexts = new Map()) {
  const packet = decode(bytes, 101);
  if (packet.payload) applyDissectors(packet, packet.payload, loadDissectors(names), contexts);
  return packet;
}

test('Ethernet-in-IP decodes IPv4/IPv6 tunnels, VLAN and inner HTTP while preserving outer endpoints', () => {
  for (const ipv6 of [false, true]) {
    const bytes = ip(frame(undefined, 0, true), 143, ipv6), outer = decode(bytes, 101);
    const packet = dissect(bytes), inner = packet.application.inner;
    assert.equal(packet.source, outer.source); assert.equal(packet.destination, outer.destination);
    assert.equal(packet.protocol, 'Ethernet-in-IP');
    assert.equal(inner.source, '192.0.2.1'); assert.equal(inner.sourceMac, '06:07:08:09:0a:0b');
    assert.equal(inner.protocol, 'HTTP'); assert.equal(inner.application.messages[0].target, '/tunnel');
    assert.equal(inner.payload, undefined);
    assert.equal(dissect(bytes, ['ethernet-in-ip']).application.inner.protocol, 'TCP');
    assert.equal(dissect(bytes, []).application, undefined);
  }
});

test('Ethernet-in-IP reports every truncated Ethernet header', () => {
  for (let n = 0; n < 14; n++) assert.ok(dissect(ip(new Uint8Array(n))).application.error);
  assert.equal(dissect(ip(frame(), 97)).application, undefined);
});

test('Ethernet-in-IP reassembles inner TCP continuations', () => {
  const contexts = new Map(), first = 'GET /split HTTP/1.1\r\nHost: example';
  assert.equal(dissect(ip(frame(first)), 'all', contexts).application.inner.application.pendingBytes, first.length);
  const bytes = ip(frame('\r\n\r\n', first.length));
  assert.equal(dissect(bytes).application.inner.protocol, 'TCP');
  assert.equal(dissect(bytes, 'all', contexts).application.inner.application.messages[0].target, '/split');
});

test('nested Ethernet-in-IP respects the dissection depth limit', () => {
  let bytes = ip(frame());
  for (let i = 0; i < 12; i++) {
    const ethernet = new Uint8Array(14 + bytes.length); ethernet[12] = 8; ethernet.set(bytes, 14);
    bytes = ip(ethernet);
  }
  let packet = dissect(bytes), depth = 0;
  while (packet.application?.inner) {
    packet = packet.application.inner; depth++;
    assert.equal(packet.payload, undefined);
  }
  assert.equal(depth, 9); assert.equal(packet.protocol, 'Ethernet-in-IP');
});

test('RFC 8986 Ethernet follows an IPv6 Segment Routing Header', () => {
  const ethernet = frame(), payload = new Uint8Array(24 + ethernet.length);
  payload[0] = 143; payload[1] = 2; payload[2] = 4;
  payload.set(ethernet, 24);
  const bytes = ip(payload, 43, true);
  assert.equal(dissect(bytes).application.inner.application.messages[0].target, '/tunnel');
  // The IPv6 payload length bounds the captured Ethernet frame.
  new DataView(bytes.buffer).setUint16(4, 24 + 13);
  assert.ok(dissect(bytes).application.error);
});

test('capture parsing enables protocol 143, resolves inner hostnames and respects selection', () => {
  const bytes = ip(frame(), 143, true), prefix = fixture().slice(0, 48);
  new DataView(prefix).setUint16(36, 101, true);
  const size = 32 + Math.ceil(bytes.length / 4) * 4, block = new Uint8Array(size), v = new DataView(block.buffer);
  v.setUint32(0, 6, true); v.setUint32(4, size, true);
  v.setUint32(20, bytes.length, true); v.setUint32(24, bytes.length, true);
  block.set(bytes, 28); v.setUint32(size - 4, size, true);
  const name = new TextEncoder().encode('inner.example\0'), len = 4 + name.length;
  const nrb = new Uint8Array(20 + Math.ceil(len / 4) * 4), n = new DataView(nrb.buffer);
  n.setUint32(0, 4, true); n.setUint32(4, nrb.length, true);
  n.setUint16(8, 1, true); n.setUint16(10, len, true);
  nrb.set([192, 0, 2, 1], 12); nrb.set(name, 16); n.setUint32(nrb.length - 4, nrb.length, true);
  const capture = new Uint8Array(prefix.byteLength + block.length + nrb.length);
  capture.set(new Uint8Array(prefix)); capture.set(block, prefix.byteLength); capture.set(nrb, prefix.byteLength + block.length);
  const {packets, streams} = parsePcapng(capture.buffer);
  assert.equal(streams.length, 0);
  assert.equal(packets[0].application.inner.protocol, 'HTTP');
  assert.deepEqual(packets[0].application.inner.sourceNames, ['inner.example']);
  assert.match(packets[0].info, /inner.example/);
  assert.equal(packets[0].application.inner.payload, undefined);
  assert.equal(parsePcapng(capture.buffer, {dissectors: []}).packets[0].application, undefined);
});
