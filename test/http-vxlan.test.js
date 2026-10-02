import {test} from 'node:test';
import assert from 'node:assert/strict';
import {applyDissectors, loadDissectors} from '../dissectors.js';
const encode = text => new TextEncoder().encode(text);
function tcp(text, sequence = 0, contexts = new Map(), extra = {}) {
  const packet = {protocol: 'TCP', stream: 0, sport: 50000, dport: 80, sequence, flags: 16, ...extra};
  applyDissectors(packet, encode(text), loadDissectors(), contexts);
  return packet;
}

test('HTTP detects requests on arbitrary ports and decodes pipelined messages', () => {
  const packet = tcp('GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\nPOST / HTTP/1.0\r\nContent-Length: 3\r\n\r\nabc', 0, new Map(), {dport: 12345});
  assert.equal(packet.protocol, 'HTTP');
  assert.equal(packet.transport, 'TCP');
  assert.equal(packet.application.messages.length, 2);
  assert.deepEqual(packet.application.messages[0].headers, [{name: 'Host', value: 'example.test'}]);
  assert.equal(packet.application.messages[1].bodyPreview, 'abc');
});

test('HTTP buffers split headers and bodies and ignores overlapping retransmissions', () => {
  const context = new Map();
  const first = 'POST / HTTP/1.1\r\nContent-Length: 5\r\n';
  assert.equal(tcp(first, 0, context).application.pendingBytes, first.length);
  const second = '\r\nhello';
  const packet = tcp(first.slice(-2) + second, first.length - 2, context);
  assert.equal(packet.application.messages[0].bodyPreview, 'hello');
  assert.equal(tcp(second, first.length, context).application.messages.length, 0);
});

test('HTTP handles chunked responses, trailers and byte lengths', () => {
  const packet = tcp('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;foo=bar\r\né\r\n0\r\nX-End: yes\r\n\r\n');
  const message = packet.application.messages[0];
  assert.equal(message.bodyLength, 2);
  assert.equal(message.trailers[0].value, 'yes');
});

test('HTTP closes unframed response bodies on a separate FIN', () => {
  const context = new Map();
  const text = 'HTTP/1.0 200 OK\r\n\r\nhello';
  assert.ok(tcp(text, 0, context).application.pendingBytes);
  assert.equal(tcp('', text.length, context, {flags: 17}).application.messages[0].bodyPreview, 'hello');
});

test('HTTP reports malformed lengths and sequence gaps without throwing', () => {
  assert.match(tcp('POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n').application.error, /Content-Length/);
  const contexts = new Map();
  tcp('GET / HTTP/1.1\r\n', 0, contexts);
  assert.match(tcp('abc', 100, contexts).application.error, /sequence gap/);
  assert.equal(tcp('\u0016\u0003\u0001binary').protocol, 'TCP');
});

test('VXLAN exposes VNI and inner Ethernet/IPv4/UDP while retaining outer endpoints', () => {
  const bytes = new Uint8Array(8 + 14 + 20 + 8);
  bytes[0] = 8; bytes.set([0x12, 0x34, 0x56], 4);
  bytes.set([0x08, 0x00], 20);
  const p = 22; bytes[p] = 0x45; bytes[p + 3] = 28; bytes[p + 9] = 17;
  bytes.set([192, 0, 2, 1, 192, 0, 2, 2], p + 12);
  new DataView(bytes.buffer).setUint16(p + 20, 1234);
  new DataView(bytes.buffer).setUint16(p + 22, 53);
  bytes[p + 25] = 8;
  const packet = {protocol: 'UDP', sport: 50000, dport: 4789, source: 'outer'};
  applyDissectors(packet, bytes, loadDissectors());
  assert.equal(packet.protocol, 'VXLAN');
  assert.equal(packet.source, 'outer');
  assert.equal(packet.application.vni, 0x123456);
  assert.equal(packet.application.inner.source, '192.0.2.1');
  assert.equal(packet.application.inner.dport, 53);
  assert.equal(packet.application.inner.payload, undefined);
  const other = {protocol: 'UDP', dport: 12345};
  applyDissectors(other, bytes, loadDissectors());
  assert.equal(other.protocol, 'VXLAN');
});

test('VXLAN reports truncated and invalid headers and rejects unrelated UDP', () => {
  for (const bytes of [new Uint8Array(3), new Uint8Array(8)]) {
    const packet = {protocol: 'UDP', dport: 4789};
    applyDissectors(packet, bytes, loadDissectors());
    assert.ok(packet.application.error);
  }
  const packet = {protocol: 'UDP', dport: 1234};
  applyDissectors(packet, new Uint8Array(30), loadDissectors());
  assert.equal(packet.protocol, 'UDP');
});

function tunnel(frame, vni = 1) {
  const bytes = new Uint8Array(8 + frame.length);
  bytes[0] = 8; bytes[6] = vni; bytes.set(frame, 8); return bytes;
}
function innerTcp(text, sequence = 0) {
  const payload = encode(text), frame = new Uint8Array(54 + payload.length), v = new DataView(frame.buffer);
  v.setUint16(12, 0x0800); frame[14] = 0x45; v.setUint16(16, 40 + payload.length); frame[23] = 6;
  frame.set([192, 0, 2, 1, 192, 0, 2, 2], 26);
  v.setUint16(34, 50000); v.setUint16(36, 80); v.setUint32(38, sequence);
  frame[46] = 0x50; frame[47] = 16; frame.set(payload, 54); return frame;
}
function outer(bytes, contexts = new Map(), names = 'all') {
  const packet = {protocol: 'UDP', source: 'outer-client', destination: 'outer-server', sport: 50000, dport: 4789};
  applyDissectors(packet, bytes, loadDissectors(names), contexts); return packet;
}

test('VXLAN dissects inner HTTP and respects enabled dissectors', () => {
  const bytes = tunnel(innerTcp('GET /inside HTTP/1.1\r\n\r\n'));
  const packet = outer(bytes);
  assert.equal(packet.protocol, 'VXLAN'); assert.equal(packet.transport, 'UDP');
  assert.equal(packet.source, 'outer-client');
  assert.equal(packet.application.inner.protocol, 'HTTP');
  assert.equal(packet.application.inner.application.messages[0].target, '/inside');
  assert.equal(packet.application.inner.payload, undefined);
  assert.match(packet.info, /HTTP.*GET \/inside/);
  assert.equal(outer(bytes, new Map(), ['vxlan']).application.inner.protocol, 'TCP');
});

test('VXLAN reassembles inner TCP messages and isolates VNIs', () => {
  const contexts = new Map(), first = 'GET /inside HTTP/1.1\r\nHost: example';
  assert.equal(outer(tunnel(innerTcp(first)), contexts).application.inner.application.pendingBytes, first.length);
  const second = '\r\n\r\n';
  const unrelated = outer(tunnel(innerTcp(second, first.length), 2), contexts);
  assert.equal(unrelated.application.inner.protocol, 'TCP');
  const inner = outer(tunnel(innerTcp(second, first.length)), contexts).application.inner;
  assert.equal(inner.application.messages[0].headers[0].value, 'example');
});

test('VXLAN dissects inner ARP', () => {
  const frame = new Uint8Array(42), v = new DataView(frame.buffer);
  v.setUint16(12, 0x0806); v.setUint16(14, 1); v.setUint16(16, 0x0800);
  frame[18] = 6; frame[19] = 4; v.setUint16(20, 1);
  frame.set([192, 0, 2, 1], 28); frame.set([192, 0, 2, 2], 38);
  const inner = outer(tunnel(frame)).application.inner;
  assert.equal(inner.application.dissector, 'arp');
  assert.equal(inner.application.targetProtocolAddress, '192.0.2.2');
});

function innerUdp(payload) {
  const frame = new Uint8Array(42 + payload.length), v = new DataView(frame.buffer);
  v.setUint16(12, 0x0800); frame[14] = 0x45; frame[23] = 17;
  v.setUint16(16, frame.length - 14); v.setUint16(34, 50000); v.setUint16(36, 4789);
  v.setUint16(38, 8 + payload.length); frame.set(payload, 42); return frame;
}

test('nested VXLAN dissection stops at the depth limit and removes raw payloads', () => {
  let bytes = tunnel(innerTcp('GET /nested HTTP/1.1\r\n\r\n'));
  const nested = outer(tunnel(innerUdp(bytes)));
  assert.equal(nested.application.inner.application.inner.protocol, 'HTTP');
  for (let i = 0; i < 12; i++) bytes = tunnel(innerUdp(bytes));
  let packet = outer(bytes), depth = 0;
  while (packet.application?.inner) {
    assert.equal(packet.payload, undefined);
    packet = packet.application.inner; depth++;
  }
  assert.equal(depth, 9); assert.equal(packet.protocol, 'UDP'); assert.equal(packet.payload, undefined);
});
