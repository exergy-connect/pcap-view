import {test} from 'node:test';
import assert from 'node:assert/strict';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {dissectMpls} from '../dissectors/mpls.js';
import {parsePcapng} from '../parser.js';
import {fixture} from './fixtures.js';

function stack(labels, payload = new Uint8Array()) {
  const bytes = new Uint8Array(labels.length * 4 + payload.length), view = new DataView(bytes.buffer);
  labels.forEach((label, i) => view.setUint32(i * 4, label * 4096 + 5 * 512 + (i === labels.length - 1 ? 256 : 0) + 64));
  bytes.set(payload, labels.length * 4); return bytes;
}
function frame(payload, link = 1, vlan = false) {
  const header = link === 113 ? 16 : link === 276 ? 20 : vlan ? 18 : 14;
  const bytes = new Uint8Array(header + payload.length), view = new DataView(bytes.buffer);
  if (link === 1) {
    bytes.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    if (vlan) {view.setUint16(12, 0x8100); view.setUint16(14, 100);}
  }
  view.setUint16(link === 276 ? 0 : header - 2, 0x8847);
  bytes.set(payload, header); return bytes;
}
function ip(ipv6 = false, text = 'GET /mpls HTTP/1.1\r\n\r\n', sequence = 0) {
  const payload = new TextEncoder().encode(text), header = ipv6 ? 40 : 20;
  const bytes = new Uint8Array(header + 20 + payload.length), view = new DataView(bytes.buffer);
  bytes[0] = ipv6 ? 0x60 : 0x45;
  view.setUint16(ipv6 ? 4 : 2, ipv6 ? bytes.length - 40 : bytes.length);
  bytes[ipv6 ? 6 : 9] = 6;
  if (!ipv6) bytes.set([192, 0, 2, 1, 192, 0, 2, 2], 12);
  view.setUint16(header, 50000); view.setUint16(header + 2, 80);
  view.setUint32(header + 4, sequence); bytes[header + 12] = 0x50; bytes[header + 13] = 16;
  bytes.set(payload, header + 20); return bytes;
}
function dissect(bytes, link = 1, names = 'all', contexts = new Map()) {
  const packet = decode(bytes, link);
  applyDissectors(packet, packet.payload, loadDissectors(names), contexts); return packet;
}
function capture(packet) {
  const size = 32 + Math.ceil(packet.length / 4) * 4;
  const bytes = new Uint8Array(48 + size), view = new DataView(bytes.buffer);
  bytes.set(new Uint8Array(fixture().slice(0, 48)));
  view.setUint32(48, 6, true); view.setUint32(52, size, true);
  view.setUint32(68, packet.length, true); view.setUint32(72, packet.length, true);
  bytes.set(packet, 76); view.setUint32(bytes.length - 4, size, true); return bytes.buffer;
}

test('MPLS label fields and inner IPv4/IPv6 applications decode across supported links', () => {
  for (const ipv6 of [false, true]) for (const [link, vlan] of [[1, false], [1, true], [113, false], [276, false]]) {
    const packet = dissect(frame(stack([1048575, ipv6 ? 2 : 0], ip(ipv6)), link, vlan), link);
    assert.equal(packet.protocol, 'MPLS');
    assert.deepEqual(packet.application.labels, [
      {label: 1048575, trafficClass: 5, bottomOfStack: false, ttl: 64},
      {label: ipv6 ? 2 : 0, trafficClass: 5, bottomOfStack: true, ttl: 64},
    ]);
    assert.equal(packet.application.inner.protocol, 'HTTP');
    assert.equal(packet.application.inner.application.messages[0].target, '/mpls');
    assert.equal(packet.application.inner.payload, undefined);
    if (link === 1) assert.equal(packet.source, '06:07:08:09:0a:0b');
  }
  assert.equal(dissect(frame(stack([100], ip()))).application.inner.source, '192.0.2.1');
});

test('MPLS reports truncated and unterminated stacks and retains opaque payloads', () => {
  for (let length = 0; length < 4; length++) {
    assert.match(dissect(frame(new Uint8Array(length))).application.error, /Truncated MPLS/);
  }
  const bytes = stack([100, 200]);
  for (let length = 4; length < 8; length++) assert.ok(dissectMpls(bytes.subarray(0, length)).error);
  assert.equal(dissectMpls(bytes.subarray(0, 4)).labels.length, 1);
  assert.equal(dissectMpls(stack([100], new Uint8Array([0x10, 2]))).rawPayload, '10:02');
  assert.equal(dissectMpls(stack([13], ip())).inner, undefined);
  assert.match(dissectMpls(stack([0], new Uint8Array([0x45]))).error, /Truncated/);
  assert.match(dissectMpls(stack([0], ip(true))).error, /Invalid.*version/);
});

test('capture parsing enables MPLS by default and respects dissector selection', () => {
  const bytes = capture(frame(stack([100], ip())));
  const {packets, streams} = parsePcapng(bytes);
  assert.equal(streams.length, 0);
  assert.equal(packets[0].application.inner.protocol, 'HTTP');
  assert.match(packets[0].info, /Label=100; HTTP/);
  assert.equal(parsePcapng(bytes, {dissectors: ['mpls']}).packets[0].application.inner.protocol, 'TCP');
  assert.equal(parsePcapng(bytes, {dissectors: []}).packets[0].application, undefined);
});

test('MPLS buffers inner TCP continuations separately for each label stack', () => {
  const contexts = new Map(), first = 'GET /split HTTP/1.1\r\nHost: example';
  const run = (label, text, sequence = 0) => dissect(frame(stack([label], ip(false, text, sequence))), 1, 'all', contexts);
  assert.equal(run(100, first).application.inner.application.pendingBytes, first.length);
  assert.equal(run(200, '\r\n\r\n', first.length).application.inner.protocol, 'TCP');
  assert.equal(run(100, '\r\n\r\n', first.length).application.inner.application.messages[0].target, '/split');
});
