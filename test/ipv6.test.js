import {test} from 'node:test';
import assert from 'node:assert/strict';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {dissectIpv6} from '../dissectors/ipv6.js';
function ip(next, data = new Uint8Array()) {
  const b = new Uint8Array(40 + data.length), v = new DataView(b.buffer);
  v.setUint32(0, 0x6ab12345); v.setUint16(4, data.length); b[6] = next; b[7] = 64; b.set(data, 40); return b;
}
function dissect(b, names = 'all') {
  const p = decode(b, 101); applyDissectors(p, p.payload ?? new Uint8Array(), loadDissectors(names)); return p;
}
test('IPv6 metadata coexists with transport and application decoding', () => {
  const udp = new Uint8Array(8); new DataView(udp.buffer).setUint16(4, 8);
  const p = dissect(ip(17, udp));
  assert.equal(p.protocol, 'UDP'); assert.equal(p.transportDetails.dissector, 'udp');
  assert.equal(p.networkDetails.trafficClass, 0xab); assert.equal(p.networkDetails.flowLabel, 0x12345);
  assert.equal(p.networkDetails.hopLimit, 64); assert.equal(dissect(ip(17, udp), []).networkDetails, undefined);
});
test('IPv6 extension chains expose options, routing, AH and fragments', () => {
  const b = new Uint8Array(44); b.set([43, 0, 1, 4], 0); b.set([51, 0, 4, 0], 8);
  b.set([44, 1], 16); b.set([59, 0, 0, 1], 28);
  const d = dissectIpv6(ip(0, b));
  assert.equal(d.extensionHeaders.length, 4); assert.equal(d.upperProtocol, 59);
  assert.equal(d.extensionHeaders[3].moreFragments, true);
  b[30] = 0; b[31] = 8;
  assert.equal(dissect(ip(0, b)).info, 'IPv6 fragment');
});
test('IPv4 protocol 4 and IPv6 protocol 41 decode inner packets preserving outer endpoints', () => {
  const v4 = new Uint8Array(28), v = new DataView(v4.buffer);
  v4[0] = 0x45; v.setUint16(2, 28); v4[9] = 17; v4.set([192, 0, 2, 1], 12); v.setUint16(24, 8);
  const p = dissect(ip(4, v4));
  assert.equal(p.application.inner.protocol, 'UDP'); assert.equal(p.application.inner.source, '192.0.2.1');
  assert.equal(p.source, '0:0:0:0:0:0:0:0'); assert.equal(p.application.inner.transportDetails.dissector, 'udp');
  assert.equal(dissect(ip(41, ip(59))).application.inner.networkDetails.upperProtocol, 59);
  assert.ok(dissect(ip(4)).application.error);
  assert.equal(dissect(ip(4, v4), []).application, undefined);
});
test('IPv6 truncations and malformed extensions never read beyond captured bytes', () => {
  const bytes = ip(60, new Uint8Array(8)); bytes[40] = 59;
  for (let n = 0; n < bytes.length; n++) assert.doesNotThrow(() => dissect(bytes.subarray(0, n)));
  bytes[43] = 255; bytes[42] = 1;
  assert.match(dissect(bytes).networkDetails.error, /option/);
  const ah = ip(51, new Uint8Array(8)); assert.match(dissect(ah).networkDetails.error, /authentication/);
});
test('common IP protocols expose fixed fields and truncation errors', () => {
  for (const [next, name, length] of [[47, 'GRE', 4], [50, 'ESP', 8], [132, 'SCTP', 12], [103, 'PIM', 4], [112, 'VRRP', 8]]) {
    assert.equal(dissect(ip(next, new Uint8Array(length))).application.protocol, name);
    for (let n = 0; n < length; n++) assert.ok(dissect(ip(next, new Uint8Array(n))).application.error);
  }
});
