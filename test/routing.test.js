import {test} from 'node:test';
import assert from 'node:assert/strict';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {dissectOspf} from '../dissectors/ospf.js';
import {dissectIsis} from '../dissectors/isis.js';
const view = b => new DataView(b.buffer);
function dissect(bytes, link = 1, names = 'all') {
  const packet = decode(bytes, link);
  applyDissectors(packet, packet.payload ?? new Uint8Array(), loadDissectors(names));
  return packet;
}
function ospf(version, body, type = 4) {
  const b = new Uint8Array((version === 2 ? 24 : 16) + body.length), v = view(b);
  b[0] = version; b[1] = type; v.setUint16(2, b.length); b.set([1, 2, 3, 4], 4); b.set(body, version === 2 ? 24 : 16); return b;
}
function ethernetIp(payload, version) {
  const b = new Uint8Array(14 + (version === 4 ? 20 : 40) + payload.length), v = view(b);
  v.setUint16(12, version === 4 ? 0x800 : 0x86dd);
  b[14] = version === 4 ? 0x45 : 0x60;
  if (version === 4) {v.setUint16(16, 20 + payload.length); b[23] = 89;}
  else {v.setUint16(18, payload.length); b[20] = 89;}
  b.set(payload, b.length - payload.length); return b;
}
test('OSPFv2 Hello over IPv4 and explicit selection', () => {
  const body = new Uint8Array(24), v = view(body); v.setUint16(4, 10); v.setUint32(8, 40); body.set([5, 6, 7, 8], 20);
  const frame = ethernetIp(ospf(2, body, 1), 4), packet = dissect(frame);
  assert.equal(packet.application.dissector, 'ospf'); assert.equal(packet.transport, 'OSPF');
  assert.equal(packet.application.routerId, '1.2.3.4'); assert.deepEqual(packet.application.neighbors, ['5.6.7.8']);
  assert.equal(dissect(frame, 1, []).application, undefined);
});
test('OSPFv3 SRv6 locator LSA with word-aligned prefix and unknown sub-TLV', () => {
  const body = new Uint8Array(48), v = view(body); v.setUint32(0, 1);
  v.setUint16(6, 0xa02a); v.setUint16(22, 44); v.setUint16(24, 1); v.setUint16(26, 20);
  body[28] = 1; body[29] = 128; body[30] = 49; v.setUint32(32, 100);
  body.set([0x20, 1, 0x0d, 0xb8, 0xab, 0xcd, 0xff, 0xff], 36);
  v.setUint16(44, 99);
  const packet = dissect(ethernetIp(ospf(3, body), 6));
  assert.equal(packet.application.error, undefined);
  const locator = packet.application.locators[0];
  assert.equal(locator.locator, '2001:db8:abcd:8000:0:0:0:0/49');
  assert.equal(locator.algorithm, 128); assert.equal(locator.metric, 100); assert.equal(locator.subTlvs[0].type, 99);
});
function isisLsp() {
  const b = new Uint8Array(45), v = view(b); b.set([0x83, 27, 1, 0, 18, 1, 0, 0]); v.setUint16(8, b.length);
  b[27] = 27; b[28] = 16; v.setUint16(29, 2); v.setUint32(31, 42); b[35] = 128; b[36] = 0; b[37] = 48;
  b.set([0x20, 1, 0x0d, 0xb8, 0, 1], 38); return b;
}
test('IS-IS LSP locator over Ethernet LLC, VLAN and cooked capture', () => {
  const pdu = isisLsp();
  for (const link of [1, 113, 276]) {
    const offset = link === 1 ? 14 : link === 113 ? 16 : 20;
    const b = new Uint8Array(offset + 3 + pdu.length), v = view(b);
    v.setUint16(link === 1 ? 12 : link === 113 ? 14 : 0, link === 1 ? 3 + pdu.length : 4);
    b.set([254, 254, 3], offset); b.set(pdu, offset + 3);
    const packet = dissect(b, link); assert.equal(packet.application.error, undefined);
    assert.equal(packet.application.tlvs[0].mtid, 2); assert.equal(packet.application.locators[0].locator, '2001:db8:1:0:0:0:0:0/48');
    assert.equal(packet.application.locators[0].down, true);
    if (link === 1) {
      const tagged = new Uint8Array(b.length + 4); tagged.set(b.subarray(0, 12)); view(tagged).setUint16(12, 0x8100); tagged.set(b.subarray(12), 16);
      assert.equal(dissect(tagged).application.dissector, 'isis');
    }
  }
});
test('routing dissectors reject all truncated prefixes without throwing', () => {
  for (const [bytes, fn] of [[ospf(2, new Uint8Array(20), 1), dissectOspf], [isisLsp(), dissectIsis]]) {
    for (let n = 0; n < bytes.length; n++) assert.ok(fn(bytes.subarray(0, n)).error, `prefix ${n}`);
  }
  const invalid = isisLsp(); invalid[37] = 129; assert.match(dissectIsis(invalid).error, /locator length/);
  const bad = ospf(3, new Uint8Array(4)); view(bad).setUint32(16, 0xffffffff); assert.ok(dissectOspf(bad).error);
});
