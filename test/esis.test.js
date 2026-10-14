import {test} from 'node:test';
import assert from 'node:assert/strict';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {dissectEsis} from '../dissectors/esis.js';

const hello = Uint8Array.from([0x82, 17, 1, 0, 4, 0, 30, 0, 0, 4, 0x49, 0, 1, 0, 0xc6, 1, 10]);
function frame(pdu, link, tags = 0, jumbo = false) {
  const offset = link === 1 ? 14 + tags * 4 : link === 113 ? 16 : 20;
  const b = new Uint8Array(Math.max(64, offset + 3 + pdu.length)), v = new DataView(b.buffer);
  if (link === 1) {
    b.set([9, 0, 0x2b, 0, 0, 4]); b.set([0x2a, 0xad, 0x39, 0x1e, 0, 0], 6);
    for (let i = 0; i < tags; i++) v.setUint16(12 + i * 4, 0x8100);
  }
  v.setUint16(link === 1 ? 12 + tags * 4 : link === 113 ? 14 : 0, jumbo ? 0x8870 : link === 1 ? pdu.length + 3 : 4);
  b.set([254, 254, 3], offset); b.set(pdu, offset + 3); return b;
}
function dissect(b, link, names = 'all') {
  const packet = decode(b, link);
  applyDissectors(packet, packet.payload, loadDissectors(names)); return packet;
}
test('ESIS IS HELLO uses NLPID across Ethernet, VLAN, jumbo and cooked captures', () => {
  for (const [link, tags, jumbo] of [[1, 0, false], [1, 2, false], [1, 0, true], [113, 0, false], [276, 0, false]]) {
    const b = frame(hello, link, tags, jumbo), packet = dissect(b, link);
    assert.equal(packet.protocol, 'ESIS'); assert.equal(packet.info, 'IS HELLO');
    assert.equal(packet.application.dissector, 'esis'); assert.equal(packet.application.error, undefined);
    assert.equal(packet.application.holdingTime, 30);
    assert.equal(packet.application.networkEntityTitle, '49.00.01.00');
    assert.equal(packet.application.options.length, 1);
    if (link === 1) {assert.equal(packet.source, '2a:ad:39:1e:00:00'); assert.equal(packet.destination, '09:00:2b:00:00:04');}
    assert.equal(dissect(b, link, []).application, undefined);
    assert.equal(dissect(b, link, ['esis']).application.dissector, 'esis');
  }
});
test('ESIS lengths reject truncation and ignore Ethernet padding', () => {
  for (let n = 0; n < hello.length; n++) assert.ok(dissectEsis(hello.subarray(0, n)).error);
  for (const [offset, value] of [[1, 8], [2, 2], [9, 30], [15, 30]]) {
    const invalid = hello.slice(); invalid[offset] = value; assert.ok(dissectEsis(invalid).error);
  }
  const padded = new Uint8Array(48); padded.set(hello);
  assert.equal(dissectEsis(padded).error, undefined);
});
test('ESIS ES HELLO and redirects decode variable addresses', () => {
  const esh = Uint8Array.from([0x82, 15, 1, 0, 2, 0, 10, 0, 0, 2, 1, 0x49, 2, 0x49, 1]);
  assert.deepEqual(dissectEsis(esh).sourceAddresses, ['49', '49.01']);
  const redirect = Uint8Array.from([0x82, 14, 1, 0, 6, 0, 10, 0, 0, 1, 0x49, 1, 0xab, 0]);
  const result = dissectEsis(redirect);
  assert.equal(result.error, undefined); assert.equal(result.destinationAddress, '49');
  assert.equal(result.subnetworkAddress, 'ab'); assert.equal(result.networkEntityTitle, '');
});
