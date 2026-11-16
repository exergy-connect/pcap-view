import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectMnh} from '../dissectors/bgp-mnh.js';
import {dissectBgp} from '../dissectors/bgp.js';
import {dissectBmp} from '../dissectors/bmp.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';

const u16 = n => [n >>> 8, n & 255];
const u32 = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const fa = (flags, type, value) => [flags, ...u16(type), ...u16(value.length), ...value];
const instruction = (flags, preference, action, args) => [flags, ...u16(preference), action, ...u16(args.length), ...args];
const nfi = (flags, instructions) => [flags, ...u16(instructions.length), ...instructions.flat()];
const mnhTlv = (flags, type, value) => [flags, type, ...u16(value.length), ...value];
const label = (value, trafficClass, bottom) => {
  const word = (value << 4) | (trafficClass << 1) | bottom;
  return [(word >>> 16) & 255, (word >>> 8) & 255, word & 255];
};
const sid = [32,1,13,184,0,1,0,2,0,0,0,0,0,0,0,5];
const sidTlv = [1, 0, 30, 7, ...sid, 0x80, 0, 19, 9, 1, 0, 6, 32, 32, 16, 0, 16, 64];
function update(value, extended = false) {
  const attr = extended
    ? [0x90, 255, value.length >>> 8, value.length & 255, ...value]
    : [0x80, 255, value.length, ...value];
  const attrs = [...attr, 64, 5, 4, 0, 0, 0, 100];
  const bytes = new Uint8Array(23 + attrs.length), view = new DataView(bytes.buffer);
  bytes.fill(255, 0, 16); view.setUint16(16, bytes.length); bytes[18] = 2;
  view.setUint16(21, attrs.length); bytes.set(attrs, 23); return bytes;
}

test('MNH decodes primary and backup paths with endpoints, constraints and encapsulation', () => {
  const primaryArgs = [
    ...fa(0x07, 1, [1, 4, 192, 0, 2, 1]),
    ...fa(0, 1, [2, 16, 32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    ...fa(0, 1, [3, 4, ...u32(100)]),
    ...fa(0, 1, [4, 8, 0, 0, 0xfd, 0xe8, 0, 0, 0x27, 0x1a]),
    ...fa(0, 1, [5, 8, 0, 1, 192, 0, 2, 1, 0, 10]),
    ...fa(0, 2, [1, 2, 0xc0, 0]),
    ...fa(0, 2, [2, 4, ...u32(70)]),
    ...fa(0, 2, [3, 2, 0, 60]),
    ...fa(0, 3, [1, ...u16(2 + 6), 0x80, 0, ...label(100, 1, 0), ...label(200, 0, 1)]),
    ...fa(0, 3, [2, ...u16(7), 3, 0x12, 0x34, ...u32(42)]),
    ...fa(0, 3, [3, ...u16(sidTlv.length), ...sidTlv]),
    ...fa(0, 3, [4, ...u16(1), 185]),
    ...fa(0x06, 4, [1, 8, 0, 0, 0, 2, 0x54, 0x0b, 0xe4, 0]),
    ...fa(0x06, 4, [2, 0, 4, ...u32(15)]),
    ...fa(0, 4, [2, 1, 4, ...u32(250)]),
    ...fa(0, 99, [9, 9]),
  ];
  const backup = fa(0, 1, [1, 4, 192, 0, 2, 9]);
  const value = [1, 192, 0, 2, 7,
    ...mnhTlv(1, 1, nfi(1, [instruction(1, 10, 1, primaryArgs), instruction(0, 20, 2, [])])),
    ...mnhTlv(0, 2, nfi(1, [instruction(1, 30, 6, backup)])),
    ...mnhTlv(0, 9, nfi(0, [instruction(0, 1, 0, fa(0, 0, [1, 2]))]))];
  const packet = update(value, true);
  const storage = new Uint8Array(packet.length + 5);
  storage.set(packet, 5);
  const message = dissectBgp(storage.subarray(5));
  assert.equal(message.error, undefined);
  const attr = message.pathAttributes[0];
  assert.equal(attr.name, 'MULTI_NEXT_HOP');
  assert.equal(attr.flags.optional, true);
  assert.equal(attr.flags.transitive, false);
  assert.equal(attr.flags.extendedLength, true);
  assert.equal(attr.mnhFlags, 1);
  assert.equal(attr.version, 0);
  assert.equal(attr.mandatory, true);
  assert.equal(attr.routerId, '192.0.2.7');
  const primary = attr.tlvs[0];
  assert.equal(primary.name, 'Primary forwarding path');
  assert.equal(primary.nfi.numNexthops, 2);
  assert.equal(primary.nfi.mandatory, true);
  const forward = primary.nfi.instructions[0];
  assert.equal(forward.actionName, 'Forward');
  assert.equal(forward.preference, 10);
  assert.equal(forward.arguments[0].address, '192.0.2.1');
  assert.equal(forward.arguments[0].cumulative, true);
  assert.equal(forward.arguments[0].egress, true);
  assert.equal(forward.arguments[1].address, '2001:db8:0:0:0:0:0:1');
  assert.equal(forward.arguments[2].label, 100);
  assert.equal(forward.arguments[2].value, 100);
  assert.equal(forward.arguments[3].routeDistinguisher, '65000:10010');
  assert.equal(forward.arguments[4].routeTarget, '192.0.2.1:10');
  assert.equal(forward.arguments[5].singleHop, true);
  assert.equal(forward.arguments[5].multiHop, true);
  assert.equal(forward.arguments[6].transportClass, 70);
  assert.equal(forward.arguments[7].balancePercentage, 60);
  assert.equal(forward.arguments[8].entropyLabelCapable, true);
  assert.deepEqual(forward.arguments[8].labels, [
    {label: 100, trafficClass: 1, bottomOfStack: false},
    {label: 200, trafficClass: 0, bottomOfStack: true}]);
  assert.equal(forward.arguments[9].labelIndex, 42);
  assert.equal(forward.arguments[9].labelIndexFlags, 0x1234);
  assert.equal(forward.arguments[9].reserved, 3);
  const sidInfo = forward.arguments[10].sids[0];
  assert.equal(sidInfo.sid, '2001:db8:1:2:0:0:0:5');
  assert.equal(sidInfo.endpointBehaviorName, 'End.DT4');
  assert.equal(sidInfo.flags, 128);
  assert.equal(sidInfo.reserved1, 7);
  assert.equal(sidInfo.reserved2, 9);
  assert.equal(sidInfo.subTlvs[0].locatorBlockLength, 32);
  assert.equal(sidInfo.subTlvs[0].transpositionOffset, 64);
  assert.equal(forward.arguments[11].dscp, 46);
  assert.equal(forward.arguments[11].ecn, 1);
  assert.equal(forward.arguments[12].bandwidth, '10000000000');
  assert.equal(forward.arguments[13].metricTypeName, 'IGP Metric');
  assert.equal(forward.arguments[13].metric, 15);
  assert.equal(forward.arguments[14].metricTypeName, 'Min Unidirectional Link Delay');
  assert.equal(forward.arguments[14].metric, 250);
  assert.equal(forward.arguments[15].name, 'Unknown Forwarding Argument 99');
  assert.equal(forward.arguments[15].raw, '09 09');
  assert.equal(primary.nfi.instructions[1].actionName, 'Pop-And-Forward');
  assert.deepEqual(primary.nfi.instructions[1].arguments, []);
  assert.equal(attr.tlvs[1].name, 'Backup forwarding path');
  assert.equal(attr.tlvs[1].nfi.instructions[0].actionName, 'Replicate');
  assert.equal(attr.tlvs[1].nfi.instructions[0].arguments[0].address, '192.0.2.9');
  assert.equal(attr.tlvs[2].name, 'Unknown MNH TLV 9');
  assert.equal(attr.tlvs[2].nfi.instructions[0].actionName, 'Reserved');
  assert.equal(attr.tlvs[2].nfi.instructions[0].arguments[0].name, 'Reserved');
  assert.equal(message.pathAttributes[1].value, 100);
  assert.doesNotThrow(() => JSON.stringify(message));
});

test('MNH works in split TCP updates and embedded BMP, including extended length', () => {
  const endpoint = fa(1, 1, [1, 4, 203, 0, 113, 1]);
  const value = [0, 10, 0, 0, 1, ...mnhTlv(1, 1, nfi(1, [instruction(1, 1, 4, [...endpoint, ...fa(0, 99, new Array(230).fill(0))])]))];
  const bytes = update(value, true);
  const contexts = new Map(), dissectors = loadDissectors(['bgp']);
  applyDissectors({protocol: 'TCP', dport: 179, sequence: 100}, bytes.subarray(0, 40), dissectors, contexts);
  const next = {protocol: 'TCP', dport: 179, sequence: 140};
  applyDissectors(next, bytes.subarray(40), dissectors, contexts);
  const decoded = next.application.messages[0].pathAttributes[0];
  assert.equal(next.application.error, undefined);
  assert.equal(decoded.flags.extendedLength, true);
  assert.equal(decoded.tlvs[0].nfi.instructions[0].actionName, 'Push');
  assert.equal(decoded.tlvs[0].nfi.instructions[0].arguments[0].address, '203.0.113.1');
  const bmp = new Uint8Array(48 + bytes.length), view = new DataView(bmp.buffer);
  bmp[0] = 3; view.setUint32(1, bmp.length); bmp.set(bytes, 48);
  const embedded = dissectBmp(bmp).messages[0].bgp;
  assert.equal(embedded.error, undefined);
  assert.equal(embedded.pathAttributes[0].routerId, '10.0.0.1');
  assert.equal(embedded.pathAttributes[0].mandatory, false);
});

test('MNH reports unsupported versions and nested length errors without dropping later attributes', () => {
  const header = [0x40, 192, 0, 2, 1, ...mnhTlv(1, 1, nfi(1, [instruction(1, 1, 1, [])]))];
  const unsupported = dissectBgp(update(header));
  assert.match(unsupported.error, /Unsupported MNH version 1/);
  assert.equal(unsupported.pathAttributes[0].routerId, '192.0.2.1');
  assert.deepEqual(unsupported.pathAttributes[0].tlvs, []);
  assert.equal(unsupported.pathAttributes[1].value, 100);
  const endpoint = [1, 4, 192, 0, 2, 1];
  const malformed = [
    [], [0x40], [1, 2, 3, 4],
    [0, 192, 0, 2, 1, 1],
    [0, 192, 0, 2, 1, ...mnhTlv(1, 1, [1, 0, 0])],
    [0, 192, 0, 2, 1, ...mnhTlv(1, 1, nfi(1, [instruction(1, 1, 1, [1])]))],
    [0, 192, 0, 2, 1, ...mnhTlv(1, 1, nfi(1, [instruction(1, 1, 1, fa(0, 1, [1, 3, 192, 0, 2]))]))],
    [0, 192, 0, 2, 1, ...mnhTlv(1, 1, nfi(1, [instruction(1, 1, 1, fa(0, 3, [2, 0, 1, 0]))]))],
    [0, 192, 0, 2, 1, ...mnhTlv(1, 1, nfi(1, [instruction(1, 1, 1, fa(0, 3, [1, 0, 3, 0, 0, 0]))]))],
    [0, 192, 0, 2, 1, ...mnhTlv(1, 1, nfi(1, [instruction(1, 1, 1, fa(0, 4, [1, 4, 0, 0, 0, 0]))]))],
    [0, 192, 0, 2, 1, ...mnhTlv(1, 1, nfi(1, [instruction(1, 1, 1, fa(0, 4, [2, 0, 2, 0, 1]))]))],
    [0, 192, 0, 2, 1, ...mnhTlv(0, 1, [1, 0, 1, 1, 0, 1, 0, 0, 0xff])],
  ];
  for (const value of malformed) {
    const message = dissectBgp(update(value));
    assert.match(message.error, /MNH/);
    assert.match(message.pathAttributes[0].error, /MNH/);
    assert.equal(message.pathAttributes[1].value, 100);
    assert.ok(message.pathAttributes[0].raw.length || value.length === 0);
  }
  const direct = [0, 192, 0, 2, 1, ...mnhTlv(1, 1, nfi(1, [instruction(1, 1, 1, fa(0, 1, endpoint))]))];
  for (let n = 1; n < direct.length; n++) {
    const parsed = dissectMnh(new Uint8Array(direct.slice(0, n)));
    if (n === 5) assert.equal(parsed.error, undefined);
    else assert.match(parsed.error, /Truncated MNH/);
  }
});
