import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectRoce} from '../dissectors/roce.js';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {parsePcapng} from '../parser.js';
import {fixture} from './fixtures.js';

function bth(opcode, body = [], pad = 0) {
  const bytes = new Uint8Array(16 + body.length + pad), view = new DataView(bytes.buffer);
  bytes[0] = opcode; bytes[1] = 0xc0 | (pad << 4); view.setUint16(2, 0xffff);
  bytes[4] = 0xc0; bytes.set([0x12, 0x34, 0x56], 5); bytes[8] = 0x80; bytes.set([0xab, 0xcd, 0xef], 9);
  bytes.set(body, 12); bytes.set([0xde, 0xad, 0xbe, 0xef], bytes.length - 4); return bytes;
}
function reth() {
  const bytes = new Uint8Array(16), view = new DataView(bytes.buffer);
  view.setBigUint64(0, 0xfedcba9876543210n); view.setUint32(8, 0x11223344); view.setUint32(12, 1024); return bytes;
}
function grh(payload) {
  const bytes = new Uint8Array(40 + payload.length + 6), view = new DataView(bytes.buffer);
  view.setUint32(0, 0x62a12345); view.setUint16(4, payload.length); bytes[6] = 0x1b; bytes[7] = 64;
  bytes[23] = 1; bytes[39] = 2; bytes.set(payload, 40); return bytes;
}
function ethernet(payload, ethertype = 0x8915, link = 1, vlan = false) {
  const size = link === 113 ? 16 : link === 276 ? 20 : vlan ? 18 : 14;
  const bytes = new Uint8Array(size + payload.length), view = new DataView(bytes.buffer);
  if (link === 1) bytes.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  if (vlan) {view.setUint16(12, 0x8100); view.setUint16(14, 42);}
  view.setUint16(link === 276 ? 0 : size - 2, ethertype); bytes.set(payload, size); return bytes;
}
function ipUdp(payload, ipv6 = false) {
  const header = ipv6 ? 40 : 20, bytes = new Uint8Array(header + 8 + payload.length), view = new DataView(bytes.buffer);
  if (ipv6) {bytes[0] = 0x60; view.setUint16(4, 8 + payload.length); bytes[6] = 17; bytes[23] = 1; bytes[39] = 2;}
  else {bytes[0] = 0x45; view.setUint16(2, bytes.length); bytes[9] = 17; bytes.set([192, 0, 2, 1, 192, 0, 2, 2], 12);}
  view.setUint16(header, 50000); view.setUint16(header + 2, 4791); view.setUint16(header + 4, payload.length + 8);
  bytes.set(payload, header + 8); return ethernet(bytes, ipv6 ? 0x86dd : 0x0800);
}
function capture(bytes) {
  const size = 32 + Math.ceil(bytes.length / 4) * 4, out = new Uint8Array(48 + size), view = new DataView(out.buffer);
  out.set(new Uint8Array(fixture().slice(0, 48))); view.setUint32(48, 6, true); view.setUint32(52, size, true);
  view.setUint32(68, bytes.length, true); view.setUint32(72, bytes.length, true); out.set(bytes, 76);
  view.setUint32(out.length - 4, size, true); return out.buffer;
}

test('RoCE decodes write header stacks and excludes immediate data, padding and iCRC from payload', () => {
  for (const base of [0, 32]) {
    const result = dissectRoce(bth(base + 11, [...reth(), 0x89, 0xab, 0xcd, 0xef, 1, 2], 2));
    assert.equal(result.error, undefined); assert.equal(result.version, 2);
    assert.equal(result.transportType, base ? 'UC' : 'RC');
    assert.equal(result.bth.destinationQp, 0x123456); assert.equal(result.bth.psn, 0xabcdef);
    assert.equal(result.bth.forwardEcn, true); assert.equal(result.bth.backwardEcn, true);
    assert.equal(result.bth.ackRequest, true); assert.equal(result.bth.solicitedEvent, true);
    assert.equal(result.reth.virtualAddress, '0xfedcba9876543210'); assert.equal(result.reth.remoteKey, 0x11223344);
    assert.equal(result.reth.dmaLength, 1024); assert.equal(result.immediateData, 0x89abcdef);
    assert.equal(result.payloadLength, 2); assert.equal(result.payloadPreview, '01 02'); assert.equal(result.icrc, 'de ad be ef');
    assert.doesNotThrow(() => JSON.stringify(result));
    // Middle/last writes have no RETH, unlike MRC.
    assert.equal(dissectRoce(bth(base + 7, [1, 2, 3, 4])).payloadLength, 4);
    assert.equal(dissectRoce(bth(base + 8, [1, 2, 3, 4])).reth, undefined);
    assert.equal(dissectRoce(bth(base + 6, reth())).reth.dmaLength, 1024);
  }
});

test('RoCE handles reads, ACK syndromes, atomic requests/responses, UD and invalidate', () => {
  assert.equal(dissectRoce(bth(12, reth())).reth.dmaLength, 1024);
  for (const op of [13, 15, 16, 17]) {
    const result = dissectRoce(bth(op, [0x63, 1, 2, 3]));
    assert.equal(result.error, undefined); assert.deepEqual(result.aeth, {syndrome: 0x63, syndromeType: 3, syndromeValue: 3, msn: 0x010203});
  }
  assert.equal(dissectRoce(bth(14, [1, 2, 3, 4])).aeth, undefined);
  const atomicBody = new Uint8Array(28), av = new DataView(atomicBody.buffer);
  av.setBigUint64(0, 0x123456789abcdef0n); av.setUint32(8, 42); av.setBigUint64(12, 1n); av.setBigUint64(20, 2n);
  for (const op of [19, 20]) {
    const result = dissectRoce(bth(op, atomicBody));
    assert.equal(result.error, undefined); assert.equal(result.atomic.swapOrAdd, '0x0000000000000001');
    assert.equal(result.atomic.compare, '0x0000000000000002');
  }
  assert.equal(dissectRoce(bth(18, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7])).atomicAck.originalRemoteData, '0x0000000000000007');
  const ud = dissectRoce(bth(0x65, [0x80, 1, 2, 3, 0, 4, 5, 6, 0, 0, 0, 42, 9]));
  assert.equal(ud.error, undefined); assert.equal(ud.deth.sourceQp, 0x040506); assert.equal(ud.deth.queueKey, 0x80010203);
  assert.equal(ud.immediateData, 42); assert.equal(ud.payloadPreview, '09');
  assert.equal(dissectRoce(bth(0x17, [1, 2, 3, 4])).invalidateKey, 0x01020304);
  assert.equal(dissectRoce(bth(0x80, new Uint8Array(16))).name, 'Congestion Notification');
});

test('RoCEv1 decodes GRH on Ethernet, VLAN and cooked captures, ignoring Ethernet padding', () => {
  for (const [link, vlan] of [[1, false], [1, true], [113, false], [276, false]]) {
    const packet = decode(ethernet(grh(bth(4, [1, 2, 3, 4])), 0x8915, link, vlan), link);
    applyDissectors(packet, packet.payload, loadDissectors());
    assert.equal(packet.application.version, 1); assert.equal(packet.application.error, undefined);
    assert.equal(packet.application.grh.flowLabel, 0x12345); assert.equal(packet.application.grh.trafficClass, 42);
    assert.equal(packet.application.grh.sourceGid, '0:0:0:0:0:0:0:1');
    assert.equal(packet.application.payloadLength, 4);
    if (link === 1) assert.equal(packet.source, '06:07:08:09:0a:0b');
  }
});

test('RoCE reports truncated headers, malformed GRH, unknown opcodes and unsupported versions', () => {
  for (const [op, length] of [[11, 20], [17, 4], [19, 28], [18, 12], [0x65, 12], [0x80, 16]]) {
    const bytes = bth(op, new Uint8Array(length));
    for (let n = 0; n < bytes.length; n++) assert.match(dissectRoce(bytes.subarray(0, n)).error, /Truncated/);
  }
  const bytes = grh(bth(4));
  for (let n = 0; n < bytes.length - 6; n++) assert.match(dissectRoce(bytes.subarray(0, n), {protocol: 'RoCE'}).error, /Truncated/);
  bytes[6] = 17; assert.match(dissectRoce(bytes, {protocol: 'RoCE'}).error, /Invalid RoCE GRH/);
  const version = bth(4); version[1] |= 1; assert.match(dissectRoce(version).error, /version/);
  assert.match(dissectRoce(bth(0xe0)).error, /Unsupported RoCE opcode/);
  const preview = dissectRoce(bth(4, new Uint8Array(300)));
  assert.equal(preview.previewTruncated, true); assert.equal(preview.payloadPreview.split(' ').length, 256);
});

test('RoCE and MRC selections stay distinct and unrelated ports are left alone', () => {
  for (const names of ['all', ['roce', 'mrc']]) {
    const packet = {protocol: 'UDP', dport: 4791};
    applyDissectors(packet, bth(0xd1, [0, 0, 0, 0]), loadDissectors(names));
    assert.equal(packet.protocol, 'MRC');
  }
  for (const [protocol, dport, payload] of [['UDP', 4791, bth(0xd1, [0, 0, 0, 0])], ['UDP', 12345, bth(4)], ['TCP', 4791, bth(4)]]) {
    const packet = {protocol, dport}; applyDissectors(packet, payload, loadDissectors(['roce'])); assert.equal(packet.application, undefined);
  }
});

test('capture parser enables both RoCE versions and respects explicit selection, including VXLAN', () => {
  for (const frame of [ethernet(grh(bth(4, [1, 2, 3, 4]))), ipUdp(bth(4), false), ipUdp(bth(4), true)]) {
    const input = capture(frame);
    for (const dissectors of ['all', ['roce']]) {
      const {packets, streams} = parsePcapng(input, {dissectors});
      assert.equal(packets[0].application.dissector, 'roce'); assert.equal(packets[0].application.error, undefined);
      assert.equal(packets[0].stream, null); assert.equal(streams.length, 0);
    }
    assert.equal(parsePcapng(input, {dissectors: []}).packets[0].application, undefined);
    const tunnel = new Uint8Array(8 + frame.length); tunnel[0] = 8; tunnel[6] = 1; tunnel.set(frame, 8);
    const outer = {protocol: 'UDP', dport: 4789}; applyDissectors(outer, tunnel, loadDissectors());
    assert.equal(outer.application.inner.application.dissector, 'roce');
  }
});
