import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectMrc} from '../dissectors/mrc.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {parsePcapng} from '../parser.js';
import {fixture} from './fixtures.js';

function packet(opcode, size) {
  const bytes = new Uint8Array(12 + size + 4), view = new DataView(bytes.buffer);
  bytes[0] = opcode; view.setUint16(2, 0xffff);
  bytes.set([0x12, 0x34, 0x56], 5); bytes.set([0xab, 0xcd, 0xef], 9);
  bytes.set([0xde, 0xad, 0xbe, 0xef], bytes.length - 4);
  return bytes;
}
function write(opcode = 0xcb, timestamp = true) {
  const immediate = [0xc9, 0xcb].includes(opcode);
  const bytes = packet(opcode, 4 + (timestamp ? 4 : 0) + 16 + (immediate ? 4 : 0) + 8);
  const view = new DataView(bytes.buffer);
  bytes[1] = 0x20; bytes[8] = 0xa0 | (timestamp ? 0x10 : 0);
  view.setUint16(12, 0x1234); view.setUint16(14, 0x5678);
  let p = 16;
  if (timestamp) {view.setUint16(p, 345); bytes[p + 3] = 1; p += 4;}
  view.setBigUint64(p, 0xfedcba9876543210n); view.setUint32(p + 8, 0x11223344); view.setUint32(p + 12, 1024); p += 16;
  if (immediate) {view.setUint32(p, 0x89abcdef); p += 4;}
  bytes.set([1, 2, 3, 4, 5, 6, 0, 0], p); return bytes;
}
function sack() {
  const bytes = packet(0xdc, 36), view = new DataView(bytes.buffer);
  bytes[13] = 0x22; view.setInt16(14, -2); view.setUint32(16, 0x12345678);
  view.setUint16(20, 0x1122); view.setUint16(22, 0x3344);
  bytes.set([0xff, 0xff, 0xff], 25); bytes[29] = 2; view.setInt16(30, 2);
  view.setBigUint64(32, 0x8000000000000001n);
  view.setUint16(40, 321); view.setUint16(42, 0x8007);
  bytes.set([0x85, 0, 0, 3], 44); return bytes;
}
function frame(payload, ipv6 = false, port = 4791) {
  const header = ipv6 ? 54 : 34, bytes = new Uint8Array(header + 8 + payload.length), view = new DataView(bytes.buffer);
  view.setUint16(12, ipv6 ? 0x86dd : 0x0800);
  if (ipv6) {bytes[14] = 0x60; view.setUint16(18, 8 + payload.length); bytes[20] = 17; bytes[37] = 1; bytes[53] = 2;}
  else {bytes[14] = 0x45; view.setUint16(16, bytes.length - 14); bytes[23] = 17;
    bytes.set([192, 0, 2, 1, 192, 0, 2, 2], 26);}
  view.setUint16(header, 50000); view.setUint16(header + 2, port); view.setUint16(header + 4, 8 + payload.length);
  bytes.set(payload, header + 8); return bytes;
}
function capture(bytes) {
  const size = 32 + Math.ceil(bytes.length / 4) * 4;
  const out = new Uint8Array(48 + size), view = new DataView(out.buffer);
  out.set(new Uint8Array(fixture().slice(0, 48)));
  view.setUint32(48, 6, true); view.setUint32(52, size, true);
  view.setUint32(68, bytes.length, true); view.setUint32(72, bytes.length, true);
  out.set(bytes, 76); view.setUint32(out.length - 4, size, true); return out.buffer;
}

test('MRC decodes all write opcodes with per-packet RETH, timestamps, immediate data and padding', () => {
  for (const opcode of [0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb]) {
    for (const timestamp of [false, true]) {
      const result = dissectMrc(write(opcode, timestamp));
      assert.equal(result.error, undefined);
      assert.equal(result.bth.destinationQp, 0x123456); assert.equal(result.bth.psn, 0xabcdef);
      assert.equal(result.bth.retransmission, true); assert.equal(result.bth.ackRequest, true);
      assert.deepEqual(result.meth, {receiveQueueMsn: 0x1234, msn: 0x5678});
      assert.equal(result.tseth?.txTimestamp, timestamp ? 345 : undefined);
      assert.equal(result.reth.virtualAddress, '0xfedcba9876543210'); assert.equal(result.reth.dmaLength, 1024);
      assert.equal(result.reth.remoteKey, 0x11223344);
      assert.equal(result.immediateData, [0xc9, 0xcb].includes(opcode) ? 0x89abcdef : undefined);
      assert.equal(result.payloadLength, 6); assert.equal(result.payloadPreview, '01 02 03 04 05 06');
      assert.equal(result.icrc, 'de ad be ef');
      assert.doesNotThrow(() => JSON.stringify(result));
    }
  }
});

test('MRC SACK decodes signed offsets, probe responses, bitmap and congestion state', () => {
  const bytes = sack(), result = dissectMrc(bytes);
  assert.equal(result.error, undefined);
  assert.equal(result.seth.pathFeedback, 1); assert.equal(result.seth.probeResponse, true);
  assert.equal(result.seth.probeId, 65534); assert.equal(result.seth.ackPsn, undefined);
  assert.equal(result.seth.sackBasePsn, 1); assert.equal(result.seth.sackBitmap, '0x8000000000000001');
  assert.equal(result.seth.maxPsnRange, 256); assert.equal(result.seth.sourceContext, 0x1122);
  assert.deepEqual(result.ccState, {txTimestamp: 321, outOfOrderCount: 7, restoreCwnd: true,
    receiverCwndPenalty: 5, receivedByteUnits: 3, receivedBytes: 768});
  bytes[13] = 0x40;
  assert.equal(dissectMrc(bytes).seth.ackPsn, 0xfffffd);
  bytes[28] = 0x90;
  assert.equal(dissectMrc(bytes).ccState.raw, '01 41 80 07 85 00 00 03');
});

test('MRC decodes ACK, NACK, reliability probes and endpoint requests/responses', () => {
  const ack = packet(0xd1, 4); ack.set([0x60, 0x12, 0x34, 0x56], 12);
  assert.deepEqual(dissectMrc(ack).aeth, {syndrome: 0x60, msn: 0x123456});
  const nack = packet(0xdd, 20), nv = new DataView(nack.buffer);
  nack[14] = 2; nack[15] = 99; nv.setUint32(16, 0x12345678); nv.setUint16(20, 11); nv.setUint16(22, 22);
  nack.set([0x12, 0x34, 0x56], 25); nack[28] = 0x20; nv.setUint16(30, 456);
  const n = dissectMrc(nack);
  assert.equal(n.error, undefined); assert.equal(n.neth.reasonName, 'TRIMMED_LASTHOP');
  assert.equal(n.neth.nackPsn, 0x123456); assert.equal(n.neth.txTimestamp, 456); assert.equal(n.neth.entropy, 0x12345678);
  const probe = packet(0xde, 16), pv = new DataView(probe.buffer);
  pv.setUint16(16, 789); pv.setUint16(20, 11); pv.setUint16(22, 22); pv.setUint16(24, 123); probe[26] = 128; probe[27] = 1;
  assert.deepEqual(dissectMrc(probe).peth, {vendorInfo: 0, probeId: 789, sourceContext: 11, destinationContext: 22,
    txTimestamp: 123, timestampResolution: 1, formatType: 1});
  const request = packet(0xd8, 16), rv = new DataView(request.buffer);
  request[13] = 1; rv.setUint32(16, 0x80000001); rv.setUint16(24, 123); request[27] = 1;
  const r = dissectMrc(request);
  assert.equal(r.error, undefined); assert.equal(r.erth.operationName, 'EV Probe'); assert.equal(r.erth.probeId, 0xcdef);
  assert.equal(r.erth.portStatusMask, 0x80000001);
  const response = packet(0xd9, 36); response[13] = 4; new DataView(response.buffer).setUint16(40, 234);
  const e = dissectMrc(response);
  assert.equal(e.error, undefined); assert.equal(e.eeth.operationName, 'EV Probe'); assert.equal(e.eeth.txTimestamp, 234);
});

test('MRC detects UDP opcodes on standard and custom ports without claiming ordinary RoCE', () => {
  for (const port of [4791, 4971, 12345]) {
    const decoded = {protocol: 'UDP', dport: port};
    applyDissectors(decoded, write(), loadDissectors());
    assert.equal(decoded.protocol, 'MRC'); assert.equal(decoded.transport, 'UDP');
  }
  for (const protocol of ['UDP', 'TCP']) {
    const decoded = {protocol, dport: 4791};
    const payload = write(); if (protocol === 'UDP') payload[0] = 0x0a;
    applyDissectors(decoded, payload, loadDissectors(['mrc']));
    assert.equal(decoded.application, undefined);
  }
});

test('MRC reports every truncated packet prefix, unsupported versions and opcodes', () => {
  for (const bytes of [write(), sack(), packet(0xd1, 4), packet(0xdd, 20), packet(0xde, 16), packet(0xd8, 16), packet(0xd9, 36)]) {
    // Writes may have a shorter captured payload with no external length hint;
    // all fixed headers, padding and the trailer must still fit.
    const minimum = bytes[0] === 0xcb ? bytes.length - 6 : bytes.length;
    for (let n = 0; n < minimum; n++) assert.match(dissectMrc(bytes.subarray(0, n)).error, /Truncated/, `opcode ${bytes[0]} prefix ${n}`);
  }
  const version = write(); version[1] |= 1;
  assert.match(dissectMrc(version).error, /version/);
  assert.match(dissectMrc(packet(0xc0, 4)).error, /opcode/);
  const malformed = {protocol: 'UDP', dport: 4791};
  applyDissectors(malformed, new Uint8Array([0xca]), loadDissectors(['mrc']));
  assert.match(malformed.application.error, /Truncated MRC BTH/);
});

test('capture parser enables MRC for IPv4/IPv6 and respects explicit selection', () => {
  for (const ipv6 of [false, true]) {
    const input = capture(frame(write(), ipv6));
    for (const dissectors of ['all', ['mrc']]) {
      const {packets, streams} = parsePcapng(input, {dissectors});
      assert.equal(packets[0].application.reth.dmaLength, 1024); assert.equal(packets[0].dport, 4791);
      assert.equal(packets[0].stream, null); assert.equal(streams.length, 0);
    }
    const result = parsePcapng(input, {dissectors: []});
    assert.equal(result.packets[0].protocol, 'UDP'); assert.equal(result.packets[0].application, undefined);
  }
});
