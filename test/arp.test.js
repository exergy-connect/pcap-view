import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectArp} from '../dissectors/arp.js';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {parsePcapng} from '../parser.js';
import {fixture} from './fixtures.js';

function arp(operation = 1) {
  const bytes = new Uint8Array(28), v = new DataView(bytes.buffer);
  v.setUint16(0, 1); v.setUint16(2, 0x0800); bytes[4] = 6; bytes[5] = 4; v.setUint16(6, operation);
  bytes.set([0, 17, 34, 51, 68, 85], 8); bytes.set([192, 0, 2, 1], 14);
  bytes.set([192, 0, 2, 2], 24);
  return bytes;
}
function frame(payload, link = 1, vlan = false) {
  const header = link === 113 ? 16 : link === 276 ? 20 : vlan ? 18 : 14;
  const bytes = new Uint8Array(header + payload.length), v = new DataView(bytes.buffer);
  if (vlan) {v.setUint16(12, 0x8100); v.setUint16(14, 42); v.setUint16(16, 0x0806);}
  else v.setUint16(link === 276 ? 0 : header - 2, 0x0806);
  bytes.set(payload, header); return bytes;
}
function capture(packet) {
  const size = 32 + Math.ceil(packet.length / 4) * 4;
  const out = new Uint8Array(48 + size), v = new DataView(out.buffer);
  out.set(new Uint8Array(fixture().slice(0, 48)));
  v.setUint32(48, 6, true); v.setUint32(52, size, true);
  v.setUint32(68, packet.length, true); v.setUint32(72, packet.length, true);
  out.set(packet, 76); v.setUint32(out.length - 4, size, true); return out.buffer;
}

test('ARP requests and replies expose addresses and useful summaries', () => {
  const request = dissectArp(arp());
  assert.equal(request.hardwareType, 1); assert.equal(request.protocolType, 0x0800);
  assert.equal(request.senderHardwareAddress, '00:11:22:33:44:55');
  assert.equal(request.senderProtocolAddress, '192.0.2.1');
  assert.equal(request.targetProtocolAddress, '192.0.2.2');
  assert.equal(request.info, 'Who has 192.0.2.2? Tell 192.0.2.1');
  assert.equal(dissectArp(arp(2)).info, '192.0.2.1 is at 00:11:22:33:44:55');
  assert.equal(dissectArp(arp(99)).operationName, 'Unknown operation 99');
});

test('ARP supports declared variable address lengths and unknown protocol types', () => {
  const bytes = new Uint8Array([0, 15, 0x12, 0x34, 2, 3, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const result = dissectArp(bytes);
  assert.equal(result.senderHardwareAddress, '01:02');
  assert.equal(result.senderProtocolAddress, '03:04:05');
  assert.equal(result.targetProtocolAddress, '08:09:0a');
});

test('ARP handles Ethernet, VLAN and Linux cooked capture links', () => {
  for (const [link, vlan] of [[1, false], [1, true], [113, false], [276, false]]) {
    const packet = decode(frame(arp(), link, vlan), link);
    applyDissectors(packet, packet.payload, loadDissectors());
    assert.equal(packet.source, '192.0.2.1');
    assert.equal(packet.destination, '192.0.2.2');
    assert.equal(packet.application.dissector, 'arp');
    assert.equal(packet.application.operation, 1);
  }
});

test('ARP reports every truncation and invalid zero lengths without throwing', () => {
  for (let n = 0; n < 28; n++) {
    const packet = decode(frame(arp().subarray(0, n)), 1);
    applyDissectors(packet, packet.payload, loadDissectors());
    assert.match(packet.application.error, /Truncated ARP/);
  }
  const bytes = arp(); bytes[4] = 0;
  assert.match(dissectArp(bytes).error, /Invalid ARP address length/);
});

test('capture parsing enables ARP by default and respects explicit selection', () => {
  const input = capture(frame(arp(), 1, true));
  for (const dissectors of ['all', ['arp']]) {
    const {packets, streams} = parsePcapng(input, {dissectors});
    assert.equal(packets[0].application.operationName, 'Request');
    assert.equal(packets[0].source, '192.0.2.1');
    assert.equal(packets[0].stream, null); assert.equal(streams.length, 0);
  }
  const packet = parsePcapng(input, {dissectors: []}).packets[0];
  assert.equal(packet.protocol, 'ARP'); assert.equal(packet.application, undefined);
  assert.equal(packet.info, 'Address resolution');
});
