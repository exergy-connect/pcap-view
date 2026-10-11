import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectIcmp} from '../dissectors/icmp.js';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {parsePcapng} from '../parser.js';
import {fixture} from './fixtures.js';

function frame(payload, version = 4, extension = false) {
  const header = version === 4 ? 20 : 40 + (extension ? 8 : 0);
  const bytes = new Uint8Array(14 + header + payload.length + 8), v = new DataView(bytes.buffer);
  v.setUint16(12, version === 4 ? 0x0800 : 0x86dd);
  bytes[14] = version === 4 ? 0x45 : 0x60;
  if (version === 4) {
    v.setUint16(16, header + payload.length); bytes[23] = 1;
    bytes.set([192, 0, 2, 1], 26); bytes.set([192, 0, 2, 2], 30);
  } else {
    v.setUint16(18, header - 40 + payload.length); bytes[20] = extension ? 0 : 58;
    if (extension) bytes[54] = 58;
  }
  bytes.set(payload, 14 + header); return bytes;
}
function capture(packet) {
  const size = 32 + Math.ceil(packet.length / 4) * 4;
  const bytes = new Uint8Array(48 + size), v = new DataView(bytes.buffer);
  bytes.set(new Uint8Array(fixture().slice(0, 48)));
  v.setUint32(48, 6, true); v.setUint32(52, size, true);
  v.setUint32(68, packet.length, true); v.setUint32(72, packet.length, true);
  bytes.set(packet, 76); v.setUint32(bytes.length - 4, size, true); return bytes.buffer;
}

test('ICMP echo decoding supports both versions and preserves endpoints', () => {
  for (const [version, types] of [[4, [8, 0]], [6, [128, 129]]]) {
    for (const type of types) {
      const payload = new Uint8Array([type, 0, 0xab, 0xcd, 0x12, 0x34, 0, 7, 42]);
      const packet = decode(frame(payload, version, version === 6), 1);
      const endpoints = [packet.source, packet.destination];
      assert.deepEqual(packet.payload, payload); // excludes Ethernet padding
      applyDissectors(packet, packet.payload, loadDissectors());
      assert.equal(packet.application.identifier, 0x1234);
      assert.equal(packet.application.sequence, 7);
      assert.equal(packet.application.checksum, 0xabcd);
      assert.equal(packet.application.data, '2a');
      assert.equal(packet.application.version, version);
      assert.deepEqual([packet.source, packet.destination], endpoints);
      assert.match(packet.info, /Echo (request|reply) id=4660 seq=7/);
    }
  }
});

test('ICMP error messages expose codes, MTUs, pointers, gateways and quotes', () => {
  const unreachable = dissectIcmp(new Uint8Array([3, 3, 0, 0, 0, 0, 0, 0, 0x45]));
  assert.equal(unreachable.codeName, 'Port unreachable');
  assert.equal(unreachable.quotedPacket, '45');
  assert.equal(dissectIcmp(new Uint8Array([3, 4, 0, 0, 0, 0, 5, 220])).mtu, 1500);
  assert.equal(dissectIcmp(new Uint8Array([2, 0, 0, 0, 0, 1, 0, 0]), {protocol: 'ICMPv6'}).mtu, 65536);
  assert.equal(dissectIcmp(new Uint8Array([12, 0, 0, 0, 19, 0, 0, 0])).pointer, 19);
  assert.equal(dissectIcmp(new Uint8Array([4, 0, 0, 0, 0, 0, 1, 0]), {protocol: 'ICMPv6'}).pointer, 256);
  assert.equal(dissectIcmp(new Uint8Array([5, 1, 0, 0, 192, 0, 2, 9])).gateway, '192.0.2.9');
});

test('ICMP timestamps, masks, unknown messages and bounded previews remain inspectable', () => {
  const timestamp = new Uint8Array(20), v = new DataView(timestamp.buffer);
  timestamp[0] = 14; v.setUint32(8, 123); v.setUint32(12, 456); v.setUint32(16, 789);
  const result = dissectIcmp(timestamp);
  assert.equal(result.originateTimestamp, 123); assert.equal(result.receiveTimestamp, 456);
  assert.equal(result.transmitTimestamp, 789);
  assert.equal(dissectIcmp(new Uint8Array([18, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0])).addressMask, '255.255.255.0');
  const unknown = new Uint8Array(400); unknown[0] = 255; unknown[1] = 99;
  const decoded = dissectIcmp(unknown);
  assert.equal(decoded.typeName, 'Unknown type 255'); assert.equal(decoded.codeName, 'Unknown code 99');
  assert.equal(decoded.dataLength, 396); assert.equal(decoded.data.length, 512);
  assert.equal(decoded.previewTruncated, true);
});

test('all fixed-header truncations report errors, including empty payloads', () => {
  for (const [version, type, length] of [[4, 8, 8], [4, 3, 8], [4, 13, 20], [4, 17, 12], [6, 128, 8], [6, 2, 8]]) {
    const payload = new Uint8Array(length); payload[0] = type;
    for (let n = 0; n < length; n++) {
      const packet = decode(frame(payload.subarray(0, n), version), 1);
      applyDissectors(packet, packet.payload, loadDissectors(['icmp']));
      assert.match(packet.application.error, /Truncated ICMP/);
    }
  }
});

test('capture parsing enables ICMP by default and respects explicit selection', () => {
  const input = capture(frame(new Uint8Array([8, 0, 0, 0, 0, 1, 0, 2])));
  for (const dissectors of ['all', ['icmp']]) {
    const {packets, streams} = parsePcapng(input, {dissectors});
    assert.equal(packets[0].application.dissector, 'icmp');
    assert.equal(packets[0].application.sequence, 2);
    assert.equal(packets[0].stream, null); assert.equal(streams.length, 0);
  }
  const packet = parsePcapng(input, {dissectors: []}).packets[0];
  assert.equal(packet.protocol, 'ICMP'); assert.equal(packet.application, undefined);
  assert.equal(packet.info, 'IP protocol 1');
});
