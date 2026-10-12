import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectLacp} from '../dissectors/lacp.js';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {parsePcapng} from '../parser.js';
import {fixture} from './fixtures.js';

function lacp() {
  const bytes = new Uint8Array(110), v = new DataView(bytes.buffer);
  bytes.set([1, 1]);
  for (const [offset, type, state] of [[2, 1, 0x3f], [22, 2, 0xc4]]) {
    bytes.set([type, 20], offset);
    v.setUint16(offset + 2, 32768);
    bytes.set([0, 17, 34, 51, 68, type], offset + 4);
    v.setUint16(offset + 10, 42); v.setUint16(offset + 12, 128);
    v.setUint16(offset + 14, 256 + type); bytes[offset + 16] = state;
  }
  bytes.set([3, 16, 0, 100], 42);
  return bytes;
}
function frame(payload, link = 1, vlan = false) {
  const header = link === 113 ? 16 : link === 276 ? 20 : vlan ? 18 : 14;
  const bytes = new Uint8Array(header + payload.length), view = new DataView(bytes.buffer);
  if (link === 1) {
    bytes.set([1, 128, 194, 0, 0, 2, 0, 17, 34, 51, 68, 85]);
    if (vlan) {view.setUint16(12, 0x8100); view.setUint16(14, 42);}
  }
  view.setUint16(link === 276 ? 0 : header - 2, 0x8809);
  bytes.set(payload, header); return bytes;
}
function capture(packet) {
  const size = 32 + Math.ceil(packet.length / 4) * 4;
  const out = new Uint8Array(48 + size), view = new DataView(out.buffer);
  out.set(new Uint8Array(fixture().slice(0, 48)));
  view.setUint32(48, 6, true); view.setUint32(52, size, true);
  view.setUint32(68, packet.length, true); view.setUint32(72, packet.length, true);
  out.set(packet, 76); view.setUint32(out.length - 4, size, true); return out.buffer;
}


test('LACP exposes actor, partner, all state bits and collector fields', () => {
  const result = dissectLacp(lacp());
  assert.equal(result.error, undefined);
  assert.equal(result.subtype, 1); assert.equal(result.version, 1);
  assert.equal(result.actor.system, '00:11:22:33:44:01');
  assert.equal(result.actor.systemPriority, 32768);
  assert.equal(result.actor.key, 42); assert.equal(result.actor.portPriority, 128);
  assert.equal(result.actor.port, 257); assert.equal(result.partner.port, 258);
  assert.deepEqual(result.actor.stateFlags, {activity: true, timeout: true, aggregation: true,
    synchronization: true, collecting: true, distributing: true, defaulted: false, expired: false});
  assert.equal(result.partner.stateFlags.defaulted, true);
  assert.equal(result.partner.stateFlags.expired, true);
  assert.equal(result.collector.maxDelay, 100);
  assert.deepEqual(result.tlvs.map(t => [t.type, t.length]), [[1, 20], [2, 20], [3, 16], [0, 0]]);
  assert.match(result.info, /Actor .* port 257 key 42.*Partner .* port 258 key 42/);
  const padded = lacp(); padded.fill(255, 60);
  assert.equal(dissectLacp(padded).error, undefined);
});

test('LACP decodes Ethernet, VLAN and cooked links while preserving MAC endpoints', () => {
  for (const [link, vlan] of [[1, false], [1, true], [113, false], [276, false]]) {
    const packet = decode(frame(lacp(), link, vlan), link);
    applyDissectors(packet, packet.payload, loadDissectors());
    assert.equal(packet.application.dissector, 'lacp');
    assert.equal(packet.application.actor.port, 257);
    if (link === 1) {
      assert.equal(packet.source, '00:11:22:33:44:55');
      assert.equal(packet.destination, '01:80:c2:00:00:02');
    }
  }
});

test('LACP reports truncated headers and TLVs and rejects invalid framing', () => {
  for (let n = 0; n < 60; n++) {
    const bytes = lacp().subarray(0, n);
    assert.match(dissectLacp(bytes).error, /Truncated LACP/, `prefix ${n}`);
    if (n) {
      const packet = decode(frame(bytes), 1);
      applyDissectors(packet, packet.payload, loadDissectors());
      assert.ok(packet.application.error);
    }
  }
  for (const [offset, value] of [[0, 2], [1, 2], [2, 2], [22, 1], [42, 0], [58, 3],
    [3, 0], [23, 19], [43, 17], [59, 2]]) {
    const bytes = lacp(); bytes[offset] = value;
    assert.ok(dissectLacp(bytes).error, `offset ${offset}`);
  }
  const backing = new Uint8Array(120); backing.set(lacp(), 5);
  assert.equal(dissectLacp(backing.subarray(5, 115)).actor.port, 257);
});

test('other Slow Protocols subtypes are not claimed as LACP', () => {
  for (const payload of [new Uint8Array(), new Uint8Array([2, 1]), new Uint8Array([3, 1])]) {
    const packet = decode(frame(payload), 1);
    applyDissectors(packet, packet.payload, loadDissectors());
    assert.equal(packet.protocol, 'Slow Protocols');
    assert.equal(packet.application, undefined);
  }
});

test('capture parsing enables LACP by default and respects explicit selection', () => {
  const input = capture(frame(lacp(), 1, true));
  for (const dissectors of ['all', ['lacp']]) {
    const {packets, streams} = parsePcapng(input, {dissectors});
    assert.equal(packets[0].application.actor.key, 42);
    assert.equal(packets[0].stream, null); assert.equal(streams.length, 0);
  }
  const packet = parsePcapng(input, {dissectors: []}).packets[0];
  assert.equal(packet.protocol, 'LACP'); assert.equal(packet.application, undefined);
});
