import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectLldp} from '../dissectors/lldp.js';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {parsePcapng} from '../parser.js';
import {fixture} from './fixtures.js';

const text = value => Array.from(new TextEncoder().encode(value));
const tlv = (type, value) => [(type << 1) | (value.length >>> 8), value.length & 255, ...value];
const mandatory = () => [...tlv(1, [4, 0, 17, 34, 51, 68, 85]), ...tlv(2, [5, ...text('eth0')]), ...tlv(3, [0, 120])];
const lldp = () => new Uint8Array([...mandatory(), ...tlv(4, text('Uplink')), ...tlv(5, text('switch1')),
  ...tlv(6, text('Test switch')), ...tlv(7, [0, 20, 0, 4]),
  ...tlv(8, [5, 1, 192, 0, 2, 1, 2, 0, 0, 0, 7, 0]),
  ...tlv(127, [0, 128, 194, 1, 0, 42]), ...tlv(9, [12, 34]), 0, 0]);
function frame(payload, link = 1, vlan = false) {
  const header = link === 113 ? 16 : link === 276 ? 20 : vlan ? 18 : 14;
  const bytes = new Uint8Array(header + payload.length), view = new DataView(bytes.buffer);
  if (link === 1) {
    bytes.set([1, 128, 194, 0, 0, 14, 0, 17, 34, 51, 68, 85]);
    if (vlan) {view.setUint16(12, 0x8100); view.setUint16(14, 42);}
  }
  view.setUint16(link === 276 ? 0 : header - 2, 0x88cc);
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

test('LLDP decodes standard TLVs and retains unknown and organizational values', () => {
  const result = dissectLldp(lldp());
  assert.equal(result.error, undefined);
  assert.deepEqual(result.chassisId, {subtype: 4, id: '00:11:22:33:44:55'});
  assert.deepEqual(result.portId, {subtype: 5, id: 'eth0'});
  assert.equal(result.ttl, 120);
  assert.equal(result.portDescription, 'Uplink');
  assert.equal(result.systemDescription, 'Test switch');
  assert.deepEqual(result.capabilities.supportedNames, ['Bridge', 'Router']);
  assert.deepEqual(result.capabilities.enabledNames, ['Bridge']);
  assert.equal(result.managementAddresses[0].address, '192.0.2.1');
  assert.equal(result.managementAddresses[0].interfaceNumber, 7);
  assert.equal(result.tlvs[8].oui, '00:80:c2');
  assert.equal(result.tlvs[8].data, '00:2a');
  assert.equal(result.tlvs[9].raw, '0c:22');
  assert.equal(result.info, 'switch1; Port=eth0; TTL=120s');
  assert.equal(dissectLldp(new Uint8Array([...lldp(), 0, 0, 255])).error, undefined);
});

test('LLDP supports network identifiers, IPv6 management addresses and shutdown TTL', () => {
  const ip = [32, 1, 13, 184, ...Array(11).fill(0), 1];
  const bytes = new Uint8Array([...tlv(1, [5, 1, 192, 0, 2, 1]), ...tlv(2, [3, 0, 17, 34, 51, 68, 85]),
    ...tlv(3, [0, 0]), ...tlv(8, [17, 2, ...ip, 1, 0, 0, 0, 0, 2, 43, 6]), 0, 0]);
  const result = dissectLldp(bytes);
  assert.equal(result.error, undefined);
  assert.equal(result.chassisId.id, '192.0.2.1');
  assert.equal(result.portId.id, '00:11:22:33:44:55');
  assert.equal(result.ttl, 0);
  assert.equal(result.managementAddresses[0].address, '2001:db8:0:0:0:0:0:1');
  assert.equal(result.managementAddresses[0].oid, '2b:06');
});

test('LLDP works over Ethernet, VLAN and Linux cooked links and preserves endpoints', () => {
  for (const [link, vlan] of [[1, false], [1, true], [113, false], [276, false]]) {
    const packet = decode(frame(lldp(), link, vlan), link);
    applyDissectors(packet, packet.payload, loadDissectors());
    assert.equal(packet.application.dissector, 'lldp');
    assert.equal(packet.application.systemName, 'switch1');
    if (link === 1) {
      assert.equal(packet.source, '00:11:22:33:44:55');
      assert.equal(packet.destination, '01:80:c2:00:00:0e');
    }
  }
});

test('LLDP reports truncation, invalid lengths and mandatory TLV errors without throwing', () => {
  const bytes = lldp();
  for (let n = 0; n < bytes.length; n++) {
    const packet = decode(frame(bytes.subarray(0, n)), 1);
    applyDissectors(packet, packet.payload, loadDissectors());
    assert.ok(packet.application.error, `prefix length ${n}`);
  }
  for (const value of [
    [...tlv(2, [5, 65]), 0, 0],
    [...tlv(1, [4, 1]), ...tlv(2, [5, 65]), ...tlv(3, [0, 1]), 0, 0],
    [...mandatory(), ...tlv(3, [0, 1]), 0, 0],
    [...mandatory(), ...tlv(7, [0]), 0, 0],
    [...mandatory(), ...tlv(8, [5, 1, 192, 0, 2, 1, 2, 0, 0, 0, 7, 5]), 0, 0],
    [...mandatory(), ...tlv(127, [0, 1]), 0, 0],
    [...mandatory(), ...tlv(0, [1])],
  ]) assert.ok(dissectLldp(new Uint8Array(value)).error);
});

test('capture parsing enables LLDP by default and respects explicit selection', () => {
  const input = capture(frame(lldp(), 1, true));
  for (const dissectors of ['all', ['lldp']]) {
    const {packets, streams} = parsePcapng(input, {dissectors});
    assert.equal(packets[0].application.systemName, 'switch1');
    assert.equal(packets[0].stream, null); assert.equal(streams.length, 0);
  }
  const packet = parsePcapng(input, {dissectors: []}).packets[0];
  assert.equal(packet.protocol, 'LLDP'); assert.equal(packet.application, undefined);
  assert.equal(packet.info, 'Link Layer Discovery');
});
