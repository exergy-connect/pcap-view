import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectUet} from '../dissectors/uet.js';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';

function native(type = 2, nh = 1, flags = 0) {
  const pdsSize = {2: 12, 3: 12, 4: 8, 5: 8, 6: 4, 7: 12, 8: 32, 9: 40, 10: 16, 11: 16, 12: 32, 13: 16, 14: 16}[type];
  const sesSize = type === 11 ? 0 : [0, 20, 32, 44, 12, 20, 12][nh];
  const b = new Uint8Array(4 + pdsSize + sesSize + 3 + 4), v = new DataView(b.buffer);
  v.setUint16(0, 0x1234); v.setUint16(4, (type << 11) | (nh << 7) | flags);
  if ([2, 3, 13, 14].includes(type)) {v.setInt16(6, -2); v.setUint32(8, 100); v.setUint16(12, 42); v.setUint16(14, 17);}
  if (sesSize) {const p = 4 + pdsSize; b[p] = 5; b[p + 1] = 3; v.setUint16(p + 2, 3); b[p + 7] = 9;}
  b.set([0xaa, 0xbb, 0xcc], b.length - 7); b.set([1, 2, 3, 4], b.length - 4);
  return b;
}
function ip(payload, version, extension = false) {
  const size = version === 4 ? 20 : extension ? 48 : 40;
  const b = new Uint8Array(size + payload.length), v = new DataView(b.buffer);
  b[0] = version === 4 ? 0x45 : 0x60;
  if (version === 4) {v.setUint16(2, b.length); b[9] = 253; b.set([192, 0, 2, 1, 192, 0, 2, 2], 12);}
  else {v.setUint16(4, b.length - 40); b[6] = extension ? 60 : 253; if (extension) b[40] = 253;}
  b.set(payload, size); return b;
}

test('native UET decodes IPv4, IPv6 and extension headers with default/explicit selection', () => {
  for (const [version, extension] of [[4, false], [6, false], [6, true]]) {
    for (const selection of ['all', ['uet']]) {
      const packet = decode(ip(native(), version, extension), 101);
      const source = packet.source;
      applyDissectors(packet, packet.payload, loadDissectors(selection));
      assert.equal(packet.protocol, 'UET'); assert.equal(packet.source, source);
      const a = packet.application;
      assert.equal(a.dissector, 'uet'); assert.equal(a.error, undefined);
      assert.equal(a.entropy, 0x1234); assert.equal(a.pds.psn, 100); assert.equal(a.pds.clearPsn, 98);
      assert.equal(a.pds.sourcePdcId, 42); assert.equal(a.pds.destinationPdcId, 17);
      assert.equal(a.ses.name, 'Send'); assert.equal(a.ses.jobId, 9); assert.equal(a.payloadLength, 3);
      assert.equal(a.payloadPreview, 'aa bb cc'); assert.equal(a.crc, '01 02 03 04');
    }
    const packet = decode(ip(native(), version, extension), 101);
    applyDissectors(packet, packet.payload, loadDissectors([])); assert.equal(packet.application, undefined);
  }
});
test('PDS variants and SES formats consume the correct header lengths', () => {
  for (const type of [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]) {
    for (let nh = 0; nh <= 6; nh++) {
      const a = dissectUet(native(type, nh));
      assert.equal(a.error, undefined, `${type}/${nh}`); assert.equal(a.payloadLength, 3, `${type}/${nh}`);
    }
  }
  const syn = dissectUet(native(2, 0, 4));
  assert.equal(syn.pds.startPsn, 83); assert.equal(syn.pds.destinationPdcId, undefined);
});
test('all truncated prefixes report errors without throwing', () => {
  const b = native(13, 3);
  // Three bytes of data are optional; header and CRC truncation must fail.
  for (let n = 0; n < b.length - 3; n++) assert.ok(dissectUet(b.subarray(0, n)).error, `prefix ${n}`);
  const packet = decode(ip(new Uint8Array(), 4), 101);
  applyDissectors(packet, packet.payload, loadDissectors(['uet']));
  assert.match(packet.application.error, /entropy/);
});
test('unsupported formats retain raw bytes and unrelated protocols do not match', () => {
  const b = native(); b[4] = 0xf8;
  assert.match(dissectUet(b).error, /PDS type/); assert.ok(dissectUet(b).raw);
  const secure = native(); secure[4] = 8; secure[5] = 0;
  assert.match(dissectUet(secure).error, /secure transport/);
  const extended = native(); extended[16] = 3;
  assert.match(dissectUet(extended).error, /SES extension/);
  for (const protocol of ['TCP', 'IPv4']) {
    const packet = {protocol, dport: 4793}; applyDissectors(packet, native(), loadDissectors(['uet']));
    assert.equal(packet.application, undefined);
  }
});

test('UDP UET decodes both IP versions, preserving ports and UDP transport details', () => {
  for (const [version, extension] of [[4, false], [6, false], [6, true]]) {
    const payload = native().subarray(4);
    const udp = new Uint8Array(8 + payload.length), v = new DataView(udp.buffer);
    v.setUint16(0, 12345); v.setUint16(2, 4793); v.setUint16(4, udp.length); udp.set(payload, 8);
    const b = ip(udp, version, extension);
    b[version === 4 ? 9 : extension ? 40 : 6] = 17;
    for (const selection of ['all', ['uet']]) {
      const packet = decode(b, 101), source = packet.source;
      applyDissectors(packet, packet.payload, loadDissectors(selection));
      assert.equal(packet.protocol, 'UET'); assert.equal(packet.transport, 'UDP');
      assert.equal(packet.sport, 12345); assert.equal(packet.dport, 4793); assert.equal(packet.source, source);
      assert.equal(packet.application.encapsulation, 'udp'); assert.equal(packet.application.entropy, undefined);
      assert.equal(packet.application.pds.psn, 100); assert.equal(packet.application.ses.name, 'Send');
      assert.equal(packet.application.payloadPreview, 'aa bb cc'); assert.equal(packet.application.error, undefined);
      if (selection === 'all') assert.equal(packet.transportDetails.dissector, 'udp');
    }
    const disabled = decode(b, 101); applyDissectors(disabled, disabled.payload, loadDissectors([]));
    assert.equal(disabled.protocol, 'UDP'); assert.equal(disabled.application, undefined);
  }
});
test('UDP UET handles all PDS/SES variants and truncated headers', () => {
  for (const type of [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]) {
    for (let nh = 0; nh <= 6; nh++) {
      const a = dissectUet(native(type, nh).subarray(4), {protocol: 'UDP'});
      assert.equal(a.error, undefined, `${type}/${nh}`); assert.equal(a.payloadLength, 3);
    }
  }
  const b = native(13, 3).subarray(4);
  for (let n = 0; n < b.length - 3; n++) {
    const packet = {protocol: 'UDP', dport: 4793};
    applyDissectors(packet, b.subarray(0, n), loadDissectors(['uet']));
    assert.ok(packet.application.error, `prefix ${n}`);
  }
  for (const packet of [{protocol: 'UDP', dport: 4794}, {protocol: 'UDP', sport: 4793, dport: 12345}]) {
    applyDissectors(packet, b, loadDissectors(['uet'])); assert.equal(packet.application, undefined);
  }
});
