import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectFalcon} from '../dissectors/falcon.js';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';

// Literal network-order base header from the section 7 bit positions:
// v1, CID 0x123456, function 0xabcdef, RDMA, Push Data, AR, window bases, PSN, RSN.
const base = Uint8Array.from(Buffer.from('10123456abcdef4b0102030480000001ffffffff12345678', 'hex'));
function packet(type, payload = new Uint8Array()) {
  const size = {0: 32, 3: 24, 5: 28, 6: 32, 8: 40, 9: 32, 10: 72}[type];
  const b = new Uint8Array(size + payload.length), v = new DataView(b.buffer);
  b.set(base); b[7] = type < 8 ? 0x40 | (type << 1) | 1 : type << 1;
  if (type >= 8) b.fill(0, 4, 7);
  if (type === 0 || type === 5) v.setUint16(26, type === 0 ? 4096 : payload.length);
  if (type === 6) {b[24] = 4; b[25] = 0x50; v.setUint32(28, 0xdeadbeef);}
  if (type >= 8) {
    const offset = type === 8 ? 20 : 16;
    v.setUint32(offset, 123); v.setUint32(offset + 4, 456);
    // Hop count=9, occupancy=17, ECN count=0x2345; RUE=0x234567.
    v.setUint32(offset + 8, 0x98c68a00); v.setUint32(offset + 12, 0x008d159f);
    if (type === 8) {b[36] = 2; b[37] = 0x21; b[39] = 0x81;}
    if (type === 10) for (let i = 32; i < 72; i++) b[i] = i;
  }
  b.set(payload, size); return b;
}
function psp(payload, version = 2, cryptWords = 0, vc = false) {
  const headerLength = vc ? 24 : 16, b = new Uint8Array(headerLength + payload.length + 16);
  b.set([252, vc ? 2 : 1, cryptWords, (version << 2) | (vc ? 2 : 0) | 1]);
  b.set([0x12, 0x34, 0x56, 0x78], 4); b[15] = 3;
  if (vc) b.fill(0xab, 16, 24);
  b.set(payload, headerLength); b.fill(0xcd, b.length - 16); return b;
}
function ip(payload, version, udp = false, extension = false, port = 1000) {
  const offset = version === 4 ? 20 : extension ? 48 : 40;
  const b = new Uint8Array(offset + (udp ? 8 : 0) + payload.length), v = new DataView(b.buffer);
  const protocol = udp ? 17 : 252;
  b[0] = version === 4 ? 0x45 : 0x60;
  if (version === 4) {v.setUint16(2, b.length); b[9] = protocol; b.set([192, 0, 2, 1, 192, 0, 2, 2], 12);}
  else {v.setUint16(4, b.length - 40); b[6] = extension ? 60 : protocol; if (extension) b[40] = protocol;}
  if (udp) {v.setUint16(offset, 50000); v.setUint16(offset + 2, port); v.setUint16(offset + 4, payload.length + 8);}
  b.set(payload, offset + (udp ? 8 : 0)); return b;
}
function dissect(bytes, selection = 'all') {
  const p = decode(bytes, 101); applyDissectors(p, p.payload, loadDissectors(selection)); return p;
}
test('Falcon base fields and all seven packet layouts follow section 7', () => {
  for (const type of [0, 3, 5, 6, 8, 9, 10]) {
    const payload = [3, 5].includes(type) ? Uint8Array.of(0xaa, 0xbb, 0xcc) : new Uint8Array();
    const a = dissectFalcon(packet(type, payload));
    assert.equal(a.error, undefined, a.info);
    assert.equal(a.version, 1); assert.equal(a.destinationCid, 0x123456); assert.equal(a.packetType, type);
    assert.equal(a.receiverDataWindowBasePsn, 0x01020304); assert.equal(a.receiverRequestWindowBasePsn, 0x80000001);
    assert.equal(a.payloadLength, payload.length);
    if (type < 8) {
      assert.equal(a.destinationFunction, 0xabcdef); assert.equal(a.protocolType, 2); assert.equal(a.ulp, 'RDMA');
      assert.equal(a.ackRequest, true); assert.equal(a.psn, 0xffffffff); assert.equal(a.rsn, 0x12345678);
    } else {
      assert.equal(a.destinationFunction, undefined); assert.equal(a.psn, undefined);
      assert.equal(a.timestamp1, 123); assert.equal(a.timestamp2, 456);
      assert.deepEqual(a.congestion, {hopCount: 9, rxBufferOccupancy: 17, ecnRxPacketCount: 0x2345, rueInfo: 0x234567});
    }
    if (type === 0) assert.equal(a.requestLength, 4096);
    if (type === 5) {assert.equal(a.requestLength, 3); assert.equal(a.payloadPreview, 'aabbcc');}
    if (type === 6) assert.deepEqual(a.resync, {code: 4, name: 'Transaction timed out', packetType: 5, vendorDefined: 0xdeadbeef});
    if (type === 8) {
      assert.equal(a.nackPsn, 0xffffffff); assert.equal(a.nack.code, 2); assert.equal(a.nack.rnrTimeoutMs, 2.56);
      assert.equal(a.nack.requestWindow, true); assert.equal(a.nack.ulpCode, 0x81);
    }
    if (type === 9 || type === 10) assert.deepEqual(a.outOfWindow, {request: true, data: true});
    if (type === 10) assert.deepEqual(a.bitmaps, {dataAck: '202122232425262728292a2b2c2d2e2f',
      dataReceived: '303132333435363738393a3b3c3d3e3f', request: '4041424344454647'});
  }
  const nvme = packet(3); nvme[7] = 0x66; assert.equal(dissectFalcon(nvme).ulp, 'NVMe');
});
test('Falcon rejects every truncated header, unsupported types/versions and invalid lengths', () => {
  for (const type of [0, 3, 5, 6, 8, 9, 10]) {
    const b = packet(type);
    for (let n = 0; n < b.length; n++) assert.ok(dissectFalcon(b.subarray(0, n)).error, `${type}/${n}`);
  }
  const version = packet(3); version[0] = 0x20; assert.match(dissectFalcon(version).error, /version 2/);
  const unknown = packet(3); unknown[7] = 0x42;
  assert.match(dissectFalcon(unknown).error, /packet type 1/); assert.ok(dissectFalcon(unknown).raw);
  const push = packet(5, Uint8Array.of(1, 2)); push[27] = 3;
  assert.match(dissectFalcon(push).error, /length/);
  const extra = new Uint8Array(33); extra.set(packet(0)); assert.match(dissectFalcon(extra).error, /Unexpected/);
  const b = packet(3, new Uint8Array(300)), wrapped = new Uint8Array(b.length + 7); wrapped.set(b, 7);
  const a = dissectFalcon(wrapped.subarray(7)); assert.equal(a.error, undefined);
  assert.equal(a.payloadLength, 300); assert.equal(a.payloadPreview.length, 512); assert.equal(a.previewTruncated, true);
});
test('cleartext IPv4/IPv6 Falcon and PSP GMAC integrate with default and explicit selection', () => {
  for (const [version, extension] of [[4, false], [6, false], [6, true]]) {
    for (const udp of [false, true]) {
      const b = ip(udp ? psp(packet(3, Uint8Array.of(1))) : packet(3, Uint8Array.of(1)), version, udp, extension);
      for (const selection of ['all', ['falcon']]) {
        const p = dissect(b, selection);
        assert.equal(p.protocol, 'Falcon'); assert.equal(p.application.error, undefined);
        assert.equal(p.application.payloadPreview, '01'); assert.equal(p.application.psn, 0xffffffff);
        if (udp) {assert.equal(p.transport, 'UDP'); assert.equal(p.sport, 50000); assert.equal(p.dport, 1000);}
        if (version === 4) assert.equal(p.source, '192.0.2.1');
      }
      assert.equal(dissect(b, []).application, undefined);
    }
  }
  const empty = dissect(ip(new Uint8Array(), 4), ['falcon']); assert.match(empty.application.error, /Truncated/);
});
test('PSP AES-GCM exposes only clear CID and does not parse ciphertext as a Falcon header', () => {
  for (const version of [0, 1]) for (const vc of [false, true]) {
    const b = psp(packet(5, new Uint8Array(300)), version, vc ? 3 : 1, vc);
    const a = dissect(ip(b, 4, true)).application;
    assert.equal(a.error, undefined); assert.equal(a.encrypted, true); assert.equal(a.destinationCid, 0x123456);
    assert.equal(a.psn, undefined); assert.equal(a.packetType, undefined); assert.equal(a.payloadPreview, undefined);
    assert.equal(a.psp.spi, 0x12345678); assert.equal(a.psp.iv, '0000000000000003');
    assert.equal(a.psp.icv, 'cd'.repeat(16)); assert.equal(a.encryptedLength, 324);
    assert.equal(a.encryptedPreview.length, 512); assert.equal(a.previewTruncated, true);
    if (vc) assert.equal(a.psp.virtualCookie, 'ab'.repeat(8));
  }
  const opaque = dissectFalcon(psp(packet(3), 0), {protocol: 'UDP'});
  assert.equal(opaque.encrypted, true); assert.equal(opaque.destinationCid, undefined);
  for (const version of [2, 3]) {
    const a = dissectFalcon(psp(packet(9), version, 2, true), {protocol: 'UDP'});
    assert.equal(a.error, undefined); assert.equal(a.name, 'BACK'); assert.equal(a.encrypted, false);
  }
});
test('malformed PSP and unrelated UDP/ESP are handled conservatively', () => {
  const good = psp(packet(3));
  for (const [offset, value] of [[0, 6], [1, 0], [1, 2], [2, 63], [2, 128], [3, 0], [3, 0x11]]) {
    const bad = good.slice(); bad[offset] = value;
    assert.ok(dissectFalcon(bad, {protocol: 'UDP'}).error, `${offset}/${value}`);
  }
  for (let n = 0; n < 32; n++) assert.ok(dissectFalcon(good.subarray(0, n), {protocol: 'UDP'}).error);
  const wrongNext = good.slice(); wrongNext[0] = 6;
  for (const [bytes, port] of [[wrongNext, 1000], [good, 9999], [packet(3), 1000], [packet(3), 4791]]) {
    assert.notEqual(dissect(ip(bytes, 4, true, false, port)).application?.dissector, 'falcon');
  }
  const esp = {protocol: 'ESP'}; applyDissectors(esp, good, loadDissectors(['falcon']));
  assert.equal(esp.application, undefined);
});
