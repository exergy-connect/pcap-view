import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectBgp} from '../dissectors/bgp.js';
import {dissectBmp} from '../dissectors/bmp.js';
function bgp(type, body = []) {
  const bytes = new Uint8Array(19 + body.length); bytes.fill(255, 0, 16);
  new DataView(bytes.buffer).setUint16(16, bytes.length); bytes[18] = type; bytes.set(body, 19); return bytes;
}
function bmp(type, body) {
  const bytes = new Uint8Array(48 + body.length); bytes[0] = 3; bytes[5] = type;
  new DataView(bytes.buffer).setUint32(1, bytes.length); bytes.set(body, 48); return bytes;
}
test('BMP UPDATE expands attributes, four-byte AS paths, communities and IPv4 routes', () => {
  const attrs = [64,1,1,0, 64,2,6,2,1,0,0,252,0, 64,3,4,192,0,2,1, 64,5,4,0,0,0,100, 192,8,4,252,0,0,42];
  const body = [0,4,24,10,0,0,0,attrs.length,...attrs,24,203,0,113];
  const result = dissectBmp(bmp(0, bgp(2, body))).messages[0].bgp;
  assert.equal(result.name, 'UPDATE'); assert.equal(result.error, undefined);
  assert.deepEqual(result.withdrawnRoutes, ['10.0.0.0/24']);
  assert.deepEqual(result.nlri, ['203.0.113.0/24']);
  assert.deepEqual(result.pathAttributes[1].segments[0].asns, [64512]);
  assert.equal(result.pathAttributes[2].nextHop, '192.0.2.1');
  assert.equal(result.pathAttributes[3].value, 100);
  assert.deepEqual(result.pathAttributes[4].communities, ['64512:42']);
});
test('OPEN capabilities and both peer-up OPEN messages are decoded', () => {
  const open = bgp(1, [4,252,0,0,90,192,0,2,1,8,2,6,65,4,0,0,252,0]);
  const body = new Uint8Array(20 + open.length * 2); body.set(open,20); body.set(open,20 + open.length);
  const result = dissectBmp(bmp(3,body)).messages[0];
  assert.equal(result.sentOpen.holdTime,90); assert.equal(result.receivedOpen.bgpId,'192.0.2.1');
  assert.equal(result.sentOpen.optionalParameters[0].capabilities[0].asn,64512);
});
test('peer-down notifications and mirrored BGP messages are expanded', () => {
  const notification = bgp(3,[6,2,42]);
  const down = dissectBmp(bmp(2, [1,...notification])).messages[0].bgp;
  assert.equal(down.errorCode,6); assert.equal(down.errorSubcode,2); assert.equal(down.data,'2a');
  const mirrored = dissectBmp(bmp(6,[0,0,0,19,...bgp(4)])).messages[0];
  assert.equal(mirrored.tlvs[0].bgp.name,'KEEPALIVE');
});
test('malformed lengths and nested attributes report errors without throwing', () => {
  for (const bytes of [new Uint8Array(3), bgp(2,[0,0,0,4,64,3,4,1]), bgp(2,[0,0,0,0,33]), bgp(1,[4])]) {
    assert.match(dissectBgp(bytes).error,/Truncated|Invalid/);
  }
  const bytes = bgp(4); bytes[17] = 18; assert.match(dissectBgp(bytes).error,/Invalid BGP message length/);
});
test('legacy two-byte AS paths and extended-length unknown attributes remain inspectable', () => {
  const attrs = [64,2,4,2,1,252,0,144,99,0,2,12,34];
  const result = dissectBgp(bgp(2,[0,0,0,attrs.length,...attrs]), {asnBytes:2});
  assert.equal(result.error,undefined); assert.deepEqual(result.pathAttributes[0].segments[0].asns,[64512]);
  assert.equal(result.pathAttributes[1].raw,'0c 22'); assert.equal(result.pathAttributes[1].flags.extendedLength,true);
});
