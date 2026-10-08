import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectBgp} from '../dissectors/bgp.js';
import {dissectBmp} from '../dissectors/bmp.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
function bgp(type, body = []) {
  const bytes = new Uint8Array(19 + body.length); bytes.fill(255, 0, 16);
  new DataView(bytes.buffer).setUint16(16, bytes.length); bytes[18] = type; bytes.set(body, 19); return bytes;
}
function bmp(type, body) {
  const bytes = new Uint8Array(48 + body.length); bytes[0] = 3; bytes[5] = type;
  new DataView(bytes.buffer).setUint32(1, bytes.length); bytes.set(body, 48); return bytes;
}
test('standalone UPDATE decodes four-byte AS_PATH and continues through subsequent attributes/messages', () => {
  const mpReach = [0,1,1,16,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,5,0,32,10,0,0,1,24,172,16,1];
  const attrs = [144,14,0,30,...mpReach,64,1,1,0,80,2,0,6,2,1,0,0,254,77,64,5,4,0,0,0,100];
  const update = bgp(2, [0,0,0,attrs.length,...attrs]);
  const endOfRib = bgp(2, [0,0,0,0]);
  const packet = {protocol: 'TCP', dport: 179, sequence: 4102700109};
  applyDissectors(packet, new Uint8Array([...update,...bgp(2,[0,0,0,6,128,15,3,0,2,1]),...update,...endOfRib]), loadDissectors(['bgp']));
  assert.equal(packet.application.error, undefined);
  assert.equal(packet.application.messages.length, 4);
  for (const message of packet.application.messages) assert.equal(message.error, undefined);
  const path = packet.application.messages[0].pathAttributes[2];
  assert.equal(path.asnBytes, 4); assert.deepEqual(path.segments[0].asns, [65101]);
  assert.equal(packet.application.messages[0].pathAttributes[3].value, 100);
  assert.deepEqual(packet.application.messages[3].nlri, []);
});
test('standalone AS_PATH width detection preserves legacy, empty and ambiguous paths', () => {
  for (const [raw, width] of [[[2,1,254,77],2], [[2,1,0,0,254,77],4], [[],2]]) {
    const attrs = [64,2,raw.length,...raw], packet = {protocol: 'TCP', dport: 179};
    applyDissectors(packet, bgp(2,[0,0,0,attrs.length,...attrs]), loadDissectors(['bgp']));
    assert.equal(packet.application.error, undefined);
    const path = packet.application.messages[0].pathAttributes[0];
    assert.equal(path.asnBytes, width);
    if (raw.length) assert.deepEqual(path.segments[0].asns,[65101]);
    else assert.deepEqual(path.segments,[]);
  }
  const attrs = [64,2,10,2,2,0,1,0,2,2,1,0,3,64,5,4,0,0,0,100];
  const message = dissectBgp(bgp(2,[0,0,0,attrs.length,...attrs]), {asnBytes:'auto'});
  assert.equal(message.error, undefined);
  assert.equal(message.pathAttributes[0].asnBytes, 'ambiguous');
  assert.equal(message.pathAttributes[0].segments, undefined);
  assert.match(message.pathAttributes[0].warning,/ambiguous/);
  assert.equal(message.pathAttributes[1].value,100);
  const malformed = [64,2,3,2,2,0];
  assert.match(dissectBgp(bgp(2,[0,0,0,malformed.length,...malformed]), {asnBytes:'auto'}).error,/Invalid AS_PATH/);
});
test('standalone BGP is registered, detects headers and decodes multiple messages', () => {
  assert.ok(loadDissectors().some(d => d.name === 'bgp'));
  const packet = {protocol: 'TCP', sport: 50000, dport: 50001, sequence: 10};
  applyDissectors(packet, new Uint8Array([...bgp(4), ...bgp(3, [6, 2])]), loadDissectors());
  assert.equal(packet.protocol, 'BGP');
  assert.equal(packet.transport, 'TCP');
  assert.deepEqual(packet.application.messages.map(m => m.name), ['KEEPALIVE', 'NOTIFICATION']);
  const udp = {protocol: 'UDP', dport: 179};
  applyDissectors(udp, bgp(4), loadDissectors(['bgp']));
  assert.equal(udp.protocol, 'UDP');
});
test('standalone BGP buffers split headers and overlapping TCP retransmissions', () => {
  const contexts = new Map(), dissectors = loadDissectors(['bgp']);
  const packet = sequence => ({protocol: 'TCP', sport: 50000, dport: 179, sequence});
  const bytes = bgp(4), first = packet(100);
  applyDissectors(first, bytes.subarray(0, 10), dissectors, contexts);
  assert.equal(first.application.pendingBytes, 10);
  const next = packet(105);
  applyDissectors(next, bytes.subarray(5), dissectors, contexts);
  assert.equal(next.application.messages[0].name, 'KEEPALIVE');
  assert.equal(next.application.pendingBytes, undefined);
  const duplicate = packet(100);
  applyDissectors(duplicate, bytes, dissectors, contexts);
  assert.match(duplicate.info, /retransmission/);
});
test('standalone BGP reports malformed framing and sequence gaps', () => {
  const contexts = new Map(), dissectors = loadDissectors(['bgp']);
  const packet = sequence => ({protocol: 'TCP', dport: 179, sequence});
  applyDissectors(packet(10), bgp(4).subarray(0, 5), dissectors, contexts);
  const next = packet(30);
  applyDissectors(next, bgp(4), dissectors, contexts);
  assert.match(next.application.error, /sequence gap/);
  assert.equal(next.application.messages[0].name, 'KEEPALIVE');
  const malformed = bgp(4); malformed[17] = 18;
  const invalid = packet(0);
  applyDissectors(invalid, malformed, dissectors);
  assert.match(invalid.application.error, /Invalid BGP message length/);
});
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
