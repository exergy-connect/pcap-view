import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectPrefixSid} from '../dissectors/bgp-prefix-sid.js';
import {dissectBgp} from '../dissectors/bgp.js';
import {dissectBmp} from '../dissectors/bmp.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';

const tlv = (type, value) => [type, value.length >>> 8, value.length & 255, ...value];
const sid = [32,1,13,184,0,1,0,2,0,0,0,0,0,0,0,5];
const structure = () => tlv(1, [32,32,16,0,16,64]);
const information = (behavior = 19, nested = structure()) => tlv(1, [7,...sid,0x80,behavior >>> 8,behavior & 255,9,...nested]);
const service = (type = 5) => tlv(type, [3,...information()]);
function update(value, extended = false) {
  const attr = extended ? [0xd0,40,value.length >>> 8,value.length & 255,...value] : [0xc0,40,value.length,...value];
  const attrs = [...attr,64,5,4,0,0,0,100];
  const bytes = new Uint8Array(23 + attrs.length), view = new DataView(bytes.buffer);
  bytes.fill(255,0,16); view.setUint16(16,bytes.length); bytes[18] = 2;
  view.setUint16(21,attrs.length); bytes.set(attrs,23); return bytes;
}

test('RFC 8669 label index and multiple SRGB ranges decode with original flags and raw values', () => {
  const value = [...tlv(1,[7,0x12,0x34,0,0,0,42]), ...tlv(3,[0x56,0x78,0,0x3e,0x80,0,0x1f,0x40,0,0x61,0xa8,0,3,0xe8])];
  const message = dissectBgp(update(value)), attr = message.pathAttributes[0];
  assert.equal(message.error,undefined); assert.equal(attr.name,'PREFIX_SID');
  assert.equal(attr.flags.optional,true); assert.equal(attr.flags.transitive,true);
  assert.equal(attr.tlvs[0].labelIndex,42); assert.equal(attr.tlvs[0].flags,0x1234); assert.equal(attr.tlvs[0].reserved,7);
  assert.deepEqual(attr.tlvs[1].ranges,[{firstLabel:16000,rangeSize:8000},{firstLabel:25000,rangeSize:1000}]);
  assert.equal(attr.tlvs[1].flags,0x5678); assert.equal(message.pathAttributes[1].value,100);
});

test('RFC 9252 service SIDs include behaviors and all SID structure/transposition fields', () => {
  for (const type of [5,6]) {
    const value = service(type), attr = dissectBgp(update(value)).pathAttributes[0];
    assert.equal(attr.error,undefined);
    const outer = attr.tlvs[0], info = outer.subTlvs[0], shape = info.subSubTlvs[0];
    assert.equal(outer.name,type === 5 ? 'SRv6 L3 Service' : 'SRv6 L2 Service');
    assert.equal(outer.reserved,3); assert.equal(info.reserved1,7); assert.equal(info.reserved2,9); assert.equal(info.flags,128);
    assert.equal(info.sid,'2001:db8:1:2:0:0:0:5'); assert.equal(info.endpointBehavior,19); assert.equal(info.endpointBehaviorName,'End.DT4');
    assert.equal(shape.locatorBlockLength,32); assert.equal(shape.locatorNodeLength,32);
    assert.equal(shape.functionLength,16); assert.equal(shape.argumentLength,0);
    assert.equal(shape.transpositionLength,16); assert.equal(shape.transpositionOffset,64);
  }
  for (const [code,name] of [[16,'End.DX6'],[17,'End.DX4'],[18,'End.DT6'],[20,'End.DT46'],[65535,'Opaque'],[0x1234,'Unknown behavior 4660']]) {
    const parsed = dissectPrefixSid(new Uint8Array(tlv(5,[0,...information(code,[])])));
    assert.equal(parsed.error,undefined); assert.equal(parsed.tlvs[0].subTlvs[0].endpointBehaviorName,name);
  }
});

test('Prefix-SID preserves unknown TLVs at every level and multiple service SIDs', () => {
  const nested = [...tlv(99,[1,2]),...structure()];
  const value = [...tlv(99,[3,4]),...tlv(5,[0,...tlv(99,[5,6]),...information(19,nested),...information(18,[])])];
  const parsed = dissectPrefixSid(new Uint8Array(value));
  assert.equal(parsed.error,undefined); assert.equal(parsed.tlvs[0].raw,'03 04');
  assert.equal(parsed.tlvs[1].subTlvs[0].raw,'05 06');
  assert.equal(parsed.tlvs[1].subTlvs[1].subSubTlvs[0].raw,'01 02');
  assert.equal(parsed.tlvs[1].subTlvs[2].endpointBehaviorName,'End.DT6');
});

test('Prefix-SID works in standalone split TCP updates and embedded BMP, with extended lengths', () => {
  const value = [...service(),...tlv(99,new Uint8Array(256))], bytes = update(value,true);
  const contexts = new Map(), dissectors = loadDissectors(['bgp']);
  const first = {protocol:'TCP',dport:179,sequence:100};
  applyDissectors(first,bytes.subarray(0,50),dissectors,contexts);
  assert.equal(first.application.pendingBytes,50);
  const next = {protocol:'TCP',dport:179,sequence:150};
  applyDissectors(next,bytes.subarray(50),dissectors,contexts);
  assert.equal(next.application.error,undefined);
  assert.equal(next.application.messages[0].pathAttributes[0].tlvs[0].subTlvs[0].endpointBehavior,19);
  const bmp = new Uint8Array(48 + bytes.length), view = new DataView(bmp.buffer);
  bmp[0] = 3; view.setUint32(1,bmp.length); bmp.set(bytes,48);
  const embedded = dissectBmp(bmp).messages[0].bgp;
  assert.equal(embedded.error,undefined); assert.equal(embedded.pathAttributes[0].tlvs[1].length,256);
});

test('Prefix-SID rejects nested lengths at their own boundaries and continues to later attributes', () => {
  const malformed = [
    [5], [5,0], [5,0,2,0], tlv(1,new Uint8Array(6)), tlv(3,new Uint8Array(2)), tlv(3,new Uint8Array(9)),
    tlv(5,[]), tlv(5,[0,1]), tlv(5,[0,1,0]), tlv(5,[0,1,0,22,...new Uint8Array(21)]),
    tlv(5,[0,...tlv(1,new Uint8Array(20))]),
    tlv(5,[0,...information(19,[1])]), tlv(5,[0,...information(19,[1,0])]),
    tlv(5,[0,...information(19,[1,0,6,0,0,0])]),
    tlv(5,[0,...information(19,tlv(1,new Uint8Array(5)))]),
  ];
  for (const value of malformed) {
    const message = dissectBgp(update(value));
    assert.match(message.error,/Prefix-SID/);
    assert.match(message.pathAttributes[0].error,/Prefix-SID/);
    assert.equal(message.pathAttributes[1].value,100);
    assert.ok(message.pathAttributes[0].raw.length);
  }
  // Prefix truncations of the service encoding must all fail; no Ethernet
  // padding or following attribute can satisfy a nested length.
  const bytes = new Uint8Array(service());
  for (let n = 1; n < bytes.length; n++) assert.match(dissectPrefixSid(bytes.subarray(0,n)).error,/Truncated/);
});
