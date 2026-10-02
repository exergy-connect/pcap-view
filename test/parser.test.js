import {test} from 'node:test';
import assert from 'node:assert/strict';
import {parsePcapng} from '../parser.js';
import {fixture} from './fixtures.js';
for(const little of [true,false]) test(`parses ${little?'little':'big'} endian captures and bidirectional streams`,()=>{
  const {packets,streams}=parsePcapng(fixture(little));assert.equal(packets.length,3);assert.equal(streams.length,1);assert.equal(streams[0].count,3);assert.deepEqual(packets.map(p=>p.stream),[0,0,0]);assert.equal(packets[1].source,'10.0.0.2');assert.ok(Math.abs(packets[2].relativeTime-.002)<1e-9);
});
test('rejects invalid and truncated captures',()=>{assert.throws(()=>parsePcapng(new ArrayBuffer(0)),/Not a PCAPNG/);assert.throws(()=>parsePcapng(fixture().slice(0,-1)),/Invalid block length/);const b=fixture();new DataView(b).setUint32(24,99,true);assert.throws(()=>parsePcapng(b),/length mismatch/);});

function concat(...buffers) {
  const out = new Uint8Array(buffers.reduce((n,b) => n+b.byteLength,0));
  let p=0; for (const b of buffers) {out.set(new Uint8Array(b),p);p+=b.byteLength;} return out.buffer;
}
function nameBlock(little, records) {
  const entries = records.map(({address,names,type=1}) => {
    const text = new TextEncoder().encode(names.join('\0')+'\0');
    const len=address.length+text.length, record=new Uint8Array(4+Math.ceil(len/4)*4),v=new DataView(record.buffer);
    v.setUint16(0,type,little);v.setUint16(2,len,little);record.set(address,4);record.set(text,4+address.length);return record;
  });
  const body=concat(...entries,new Uint8Array(4)), out=new Uint8Array(body.byteLength+12),v=new DataView(out.buffer);
  v.setUint32(0,4,little);v.setUint32(4,out.length,little);out.set(new Uint8Array(body),8);v.setUint32(out.length-4,out.length,little);return out.buffer;
}
for (const little of [true,false]) test(`resolves late hostname records and aliases (${little?'LE':'BE'})`,()=>{
  const input=concat(fixture(little),nameBlock(little,[{address:[10,0,0,1],names:['client.example','alias.example']}]));
  const {packets,streams}=parsePcapng(input);
  assert.deepEqual(packets[0].sourceNames,['client.example','alias.example']);
  assert.deepEqual(packets[1].destinationNames,['client.example','alias.example']);
  assert.deepEqual(packets[0].destinationNames,[]);
  assert.equal(packets[0].source,'10.0.0.1');assert.equal(streams.length,1);assert.equal(streams[0].sourceNames[0],'client.example');
});
test('hostname mappings stay scoped to their section',()=>{
  const {packets}=parsePcapng(concat(fixture(),nameBlock(true,[{address:[10,0,0,1],names:['first.example']}]),fixture()));
  assert.equal(packets[0].sourceNames[0],'first.example');assert.deepEqual(packets[3].sourceNames,[]);
});
test('resolves IPv6 hostname records',()=>{
  const prefix=fixture().slice(0,48),body=new Uint8Array(60),b=new DataView(body.buffer);
  b.setUint32(12,40,true);b.setUint32(16,40,true);body[20]=0x60;body[26]=59;
  const address=[0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1];body.set(address,28);
  const packet=new Uint8Array(72),v=new DataView(packet.buffer);v.setUint32(0,6,true);v.setUint32(4,72,true);packet.set(body,8);v.setUint32(68,72,true);
  // Change interface link type to raw IP for this fixture.
  new DataView(prefix).setUint16(36,101,true);
  const {packets}=parsePcapng(concat(prefix,packet,nameBlock(true,[{address,names:['ipv6.example'],type:2}])));
  assert.equal(packets[0].source,'2001:db8:0:0:0:0:0:1');assert.equal(packets[0].sourceNames[0],'ipv6.example');
});
test('rejects malformed name records',()=>{
  const block=nameBlock(true,[{address:[10,0,0,1],names:['host']}]);
  new DataView(block).setUint16(10,65535,true);
  assert.throws(()=>parsePcapng(concat(fixture(),block)),/Truncated name resolution record/);
  const missing=nameBlock(true,[]);new DataView(missing).setUint16(8,99,true);
  assert.throws(()=>parsePcapng(concat(fixture(),missing)),/Missing name resolution terminator/);
});

function bmpFixture(payload, reverse = false) {
  const prefix = fixture().slice(0,48);
  const packet = new Uint8Array(54 + payload.length), v = new DataView(packet.buffer);
  v.setUint16(12,0x0800); packet[14]=0x45; v.setUint16(16,40+payload.length); packet[23]=6;
  packet.set([10,0,0,1],26);packet.set([10,0,0,2],30);
  v.setUint16(34,reverse?11019:50000);v.setUint16(36,reverse?50000:11019);packet[46]=0x50;packet[47]=16;packet.set(payload,54);
  const size=32+Math.ceil(packet.length/4)*4, block=new Uint8Array(size),b=new DataView(block.buffer);
  b.setUint32(0,6,true);b.setUint32(4,size,true);b.setUint32(20,packet.length,true);b.setUint32(24,packet.length,true);block.set(packet,28);b.setUint32(size-4,size,true);
  return concat(prefix,block);
}
test('BMP selection retains TCP streams in both directions and decodes multiple messages',()=>{
  for(const reverse of [false,true]) {
    const input=bmpFixture(new Uint8Array([3,0,0,0,6,4,3,0,0,0,6,5]),reverse);
    const {packets,streams}=parsePcapng(input);
    assert.equal(packets[0].protocol,'BMP');assert.equal(packets[0].transport,'TCP');
    assert.equal(packets[0].stream,0);assert.equal(streams[0].count,1);
    assert.deepEqual(packets[0].application.messages.map(m=>m.name),['Initiation','Termination']);
    assert.equal(parsePcapng(input,{dissectors:[]}).packets[0].protocol,'TCP');
    assert.equal(parsePcapng(input,{dissectors:['bmp']}).packets[0].protocol,'BMP');
  }
  assert.throws(()=>parsePcapng(fixture(),{dissectors:['missing']}),/Unknown dissector/);
});
test('BMP handles empty, truncated, invalid and unsupported payloads',()=>{
  assert.equal(parsePcapng(bmpFixture(new Uint8Array())).packets[0].protocol,'TCP');
  for(const payload of [[3],[3,0,0,0,5,4],[2,0,0,0,6,4],[3,0,0,0,48,0],[3,0,0,0,10,4,0,0,0,8]]) {
    const packet=parsePcapng(bmpFixture(new Uint8Array(payload))).packets[0];
    assert.ok(packet.application.error || packet.application.pendingBytes);assert.equal(packet.stream,0);
  }
});
test('BMP decodes peer and initiation fields',()=>{
  const payload=new Uint8Array(67),v=new DataView(payload.buffer);
  payload[0]=3;v.setUint32(1,48);payload[5]=99;
  // Unknown types are skipped by their declared length.
  payload[48]=3;v.setUint32(49,19);payload[53]=4;v.setUint16(54,2);v.setUint16(56,9);payload.set(new TextEncoder().encode('router-01'),58);
  assert.equal(parsePcapng(bmpFixture(payload)).packets[0].application.messages[1].tlvs[0].text,'router-01');
  const peer=new Uint8Array(49),p=new DataView(peer.buffer);peer[0]=3;p.setUint32(1,49);peer[5]=2;
  peer.set([192,0,2,1],28);p.setUint32(32,64512);peer[48]=1;
  const message=parsePcapng(bmpFixture(peer)).packets[0].application.messages[0];
  assert.equal(message.peer.address,'192.0.2.1');assert.equal(message.peer.asn,64512);assert.equal(message.reason,1);
});


test('BMP reassembles continuations beginning with 51, 231, 233 and 255', async()=>{
  const {dissectBmpSegment}=await import('../dissectors/bmp.js');
  for(const value of [51,231,233,255]) {
    const bytes=new Uint8Array([3,0,0,0,12,4,0,0,0,2,value,65]);
    const context={pending:new Uint8Array(),nextSequence:null};
    const first=dissectBmpSegment(bytes.subarray(0,10),{sequence:100,flags:16},context);
    assert.equal(first.pendingBytes,10);
    const second=dissectBmpSegment(bytes.subarray(10),{sequence:110,flags:16},context);
    assert.equal(second.messages.length,1);assert.equal(second.messages[0].version,3);assert.equal(second.error,undefined);
    assert.deepEqual(second.messages[0].tlvs[0].value,[value,65]);
    const duplicate=dissectBmpSegment(bytes.subarray(10),{sequence:110,flags:16},context);
    assert.match(duplicate.info,/retransmission/);
  }
});
test('BMP continuation handles overlapping retransmissions and sequence wrap', async()=>{
  const {dissectBmpSegment}=await import('../dissectors/bmp.js');
  const bytes=new Uint8Array([3,0,0,0,6,4]), context={pending:new Uint8Array(),nextSequence:null};
  dissectBmpSegment(bytes.subarray(0,4),{sequence:0xfffffffe,flags:16},context);
  const result=dissectBmpSegment(bytes.subarray(2),{sequence:0,flags:16},context);
  assert.equal(result.messages[0].name,'Initiation');assert.equal(context.nextSequence,4);
});

test('HTTP is included by default and explicit selection preserves transport streams', () => {
  const input = bmpFixture(new TextEncoder().encode('GET / HTTP/1.1\r\nHost: example.test\r\n\r\n'));
  for (const dissectors of ['all', ['http']]) {
    const {packets, streams} = parsePcapng(input, {dissectors});
    assert.equal(packets[0].protocol, 'HTTP');
    assert.equal(packets[0].transport, 'TCP');
    assert.equal(packets[0].application.messages[0].target, '/');
    assert.equal(streams[0].count, 1);
  }
  assert.equal(parsePcapng(input, {dissectors: []}).packets[0].protocol, 'TCP');
});

function vxlanFixture(ipv6 = false) {
  const frame = new Uint8Array(14 + (ipv6 ? 40 : 20));
  const f = new DataView(frame.buffer);
  f.setUint16(12, ipv6 ? 0x86dd : 0x0800);
  if (ipv6) {
    frame[14] = 0x60; frame[20] = 59;
    frame.set([0x20, 1, 0x0d, 0xb8], 22); frame[37] = 1;
    frame.set([0x20, 1, 0x0d, 0xb8], 38); frame[53] = 2;
  } else {
    frame[14] = 0x45; f.setUint16(16, 20); frame[23] = 1;
    frame.set([192, 0, 2, 1, 192, 0, 2, 2], 26);
  }
  const packet = new Uint8Array(42 + 8 + frame.length), v = new DataView(packet.buffer);
  v.setUint16(12, 0x0800); packet[14] = 0x45;
  v.setUint16(16, packet.length - 14); packet[23] = 17;
  packet.set([10, 0, 0, 1, 10, 0, 0, 2], 26);
  v.setUint16(34, 50000); v.setUint16(36, 4789); v.setUint16(38, packet.length - 34);
  packet[42] = 8; packet[48] = 42; packet.set(frame, 50);
  const size = 32 + Math.ceil(packet.length / 4) * 4;
  const block = new Uint8Array(size), b = new DataView(block.buffer);
  b.setUint32(0, 6, true); b.setUint32(4, size, true);
  b.setUint32(20, packet.length, true); b.setUint32(24, packet.length, true);
  block.set(packet, 28); b.setUint32(size - 4, size, true);
  return concat(fixture().slice(0, 48), block);
}

for (const ipv6 of [false, true]) test(`VXLAN resolves late inner IPv${ipv6 ? 6 : 4} hostnames and retains numeric addresses`, () => {
  const address = last => ipv6 ? [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last] : [192, 0, 2, last];
  const input = concat(vxlanFixture(ipv6), nameBlock(true, [
    {type: ipv6 ? 2 : 1, address: address(1), names: ['inner-client.example', 'alias.example']},
    {type: ipv6 ? 2 : 1, address: address(2), names: ['inner-server.example']},
  ]), vxlanFixture(ipv6));
  const {packets} = parsePcapng(input);
  const inner = packets[0].application.inner;
  assert.deepEqual(inner.sourceNames, ['inner-client.example', 'alias.example']);
  assert.deepEqual(inner.destinationNames, ['inner-server.example']);
  assert.equal(inner.source, ipv6 ? '2001:db8:0:0:0:0:0:1' : '192.0.2.1');
  assert.equal(packets[0].source, '10.0.0.1');
  assert.match(packets[0].info, /inner-client.example → inner-server.example/);
  assert.equal(packets[0].info, packets[0].application.info);
  assert.deepEqual(packets[1].application.inner.sourceNames, []);
  assert.deepEqual(packets[1].application.inner.destinationNames, []);
  assert.match(packets[1].info, ipv6 ? /2001:db8:/ : /192\.0\.2\.1/);
});
