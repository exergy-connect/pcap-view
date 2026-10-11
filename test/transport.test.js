import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectTcp} from '../dissectors/tcp.js';
import {dissectUdp} from '../dissectors/udp.js';
import {decode} from '../decode.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {parsePcapng} from '../parser.js';
import {fixture} from './fixtures.js';

function tcp(options = [], payload = []) {
  const header = 20 + Math.ceil(options.length / 4) * 4;
  const bytes = new Uint8Array(header + payload.length), v = new DataView(bytes.buffer);
  v.setUint16(0, 50000); v.setUint16(2, 80); v.setUint32(4, 123); v.setUint32(8, 456);
  bytes[12] = (header / 4) << 4; bytes[13] = 0x12;
  v.setUint16(14, 8192); v.setUint16(16, 0xabcd); v.setUint16(18, 7);
  bytes.set(options, 20); bytes.set(payload, header); return bytes;
}
function udp(payload = []) {
  const bytes = new Uint8Array(8 + payload.length), v = new DataView(bytes.buffer);
  v.setUint16(0, 1234); v.setUint16(2, 4321); v.setUint16(4, bytes.length); v.setUint16(6, 0x1234);
  bytes.set(payload, 8); return bytes;
}
function packet(segment, proto = 6, version = 4) {
  const header = version === 4 ? 20 : 40;
  const bytes = new Uint8Array(header + segment.length + 12), v = new DataView(bytes.buffer);
  bytes[0] = version === 4 ? 0x45 : 0x60;
  v.setUint16(version === 4 ? 2 : 4, segment.length + (version === 4 ? header : 0));
  bytes[version === 4 ? 9 : 6] = proto; bytes.set(segment, header);
  return decode(bytes, 101);
}
function apply(segment, proto = 6, names = 'all', contexts = new Map(), version = 4) {
  const decoded = packet(segment, proto, version);
  applyDissectors(decoded, decoded.payload, loadDissectors(names), contexts); return decoded;
}

test('TCP exposes fixed header fields and ordered common options', () => {
  const options = [2, 4, 5, 180, 3, 3, 7, 1, 4, 2, 8, 10, 0, 0, 0, 9, 0, 0, 0, 8];
  const result = dissectTcp(tcp(options, [42]));
  assert.equal(result.sport, 50000); assert.equal(result.dport, 80);
  assert.equal(result.sequence, 123); assert.equal(result.acknowledgment, 456);
  assert.equal(result.window, 8192); assert.equal(result.checksum, 0xabcd); assert.equal(result.urgentPointer, 7);
  assert.deepEqual(result.flagNames, ['SYN', 'ACK']); assert.equal(result.headerLength, 40);
  assert.equal(result.options[0].value, 1460); assert.equal(result.options[1].shift, 7);
  assert.equal(result.options[3].name, 'SACK permitted');
  assert.equal(result.options[4].value, 9); assert.equal(result.options[4].echoReply, 8);
  assert.equal(result.payloadPreview, '2a');
  const sack = dissectTcp(tcp([5, 10, 0, 0, 0, 10, 0, 0, 0, 20, 0, 0]));
  assert.deepEqual(sack.options[0].blocks, [{left: 10, right: 20}]);
  assert.equal(sack.padding, '00');
  assert.equal(dissectTcp(tcp([254, 4, 42, 43])).options[0].data, '2a2b');
});

test('TCP reports fixed-header, offset and option errors without throwing', () => {
  const segment = tcp();
  for (let n = 0; n < 20; n++) assert.match(dissectTcp(segment.subarray(0, n)).error, /Truncated TCP/);
  segment[12] = 0x40; assert.match(dissectTcp(segment).error, /data offset/);
  segment[12] = 0xf0; assert.match(dissectTcp(segment).error, /Truncated TCP options/);
  for (const options of [[2, 0, 0, 0], [2, 3, 0, 0], [5, 2, 0, 0], [8, 10, 0, 0], [1, 1, 1, 254]]) {
    assert.match(dissectTcp(tcp(options)).error, /TCP option/);
  }
});

test('UDP checks lengths, excludes padding and caps previews', () => {
  const bytes = udp([1, 2, 3]);
  const padded = new Uint8Array(20); padded.set(bytes);
  const result = dissectUdp(padded);
  assert.equal(result.length, 11); assert.equal(result.checksum, 0x1234);
  assert.equal(result.sport, 1234); assert.equal(result.dport, 4321);
  assert.equal(result.payloadLength, 3); assert.equal(result.payloadPreview, '010203');
  for (let n = 0; n < 8; n++) assert.match(dissectUdp(bytes.subarray(0, n)).error, /Truncated UDP header/);
  assert.match(dissectUdp(bytes.subarray(0, 10)).error, /Truncated UDP datagram/);
  bytes[5] = 7; assert.match(dissectUdp(bytes).error, /Invalid UDP length/);
  const large = dissectUdp(udp(new Uint8Array(300)));
  assert.equal(large.payloadLength, 300); assert.equal(large.payloadPreview.length, 512);
  assert.equal(large.previewTruncated, true);
});

test('transport selection works for IPv4/IPv6, empty packets and malformed headers', () => {
  for (const version of [4, 6]) {
    for (const [proto, name, segment] of [[6, 'tcp', tcp()], [17, 'udp', udp()]]) {
      for (const names of ['all', [name]]) {
        const decoded = apply(segment, proto, names, new Map(), version);
        assert.equal(decoded.application.dissector, name);
        assert.equal(decoded.transportDetails.payloadLength, 0);
        assert.equal(Object.getOwnPropertySymbols(decoded).length, 0);
      }
      const disabled = apply(segment, proto, [], new Map(), version);
      assert.equal(disabled.application, undefined); assert.equal(disabled.transportDetails, undefined);
      for (let n = 0; n < (proto === 6 ? 20 : 8); n++) {
        assert.match(apply(segment.subarray(0, n), proto, [name], new Map(), version).application.error, /Truncated/);
      }
    }
  }
});

test('transport fallback does not pin TCP selection and retains details beside HTTP', () => {
  const contexts = new Map();
  const syn = tcp(); syn[13] = 2;
  assert.equal(apply(syn, 6, 'all', contexts).application.dissector, 'tcp');
  const request = new TextEncoder().encode('GET / HTTP/1.1\r\nHost: example\r\n\r\n');
  const decoded = apply(tcp([], request), 6, ['tcp', 'http'], contexts);
  assert.equal(decoded.protocol, 'HTTP'); assert.equal(decoded.transport, 'TCP');
  assert.equal(decoded.transportDetails.window, 8192);
  assert.equal(decoded.application.messages[0].target, '/');
});

test('capture parsing preserves TCP stream grouping and honors selection', () => {
  for (const dissectors of ['all', ['tcp']]) {
    const {packets, streams} = parsePcapng(fixture(), {dissectors});
    assert.equal(streams.length, 1);
    assert.deepEqual(packets.map(p => p.stream), [0, 0, 0]);
    assert.ok(packets.every(p => p.application.dissector === 'tcp'));
  }
  assert.ok(parsePcapng(fixture(), {dissectors: []}).packets.every(p => !p.transportDetails && !p.application));
});
