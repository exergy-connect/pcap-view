// IPv6 fixed and extension headers (RFC 8200, RFC 4302).
export const ipv6Bytes = Symbol('ipv6Bytes');
export const nextHeaderNames = {0: 'Hop-by-Hop Options', 1: 'ICMP', 2: 'IGMP', 4: 'IPv4-in-IP',
  6: 'TCP', 17: 'UDP', 41: 'IPv6-in-IP', 43: 'Routing', 44: 'Fragment', 47: 'GRE',
  50: 'ESP', 51: 'AH', 58: 'ICMPv6', 59: 'No Next Header', 60: 'Destination Options',
  89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP', 143: 'Ethernet-in-IP', 252: 'Falcon', 253: 'UET'};
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export function dissectIpv6(bytes) {
  const result = {protocol: 'IPv6', extensionHeaders: []};
  const fail = error => ({...result, error, info: error});
  if (bytes.length < 40) return fail('Truncated IPv6 header');
  if (bytes[0] >> 4 !== 6) return fail('Invalid IPv6 version');
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const address = p => Array.from({length: 8}, (_, i) => v.getUint16(p + i * 2).toString(16)).join(':');
  Object.assign(result, {version: 6, trafficClass: (v.getUint32(0) >>> 20) & 255,
    flowLabel: v.getUint32(0) & 0xfffff, payloadLength: v.getUint16(4), nextHeader: bytes[6],
    hopLimit: bytes[7], source: address(8), destination: address(24)});
  let p = 40, next = result.nextHeader;
  const limit = Math.min(bytes.length, 40 + result.payloadLength);
  while ([0, 43, 44, 51, 60].includes(next)) {
    if (p + 2 > limit) return fail('Truncated IPv6 extension');
    const length = next === 44 ? 8 : next === 51 ? (bytes[p + 1] + 2) * 4 : (bytes[p + 1] + 1) * 8;
    if (p + length > limit) return fail('Truncated IPv6 extension');
    if (next === 51 && length < 12) return fail('Invalid IPv6 authentication header');
    const header = {type: next, name: nextHeaderNames[next], nextHeader: bytes[p], length};
    if (next === 44) Object.assign(header, {fragmentOffset: (v.getUint16(p + 2) & 0xfff8) >>> 3,
      moreFragments: !!(bytes[p + 3] & 1), identification: v.getUint32(p + 4)});
    else if (next === 43) Object.assign(header, {routingType: bytes[p + 2], segmentsLeft: bytes[p + 3], data: hex(bytes.subarray(p + 4, p + length))});
    else if (next === 51) Object.assign(header, {spi: v.getUint32(p + 4), sequence: v.getUint32(p + 8), authenticationData: hex(bytes.subarray(p + 12, p + length))});
    else {
      header.options = [];
      for (let q = p + 2; q < p + length;) {
        const type = bytes[q++];
        if (!type) {header.options.push({type, name: 'Pad1'}); continue;}
        if (q >= p + length || q + 1 + bytes[q] > p + length) return fail('Truncated IPv6 option');
        const size = bytes[q++];
        header.options.push({type, length: size, data: hex(bytes.subarray(q, q + size))}); q += size;
      }
    }
    result.extensionHeaders.push(header); p += length; next = header.nextHeader;
    if (header.fragmentOffset) {result.fragment = true; break;}
  }
  Object.assign(result, {headerLength: p, payloadOffset: p, capturedLength: limit,
    upperProtocol: next, upperProtocolName: nextHeaderNames[next] ?? `IP protocol ${next}`});
  result.info = result.fragment ? 'IPv6 fragment' : `IPv6 ${result.upperProtocolName}`;
  if (bytes.length < 40 + result.payloadLength) result.truncated = true;
  return result;
}
export default {name: 'ipv6', layer: 'network', matches: packet => packet.protocol === 'IPv6', dissect: dissectIpv6};
