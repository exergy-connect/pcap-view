// Packet-local ICMP (RFC 792) and ICMPv6 (RFC 4443) decoding.
const types4 = {0: 'Echo reply', 3: 'Destination unreachable', 4: 'Source quench',
  5: 'Redirect', 8: 'Echo request', 11: 'Time exceeded', 12: 'Parameter problem',
  13: 'Timestamp request', 14: 'Timestamp reply', 17: 'Address mask request', 18: 'Address mask reply'};
const types6 = {1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded',
  4: 'Parameter problem', 128: 'Echo request', 129: 'Echo reply',
  131: 'Multicast Listener Report', 132: 'Multicast Listener Done',
  133: 'Router Solicitation', 134: 'Router Advertisement',
  135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement',
  143: 'Version 2 Multicast Listener Report'};
const codes4 = {
  3: ['Network unreachable', 'Host unreachable', 'Protocol unreachable', 'Port unreachable',
    'Fragmentation needed', 'Source route failed', 'Destination network unknown', 'Destination host unknown',
    'Source host isolated', 'Network administratively prohibited', 'Host administratively prohibited',
    'Network unreachable for ToS', 'Host unreachable for ToS', 'Communication administratively prohibited',
    'Host precedence violation', 'Precedence cutoff in effect'],
  5: ['Redirect for network', 'Redirect for host', 'Redirect for ToS and network', 'Redirect for ToS and host'],
  11: ['TTL exceeded in transit', 'Fragment reassembly time exceeded'],
  12: ['Pointer indicates error', 'Missing required option', 'Bad length'],
};
const codes6 = {
  1: ['No route to destination', 'Communication administratively prohibited', 'Beyond scope of source address',
    'Address unreachable', 'Port unreachable', 'Source address failed policy', 'Reject route to destination'],
  3: ['Hop limit exceeded in transit', 'Fragment reassembly time exceeded'],
  4: ['Erroneous header field', 'Unrecognized next header', 'Unrecognized IPv6 option'],
};
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

export function dissectIcmp(bytes, packet = {protocol: 'ICMP'}) {
  const version = packet.protocol === 'ICMPv6' ? 6 : 4;
  const protocol = version === 6 ? 'ICMPv6' : 'ICMP';
  const result = {protocol, version};
  const fail = error => ({...result, info: error, error});
  if (bytes.length < 4) return fail(`Truncated ${protocol} header`);
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const type = bytes[0], code = bytes[1];
  const typeName = (version === 6 ? types6 : types4)[type] ?? `Unknown type ${type}`;
  const codeNames = (version === 6 ? codes6 : codes4)[type];
  Object.assign(result, {type, code, checksum: v.getUint16(2), typeName,
    codeName: codeNames?.[code] ?? (code === 0 ? 'No code' : `Unknown code ${code}`), info: typeName});
  if (codeNames || code) result.info += ` (${result.codeName})`;
  const echo = version === 6 ? [128, 129].includes(type) : [0, 8, 13, 14, 17, 18].includes(type);
  const errorMessage = version === 6 ? [1, 2, 3, 4].includes(type) : [3, 4, 5, 11, 12].includes(type);
  const required = version === 4 && [13, 14].includes(type) ? 20
    : version === 4 && [17, 18].includes(type) ? 12 : echo || errorMessage ? 8 : 4;
  if (bytes.length < required) return fail(`Truncated ${protocol} ${typeName.toLowerCase()}`);
  if (echo) {
    result.identifier = v.getUint16(4); result.sequence = v.getUint16(6);
    result.info += ` id=${result.identifier} seq=${result.sequence}`;
  }
  if (version === 4 && [13, 14].includes(type)) {
    result.originateTimestamp = v.getUint32(8);
    result.receiveTimestamp = v.getUint32(12); result.transmitTimestamp = v.getUint32(16);
  }
  if (version === 4 && [17, 18].includes(type)) result.addressMask = Array.from(bytes.subarray(8, 12)).join('.');
  if (version === 4 && type === 5) result.gateway = Array.from(bytes.subarray(4, 8)).join('.');
  if ((version === 4 && type === 12) || (version === 6 && type === 4)) result.pointer = version === 4 ? bytes[4] : v.getUint32(4);
  if ((version === 4 && type === 3 && code === 4) || (version === 6 && type === 2)) {
    result.mtu = version === 4 ? v.getUint16(6) : v.getUint32(4);
    result.info += ` MTU=${result.mtu}`;
  }
  // Error quotes may intentionally contain only a prefix of the original packet.
  // Keep them separate from encapsulated packets and never apply stream state.
  const data = bytes.subarray(required);
  result.dataLength = data.length;
  result[errorMessage ? 'quotedPacket' : 'data'] = hex(data.subarray(0, 256));
  if (data.length > 256) result.previewTruncated = true;
  return result;
}

export default {
  name: 'icmp',
  matches: packet => ['ICMP', 'ICMPv6'].includes(packet.protocol),
  dissect: dissectIcmp,
};
