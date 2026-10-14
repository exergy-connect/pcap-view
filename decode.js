import {dissectArp} from './dissectors/arp.js';
import {dissectIpv6, ipv6Bytes, nextHeaderNames} from './dissectors/ipv6.js';
import {transportBytes} from './dissectors/transport.js';

// Shared packet-local link, network, and transport decoding.
export function decode(bytes, link) {
  const result = {source: '—', destination: '—', protocol: 'Unknown', info: `Link type ${link}`};
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const has = (p, n) => p + n <= bytes.length;
  const u16 = p => v.getUint16(p), u32 = p => v.getUint32(p);
  const ipv4 = p => Array.from(bytes.subarray(p, p + 4)).join('.');
  let p = 0, ether;
  if (link === 1) {
    if (!has(0,14)) return {...result, info:'Truncated Ethernet header'};
    ether = u16(12); p = 14;
    while ([0x8100,0x88a8,0x9100].includes(ether)) {if (!has(p,4)) return result; ether = u16(p+2); p += 4;}
  } else if (link === 101 || link === 228 || link === 229) ether = bytes[0] >> 4 === 6 ? 0x86dd : 0x0800;
  else if (link === 113) {if (!has(0,16)) return result; ether = u16(14); p = 16;}
  else if (link === 276) {if (!has(0,20)) return result; ether = u16(0); p = 20;}
  else return result;
  // OSI protocols share FE-FE-03 LLC; the NLPID selects ESIS or IS-IS.
  const llc = ether === 0x8870 || (link === 1 && ether <= 1500) || ([113, 276].includes(link) && ether === 4);
  if (llc) {
    const end = link === 1 && ether <= 1500 ? Math.min(bytes.length, p + ether) : bytes.length;
    const payload = bytes.subarray(p, end);
    const addresses = link === 1 ? {
      source: Array.from(bytes.subarray(6, 12), b => b.toString(16).padStart(2, '0')).join(':'),
      destination: Array.from(bytes.subarray(0, 6), b => b.toString(16).padStart(2, '0')).join(':'),
    } : {};
    if (payload.length < 3) return {...result, ...addresses, protocol: 'LLC', info: ether === 0x8870 ? 'Jumbo LLC (EtherType 0x8870): truncated LLC header' : 'Truncated LLC header'};
    if (payload[0] === 0xfe && payload[1] === 0xfe && payload[2] === 3) {
      const protocol = payload[3] === 0x82 ? 'ESIS' : payload[3] === 0x83 || payload.length === 3 ? 'IS-IS' : 'OSI';
      return {...result, ...addresses, protocol, info: `${protocol}${ether === 0x8870 ? ' over Jumbo LLC' : ''}`, payload: payload.subarray(3)};
    }
    const hex = n => n.toString(16).padStart(2, '0');
    return {...result, ...addresses, protocol: 'LLC', info: `${ether === 0x8870 ? 'Jumbo LLC (EtherType 0x8870)' : 'LLC'}: DSAP 0x${hex(payload[0])}, SSAP 0x${hex(payload[1])}, Control 0x${hex(payload[2])}`};
  }
  if (ether === 0x8809) {
    const payload = bytes.subarray(p), isLacp = payload[0] === 1;
    return {...result, protocol: isLacp ? 'LACP' : 'Slow Protocols',
      info: isLacp ? 'Link Aggregation Control Protocol' : `Slow Protocols${payload.length ? ` subtype ${payload[0]}` : ': truncated subtype'}`,
      payload,
      ...(link === 1 ? {source: Array.from(bytes.subarray(6, 12), b => b.toString(16).padStart(2, '0')).join(':'),
        destination: Array.from(bytes.subarray(0, 6), b => b.toString(16).padStart(2, '0')).join(':')} : {})};
  }
  if (ether === 0x8915) {
    return {...result, protocol: 'RoCE', info: 'RDMA over Converged Ethernet', payload: bytes.subarray(p),
      ...(link === 1 ? {source: Array.from(bytes.subarray(6, 12), b => b.toString(16).padStart(2, '0')).join(':'),
        destination: Array.from(bytes.subarray(0, 6), b => b.toString(16).padStart(2, '0')).join(':')} : {})};
  }
  if (ether === 0x88cc) {
    return {...result, protocol: 'LLDP', info: 'Link Layer Discovery', payload: bytes.subarray(p),
      ...(link === 1 ? {source: Array.from(bytes.subarray(6, 12), b => b.toString(16).padStart(2, '0')).join(':'),
        destination: Array.from(bytes.subarray(0, 6), b => b.toString(16).padStart(2, '0')).join(':')} : {})};
  }
  if (ether === 0x0806) {
    const payload = bytes.subarray(p), arp = dissectArp(payload);
    return {...result, protocol: 'ARP', info: 'Address resolution', payload,
      ...(arp.senderProtocolAddress ? {source: arp.senderProtocolAddress, destination: arp.targetProtocolAddress} : {})};
  }
  let proto, limit = bytes.length;
  if (ether === 0x0800) {
    result.protocol = 'IPv4';
    if (!has(p,20)) return {...result, info:'Truncated IPv4 header'};
    const header = (bytes[p] & 15) * 4, total = u16(p+2);
    if (header < 20 || !has(p,header) || total < header) return {...result,info:'Invalid IPv4 header'};
    result.source = ipv4(p+12); result.destination = ipv4(p+16); proto = bytes[p+9]; limit = Math.min(limit,p+total);
    if (u16(p+6) & 0x1fff) return {...result, info:'IPv4 fragment'};
    p += header;
  } else if (ether === 0x86dd) {
    result.protocol = 'IPv6';
    const network = bytes.subarray(p), details = dissectIpv6(network);
    result[ipv6Bytes] = network;
    if (details.source) {result.source = details.source; result.destination = details.destination;}
    if (details.error || details.fragment) return {...result, payload: new Uint8Array(), info: details.info};
    proto = details.upperProtocol; limit = p + details.capturedLength; p += details.payloadOffset;
  } else return {...result, protocol: 'Ethernet', info: `EtherType 0x${ether.toString(16)}`};
  if (proto === 4 || proto === 41) return {...result, protocol: nextHeaderNames[proto],
    payload: bytes.subarray(p, limit), info: nextHeaderNames[proto]};
  if (proto === 59) return {...result, payload: new Uint8Array(), info: 'IPv6 No Next Header'};
  if (proto === 143) {
    const protocol = 'Ethernet-in-IP';
    return {...result, protocol, payload: bytes.subarray(p, limit), info: protocol};
  }
  if (proto === 253) return {...result, protocol: 'UET', payload: bytes.subarray(p, limit), info: 'Native UET'};
  if (proto === 89) return {...result, protocol: 'OSPF', payload: bytes.subarray(p, limit), info: 'OSPF'};
  if (proto === 1 || proto === 58) return {...result, protocol: proto === 1 ? 'ICMP' : 'ICMPv6', payload: bytes.subarray(p, limit), info: `IP protocol ${proto}`};
  if (proto === 6) {
    result[transportBytes] = {protocol: 'TCP', bytes: bytes.subarray(p, limit)};
    if (p+20 > limit) return {...result,payload:new Uint8Array(),info:'Truncated TCP header'};
    const header = (bytes[p+12] >> 4)*4;
    if (header < 20 || p+header > limit) return {...result,payload:new Uint8Array(),info:'Invalid or truncated TCP header'};
    const flags = bytes[p+13], names = ['FIN','SYN','RST','PSH','ACK','URG','ECE','CWR'].filter((_,i) => flags & (1<<i));
    return {...result,protocol:'TCP',payload:bytes.subarray(p+header,limit),sport:u16(p),dport:u16(p+2),flags,sequence:u32(p+4),acknowledgment:u32(p+8),info:`${u16(p)} → ${u16(p+2)} [${names.join(', ')}] Seq=${u32(p+4)} Ack=${u32(p+8)} Len=${limit-p-header}`};
  }
  if (proto === 17) {
    result[transportBytes] = {protocol: 'UDP', bytes: bytes.subarray(p, limit)};
    if (p+8 > limit) return {...result,payload:new Uint8Array(),info:'Truncated UDP header'};
    const length = u16(p+4);
    return {...result,protocol:'UDP',payload:length >= 8 ? bytes.subarray(p+8,Math.min(limit,p+length)) : new Uint8Array(),sport:u16(p),dport:u16(p+2),info:`${u16(p)} → ${u16(p+2)} Len=${Math.max(0,length-8)}`};
  }
  return {...result,protocol:nextHeaderNames[proto] ?? result.protocol,payload:bytes.subarray(p,limit),info:`IP protocol ${proto}${nextHeaderNames[proto] ? ` (${nextHeaderNames[proto]})` : ''}`};
}
