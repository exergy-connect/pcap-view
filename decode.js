// Shared packet-local link, network, and transport decoding.
export function decode(bytes, link) {
  const result = {source: '—', destination: '—', protocol: 'Unknown', info: `Link type ${link}`};
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const has = (p, n) => p + n <= bytes.length;
  const u16 = p => v.getUint16(p), u32 = p => v.getUint32(p);
  const ipv4 = p => Array.from(bytes.subarray(p, p + 4)).join('.');
  const ipv6 = p => Array.from({length: 8}, (_, i) => u16(p + 2 * i).toString(16)).join(':');
  let p = 0, ether;
  if (link === 1) {
    if (!has(0,14)) return {...result, info:'Truncated Ethernet header'};
    ether = u16(12); p = 14;
    while ([0x8100,0x88a8,0x9100].includes(ether)) {if (!has(p,4)) return result; ether = u16(p+2); p += 4;}
  } else if (link === 101 || link === 228 || link === 229) ether = bytes[0] >> 4 === 6 ? 0x86dd : 0x0800;
  else if (link === 113) {if (!has(0,16)) return result; ether = u16(14); p = 16;}
  else if (link === 276) {if (!has(0,20)) return result; ether = u16(0); p = 20;}
  else return result;
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
    if (!has(p,40)) return {...result,info:'Truncated IPv6 header'};
    result.source = ipv6(p+8); result.destination = ipv6(p+24); proto = bytes[p+6];
    limit = Math.min(limit,p+40+u16(p+4)); p += 40;
    while ([0,43,44,51,60].includes(proto)) {
      if (p+2 > limit) return {...result, info:'Truncated IPv6 extension'};
      const next = bytes[p], len = proto === 44 ? 8 : proto === 51 ? (bytes[p+1]+2)*4 : (bytes[p+1]+1)*8;
      if (p+len > limit) return {...result,info:'Truncated IPv6 extension'};
      if (proto === 44 && (u16(p+2) & 0xfff8)) return {...result,info:'IPv6 fragment'};
      p += len; proto = next;
    }
  } else return {...result, protocol: ether === 0x0806 ? 'ARP' : 'Ethernet', info: ether === 0x0806 ? 'Address resolution' : `EtherType 0x${ether.toString(16)}`};
  if (proto === 6) {
    if (p+20 > limit) return {...result,info:'Truncated TCP header'};
    const header = (bytes[p+12] >> 4)*4;
    if (header < 20 || p+header > limit) return {...result,info:'Invalid or truncated TCP header'};
    const flags = bytes[p+13], names = ['FIN','SYN','RST','PSH','ACK','URG','ECE','CWR'].filter((_,i) => flags & (1<<i));
    return {...result,protocol:'TCP',payload:bytes.subarray(p+header,limit),sport:u16(p),dport:u16(p+2),flags,sequence:u32(p+4),acknowledgment:u32(p+8),info:`${u16(p)} → ${u16(p+2)} [${names.join(', ')}] Seq=${u32(p+4)} Ack=${u32(p+8)} Len=${limit-p-header}`};
  }
  if (proto === 17 && p+8 <= limit) return {...result,protocol:'UDP',payload:bytes.subarray(p+8,Math.min(limit,p+u16(p+4))),sport:u16(p),dport:u16(p+2),info:`${u16(p)} → ${u16(p+2)} Len=${Math.max(0,u16(p+4)-8)}`};
  return {...result,protocol:proto === 1 ? 'ICMP' : proto === 58 ? 'ICMPv6' : result.protocol,info:`IP protocol ${proto}`};
}
