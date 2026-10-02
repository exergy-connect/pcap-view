import {loadDissectors, applyDissectors} from './dissectors.js';

// PCAPNG section, interface, and packet blocks; packet fields use network byte order.
export function parsePcapng(buffer, {dissectors = 'all'} = {}) {
  const enabled = loadDissectors(dissectors);
  const dissectionContexts = new Map();
  const view = new DataView(buffer), packets = [], streams = [], flows = new Map();
  const nameMaps = [], textDecoder = new TextDecoder();
  let offset = 0, little = true, interfaces = [], section = -1;
  const fail = message => { throw new Error(`${message} at byte ${offset}.`); };
  const u16 = p => view.getUint16(p, little), u32 = p => view.getUint32(p, little);
  while (offset < buffer.byteLength) {
    if (offset + 12 > buffer.byteLength) fail('Truncated block');
    const isSection = view.getUint32(offset, false) === 0x0a0d0d0a;
    if (isSection) {
      const magic = view.getUint32(offset + 8, false);
      if (magic !== 0x1a2b3c4d && magic !== 0x4d3c2b1a) fail('Invalid byte-order marker');
      little = magic === 0x4d3c2b1a;
    } else if (section < 0) fail('Not a PCAPNG file');
    const type = u32(offset), size = u32(offset + 4), end = offset + size - 4;
    if (size < 12 || size % 4 || offset + size > buffer.byteLength) fail('Invalid block length');
    if (u32(end) !== size) fail('Block length mismatch');
    if (isSection) {
      if (size < 28) fail('Invalid section header');
      if (u16(offset + 12) !== 1) fail('Unsupported PCAPNG version');
      interfaces = []; section++; nameMaps.push(new Map());
    } else if (type === 1) {
      if (size < 20) fail('Invalid interface block');
      const iface = {link: u16(offset + 8), snap: u32(offset + 12), resolution: 1e-6, timeOffset: 0};
      for (let p = offset + 16; p + 4 <= end;) {
        const code = u16(p), len = u16(p + 2); p += 4;
        if (!code) break;
        if (p + len > end) fail('Invalid interface option');
        if (code === 9 && len === 1) { const r = view.getUint8(p); iface.resolution = r & 128 ? 2 ** -(r & 127) : 10 ** -r; }
        if (code === 14 && len === 8) iface.timeOffset = Number(view.getBigInt64(p, little));
        p += (len + 3) & ~3;
      }
      interfaces.push(iface);
    } else if (type === 4) {
      let p = offset + 8, terminated = false;
      while (p + 4 <= end) {
        const code = u16(p), len = u16(p + 2); p += 4;
        if (code === 0) {
          if (len !== 0) fail('Invalid name resolution terminator');
          terminated = true; break;
        }
        const padded = Math.ceil(len / 4) * 4;
        if (p + padded > end) fail('Truncated name resolution record');
        if (code === 1 || code === 2) {
          const addressLength = code === 1 ? 4 : 16;
          if (len < addressLength + 2 || view.getUint8(p + len - 1) !== 0) fail('Invalid name resolution record');
          const address = code === 1
            ? Array.from(new Uint8Array(buffer, p, 4)).join('.')
            : Array.from({length: 8}, (_, i) => view.getUint16(p + i * 2, false).toString(16)).join(':');
          const names = textDecoder.decode(new Uint8Array(buffer, p + addressLength, len - addressLength)).split('\0').filter(Boolean);
          const existing = nameMaps[section].get(address) || [];
          nameMaps[section].set(address, [...new Set([...existing, ...names])]);
        }
        p += padded;
      }
      if (!terminated) fail('Missing name resolution terminator');
    } else if (type === 6 || type === 2 || type === 3) {
      const simple = type === 3;
      if (size < (simple ? 16 : 32)) fail('Invalid packet block');
      const id = simple ? 0 : type === 2 ? u16(offset + 8) : u32(offset + 8);
      const iface = interfaces[id];
      if (!iface) fail('Packet references an unknown interface');
      const original = u32(offset + (simple ? 8 : 24));
      const captured = simple ? Math.min(original, iface.snap || original) : u32(offset + 20);
      const start = offset + (simple ? 12 : 28);
      if (start + ((captured + 3) & ~3) > end) fail('Truncated packet data');
      const time = simple ? null : (u32(offset + 12) * 4294967296 + u32(offset + 16)) * iface.resolution + iface.timeOffset;
      const packet = {number: packets.length + 1, section, time, length: original, captured, stream: null, ...decode(new Uint8Array(buffer, start, captured), iface.link)};
      if (packet.protocol === 'TCP') {
        const endpoints = [`${packet.source}|${packet.sport}`, `${packet.destination}|${packet.dport}`].sort();
        const key = `${section}:${id}:${endpoints.join('/')}`;
        let flow = flows.get(key);
        // A fresh SYN after a closed connection starts a new stream. SYN retransmits stay together.
        const syn = (packet.flags & 2) && !(packet.flags & 16);
        if (!flow || (syn && (flow.closed || flow.established))) {
          flow = {id: streams.length, closed: false, established: false}; flows.set(key, flow);
          streams.push({id: flow.id, section, source: packet.source, destination: packet.destination, sport: packet.sport, dport: packet.dport, count: 0});
        }
        if (packet.flags & 16) flow.established = true;
        if (packet.flags & 5) flow.closed = true;
        packet.stream = flow.id; streams[flow.id].count++;
      }
      if (packet.payload) {
        const key = `${packet.stream}:${packet.source}:${packet.sport}:${packet.destination}:${packet.dport}`;
        let contexts = dissectionContexts.get(key);
        if (!contexts) {contexts = new Map(); dissectionContexts.set(key, contexts);}
        applyDissectors(packet, packet.payload, enabled, contexts);
        delete packet.payload;
      }
      packets.push(packet);
    }
    offset += size;
  }
  if (section < 0) throw new Error('Not a PCAPNG file.');
  const base = packets.find(p => p.time !== null)?.time ?? 0;
  for (const p of packets) p.relativeTime = p.time === null ? null : p.time - base;
  // Resolve after parsing so mappings also apply to packets preceding their NRB.
  for (const endpoint of [...packets, ...streams]) {
    endpoint.sourceNames = nameMaps[endpoint.section].get(endpoint.source) || [];
    endpoint.destinationNames = nameMaps[endpoint.section].get(endpoint.destination) || [];
    delete endpoint.section;
  }
  return {packets, streams};
}

function decode(bytes, link) {
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
