import {decode} from './decode.js';
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
