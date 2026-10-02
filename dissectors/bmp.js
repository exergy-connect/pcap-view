import {dissectBgp} from './bgp.js';

// BMP v3 common/per-peer headers, RFC 7854. Payloads are packet-local;
// TCP payloads are buffered independently for each stream direction.
const types = ['Route Monitoring', 'Statistics Report', 'Peer Down Notification',
  'Peer Up Notification', 'Initiation', 'Termination', 'Route Mirroring'];
const decoder = new TextDecoder();

export function dissectBmp(bytes) {
  if (!bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const messages = [];
  let offset = 0, error;
  while (offset < bytes.length) {
    if (bytes.length - offset < 6) {error = 'Truncated BMP common header'; break;}
    const version = bytes[offset], length = view.getUint32(offset + 1), type = bytes[offset + 5];
    if (version !== 3) {error = `Unsupported BMP version ${version}`; break;}
    if (length < 6) {error = `Invalid BMP message length ${length}`; break;}
    const message = {version, length, type, name: types[type] ?? `Unknown type ${type}`};
    messages.push(message);
    if (length > bytes.length - offset) {error = `Truncated BMP ${message.name} (${bytes.length - offset}/${length} bytes)`; break;}
    const end = offset + length;
    let p = offset + 6;
    if ([0, 1, 2, 3, 6].includes(type)) {
      if (end - p < 42) {error = 'Truncated BMP per-peer header'; break;}
      const flags = bytes[p + 1];
      const address = flags & 128
        ? Array.from({length: 8}, (_, i) => view.getUint16(p + 10 + i * 2).toString(16)).join(':')
        : Array.from(bytes.subarray(p + 22, p + 26)).join('.');
      message.peer = {type: bytes[p], flags, distinguisher: view.getBigUint64(p + 2).toString(),
        address, asn: view.getUint32(p + 26),
        bgpId: Array.from(bytes.subarray(p + 30, p + 34)).join('.'),
        timestamp: view.getUint32(p + 34) + view.getUint32(p + 38) / 1e6};
      p += 42;
    }
    if (type === 4 || type === 5 || type === 6) {
      message.tlvs = [];
      while (p < end) {
        if (end - p < 4) {error = 'Truncated BMP TLV header'; break;}
        const tlvType = view.getUint16(p), size = view.getUint16(p + 2); p += 4;
        if (size > end - p) {error = 'Truncated BMP TLV value'; break;}
        const value = Array.from(bytes.subarray(p, p + size));
        const tlv = {type: tlvType, length: size, value};
        if (type === 4 || (type === 5 && tlvType === 0)) tlv.text = decoder.decode(bytes.subarray(p, p + size));
        if (type === 5 && tlvType === 1 && size === 2) tlv.reason = view.getUint16(p);
        if (type === 6 && tlvType === 0) tlv.bgp = dissectBgp(bytes.subarray(p, p + size), {asnBytes: message.peer.flags & 32 ? 2 : 4});
        message.tlvs.push(tlv); p += size;
      }
    } else if (type === 1) {
      if (end - p < 4) {error = 'Truncated BMP statistics count'; break;}
      message.statisticsCount = view.getUint32(p);
    } else if (type === 2) {
      if (p === end) {error = 'Truncated BMP peer-down reason'; break;}
      message.reason = bytes[p++];
      if ([1, 3].includes(message.reason)) message.bgp = dissectBgp(bytes.subarray(p, end));
    } else if (type === 0) {
      if (end - p < 19) {error = 'Truncated BMP BGP header'; break;}
      message.bgp = dissectBgp(bytes.subarray(p, end), {asnBytes: message.peer.flags & 32 ? 2 : 4});
    } else if (type === 3) {
      if (end - p < 20) {error = 'Truncated BMP peer-up header'; break;}
      message.localPort = view.getUint16(p + 16);
      message.remotePort = view.getUint16(p + 18);
      p += 20;
      message.sentOpen = dissectBgp(bytes.subarray(p, end));
      if (!message.sentOpen.error) {
        p += message.sentOpen.length;
        message.receivedOpen = dissectBgp(bytes.subarray(p, end));
      }
    }
    if (error) break;
    offset = end;
  }
  const summaries = messages.map(m => `${m.name}${m.peer ? ` Peer=${m.peer.address} AS=${m.peer.asn}` : ''}${m.tlvs ? m.tlvs.filter(t => t.text).map(t => ` ${t.text}`).join('') : ''}`);
  if (error) summaries.push(error);
  return {protocol: 'BMP', info: summaries.join('; '), messages, ...(error ? {error} : {})};
}

export default {
  name: 'bmp',
  matches: packet => packet.protocol === 'TCP' && (packet.sport === 11019 || packet.dport === 11019),
  probe(payload, packet) {
    if (packet.protocol !== 'TCP') return 0;
    // A complete plausible common header is stronger evidence than a port.
    if (payload.length >= 6 && payload[0] === 3) {
      const length = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(1);
      if (length >= 6 && length <= 16 * 1024 * 1024) return 100;
    }
    return packet.sport === 11019 || packet.dport === 11019 ? 1 : 0;
  },
  createContext: () => ({pending: new Uint8Array(), nextSequence: null}),
  dissect: dissectBmpSegment,
};


// Serial-number arithmetic supports wraparound and overlapping retransmissions.
export function dissectBmpSegment(payload, packet, context) {
  if (!payload.length) return null;
  let sequence = (packet.sequence + ((packet.flags & 2) ? 1 : 0)) >>> 0;
  let gap = false;
  if (context.nextSequence !== null) {
    const delta = (sequence - context.nextSequence) | 0;
    if (delta < 0) {
      const overlap = -delta;
      if (overlap >= payload.length) return {protocol: 'BMP', info: 'BMP TCP retransmission', messages: []};
      payload = payload.subarray(overlap);
      sequence = context.nextSequence;
    } else if (delta > 0) {
      context.pending = new Uint8Array(); gap = true;
    }
  }
  context.nextSequence = (sequence + payload.length) >>> 0;
  const bytes = new Uint8Array(context.pending.length + payload.length);
  bytes.set(context.pending); bytes.set(payload, context.pending.length);
  const view = new DataView(bytes.buffer);
  let offset = 0;
  while (bytes.length - offset >= 6) {
    const length = view.getUint32(offset + 1);
    if (bytes[offset] !== 3 || length < 6 || length > 16 * 1024 * 1024) {
      context.pending = new Uint8Array();
      return dissectBmp(bytes);
    }
    if (length > bytes.length - offset) break;
    offset += length;
  }
  context.pending = bytes.slice(offset);
  const result = offset ? dissectBmp(bytes.subarray(0, offset)) : {protocol: 'BMP', info: '', messages: []};
  if (context.pending.length) {
    const waiting = `BMP continuation (${context.pending.length} buffered bytes; awaiting TCP data)`;
    result.info = result.info ? `${result.info}; ${waiting}` : waiting;
    result.pendingBytes = context.pending.length;
  }
  if (gap) {
    result.error = 'TCP sequence gap; BMP framing may be incomplete';
    result.info += `; ${result.error}`;
  }
  return result;
}
