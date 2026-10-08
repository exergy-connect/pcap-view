// BGP message bodies (RFC 4271). Unknown attributes retain their raw bytes.
const names = ['', 'OPEN', 'UPDATE', 'NOTIFICATION', 'KEEPALIVE', 'ROUTE-REFRESH'];
const attributeNames = {1: 'ORIGIN', 2: 'AS_PATH', 3: 'NEXT_HOP', 4: 'MULTI_EXIT_DISC',
  5: 'LOCAL_PREF', 6: 'ATOMIC_AGGREGATE', 7: 'AGGREGATOR', 8: 'COMMUNITIES',
  14: 'MP_REACH_NLRI', 15: 'MP_UNREACH_NLRI', 17: 'AS4_PATH', 18: 'AS4_AGGREGATOR', 32: 'LARGE_COMMUNITIES'};
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(' ');
const ipv4 = bytes => Array.from(bytes).join('.');

export function dissectBgp(bytes, {asnBytes = 4} = {}) {
  const message = {};
  let p = 0;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  function need(size, end = bytes.length) {
    if (p + size > end) throw new Error('Truncated BGP message');
  }
  function prefixes(end) {
    const result = [];
    while (p < end) {
      const length = bytes[p++], size = Math.ceil(length / 8);
      if (length > 32) throw new Error(`Invalid IPv4 prefix length ${length}`);
      need(size, end);
      const address = new Uint8Array(4); address.set(bytes.subarray(p, p + size)); p += size;
      if (length % 8) address[size - 1] &= 255 << (8 - length % 8);
      result.push(`${ipv4(address)}/${length}`);
    }
    return result;
  }
  try {
    need(19);
    message.marker = hex(bytes.subarray(0, 16));
    message.length = view.getUint16(16); message.type = bytes[18];
    message.name = names[message.type] ?? `Unknown type ${message.type}`;
    if (!bytes.subarray(0, 16).every(b => b === 255)) throw new Error('Invalid BGP marker');
    if (message.length < 19) throw new Error(`Invalid BGP message length ${message.length}`);
    if (message.length > bytes.length) throw new Error('Truncated BGP message');
    const end = message.length; p = 19;
    if (message.type === 1) {
      need(10, end);
      message.version = bytes[p++]; message.asn = view.getUint16(p); p += 2;
      message.holdTime = view.getUint16(p); p += 2;
      message.bgpId = ipv4(bytes.subarray(p, p + 4)); p += 4;
      message.optionalParametersLength = bytes[p++];
      const paramsEnd = p + message.optionalParametersLength; need(message.optionalParametersLength, end);
      message.optionalParameters = [];
      while (p < paramsEnd) {
        need(2, paramsEnd); const type = bytes[p++], length = bytes[p++]; need(length, paramsEnd);
        const param = {type, length, value: hex(bytes.subarray(p, p + length))};
        const paramEnd = p + length;
        if (type === 2) {
          param.capabilities = [];
          while (p < paramEnd) {
            need(2, paramEnd); const code = bytes[p++], size = bytes[p++]; need(size, paramEnd);
            const capability = {code, length: size, value: hex(bytes.subarray(p, p + size))};
            if (code === 65 && size === 4) capability.asn = view.getUint32(p);
            if (code === 1 && size === 4) {capability.afi = view.getUint16(p); capability.safi = bytes[p + 3];}
            param.capabilities.push(capability); p += size;
          }
        }
        p = paramEnd; message.optionalParameters.push(param);
      }
    } else if (message.type === 2) {
      need(2, end); message.withdrawnRoutesLength = view.getUint16(p); p += 2;
      need(message.withdrawnRoutesLength, end); message.withdrawnRoutes = prefixes(p + message.withdrawnRoutesLength);
      need(2, end); message.pathAttributesLength = view.getUint16(p); p += 2;
      const attrsEnd = p + message.pathAttributesLength; need(message.pathAttributesLength, end);
      message.pathAttributes = [];
      while (p < attrsEnd) {
        need(2, attrsEnd); const flags = bytes[p++], type = bytes[p++];
        need(flags & 16 ? 2 : 1, attrsEnd);
        const length = flags & 16 ? view.getUint16(p) : bytes[p]; p += flags & 16 ? 2 : 1;
        need(length, attrsEnd); const start = p, attrEnd = p + length;
        const attr = {flags: {raw: flags, optional: !!(flags & 128), transitive: !!(flags & 64), partial: !!(flags & 32), extendedLength: !!(flags & 16)},
          type, name: attributeNames[type] ?? `Unknown attribute ${type}`, length, raw: hex(bytes.subarray(p, attrEnd))};
        message.pathAttributes.push(attr);
        if (type === 1 && length === 1) attr.origin = ['IGP', 'EGP', 'INCOMPLETE'][bytes[p]] ?? bytes[p];
        else if (type === 3 && length === 4) attr.nextHop = ipv4(bytes.subarray(p, attrEnd));
        else if ([4, 5].includes(type) && length === 4) attr.value = view.getUint32(p);
        else if ([2, 17].includes(type)) {
          const width = type === 17 ? 4 : asnBytes; attr.segments = [];
          while (p < attrEnd) {
            need(2, attrEnd); const segmentType = bytes[p++], count = bytes[p++]; need(count * width, attrEnd);
            const segment = {type: segmentType, name: {1: 'AS_SET', 2: 'AS_SEQUENCE', 3: 'AS_CONFED_SEQUENCE', 4: 'AS_CONFED_SET'}[segmentType], asns: []};
            for (let i = 0; i < count; i++, p += width) segment.asns.push(width === 4 ? view.getUint32(p) : view.getUint16(p));
            attr.segments.push(segment);
          }
        } else if (type === 8 && length % 4 === 0) {
          attr.communities = []; for (; p < attrEnd; p += 4) attr.communities.push(`${view.getUint16(p)}:${view.getUint16(p + 2)}`);
        } else if (type === 32 && length % 12 === 0) {
          attr.communities = []; for (; p < attrEnd; p += 12) attr.communities.push(`${view.getUint32(p)}:${view.getUint32(p + 4)}:${view.getUint32(p + 8)}`);
        } else if ([7, 18].includes(type) && [6, 8].includes(length)) {
          const width = length - 4; attr.asn = width === 4 ? view.getUint32(start) : view.getUint16(start);
          attr.address = ipv4(bytes.subarray(start + width, attrEnd));
        }
        p = attrEnd;
      }
      message.nlri = prefixes(end);
    } else if (message.type === 3) {
      need(2, end); message.errorCode = bytes[p++]; message.errorSubcode = bytes[p++];
      message.data = hex(bytes.subarray(p, end)); p = end;
    } else if (message.type === 5) {
      need(4, end); message.afi = view.getUint16(p); message.subtype = bytes[p + 2]; message.safi = bytes[p + 3]; p += 4;
    }
    if (p < end) message.data = hex(bytes.subarray(p, end));
  } catch (error) {message.error = error.message;}
  return message;
}

export function dissectBgpSegment(payload, packet, context) {
  if (!payload.length) return null;
  let sequence = (packet.sequence + ((packet.flags & 2) ? 1 : 0)) >>> 0;
  let gap = false;
  if (context.nextSequence !== null && packet.sequence !== undefined) {
    const delta = (sequence - context.nextSequence) | 0;
    if (delta < 0) {
      if (-delta >= payload.length) return {protocol: 'BGP', info: 'BGP TCP retransmission', messages: []};
      payload = payload.subarray(-delta);
      sequence = context.nextSequence;
    } else if (delta > 0) {
      context.pending = new Uint8Array(); gap = true;
    }
  }
  context.nextSequence = (sequence + payload.length) >>> 0;
  const bytes = new Uint8Array(context.pending.length + payload.length);
  bytes.set(context.pending); bytes.set(payload, context.pending.length);
  const view = new DataView(bytes.buffer);
  const result = {protocol: 'BGP', info: '', messages: []};
  let offset = 0;
  while (bytes.length - offset >= 19) {
    const length = view.getUint16(offset + 16);
    const marker = bytes.subarray(offset, offset + 16).every(b => b === 255);
    if (!marker || length < 19) {
      const message = dissectBgp(bytes.subarray(offset));
      result.messages.push(message); result.error = message.error;
      offset = bytes.length; break;
    }
    if (length > bytes.length - offset) break;
    // Standalone BGP defaults to legacy two-octet AS_PATH encoding. BMP
    // supplies its per-peer ASN width explicitly to dissectBgp instead.
    const message = dissectBgp(bytes.subarray(offset, offset + length), {asnBytes: 2});
    result.messages.push(message);
    if (message.error) result.error = message.error;
    offset += length;
  }
  context.pending = bytes.slice(offset);
  const summaries = result.messages.map(message => `${message.name ?? 'BGP'}${message.error ? `: ${message.error}` : ''}`);
  if (context.pending.length) {
    result.pendingBytes = context.pending.length;
    summaries.push(`BGP continuation (${context.pending.length} buffered bytes; awaiting TCP data)`);
  }
  if (gap) {
    result.error = 'TCP sequence gap; BGP framing may be incomplete';
    summaries.push(result.error);
  }
  result.info = summaries.join('; ');
  return result;
}

export default {
  name: 'bgp',
  matches: packet => packet.protocol === 'TCP' && (packet.sport === 179 || packet.dport === 179),
  probe(payload, packet) {
    if (packet.protocol !== 'TCP') return 0;
    if (payload.length >= 19 && payload.subarray(0, 16).every(b => b === 255)) {
      const length = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint16(16);
      if (length >= 19 && payload[18] >= 1 && payload[18] <= 5) return 100;
    }
    return packet.sport === 179 || packet.dport === 179 ? 1 : 0;
  },
  createContext: () => ({pending: new Uint8Array(), nextSequence: null}),
  dissect: dissectBgpSegment,
};
