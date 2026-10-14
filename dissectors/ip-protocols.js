// Packet-local headers for common IP protocols; encrypted bodies remain opaque.
const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
export function dissectIpProtocol(bytes, packet) {
  const protocol = packet.protocol, result = {protocol};
  const fail = error => ({...result, error, info: error});
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const minimum = {ESP: 8, SCTP: 12, GRE: 4, PIM: 4, VRRP: 8, IGMP: 8}[protocol];
  if (bytes.length < minimum) return fail(`Truncated ${protocol} header`);
  let p = minimum;
  if (protocol === 'ESP') Object.assign(result, {spi: v.getUint32(0), sequence: v.getUint32(4), encrypted: true});
  if (protocol === 'SCTP') {
    Object.assign(result, {sourcePort: v.getUint16(0), destinationPort: v.getUint16(2), verificationTag: v.getUint32(4), checksum: v.getUint32(8, true), chunks: []});
    while (p < bytes.length) {
      if (p + 4 > bytes.length) return fail('Truncated SCTP chunk');
      const length = v.getUint16(p + 2);
      if (length < 4 || p + length > bytes.length) return fail('Invalid or truncated SCTP chunk');
      result.chunks.push({type: bytes[p], flags: bytes[p + 1], length, data: hex(bytes.subarray(p + 4, Math.min(p + length, p + 260)))});
      p += Math.ceil(length / 4) * 4;
      if (p > bytes.length) return fail('Truncated SCTP chunk padding');
    }
  }
  if (protocol === 'GRE') {
    const flags = v.getUint16(0);
    Object.assign(result, {flags, version: flags & 7, protocolType: v.getUint16(2)});
    if ((flags & 7) || (flags & 0x4000)) return fail('Unsupported GRE version or routing header');
    for (const [flag, field] of [[0x8000, 'checksum'], [0x2000, 'key'], [0x1000, 'sequence']]) {
      if (!(flags & flag)) continue;
      if (p + 4 > bytes.length) return fail('Truncated GRE optional header');
      result[field] = flag === 0x8000 ? v.getUint16(p) : v.getUint32(p); p += 4;
    }
  }
  if (protocol === 'PIM') Object.assign(result, {version: bytes[0] >> 4, type: bytes[0] & 15, checksum: v.getUint16(2)});
  if (protocol === 'VRRP') Object.assign(result, {version: bytes[0] >> 4, type: bytes[0] & 15, virtualRouterId: bytes[1], priority: bytes[2], addressCount: bytes[3], checksum: v.getUint16(6)});
  if (protocol === 'IGMP') Object.assign(result, {type: bytes[0], maxResponseTime: bytes[1], checksum: v.getUint16(2), group: Array.from(bytes.subarray(4, 8)).join('.')});
  result.dataLength = bytes.length - p; result.data = hex(bytes.subarray(p, p + 256));
  if (result.dataLength > 256) result.previewTruncated = true;
  result.info = `${protocol}${result.spi !== undefined ? ` SPI=${result.spi} Seq=${result.sequence}` : ''}`;
  return result;
}
export default {name: 'ip-protocols', matches: packet => ['ESP', 'SCTP', 'GRE', 'PIM', 'VRRP', 'IGMP'].includes(packet.protocol), dissect: dissectIpProtocol};
