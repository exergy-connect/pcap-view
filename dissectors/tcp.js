import {hex, preview} from './transport.js';

export function dissectTcp(bytes) {
  const result = {protocol: 'TCP'};
  const fail = error => ({...result, info: error, error});
  if (bytes.length < 20) return fail('Truncated TCP header');
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerLength = (bytes[12] >> 4) * 4;
  const flags = bytes[13];
  const flagNames = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'].filter((_, i) => flags & (1 << i));
  Object.assign(result, {sport: v.getUint16(0), dport: v.getUint16(2), sequence: v.getUint32(4),
    acknowledgment: v.getUint32(8), headerLength, reserved: bytes[12] & 15, flags, flagNames,
    window: v.getUint16(14), checksum: v.getUint16(16), urgentPointer: v.getUint16(18), options: []});
  if (headerLength < 20) return fail('Invalid TCP data offset');
  if (headerLength > bytes.length) return fail('Truncated TCP options');
  for (let p = 20; p < headerLength;) {
    const kind = bytes[p];
    if (kind === 0 || kind === 1) {
      result.options.push({kind, name: kind === 0 ? 'End of option list' : 'No operation', length: 1});
      p++;
      if (kind === 0) {result.padding = hex(bytes.subarray(p, headerLength)); break;}
      continue;
    }
    if (p + 2 > headerLength) return fail('Truncated TCP option length');
    const length = bytes[p + 1];
    if (length < 2 || p + length > headerLength) return fail('Invalid TCP option length');
    const option = {kind, length, data: hex(bytes.subarray(p + 2, p + length))};
    result.options.push(option);
    const expected = {2: 4, 3: 3, 4: 2, 8: 10}[kind];
    if ((expected && length !== expected) || (kind === 5 && (length < 10 || (length - 2) % 8))) return fail('Invalid TCP option length');
    if (kind === 2) Object.assign(option, {name: 'Maximum segment size', value: v.getUint16(p + 2)});
    if (kind === 3) Object.assign(option, {name: 'Window scale', shift: bytes[p + 2]});
    if (kind === 4) option.name = 'SACK permitted';
    if (kind === 5) {
      option.name = 'SACK'; option.blocks = [];
      for (let q = p + 2; q < p + length; q += 8) option.blocks.push({left: v.getUint32(q), right: v.getUint32(q + 4)});
    }
    if (kind === 8) Object.assign(option, {name: 'Timestamps', value: v.getUint32(p + 2), echoReply: v.getUint32(p + 6)});
    p += length;
  }
  preview(result, bytes.subarray(headerLength));
  result.info = `${result.sport} → ${result.dport} [${flagNames.join(', ')}] Seq=${result.sequence} Ack=${result.acknowledgment} Len=${result.payloadLength}`;
  return result;
}

export default {name: 'tcp', layer: 'transport', matches: packet => packet.protocol === 'TCP', dissect: dissectTcp};
