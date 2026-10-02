import {decode} from '../decode.js';

export function dissectVxlan(bytes) {
  if (bytes.length < 8) return {protocol: 'VXLAN', info: 'Truncated VXLAN header', error: 'Truncated VXLAN header'};
  const flags = bytes[0], vni = bytes[4] * 65536 + bytes[5] * 256 + bytes[6];
  if (!(flags & 8)) return {protocol: 'VXLAN', flags, vni, info: 'Invalid VXLAN header: VNI flag unset', error: 'VNI flag unset'};
  const frame = bytes.subarray(8);
  const inner = decode(frame, 1);
  delete inner.payload;
  if (frame.length >= 14) {
    const mac = start => Array.from(frame.subarray(start, start + 6), b => b.toString(16).padStart(2, '0')).join(':');
    inner.sourceMac = mac(6); inner.destinationMac = mac(0);
  }
  return {protocol: 'VXLAN', flags, vni, inner, info: `VNI=${vni} ${inner.protocol} ${inner.source} → ${inner.destination}; ${inner.info}`};
}

export default {
  name: 'vxlan',
  probe(bytes, packet) {
    if (packet.protocol !== 'UDP') return 0;
    if (packet.sport === 4789 || packet.dport === 4789 || packet.sport === 8472 || packet.dport === 8472) return 100;
    return bytes.length >= 22 && bytes[0] === 8 && !bytes[1] && !bytes[2] && !bytes[3] && !bytes[7] ? 50 : 0;
  },
  dissect: dissectVxlan,
};
