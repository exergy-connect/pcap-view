import {preview} from './transport.js';

export function dissectUdp(bytes) {
  const result = {protocol: 'UDP'};
  const fail = error => ({...result, info: error, error});
  if (bytes.length < 8) return fail('Truncated UDP header');
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  Object.assign(result, {sport: v.getUint16(0), dport: v.getUint16(2), length: v.getUint16(4), checksum: v.getUint16(6)});
  if (result.length < 8) return fail('Invalid UDP length');
  preview(result, bytes.subarray(8, Math.min(bytes.length, result.length)));
  result.declaredPayloadLength = result.length - 8;
  if (result.length > bytes.length) return fail('Truncated UDP datagram');
  result.info = `${result.sport} → ${result.dport} Len=${result.declaredPayloadLength}`;
  return result;
}

export default {name: 'udp', layer: 'transport', matches: packet => packet.protocol === 'UDP', dissect: dissectUdp};
