import {decode} from '../decode.js';

export function summarizeVxlan({vni, inner}) {
  return `VNI=${vni} ${inner.protocol} ${inner.sourceNames?.[0] || inner.source} → ${inner.destinationNames?.[0] || inner.destination}; ${inner.info}`;
}

export function dissectVxlan(bytes, packet = {}, context = {flows: new Map()}, helpers) {
  if (bytes.length < 8) return {protocol: 'VXLAN', info: 'Truncated VXLAN header', error: 'Truncated VXLAN header'};
  const flags = bytes[0], vni = bytes[4] * 65536 + bytes[5] * 256 + bytes[6];
  if (!(flags & 8)) return {protocol: 'VXLAN', flags, vni, info: 'Invalid VXLAN header: VNI flag unset', error: 'VNI flag unset'};
  const frame = bytes.subarray(8);
  const inner = decode(frame, 1);
  if (helpers?.dissectInner && inner.payload) {
    // Outer context scopes the tunnel; VNI and directional inner endpoints
    // isolate application buffers without adding inner TCP streams to the UI.
    const key = `${vni}:${inner.source}:${inner.sport}:${inner.destination}:${inner.dport}`;
    let flow = context.flows.get(key);
    const syn = inner.protocol === 'TCP' && (inner.flags & 2) && !(inner.flags & 16);
    if (!flow || (syn && (flow.established || flow.closed))) {
      flow = {contexts: new Map(), established: false, closed: false};
      context.flows.set(key, flow);
    }
    if (inner.flags & 16) flow.established = true;
    if (inner.flags & 5) flow.closed = true;
    helpers.dissectInner(inner, flow.contexts);
  }
  delete inner.payload;
  if (frame.length >= 14) {
    const mac = start => Array.from(frame.subarray(start, start + 6), b => b.toString(16).padStart(2, '0')).join(':');
    inner.sourceMac = mac(6); inner.destinationMac = mac(0);
  }
  return {protocol: 'VXLAN', flags, vni, inner, info: summarizeVxlan({vni, inner})};
}

export default {
  name: 'vxlan',
  probe(bytes, packet) {
    if (packet.protocol !== 'UDP') return 0;
    if (packet.sport === 4789 || packet.dport === 4789 || packet.sport === 8472 || packet.dport === 8472) return 100;
    return bytes.length >= 22 && bytes[0] === 8 && !bytes[1] && !bytes[2] && !bytes[3] && !bytes[7] ? 50 : 0;
  },
  createContext: () => ({flows: new Map()}),
  dissect: dissectVxlan,
};
