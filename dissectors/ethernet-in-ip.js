import {decode} from '../decode.js';

export function summarizeEthernetInIp({protocol, inner}) {
  return `${protocol} ${inner.protocol} ${inner.sourceNames?.[0] || inner.source} → ${inner.destinationNames?.[0] || inner.destination}; ${inner.info}`;
}

export function dissectEthernetInIp(frame, packet = {}, context = {flows: new Map()}, helpers) {
  const result = {protocol: 'Ethernet-in-IP'};
  if (frame.length < 14) return {...result, info: 'Truncated encapsulated Ethernet header', error: 'Truncated encapsulated Ethernet header'};
  const inner = decode(frame, 1);
  const mac = start => Array.from(frame.subarray(start, start + 6), b => b.toString(16).padStart(2, '0')).join(':');
  inner.sourceMac = mac(6); inner.destinationMac = mac(0);
  if (helpers?.dissectInner && inner.payload) {
    const key = `${inner.sourceMac}:${inner.destinationMac}:${inner.source}:${inner.sport}:${inner.destination}:${inner.dport}`;
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
  return {...result, inner, info: summarizeEthernetInIp({...result, inner})};
}

export default {
  name: 'ethernet-in-ip',
  matches: packet => packet.protocol === 'Ethernet-in-IP',
  createContext: () => ({flows: new Map()}),
  dissect: dissectEthernetInIp,
};

