import {dissectIpInIp} from './ip-in-ip.js';

export function summarizeMpls({labels, inner}) {
  const stack = `MPLS Label=${labels.map(entry => entry.label).join('/')}`;
  return inner ? `${stack}; ${inner.protocol} ${inner.sourceNames?.[0] || inner.source} → ${inner.destinationNames?.[0] || inner.destination}; ${inner.info}` : stack;
}

export function dissectMpls(bytes, packet = {}, context = {stacks: new Map()}, helpers) {
  const result = {protocol: 'MPLS', labels: []};
  const fail = error => ({...result, error, info: error});
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0, bottom;
  do {
    if (offset + 4 > bytes.length) return fail(offset === bytes.length && offset > 0
      ? 'MPLS label stack missing bottom-of-stack entry' : 'Truncated MPLS label stack entry');
    const word = view.getUint32(offset);
    bottom = {label: word >>> 12, trafficClass: (word >>> 9) & 7, bottomOfStack: !!(word & 256), ttl: word & 255};
    result.labels.push(bottom);
    offset += 4;
  } while (!bottom.bottomOfStack);
  const payload = bytes.subarray(offset), version = payload[0] >>> 4;
  result.payloadLength = payload.length;
  // A version-nibble heuristic applies to ordinary forwarding labels. Other
  // special-purpose labels (e.g. GAL) carry payloads with their own formats.
  if (bottom.label === 0 || bottom.label === 2 || (bottom.label >= 16 && [4, 6].includes(version))) {
    const expected = bottom.label === 0 ? 4 : bottom.label === 2 ? 6 : version;
    const key = result.labels.map(entry => entry.label).join('/');
    let stack = context.stacks.get(key);
    if (!stack) {stack = {flows: new Map()}; context.stacks.set(key, stack);}
    const decoded = dissectIpInIp(payload, {protocol: expected === 4 ? 'IPv4-in-IP' : 'IPv6-in-IP'}, stack, helpers);
    if (decoded.error) return fail(decoded.error);
    result.inner = decoded.inner;
  } else {
    result.rawPayload = Array.from(payload, b => b.toString(16).padStart(2, '0')).join(':');
  }
  return {...result, info: summarizeMpls(result)};
}

export default {name: 'mpls', matches: packet => packet.protocol === 'MPLS',
  createContext: () => ({stacks: new Map()}), dissect: dissectMpls};
