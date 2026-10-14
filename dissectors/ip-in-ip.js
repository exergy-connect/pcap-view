import {decode} from '../decode.js';
import {transportBytes} from './transport.js';
import {ipv6Bytes} from './ipv6.js';
import {summarizeEthernetInIp} from './ethernet-in-ip.js';
export function dissectIpInIp(bytes, packet, context = {flows: new Map()}, helpers) {
  const protocol = packet.protocol, version = protocol === 'IPv4-in-IP' ? 4 : 6;
  const fail = error => ({protocol, info: error, error});
  if (bytes.length < (version === 4 ? 20 : 40)) return fail(`Truncated encapsulated IPv${version} header`);
  if (bytes[0] >> 4 !== version) return fail(`Invalid encapsulated IPv${version} version`);
  const inner = decode(bytes, version === 4 ? 228 : 229);
  const key = `${inner.source}:${inner.sport}:${inner.destination}:${inner.dport}`;
  let flow = context.flows.get(key);
  const syn = inner.protocol === 'TCP' && (inner.flags & 2) && !(inner.flags & 16);
  if (!flow || (syn && (flow.established || flow.closed))) {
    flow = {contexts: new Map(), established: false, closed: false}; context.flows.set(key, flow);
  }
  if (inner.flags & 16) flow.established = true;
  if (inner.flags & 5) flow.closed = true;
  if (inner.payload) helpers?.dissectInner?.(inner, flow.contexts);
  delete inner.payload; delete inner[transportBytes]; delete inner[ipv6Bytes];
  return {protocol, inner, info: summarizeEthernetInIp({protocol, inner})};
}
export default {name: 'ip-in-ip', matches: packet => ['IPv4-in-IP', 'IPv6-in-IP'].includes(packet.protocol),
  createContext: () => ({flows: new Map()}), dissect: dissectIpInIp};
