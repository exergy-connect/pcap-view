import bmp from './dissectors/bmp.js';
import bgp from './dissectors/bgp.js';
import vxlan from './dissectors/vxlan.js';
import http from './dissectors/http.js';
import arp from './dissectors/arp.js';
import lldp from './dissectors/lldp.js';
import lacp from './dissectors/lacp.js';
import mrc from './dissectors/mrc.js';
import roce from './dissectors/roce.js';
import ospf from './dissectors/ospf.js';
import isis from './dissectors/isis.js';
import ethernetInIp from './dissectors/ethernet-in-ip.js';
import icmp from './dissectors/icmp.js';
import tcp from './dissectors/tcp.js';
import udp from './dissectors/udp.js';
import {transportBytes} from './dissectors/transport.js';

const registry = new Map();
const selectedDissector = Symbol('selectedDissector');

// Register modules before parsing. Each has a name, matches(packet), and
// dissect(payload, packet) returning application fields or null.
export function registerDissector(dissector) {
  if (!dissector || typeof dissector.name !== 'string' || !dissector.name ||
      (typeof dissector.matches !== 'function' && typeof dissector.probe !== 'function') ||
      (dissector.probe !== undefined && typeof dissector.probe !== 'function') ||
      typeof dissector.dissect !== 'function') {
    throw new TypeError('Invalid dissector');
  }
  if (registry.has(dissector.name)) throw new Error(`Duplicate dissector: ${dissector.name}`);
  registry.set(dissector.name, dissector);
}

registerDissector(bmp);
registerDissector(bgp);
registerDissector(vxlan);
registerDissector(http);
registerDissector(arp);
registerDissector(lldp);
registerDissector(lacp);
registerDissector(mrc);
registerDissector(roce);
registerDissector(ospf);
registerDissector(isis);
registerDissector(ethernetInIp);
registerDissector(icmp);
registerDissector(tcp);
registerDissector(udp);

export function loadDissectors(names = 'all') {
  if (names === 'all') return [...registry.values()];
  if (!Array.isArray(names)) throw new TypeError('dissectors must be "all" or an array of names');
  return [...new Set(names)].map(name => {
    if (!registry.has(name)) throw new Error(`Unknown dissector: ${name}`);
    return registry.get(name);
  });
}

export function applyDissectors(packet, payload, dissectors, contexts = new Map(), depth = 0) {
  const raw = packet[transportBytes];
  delete packet[transportBytes];
  if (raw) {
    const transport = dissectors.find(d => d.layer === 'transport' && d.matches({protocol: raw.protocol}));
    if (transport) {
      const result = transport.dissect(raw.bytes, packet);
      if (result) {
        packet.transport = raw.protocol;
        packet.transportDetails = {dissector: transport.name, ...result};
        packet.application = packet.transportDetails;
        packet.protocol = result.protocol;
        packet.info = result.info;
      }
    }
  }
  const selected = contexts.get(selectedDissector);
  if (!payload.length && !['ARP', 'LLDP', 'LACP', 'RoCE', 'OSPF', 'IS-IS', 'Ethernet-in-IP', 'ICMP', 'ICMPv6'].includes(packet.protocol) && !(selected?.flushOnFin && (packet.flags & 1))) return;
  // Probe without mutating decoder state. Higher confidence wins; ties retain
  // the caller's order. Legacy match predicates remain low-confidence hints.
  const candidates = selected && dissectors.includes(selected)
    ? [selected]
    : dissectors.filter(d => d.layer !== 'transport').map((dissector, order) => ({
      dissector, order,
      score: dissector.probe ? dissector.probe(payload, packet)
        : (dissector.matches(packet) ? 1 : 0),
    })).filter(({score}) => Number.isFinite(score) && score > 0)
      .sort((a, b) => b.score - a.score || a.order - b.order)
      .map(({dissector}) => dissector);
  for (const dissector of candidates) {
    if (!contexts.has(dissector.name)) contexts.set(dissector.name, dissector.createContext?.() ?? {});
    const result = dissector.dissect(payload, packet, contexts.get(dissector.name), {
      dissectInner(inner, innerContexts) {
        if (inner.payload && depth < 8) applyDissectors(inner, inner.payload, dissectors, innerContexts, depth + 1);
      },
    });
    if (result) {
      if (packet.protocol === 'TCP') contexts.set(selectedDissector, dissector);
      packet.transport = packet.protocol;
      // Keep addresses, ports, flags, and stream identity owned by the parser.
      packet.protocol = result.protocol ?? dissector.name.toUpperCase();
      packet.info = result.info ?? packet.info;
      packet.application = {dissector: dissector.name, ...result};
      break;
    }
  }
}
