import bmp from './dissectors/bmp.js';

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

export function loadDissectors(names = 'all') {
  if (names === 'all') return [...registry.values()];
  if (!Array.isArray(names)) throw new TypeError('dissectors must be "all" or an array of names');
  return [...new Set(names)].map(name => {
    if (!registry.has(name)) throw new Error(`Unknown dissector: ${name}`);
    return registry.get(name);
  });
}

export function applyDissectors(packet, payload, dissectors, contexts = new Map()) {
  if (!payload.length) return;
  const selected = contexts.get(selectedDissector);
  // Probe without mutating decoder state. Higher confidence wins; ties retain
  // the caller's order. Legacy match predicates remain low-confidence hints.
  const candidates = selected && dissectors.includes(selected)
    ? [selected]
    : dissectors.map((dissector, order) => ({
      dissector, order,
      score: dissector.probe ? dissector.probe(payload, packet)
        : (dissector.matches(packet) ? 1 : 0),
    })).filter(({score}) => Number.isFinite(score) && score > 0)
      .sort((a, b) => b.score - a.score || a.order - b.order)
      .map(({dissector}) => dissector);
  for (const dissector of candidates) {
    if (!contexts.has(dissector.name)) contexts.set(dissector.name, dissector.createContext?.() ?? {});
    const result = dissector.dissect(payload, packet, contexts.get(dissector.name));
    if (result) {
      if (packet.protocol === 'TCP' && packet.stream != null) contexts.set(selectedDissector, dissector);
      packet.transport = packet.protocol;
      // Keep addresses, ports, flags, and stream identity owned by the parser.
      packet.protocol = result.protocol ?? dissector.name.toUpperCase();
      packet.info = result.info ?? packet.info;
      packet.application = {dissector: dissector.name, ...result};
      break;
    }
  }
}
