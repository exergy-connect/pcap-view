// IEEE 802.1AX LACPDU, including the Slow Protocols subtype byte.
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(':');
const stateBits = ['activity', 'timeout', 'aggregation', 'synchronization', 'collecting', 'distributing', 'defaulted', 'expired'];

export function dissectLacp(bytes) {
  const result = {protocol: 'LACP', tlvs: []};
  const fail = error => ({...result, info: error, error});
  if (bytes.length < 2) return fail('Truncated LACP header');
  result.subtype = bytes[0]; result.version = bytes[1];
  if (result.subtype !== 1) return fail(`Invalid LACP subtype ${result.subtype}`);
  if (result.version !== 1) return fail(`Unsupported LACP version ${result.version}`);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 2;
  for (const [type, length, name] of [[1, 20, 'actor'], [2, 20, 'partner'], [3, 16, 'collector'], [0, 0, 'terminator']]) {
    if (offset + 2 > bytes.length) return fail(`Truncated LACP ${name} TLV header`);
    const actualType = bytes[offset], actualLength = bytes[offset + 1];
    const tlv = {type: actualType, length: actualLength};
    result.tlvs.push(tlv);
    if (actualType !== type) return fail(`Invalid LACP TLV order: expected ${name}, got type ${actualType}`);
    if (actualLength !== length) return fail(`Invalid LACP ${name} TLV length ${actualLength} (expected ${length})`);
    if (type === 0) {
      result.info = `LACP v${result.version} Actor ${result.actor.system} port ${result.actor.port} key ${result.actor.key} → Partner ${result.partner.system} port ${result.partner.port} key ${result.partner.key}`;
      return result; // Remaining bytes are reserved/padding.
    }
    if (offset + length > bytes.length) return fail(`Truncated LACP ${name} TLV`);
    tlv.value = hex(bytes.subarray(offset + 2, offset + length));
    if (type === 3) {
      result.collector = {maxDelay: view.getUint16(offset + 2)};
    } else {
      const state = bytes[offset + 16];
      result[name] = {
        systemPriority: view.getUint16(offset + 2), system: hex(bytes.subarray(offset + 4, offset + 10)),
        key: view.getUint16(offset + 10), portPriority: view.getUint16(offset + 12),
        port: view.getUint16(offset + 14), state,
        stateFlags: Object.fromEntries(stateBits.map((name, bit) => [name, Boolean(state & (1 << bit))])),
      };
    }
    offset += length;
  }
}

export default {
  name: 'lacp',
  matches: packet => packet.protocol === 'LACP',
  dissect: dissectLacp,
};
