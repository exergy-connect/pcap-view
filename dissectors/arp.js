// RFC 826: address sizes come from the header, not the link type.
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(':');
const operations = {1: 'Request', 2: 'Reply', 3: 'Reverse request', 4: 'Reverse reply', 8: 'Inverse request', 9: 'Inverse reply'};

export function dissectArp(bytes) {
  const result = {protocol: 'ARP'};
  const fail = error => ({...result, info: error, error});
  if (bytes.length < 8) return fail('Truncated ARP header');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const hardwareType = view.getUint16(0), protocolType = view.getUint16(2);
  const hardwareLength = bytes[4], protocolLength = bytes[5], operation = view.getUint16(6);
  Object.assign(result, {hardwareType, protocolType, hardwareLength, protocolLength, operation,
    operationName: operations[operation] ?? `Unknown operation ${operation}`});
  if (!hardwareLength || !protocolLength) return fail('Invalid ARP address length');
  if (bytes.length < 8 + 2 * (hardwareLength + protocolLength)) return fail('Truncated ARP addresses');
  let offset = 8;
  const take = length => {const address = bytes.subarray(offset, offset + length); offset += length; return address;};
  const protocolAddress = address => {
    if (protocolType === 0x0800 && protocolLength === 4) return Array.from(address).join('.');
    if (protocolType === 0x86dd && protocolLength === 16) {
      const v = new DataView(address.buffer, address.byteOffset, address.byteLength);
      return Array.from({length: 8}, (_, i) => v.getUint16(i * 2).toString(16)).join(':');
    }
    return hex(address);
  };
  result.senderHardwareAddress = hex(take(hardwareLength));
  result.senderProtocolAddress = protocolAddress(take(protocolLength));
  result.targetHardwareAddress = hex(take(hardwareLength));
  result.targetProtocolAddress = protocolAddress(take(protocolLength));
  result.info = operation === 1 ? `Who has ${result.targetProtocolAddress}? Tell ${result.senderProtocolAddress}`
    : operation === 2 ? `${result.senderProtocolAddress} is at ${result.senderHardwareAddress}`
    : `${result.operationName}: ${result.senderProtocolAddress} → ${result.targetProtocolAddress}`;
  return result;
}

export default {
  name: 'arp',
  matches: packet => packet.protocol === 'ARP',
  dissect: dissectArp,
};
