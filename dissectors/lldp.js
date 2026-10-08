// IEEE 802.1AB LLDP: seven-bit type and nine-bit length TLV headers.
const decoder = new TextDecoder();
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(':');
const names = ['End of LLDPDU', 'Chassis ID', 'Port ID', 'Time to Live',
  'Port Description', 'System Name', 'System Description', 'System Capabilities', 'Management Address'];
const capabilityNames = ['Other', 'Repeater', 'Bridge', 'WLAN Access Point', 'Router',
  'Telephone', 'DOCSIS Cable Device', 'Station Only', 'C-VLAN Component', 'S-VLAN Component', 'Two-port MAC Relay'];

function address(family, bytes) {
  if (family === 1 && bytes.length === 4) return Array.from(bytes).join('.');
  if (family === 2 && bytes.length === 16) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return Array.from({length: 8}, (_, i) => view.getUint16(i * 2).toString(16)).join(':');
  }
  return hex(bytes);
}

export function dissectLldp(bytes) {
  const result = {protocol: 'LLDP', tlvs: []};
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let p = 0, ended = false;
  try {
    while (p < bytes.length) {
      if (bytes.length - p < 2) throw new Error('Truncated LLDP TLV header');
      const header = view.getUint16(p), type = header >>> 9, length = header & 511; p += 2;
      if (bytes.length - p < length) throw new Error('Truncated LLDP TLV value');
      const value = bytes.subarray(p, p + length);
      const tlv = {type, length, name: names[type] ?? (type === 127 ? 'Organizationally Specific' : `Unknown TLV ${type}`), raw: hex(value)};
      result.tlvs.push(tlv);
      if (result.tlvs.length <= 3 && type !== result.tlvs.length) throw new Error('Invalid LLDP mandatory TLV order');
      if (type >= 1 && type <= 3 && result.tlvs.slice(0, -1).some(t => t.type === type)) throw new Error('Duplicate LLDP mandatory TLV');
      if (type === 0) {
        if (length !== 0) throw new Error('Invalid LLDP end TLV length');
        ended = true; break; // Remaining Ethernet padding is not a TLV.
      } else if (type === 1 || type === 2) {
        if (length < 2 || length > 256 || value[0] < 1 || value[0] > 7) throw new Error('Invalid LLDP identifier');
        tlv.subtype = value[0];
        const id = value.subarray(1), macType = type === 1 ? 4 : 3, networkType = type === 1 ? 5 : 4;
        if (tlv.subtype === macType) {
          if (id.length !== 6) throw new Error('Invalid LLDP MAC identifier length');
          tlv.id = hex(id);
        } else if (tlv.subtype === networkType) {
          if (id.length < 2) throw new Error('Invalid LLDP network identifier length');
          tlv.addressFamily = id[0]; tlv.id = address(id[0], id.subarray(1));
        } else tlv.id = decoder.decode(id);
        result[type === 1 ? 'chassisId' : 'portId'] = {subtype: tlv.subtype, id: tlv.id, ...(tlv.addressFamily !== undefined ? {addressFamily: tlv.addressFamily} : {})};
      } else if (type === 3) {
        if (length !== 2) throw new Error('Invalid LLDP TTL length');
        result.ttl = tlv.seconds = view.getUint16(p);
      } else if (type >= 4 && type <= 6) {
        tlv.text = decoder.decode(value);
        result[{4: 'portDescription', 5: 'systemName', 6: 'systemDescription'}[type]] = tlv.text;
      } else if (type === 7) {
        if (length !== 4) throw new Error('Invalid LLDP capabilities length');
        tlv.supported = view.getUint16(p); tlv.enabled = view.getUint16(p + 2);
        tlv.supportedNames = capabilityNames.filter((_, i) => tlv.supported & (1 << i));
        tlv.enabledNames = capabilityNames.filter((_, i) => tlv.enabled & (1 << i));
        result.capabilities = {supported: tlv.supported, enabled: tlv.enabled, supportedNames: tlv.supportedNames, enabledNames: tlv.enabledNames};
      } else if (type === 8) {
        const size = value[0];
        if (length < 9 || size < 2 || size > 32 || length < size + 7) throw new Error('Invalid LLDP management address length');
        tlv.addressFamily = value[1]; tlv.address = address(value[1], value.subarray(2, 1 + size));
        tlv.interfaceSubtype = value[1 + size]; tlv.interfaceNumber = view.getUint32(p + 2 + size);
        const oidLength = value[6 + size];
        if (length !== size + 7 + oidLength) throw new Error('Invalid LLDP management OID length');
        tlv.oid = hex(value.subarray(7 + size));
        (result.managementAddresses ??= []).push({addressFamily: tlv.addressFamily, address: tlv.address,
          interfaceSubtype: tlv.interfaceSubtype, interfaceNumber: tlv.interfaceNumber, oid: tlv.oid});
      } else if (type === 127) {
        if (length < 4) throw new Error('Invalid LLDP organizational TLV length');
        tlv.oui = hex(value.subarray(0, 3)); tlv.subtype = value[3]; tlv.data = hex(value.subarray(4));
      }
      p += length;
    }
    if (!ended) throw new Error('Missing LLDP end TLV');
  } catch (error) {result.error = error.message;}
  result.info = [result.systemName ?? result.chassisId?.id, result.portId ? `Port=${result.portId.id}` : '',
    result.ttl !== undefined ? `TTL=${result.ttl}s` : '', result.error].filter(Boolean).join('; ');
  return result;
}

export default {
  name: 'lldp',
  matches: packet => packet.protocol === 'LLDP',
  dissect: dissectLldp,
};
