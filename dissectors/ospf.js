import {reader, ipv4, prefix, tlvs} from './routing.js';
const types = {1: 'Hello', 2: 'Database Description', 3: 'Link State Request', 4: 'Link State Update', 5: 'Link State Acknowledgment'};
function lsa(bytes, version, headerOnly = false) {
  const r = reader(bytes); r.need(0, 20);
  const type = version === 2 ? r.u8(3) : r.u16(2), length = r.u16(18);
  if (length < 20) throw new Error('Invalid OSPF LSA length');
  const result = {age: r.u16(0), type, linkStateId: ipv4(r.take(4, 4)), advertisingRouter: ipv4(r.take(8, 4)), sequence: r.u32(12), checksum: r.u16(16), length};
  if (headerOnly) return result;
  result.raw = r.take(20, length - 20);
  if (version === 3 && (type & 0x1fff) === 42) {
    result.name = 'SRv6 Locator'; result.tlvs = tlvs(result.raw, true);
    for (const tlv of result.tlvs) if (tlv.type === 1) {
      const q = reader(tlv.value); q.need(0, 8);
      const prefixLength = q.u8(2), size = Math.ceil(prefixLength / 32) * 4;
      Object.assign(tlv, {name: 'SRv6 Locator', routeType: q.u8(0), algorithm: q.u8(1), prefixLength, prefixOptions: q.u8(3), metric: q.u32(4), locator: prefix(q.take(8, size), prefixLength), subTlvs: tlvs(q.take(8 + size, tlv.length - 8 - size), true)});
    }
    result.locators = result.tlvs.filter(t => t.locator);
  }
  return result;
}
export function dissectOspf(bytes) {
  const result = {protocol: 'OSPF'};
  try {
    const r = reader(bytes); r.need(0, 4);
    const version = r.u8(0), type = r.u8(1), length = r.u16(2), header = version === 2 ? 24 : 16;
    Object.assign(result, {version, type, packetName: types[type] ?? `Unknown type ${type}`, length});
    if (![2, 3].includes(version)) throw new Error('Unsupported OSPF version');
    if (length < header) throw new Error('Invalid OSPF packet length');
    r.need(0, length);
    Object.assign(result, {routerId: ipv4(r.take(4, 4)), areaId: ipv4(r.take(8, 4)), checksum: r.u16(12)});
    if (version === 2) Object.assign(result, {authenticationType: r.u16(14), authentication: r.take(16, 8)});
    else result.instanceId = r.u8(14);
    const b = r.take(header, length - header), q = reader(b);
    if (type === 1) {
      q.need(0, 20);
      Object.assign(result, {helloInterval: q.u16(version === 2 ? 4 : 8), deadInterval: version === 2 ? q.u32(8) : q.u16(10), priority: q.u8(version === 2 ? 7 : 4), designatedRouter: ipv4(q.take(12, 4)), backupDesignatedRouter: ipv4(q.take(16, 4)), neighbors: []});
      if (version === 2) result.networkMask = ipv4(q.take(0, 4)); else result.interfaceId = q.u32(0);
      for (let p = 20; p < b.length; p += 4) result.neighbors.push(ipv4(q.take(p, 4)));
    } else if (type === 4) {
      const count = q.u32(0); result.lsaCount = count; result.lsas = []; let p = 4;
      for (let i = 0; i < count; i++) {const entry = lsa(b.subarray(p), version); result.lsas.push(entry); p += entry.length;}
      if (p !== b.length) throw new Error('Invalid OSPF update length');
    } else if (type === 2 || type === 5) {
      let p = type === 5 ? 0 : version === 2 ? 8 : 12;
      q.need(0, p); result.lsas = [];
      if (type === 2) Object.assign(result, {interfaceMtu: q.u16(version === 2 ? 0 : 4), flags: q.u8(version === 2 ? 3 : 7), ddSequence: q.u32(version === 2 ? 4 : 8)});
      for (; p < b.length; p += 20) result.lsas.push(lsa(b.subarray(p), version, true));
    } else if (type === 3) {
      result.requests = [];
      for (let p = 0; p < b.length; p += 12) result.requests.push({type: q.u32(p), linkStateId: ipv4(q.take(p + 4, 4)), advertisingRouter: ipv4(q.take(p + 8, 4))});
    } else result.raw = b;
    result.locators = (result.lsas ?? []).flatMap(l => l.locators ?? []);
    result.info = `OSPFv${version} ${result.packetName} Router=${result.routerId} Area=${result.areaId}${result.locators.length ? ` SRv6 ${result.locators.map(l => l.locator).join(', ')}` : ''}`;
  } catch (error) {result.error = error.message; result.info = `OSPF: ${error.message}`;}
  return result;
}
export default {name: 'ospf', matches: packet => packet.protocol === 'OSPF', dissect: dissectOspf};
