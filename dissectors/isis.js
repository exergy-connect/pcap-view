import {reader, hex, prefix, tlvs} from './routing.js';
const types = {15: 'L1 LAN Hello', 16: 'L2 LAN Hello', 17: 'Point-to-point Hello', 18: 'L1 LSP', 20: 'L2 LSP', 24: 'L1 CSNP', 25: 'L2 CSNP', 26: 'L1 PSNP', 27: 'L2 PSNP'};
function locators(value) {
  const r = reader(value), entries = [];
  const mtid = r.u16(0) & 0xfff;
  for (let p = 2; p < value.length;) {
    r.need(p, 7);
    const metric = r.u32(p), flags = r.u8(p + 4), algorithm = r.u8(p + 5), prefixLength = r.u8(p + 6);
    if (prefixLength < 1 || prefixLength > 128) throw new Error('Invalid SRv6 locator length');
    const size = Math.ceil(prefixLength / 8), locator = prefix(r.take(p + 7, size), prefixLength);
    p += 7 + size;
    const length = r.u8(p++), subTlvs = tlvs(r.take(p, length)); p += length;
    entries.push({locator, prefixLength, metric, flags, down: !!(flags & 128), algorithm, subTlvs});
  }
  return {mtid, locators: entries};
}
export function dissectIsis(bytes) {
  const result = {protocol: 'IS-IS'};
  try {
    const r = reader(bytes); r.need(0, 8);
    if (r.u8(0) !== 0x83) throw new Error('Invalid IS-IS discriminator');
    const headerLength = r.u8(1), version = r.u8(2), idLength = r.u8(3) || 6, pduType = r.u8(4) & 31;
    Object.assign(result, {version, idLength, pduType, pduName: types[pduType] ?? `Unknown PDU ${pduType}`, headerLength});
    if (version !== 1 || r.u8(5) !== 1 || idLength !== 6) throw new Error('Unsupported IS-IS version or system ID length');
    const lsp = [18, 20].includes(pduType), hello = [15, 16, 17].includes(pduType), snp = [24, 25, 26, 27].includes(pduType);
    if (!lsp && !hello && !snp) {result.raw = bytes.slice(8); return {...result, info: result.pduName};}
    const minimum = lsp ? 27 : hello ? (pduType === 17 ? 20 : 27) : [24, 25].includes(pduType) ? 33 : 17;
    if (headerLength < minimum) throw new Error('Invalid IS-IS header length');
    const pduLength = r.u16(hello ? 17 : 8); result.pduLength = pduLength;
    if (pduLength < headerLength) throw new Error('Invalid IS-IS PDU length');
    r.need(0, pduLength);
    if (lsp) Object.assign(result, {remainingLifetime: r.u16(10), lspId: hex(r.take(12, 8)), sequence: r.u32(20), checksum: r.u16(24), flags: r.u8(26)});
    else Object.assign(result, {sourceId: hex(r.take(hello ? 9 : 10, 6)), ...(hello ? {circuitType: r.u8(8), holdingTime: r.u16(15)} : {})});
    result.tlvs = tlvs(r.take(headerLength, pduLength - headerLength));
    for (const tlv of result.tlvs) {
      if (tlv.type === 27) Object.assign(tlv, {name: 'SRv6 Locator', ...locators(tlv.value)});
      if (tlv.type === 137) tlv.hostname = new TextDecoder().decode(tlv.value);
    }
    result.locators = result.tlvs.flatMap(t => t.locators ?? []);
    result.info = `${result.pduName} ${result.lspId ?? result.sourceId}${result.locators.length ? ` SRv6 ${result.locators.map(l => l.locator).join(', ')}` : ''}`;
  } catch (error) {result.error = error.message; result.info = `IS-IS: ${error.message}`;}
  return result;
}
export default {name: 'isis', matches: packet => packet.protocol === 'IS-IS', dissect: dissectIsis};
