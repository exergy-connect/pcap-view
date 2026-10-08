// RFC 8669 §3 and RFC 9252 §§2–3: all three TLV levels use
// one-byte types and two-byte lengths, excluding the TLV header.
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(' ');
const behaviors = {16: 'End.DX6', 17: 'End.DX4', 18: 'End.DT6', 19: 'End.DT4', 20: 'End.DT46',
  21: 'End.DX2', 22: 'End.DX2V', 23: 'End.DT2U', 24: 'End.DT2M',
  // IANA SRv6 Endpoint Behaviors: service behaviors with NEXT-CSID.
  60: 'uDX6 (End.DX6 with NEXT-CSID)', 61: 'uDX4 (End.DX4 with NEXT-CSID)',
  62: 'uDT6 (End.DT6 with NEXT-CSID)', 63: 'uDT4 (End.DT4 with NEXT-CSID)',
  64: 'uDT46 (End.DT46 with NEXT-CSID)', 65: 'uDX2 (End.DX2 with NEXT-CSID)',
  66: 'uDX2V (End.DX2V with NEXT-CSID)', 67: 'uDT2U (End.DT2U with NEXT-CSID)',
  68: 'uDT2M (End.DT2M with NEXT-CSID)', 65535: 'Opaque'};
const names = {1: 'Label-Index', 3: 'Originator SRGB', 5: 'SRv6 L3 Service', 6: 'SRv6 L2 Service'};

export function dissectPrefixSid(bytes) {
  const result = {tlvs: []};
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u24 = p => (bytes[p] << 16) | (bytes[p + 1] << 8) | bytes[p + 2];
  function parse(start, end, level, output) {
    let p = start;
    while (p < end) {
      if (end - p < 3) throw new Error(`Truncated Prefix-SID ${level} header`);
      const type = bytes[p], length = view.getUint16(p + 1); p += 3;
      const stop = p + length;
      if (stop > end) throw new Error(`Truncated Prefix-SID ${level} value`);
      const name = level === 'TLV' ? names[type]
        : type === 1 ? (level === 'Sub-TLV' ? 'SRv6 SID Information' : 'SRv6 SID Structure') : undefined;
      const tlv = {type, length, name: name ?? `Unknown ${level} ${type}`, raw: hex(bytes.subarray(p, stop))};
      output.push(tlv);
      if (level === 'TLV' && type === 1) {
        if (length !== 7) throw new Error('Invalid Prefix-SID Label-Index length');
        tlv.reserved = bytes[p]; tlv.flags = view.getUint16(p + 1); tlv.labelIndex = view.getUint32(p + 3);
      } else if (level === 'TLV' && type === 3) {
        if (length < 8 || (length - 2) % 6) throw new Error('Invalid Prefix-SID Originator SRGB length');
        tlv.flags = view.getUint16(p); tlv.ranges = [];
        for (let q = p + 2; q < stop; q += 6) tlv.ranges.push({firstLabel: u24(q), rangeSize: u24(q + 3)});
      } else if (level === 'TLV' && [5, 6].includes(type)) {
        if (length < 1) throw new Error('Invalid Prefix-SID SRv6 Service length');
        tlv.reserved = bytes[p]; tlv.subTlvs = [];
        parse(p + 1, stop, 'Sub-TLV', tlv.subTlvs);
      } else if (level === 'Sub-TLV' && type === 1) {
        if (length < 21) throw new Error('Invalid Prefix-SID SRv6 SID Information length');
        tlv.reserved1 = bytes[p];
        tlv.sid = Array.from({length: 8}, (_, i) => view.getUint16(p + 1 + i * 2).toString(16)).join(':');
        tlv.flags = bytes[p + 17]; tlv.endpointBehavior = view.getUint16(p + 18);
        tlv.endpointBehaviorName = behaviors[tlv.endpointBehavior] ?? `Unknown behavior ${tlv.endpointBehavior}`;
        tlv.reserved2 = bytes[p + 20]; tlv.subSubTlvs = [];
        parse(p + 21, stop, 'Sub-Sub-TLV', tlv.subSubTlvs);
      } else if (level === 'Sub-Sub-TLV' && type === 1) {
        if (length !== 6) throw new Error('Invalid Prefix-SID SRv6 SID Structure length');
        Object.assign(tlv, {locatorBlockLength: bytes[p], locatorNodeLength: bytes[p + 1],
          functionLength: bytes[p + 2], argumentLength: bytes[p + 3],
          transpositionLength: bytes[p + 4], transpositionOffset: bytes[p + 5]});
      }
      p = stop;
    }
  }
  try {parse(0, bytes.length, 'TLV', result.tlvs);}
  catch (error) {result.error = error.message;}
  return result;
}
