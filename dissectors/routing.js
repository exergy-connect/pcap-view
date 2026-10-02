// Bounds-checked helpers shared by the packet-local routing dissectors.
export function reader(bytes) {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const need = (p, n) => {if (p < 0 || p + n > bytes.length) throw new Error('Truncated routing data');};
  return {need, u8: p => {need(p, 1); return bytes[p];},
    u16: p => {need(p, 2); return v.getUint16(p);},
    u32: p => {need(p, 4); return v.getUint32(p);},
    take: (p, n) => {need(p, n); return bytes.slice(p, p + n);}};
}
export const ipv4 = bytes => Array.from(bytes).join('.');
export const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('.');
export function prefix(bytes, length) {
  if (length < 1 || length > 128) throw new Error('Invalid SRv6 locator length');
  const address = new Uint8Array(16);
  address.set(bytes.subarray(0, Math.ceil(length / 8)));
  if (length % 8) address[Math.floor(length / 8)] &= 255 << (8 - length % 8);
  const v = new DataView(address.buffer);
  return `${Array.from({length: 8}, (_, i) => v.getUint16(i * 2).toString(16)).join(':')}/${length}`;
}
export function tlvs(bytes, wide = false) {
  const r = reader(bytes), result = [], header = wide ? 4 : 2;
  for (let p = 0; p < bytes.length;) {
    r.need(p, header);
    const type = wide ? r.u16(p) : r.u8(p), length = wide ? r.u16(p + 2) : r.u8(p + 1);
    const value = r.take(p + header, length);
    result.push({type, length, value});
    const size = header + length, step = wide ? Math.ceil(size / 4) * 4 : size;
    r.need(p, step); p += step;
  }
  return result;
}
