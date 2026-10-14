import {reader, hex, tlvs} from './routing.js';

const types = {2: 'ES HELLO', 4: 'IS HELLO', 6: 'RD REQUEST'};

export function dissectEsis(bytes) {
  const result = {protocol: 'ESIS'};
  try {
    const header = reader(bytes); header.need(0, 9);
    if (header.u8(0) !== 0x82) throw new Error('Invalid ESIS discriminator');
    const pduLength = header.u8(1), version = header.u8(2), pduType = header.u8(4) & 31;
    Object.assign(result, {pduLength, version, pduType, pduName: types[pduType] ?? `Unknown PDU ${pduType}`,
      holdingTime: header.u16(5), checksum: header.u16(7)});
    if (version !== 1) throw new Error('Unsupported ESIS version');
    if (pduLength < 9) throw new Error('Invalid ESIS PDU length');
    const r = reader(header.take(0, pduLength));
    let p = 9;
    const address = () => {const length = r.u8(p++); const value = hex(r.take(p, length)); p += length; return value;};
    if (pduType === 4) result.networkEntityTitle = address();
    else if (pduType === 2) {
      const count = r.u8(p++); result.sourceAddresses = [];
      for (let i = 0; i < count; i++) result.sourceAddresses.push(address());
    } else if (pduType === 6) {
      result.destinationAddress = address();
      result.subnetworkAddress = address();
      result.networkEntityTitle = address();
    } else {
      result.raw = r.take(p, pduLength - p);
      result.info = result.pduName;
      return result;
    }
    result.options = tlvs(r.take(p, pduLength - p));
    result.info = result.pduName;
  } catch (error) {result.error = error.message; result.info = `ESIS: ${error.message}`;}
  return result;
}

export default {name: 'esis', matches: packet => packet.protocol === 'ESIS', dissect: dissectEsis};
