// UET: optional native entropy header + PDS + SES + payload + CRC.
// Field layouts: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-uet.c
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(' ');
const types = {2: 'RUD Request', 3: 'ROD Request', 4: 'RUDI Request', 5: 'RUDI Response',
  6: 'UUD Request', 7: 'ACK', 8: 'ACK CC', 9: 'ACK CCX', 10: 'NACK', 11: 'Control',
  12: 'NACK CCX', 13: 'RUD CC Request', 14: 'ROD CC Request'};
const formats = ['None', 'Small Request', 'Medium Request', 'Standard Request', 'Response', 'Response Data', 'Small Response Data'];
const operations = ['No Op', 'Write', 'Read', 'Atomic', 'Fetching Atomic', 'Send', 'Rendezvous Send',
  'Datagram Send', 'Deferrable Send', 'Tagged Send', 'Rendezvous Tagged Send', 'Deferrable Tagged Send',
  'Ready to Restart', 'Tagged Send Atomic', 'Tagged Send Fetching Atomic', 'Message Error'];

export function dissectUet(bytes, packet = {}) {
  const udp = packet.protocol === 'UDP';
  const result = {protocol: 'UET', encapsulation: udp ? 'udp' : 'native'};
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let p = 0, end = bytes.length;
  const need = (n, label) => {if (p + n > end) throw new Error(`Truncated UET ${label}`);};
  const u24 = offset => (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
  const u64 = offset => `0x${v.getBigUint64(offset).toString(16).padStart(16, '0')}`;
  try {
    if (!udp) {
      need(4, 'entropy header');
      result.entropy = v.getUint16(0); result.entropyReserved = v.getUint16(2); p = 4;
    }
    need(4, 'CRC trailer'); end -= 4; result.crc = hex(bytes.subarray(end));
    need(2, 'PDS header');
    const common = v.getUint16(p), type = common >>> 11, nextHeader = (common >>> 7) & 15, flags = common & 127;
    result.pds = {type, name: types[type] ?? `Unknown type ${type}`, nextHeader, flags};
    const d = result.pds;
    if (!types[type]) {
      result.raw = hex(bytes.subarray(p, end));
      throw new Error(type === 1 ? 'UET secure transport is not supported' : `Unsupported UET PDS type ${type}`);
    }
    p += 2;
    if ([2, 3, 13, 14].includes(type)) {
      need(10, 'PDS request header');
      Object.assign(d, {clearPsnOffset: v.getInt16(p), psn: v.getUint32(p + 2), sourcePdcId: v.getUint16(p + 6),
        retransmission: !!(flags & 16), ackRequest: !!(flags & 8), syn: !!(flags & 4)});
      d.clearPsn = (d.psn + d.clearPsnOffset) >>> 0;
      if (d.syn) {d.pdcMode = v.getUint16(p + 8) >>> 12; d.psnOffset = v.getUint16(p + 8) & 0xfff; d.startPsn = (d.psn - d.psnOffset) >>> 0;}
      else d.destinationPdcId = v.getUint16(p + 8);
      p += 10;
      if (type >= 13) {need(4, 'PDS request CC state'); d.ccState = {cccId: bytes[p], creditTarget: u24(p + 1)}; p += 4;}
    } else if ([4, 5].includes(type)) {
      need(6, 'PDS RUDI header'); d.packetId = v.getUint32(p + 2); p += 6;
    } else if (type === 6) {need(2, 'PDS UUD header'); p += 2;}
    else {
      const size = [10, 11, 12].includes(type) ? 14 : 10;
      need(size, 'PDS acknowledgment/control header');
      Object.assign(d, {sourcePdcId: v.getUint16(p + 6), destinationPdcId: v.getUint16(p + 8)});
      if ([7, 8, 9].includes(type)) {
        d.ackPsnOffset = v.getInt16(p); d.cumulativeAckPsn = v.getUint32(p + 2);
        d.ackPsn = (d.cumulativeAckPsn + d.ackPsnOffset) >>> 0;
      } else if (type === 11) {d.controlType = nextHeader; d.probeOpaque = v.getUint16(p); d.psn = v.getUint32(p + 2); d.controlPayload = v.getUint32(p + 10);}
      else {d.nackCode = bytes[p]; d.vendorCode = bytes[p + 1]; d.psn = v.getUint32(p + 2); d.maxReceivedPsn = v.getUint32(p + 10);}
      p += size;
      if ([8, 9, 12].includes(type)) {
        const n = type === 8 ? 20 : type === 9 ? 28 : 16;
        need(n, 'PDS CC extension'); d.ccExtension = hex(bytes.subarray(p, p + n)); p += n;
      }
    }
    if (type !== 11 && nextHeader) {
      const n = [0, 20, 32, 44, 12, 20, 12][nextHeader];
      if (!n) {result.raw = hex(bytes.subarray(p, end)); throw new Error(`Unsupported UET SES next header ${nextHeader}`);}
      need(n, 'SES header');
      const s = result.ses = {format: formats[nextHeader], opcode: bytes[p] & 63, flags: bytes[p + 1], jobId: u24(p + 5)};
      if (nextHeader <= 3) {
        Object.assign(s, {name: operations[s.opcode] ?? `Unknown opcode ${s.opcode}`, version: s.flags >>> 6,
          startOfMessage: !!(s.flags & 1), endOfMessage: !!(s.flags & 2), indexGeneration: bytes[p + 4],
          pidOnFep: v.getUint16(p + 8) & 0xfff, resourceIndex: v.getUint16(p + 10) & 0xfff, bufferOffset: u64(p + 12)});
        if (nextHeader === 3) {
          s.messageId = v.getUint16(p + 2); s.initiator = v.getUint32(p + 20); s.memoryKey = u64(p + 24); s.requestLength = v.getUint32(p + 40);
          if (s.startOfMessage) s.headerData = u64(p + 32);
          else {s.payloadLength = v.getUint32(p + 32) & 0x3fff; s.messageOffset = v.getUint32(p + 36);}
        } else {s.requestLength = v.getUint16(p + 2) & 0x3fff; if (nextHeader === 2) {s.initiator = v.getUint32(p + 20); s.memoryKey = u64(p + 24);}}
        p += n;
        // Keep opcode-specific extensions intact instead of treating them as data.
        if ([3, 4, 6, 10, 13, 14].includes(s.opcode)) {
          result.raw = hex(bytes.subarray(p, end)); throw new Error(`Unsupported UET SES extension for ${s.name}`);
        }
      } else {
        s.version = s.flags >>> 6; s.returnCode = s.flags & 63;
        if (nextHeader === 6) {s.payloadLength = v.getUint16(p + 2) & 0x3fff; s.originalRequestPsn = v.getUint32(p + 8);}
        else {
          s.messageId = v.getUint16(p + 2); s.modifiedLength = v.getUint32(p + (nextHeader === 4 ? 8 : 12));
          if (nextHeader === 5) {s.readRequestMessageId = v.getUint16(p + 8); s.payloadLength = v.getUint16(p + 10) & 0x3fff; s.messageOffset = v.getUint32(p + 16);}
        }
        p += n;
      }
    }
    result.payloadLength = end - p;
    result.payloadPreview = hex(bytes.subarray(p, Math.min(end, p + 256)));
    if (result.payloadLength > 256) result.previewTruncated = true;
  } catch (error) {result.error = error.message;}
  result.info = ['UET', result.pds?.name, result.ses?.name ?? result.ses?.format,
    result.pds?.psn !== undefined ? `PSN=${result.pds.psn}` : '',
    result.payloadLength !== undefined ? `Len=${result.payloadLength}` : '', result.error].filter(Boolean).join('; ');
  return result;
}
export default {name: 'uet', matches: packet => packet.protocol === 'UET' || (packet.protocol === 'UDP' && packet.dport === 4793), dissect: dissectUet};
