// OCP MRC 1.0, sections 6.2.2 and 7.5.5–7.5.6. All fields are network order.
const operations = {0xc6: 'RDMA WRITE First', 0xc7: 'RDMA WRITE Middle', 0xc8: 'RDMA WRITE Last',
  0xc9: 'RDMA WRITE Last with Immediate', 0xca: 'RDMA WRITE Only', 0xcb: 'RDMA WRITE Only with Immediate',
  0xd1: 'Acknowledge', 0xd8: 'Endpoint Request', 0xd9: 'Endpoint Response',
  0xdc: 'Reliability SACK', 0xdd: 'Reliability NACK', 0xde: 'Reliability PROBE Request'};
const reasons = {1: 'TRIMMED', 2: 'TRIMMED_LASTHOP', 6: 'NO_BITMAP', 7: 'NO_PKT_BUFFER',
  10: 'NO_RESOURCE', 11: 'PSN_OOR_WINDOW', 25: 'UNEXP_EVENT'};
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(' ');
const ports = [4791, 4971]; // RoCEv2 and the default printed in MRC 1.0 §7.5.5.2.

export function dissectMrc(bytes) {
  const result = {protocol: 'MRC'};
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let p = 0, end = bytes.length;
  const need = (size, name) => {if (p + size > end) throw new Error(`Truncated MRC ${name}`);};
  const u24 = offset => (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
  const timestamp = offset => ({txTimestamp: view.getUint16(offset),
    timestampResolution: bytes[offset + 2] >>> 7, formatType: bytes[offset + 3] & 15});
  const contexts = offset => ({sourceContext: view.getUint16(offset), destinationContext: view.getUint16(offset + 2)});
  try {
    need(12, 'BTH');
    result.opcode = bytes[0]; result.name = operations[result.opcode] ?? `Unknown opcode 0x${bytes[0].toString(16)}`;
    result.bth = {opcode: bytes[0], solicitedEvent: !!(bytes[1] & 128), migration: !!(bytes[1] & 64),
      padCount: (bytes[1] >>> 4) & 3, version: bytes[1] & 15, partitionKey: view.getUint16(2),
      destinationQp: u24(5), ackRequest: !!(bytes[8] & 128), retransmission: !!(bytes[8] & 32),
      timestampPresent: !!(bytes[8] & 16), psn: u24(9)};
    p = 12;
    if (!operations[result.opcode]) throw new Error(`Unsupported MRC opcode 0x${result.opcode.toString(16)}`);
    if (result.bth.version !== 0) throw new Error(`Unsupported MRC transport version ${result.bth.version}`);
    if (bytes.length < 16) throw new Error('Truncated MRC iCRC');
    end -= 4;
    result.icrc = hex(bytes.subarray(end));
    if (result.opcode >= 0xc6 && result.opcode <= 0xcb) {
      need(4, 'METH');
      result.meth = {receiveQueueMsn: view.getUint16(p), msn: view.getUint16(p + 2)}; p += 4;
      if (result.bth.timestampPresent) {
        need(4, 'TSETH'); result.tseth = timestamp(p); p += 4;
      }
      need(16, 'RETH');
      result.reth = {virtualAddress: `0x${view.getBigUint64(p).toString(16).padStart(16, '0')}`,
        remoteKey: view.getUint32(p + 8), dmaLength: view.getUint32(p + 12)}; p += 16;
      if ([0xc9, 0xcb].includes(result.opcode)) {
        need(4, 'immediate data'); result.immediateData = view.getUint32(p); p += 4;
      }
      if (p + result.bth.padCount > end) throw new Error('Truncated MRC payload padding');
      result.payloadLength = end - p - result.bth.padCount;
      result.payloadPreview = hex(bytes.subarray(p, Math.min(p + result.payloadLength, p + 256)));
      if (result.payloadLength > 256) result.previewTruncated = true;
      p = end;
    } else if (result.opcode === 0xd1) {
      need(4, 'AETH'); result.aeth = {syndrome: bytes[p], msn: u24(p + 1)}; p += 4;
    } else if (result.opcode === 0xdc) {
      need(28, 'SETH');
      const cumulativePsn = u24(p + 13), ackOffset = view.getInt16(p + 2), sackOffset = view.getInt16(p + 18);
      const probeResponse = !!(bytes[p + 1] & 2);
      result.seth = {pathFeedback: (bytes[p + 1] >>> 5) & 3, probeResponse, ackOffset,
        ...(probeResponse ? {probeId: view.getUint16(p + 2)} : {ackPsn: (cumulativePsn + ackOffset) & 0xffffff}),
        entropy: view.getUint32(p + 4), ...contexts(p + 8), cumulativePsn,
        ccType: bytes[p + 16] >>> 4, ccFlags: bytes[p + 16] & 15, maxPsnRange: bytes[p + 17] * 128,
        sackOffset, sackBasePsn: (cumulativePsn + sackOffset) & 0xffffff,
        sackBitmap: `0x${view.getBigUint64(p + 20).toString(16).padStart(16, '0')}`};
      p += 28; need(8, 'CC_STATE');
      if (result.seth.ccType === 0) {
        result.ccState = {txTimestamp: view.getUint16(p), outOfOrderCount: view.getUint16(p + 2) & 0x7fff,
          restoreCwnd: !!(bytes[p + 4] & 128), receiverCwndPenalty: bytes[p + 4] & 127,
          receivedByteUnits: u24(p + 5), receivedBytes: u24(p + 5) * 256};
      } else result.ccState = {raw: hex(bytes.subarray(p, p + 8))};
      p += 8;
    } else if (result.opcode === 0xdd) {
      need(20, 'NETH');
      result.neth = {reason: bytes[p + 2], reasonName: reasons[bytes[p + 2]] ?? `Unknown reason ${bytes[p + 2]}`,
        vendorInfo: bytes[p + 3], entropy: view.getUint32(p + 4), ...contexts(p + 8),
        nackPsn: u24(p + 13), ccType: bytes[p + 16] >>> 4, ccFlags: bytes[p + 16] & 15,
        txTimestamp: view.getUint16(p + 18)}; p += 20;
    } else if (result.opcode === 0xde) {
      need(16, 'PETH');
      result.peth = {vendorInfo: bytes[p + 3], probeId: view.getUint16(p + 4),
        ...contexts(p + 8), ...timestamp(p + 12)}; p += 16;
    } else if (result.opcode === 0xd8) {
      need(16, 'ERTH');
      const operation = bytes[p + 1] & 3;
      result.erth = {operation, operationName: ['Port Status Update', 'EV Probe'][operation] ?? `Unknown operation ${operation}`,
        probeId: result.bth.psn & 0xffff, vendorInfo: bytes[p + 3], portStatusMask: view.getUint32(p + 4), ...timestamp(p + 12)};
      p += 16;
    } else if (result.opcode === 0xd9) {
      need(36, 'EETH');
      const operation = (bytes[p + 1] >>> 2) & 3;
      result.eeth = {operation, operationName: ['Port Status Update', 'EV Probe'][operation] ?? `Unknown operation ${operation}`,
        probeId: result.bth.psn & 0xffff, txTimestamp: view.getUint16(p + 28)}; p += 36;
    }
    if (p < end) result.data = hex(bytes.subarray(p, end));
  } catch (error) {result.error = error.message;}
  result.info = [result.name ?? 'MRC', result.bth ? `QP=${result.bth.destinationQp} PSN=${result.bth.psn}` : '',
    result.bth?.retransmission ? 'Retransmission' : '', result.neth?.reasonName, result.error].filter(Boolean).join('; ');
  return result;
}

export default {
  name: 'mrc',
  probe(payload, packet) {
    if (packet.protocol !== 'UDP' || !operations[payload[0]]) return 0;
    if (payload.length >= 12 && (payload[1] & 15) === 0) return 100;
    return ports.includes(packet.dport) ? 1 : 0;
  },
  dissect: dissectMrc,
};
