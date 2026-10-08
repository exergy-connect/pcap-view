// InfiniBand transport headers carried by RoCEv1 (GRH) and RoCEv2 (UDP).
// Header stacks match Linux include/rdma/ib_pack.h and rxe_opcode.c.
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(' ');
const operationNames = ['SEND First', 'SEND Middle', 'SEND Last', 'SEND Last with Immediate',
  'SEND Only', 'SEND Only with Immediate', 'RDMA WRITE First', 'RDMA WRITE Middle', 'RDMA WRITE Last',
  'RDMA WRITE Last with Immediate', 'RDMA WRITE Only', 'RDMA WRITE Only with Immediate', 'RDMA READ Request',
  'RDMA READ Response First', 'RDMA READ Response Middle', 'RDMA READ Response Last', 'RDMA READ Response Only',
  'Acknowledge', 'Atomic Acknowledge', 'Compare Swap', 'Fetch Add'];
const operations = new Map();
for (const [base, transport, limit] of [[0, 'RC', 20], [32, 'UC', 11]]) {
  for (let op = 0; op <= limit; op++) operations.set(base + op, {transport, op, name: `${transport} ${operationNames[op]}`});
}
for (const op of [0x16, 0x17]) operations.set(op, {transport: 'RC', op,
  name: `RC SEND ${op === 0x16 ? 'Last' : 'Only'} with Invalidate`});
for (const op of [4, 5]) operations.set(0x60 + op, {transport: 'UD', op, name: `UD ${operationNames[op]}`});
operations.set(0x80, {transport: 'CNP', op: 0x80, name: 'Congestion Notification'});

export function dissectRoce(bytes, packet = {}) {
  const result = {protocol: 'RoCE', version: packet.protocol === 'RoCE' ? 1 : 2};
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let p = 0, end = bytes.length;
  const need = (size, name) => {if (p + size > end) throw new Error(`Truncated RoCE ${name}`);};
  const u24 = offset => (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
  const u64 = offset => `0x${view.getBigUint64(offset).toString(16).padStart(16, '0')}`;
  const gid = offset => Array.from({length: 8}, (_, i) => view.getUint16(offset + i * 2).toString(16)).join(':');
  try {
    if (result.version === 1) {
      need(40, 'GRH');
      result.grh = {version: bytes[0] >>> 4, trafficClass: (view.getUint32(0) >>> 20) & 255,
        flowLabel: view.getUint32(0) & 0xfffff, payloadLength: view.getUint16(4), nextHeader: bytes[6],
        hopLimit: bytes[7], sourceGid: gid(8), destinationGid: gid(24)};
      if (result.grh.version !== 6 || result.grh.nextHeader !== 0x1b) throw new Error('Invalid RoCE GRH');
      if (40 + result.grh.payloadLength > bytes.length) throw new Error('Truncated RoCE GRH payload');
      end = 40 + result.grh.payloadLength; p = 40; // Exclude Ethernet padding.
    }
    need(12, 'BTH');
    result.opcode = bytes[p]; const operation = operations.get(result.opcode);
    result.name = operation?.name ?? `Unknown opcode 0x${result.opcode.toString(16)}`;
    result.bth = {opcode: bytes[p], solicitedEvent: !!(bytes[p + 1] & 128), migration: !!(bytes[p + 1] & 64),
      padCount: (bytes[p + 1] >>> 4) & 3, version: bytes[p + 1] & 15, partitionKey: view.getUint16(p + 2),
      forwardEcn: !!(bytes[p + 4] & 128), backwardEcn: !!(bytes[p + 4] & 64), destinationQp: u24(p + 5),
      ackRequest: !!(bytes[p + 8] & 128), psn: u24(p + 9)}; p += 12;
    if (result.bth.version !== 0) throw new Error(`Unsupported RoCE transport version ${result.bth.version}`);
    need(4, 'iCRC'); end -= 4; result.icrc = hex(bytes.subarray(end, end + 4));
    if (!operation) {
      result.raw = hex(bytes.subarray(p, end));
      throw new Error(`Unsupported RoCE opcode 0x${result.opcode.toString(16)}`);
    }
    result.transportType = operation.transport;
    const op = operation.op;
    if (operation.transport === 'UD') {
      need(8, 'DETH'); result.deth = {queueKey: view.getUint32(p), sourceQp: u24(p + 5)}; p += 8;
    }
    if ([6, 10, 11, 12].includes(op) && operation.transport !== 'UD') {
      need(16, 'RETH'); result.reth = {virtualAddress: u64(p), remoteKey: view.getUint32(p + 8), dmaLength: view.getUint32(p + 12)}; p += 16;
    }
    if ([13, 15, 16, 17, 18].includes(op)) {
      need(4, 'AETH'); const syndrome = bytes[p];
      result.aeth = {syndrome, syndromeType: syndrome >>> 5, syndromeValue: syndrome & 31, msn: u24(p + 1)}; p += 4;
    }
    if (op === 18) {
      need(8, 'Atomic ACK ETH'); result.atomicAck = {originalRemoteData: u64(p)}; p += 8;
    }
    if ([19, 20].includes(op)) {
      need(28, 'Atomic ETH'); result.atomic = {virtualAddress: u64(p), remoteKey: view.getUint32(p + 8),
        swapOrAdd: u64(p + 12), compare: u64(p + 20)}; p += 28;
    }
    if ([3, 5, 9, 11].includes(op)) {
      need(4, 'immediate data'); result.immediateData = view.getUint32(p); p += 4;
    }
    if ([0x16, 0x17].includes(op)) {
      need(4, 'IETH'); result.invalidateKey = view.getUint32(p); p += 4;
    }
    if (op === 0x80) {
      need(16, 'CNP reserved data'); result.cnp = {raw: hex(bytes.subarray(p, p + 16))}; p += 16;
    }
    if (p + result.bth.padCount > end) throw new Error('Truncated RoCE payload padding');
    result.payloadLength = end - p - result.bth.padCount;
    result.payloadPreview = hex(bytes.subarray(p, Math.min(p + result.payloadLength, p + 256)));
    if (result.payloadLength > 256) result.previewTruncated = true;
  } catch (error) {result.error = error.message;}
  result.info = [result.name ?? 'RoCE', result.bth ? `QP=${result.bth.destinationQp} PSN=${result.bth.psn}` : '',
    result.payloadLength !== undefined ? `Len=${result.payloadLength}` : '', result.error].filter(Boolean).join('; ');
  return result;
}

export default {
  name: 'roce',
  probe(payload, packet) {
    if (packet.protocol === 'RoCE') return 100;
    if (packet.protocol !== 'UDP' || packet.dport !== 4791) return 0;
    // The MRC extension has its own dissector; never treat it as classic RoCE.
    if (payload.length && (payload[0] & 0xe0) === 0xc0) return 0;
    return payload.length >= 12 && operations.has(payload[0]) && (payload[1] & 15) === 0 ? 100 : 1;
  },
  dissect: dissectRoce,
};
