// OCP Falcon Transport Protocol revision 1.0, section 7 (network byte order).
// https://www.opencompute.org/documents/falcon-spec-v1-1-pdf-1
// PSP envelope: https://github.com/google/psp/blob/main/src/psp.h
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const names = {0: 'Pull Request', 3: 'Pull Data', 5: 'Push Data', 6: 'Resync', 8: 'NACK', 9: 'BACK', 10: 'EACK'};
const sizes = {0: 32, 3: 24, 5: 28, 6: 32, 8: 40, 9: 32, 10: 72};
const nackNames = {1: 'Insufficient resources', 2: 'Receiver Not Ready', 4: 'xLR drop',
  6: 'ULP complete in error', 7: 'ULP non-recoverable error', 8: 'Invalid CID'};
const resyncNames = {1: 'Target ULP complete in error', 2: 'Local xLR flow', 3: 'Retransmission error',
  4: 'Transaction timed out', 5: 'Remote xLR flow', 6: 'Target ULP non-recoverable error', 7: 'Target ULP invalid CID'};
const rnrDelays = [655.36, .01, .02, .03, .04, .06, .08, .12, .16, .24, .32, .48, .64, .96, 1.28, 1.92,
  2.56, 3.84, 5.12, 7.68, 10.24, 15.36, 20.48, 30.72, 40.96, 61.44, 81.92, 122.88, 163.84, 245.76, 327.68, 491.52];

export function dissectFalcon(bytes, packet = {}) {
  const result = {protocol: 'Falcon', encapsulation: packet.protocol === 'UDP' ? 'psp' : 'cleartext'};
  try {
    if (packet.protocol === 'UDP') {
      const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      if (bytes.length < 16) throw new Error('Truncated Falcon PSP header');
      const version = (bytes[3] >>> 2) & 15, headerLength = (bytes[1] + 1) * 8;
      const virtualCookiePresent = !!(bytes[3] & 2), cryptOffset = (bytes[2] & 63) * 4;
      result.psp = {nextHeader: bytes[0], version, headerLength, cryptOffset, virtualCookiePresent,
        spi: v.getUint32(4), iv: hex(bytes.subarray(8, 16))};
      if (bytes[0] !== 252) throw new Error('PSP next header is not Falcon');
      if (version > 3) throw new Error(`Unsupported PSP version ${version}`);
      if (!(bytes[3] & 1) || (bytes[2] & 0xc0) || headerLength !== (virtualCookiePresent ? 24 : 16)) {
        throw new Error('Invalid Falcon PSP header');
      }
      if (bytes.length < headerLength + 16) throw new Error('Truncated Falcon PSP payload or ICV');
      const end = bytes.length - 16;
      result.psp.icv = hex(bytes.subarray(end));
      if (virtualCookiePresent) result.psp.virtualCookie = hex(bytes.subarray(16, 24));
      // Crypt offset starts after the IV, so includes the optional VC.
      const clearEnd = 16 + cryptOffset;
      if (clearEnd < headerLength || clearEnd > end) throw new Error('Invalid Falcon PSP crypt offset');
      result.encrypted = version < 2 && clearEnd < end;
      if (result.encrypted) {
        const clear = bytes.subarray(headerLength, clearEnd);
        if (clear.length >= 4) {
          result.version = clear[0] >>> 4;
          result.destinationCid = (clear[1] << 16) | (clear[2] << 8) | clear[3];
        }
        result.cleartextPreview = hex(clear.subarray(0, 256));
        result.encryptedLength = end - clearEnd;
        result.encryptedPreview = hex(bytes.subarray(clearEnd, Math.min(end, clearEnd + 256)));
        if (result.encryptedLength > 256 || clear.length > 256) result.previewTruncated = true;
        result.info = `Falcon encrypted${result.destinationCid !== undefined ? ` CID=${result.destinationCid}` : ''}`;
        return result;
      }
      bytes = bytes.subarray(headerLength, end);
    }
    const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const need = (n, label) => {if (bytes.length < n) throw new Error(`Truncated Falcon ${label}`);};
    need(4, 'connection header');
    result.version = bytes[0] >>> 4;
    result.reserved = bytes[0] & 15;
    result.destinationCid = v.getUint32(0) & 0xffffff;
    if (result.version !== 1) throw new Error(`Unsupported Falcon version ${result.version}`);
    need(8, 'packet type');
    const packetType = (bytes[7] >>> 1) & 15;
    Object.assign(result, {packetType, name: names[packetType] ?? `Unknown packet type ${packetType}`});
    const headerLength = sizes[packetType];
    if (headerLength === undefined) {
      result.raw = hex(bytes.subarray(8, 264));
      throw new Error(`Unsupported Falcon packet type ${packetType}`);
    }
    need(headerLength, `${result.name} header`);
    Object.assign(result, {headerLength, receiverDataWindowBasePsn: v.getUint32(8), receiverRequestWindowBasePsn: v.getUint32(12)});
    const congestion = offset => {
      const word = v.getUint32(offset);
      return {hopCount: word >>> 28, rxBufferOccupancy: (word >>> 23) & 31,
        ecnRxPacketCount: (word >>> 9) & 0x3fff, rueInfo: (v.getUint32(offset + 4) >>> 2) & 0x3fffff};
    };
    if (packetType < 8) {
      Object.assign(result, {destinationFunction: v.getUint32(4) >>> 8, protocolType: bytes[7] >>> 5,
        ackRequest: !!(bytes[7] & 1), psn: v.getUint32(16), rsn: v.getUint32(20)});
      result.ulp = {2: 'RDMA', 3: 'NVMe'}[result.protocolType] ?? `Reserved ${result.protocolType}`;
      if (packetType === 0 || packetType === 5) result.requestLength = v.getUint16(26);
      if (packetType === 6) result.resync = {code: bytes[24], name: resyncNames[bytes[24]] ?? 'Reserved',
        packetType: bytes[25] >>> 4, vendorDefined: v.getUint32(28)};
    } else if (packetType === 8) {
      Object.assign(result, {nackPsn: v.getUint32(16), timestamp1: v.getUint32(20), timestamp2: v.getUint32(24),
        congestion: congestion(28)});
      const rnrTimeout = (bytes[37] >>> 1) & 31;
      result.nack = {code: bytes[36], name: nackNames[bytes[36]] ?? 'Reserved', rnrTimeout,
        requestWindow: !!(bytes[37] & 1), ulpCode: bytes[39]};
      if (bytes[36] === 2) result.nack.rnrTimeoutMs = rnrDelays[rnrTimeout];
    } else {
      Object.assign(result, {timestamp1: v.getUint32(16), timestamp2: v.getUint32(20), congestion: congestion(24),
        outOfWindow: {request: !!(bytes[31] & 1), data: !!(bytes[31] & 2)}});
      if (packetType === 10) result.bitmaps = {dataAck: hex(bytes.subarray(32, 48)), dataReceived: hex(bytes.subarray(48, 64)),
        request: hex(bytes.subarray(64, 72))};
    }
    result.payloadLength = bytes.length - headerLength;
    result.payloadPreview = hex(bytes.subarray(headerLength, headerLength + 256));
    if (result.payloadLength > 256) result.previewTruncated = true;
    if (packetType === 5 && result.payloadLength !== result.requestLength) throw new Error('Falcon Push Data length does not match request length');
    if (![3, 5].includes(packetType) && result.payloadLength) throw new Error(`Unexpected Falcon ${result.name} payload`);
  } catch (error) {result.error = error.message;}
  result.info = ['Falcon', result.name, result.ulp, result.destinationCid !== undefined ? `CID=${result.destinationCid}` : '',
    result.psn !== undefined ? `PSN=${result.psn}` : '', result.error].filter(Boolean).join('; ');
  return result;
}

export default {name: 'falcon', matches: packet => packet.protocol === 'Falcon',
  probe: (bytes, packet) => packet.protocol === 'Falcon' ? 100 :
    packet.protocol === 'UDP' && packet.dport === 1000 && bytes[0] === 252 ? 100 : 0,
  dissect: dissectFalcon};
