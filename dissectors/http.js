// HTTP/1.x framing (RFC 9112). Headers preserve order and duplicate fields.
const decoder = new TextDecoder('latin1');
const maxBytes = 16 * 1024 * 1024;
const token = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
const request = new RegExp(`^(${token}) ([^ \\r\\n]+) HTTP/(1\\.[01])$`);
const response = /^HTTP\/(1\.[01]) ([0-9]{3})(?: (.*))?$/;
const ports = [80, 8000, 8080];

function parseMessage(bytes, closed) {
  const text = decoder.decode(bytes);
  const end = text.indexOf('\r\n\r\n');
  if (end < 0) return null;
  const lines = text.slice(0, end).split('\r\n');
  const req = request.exec(lines[0]), res = response.exec(lines[0]);
  if (!req && !res) throw new Error('Invalid HTTP start line');
  const message = req ? {type: 'request', method: req[1], target: req[2], version: req[3]}
    : {type: 'response', version: res[1], statusCode: Number(res[2]), reason: res[3] ?? ''};
  message.startLine = lines[0]; message.headers = [];
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(':');
    if (colon < 1 || !new RegExp(`^${token}$`).test(line.slice(0, colon))) throw new Error('Invalid HTTP header');
    message.headers.push({name: line.slice(0, colon), value: line.slice(colon + 1).trim()});
  }
  const values = name => message.headers.filter(h => h.name.toLowerCase() === name).map(h => h.value);
  const lengths = values('content-length').flatMap(v => v.split(',').map(s => s.trim()));
  const transfer = values('transfer-encoding').join(',').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
  let p = end + 4, body;
  const noBody = res && (message.statusCode < 200 || [204, 304].includes(message.statusCode));
  if (noBody) body = new Uint8Array();
  else if (transfer.at(-1) === 'chunked') {
    const chunks = []; let size = 0;
    message.trailers = [];
    while (true) {
      const lineEnd = text.indexOf('\r\n', p);
      if (lineEnd < 0) return null;
      const hex = text.slice(p, lineEnd).split(';')[0];
      if (!/^[0-9a-f]+$/i.test(hex)) throw new Error('Invalid HTTP chunk size');
      const n = Number.parseInt(hex, 16); p = lineEnd + 2;
      if (!Number.isSafeInteger(n) || size + n > maxBytes) throw new Error('HTTP body exceeds 16 MiB');
      if (n === 0) {
        while (true) {
          const trailerEnd = text.indexOf('\r\n', p);
          if (trailerEnd < 0) return null;
          const line = text.slice(p, trailerEnd); p = trailerEnd + 2;
          if (!line) break;
          const colon = line.indexOf(':');
          if (colon < 1) throw new Error('Invalid HTTP trailer');
          message.trailers.push({name: line.slice(0, colon), value: line.slice(colon + 1).trim()});
        }
        break;
      }
      if (bytes.length < p + n + 2) return null;
      if (text.slice(p + n, p + n + 2) !== '\r\n') throw new Error('Invalid HTTP chunk terminator');
      chunks.push(bytes.subarray(p, p + n)); size += n; p += n + 2;
    }
    body = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) {body.set(chunk, offset); offset += chunk.length;}
  } else if (transfer.length) {
    if (req) throw new Error('Unsupported HTTP request transfer coding');
    if (!closed) return null;
    body = bytes.subarray(p); p = bytes.length;
  } else if (lengths.length) {
    if (lengths.some(v => !/^\d+$/.test(v) || v !== lengths[0])) throw new Error('Invalid HTTP Content-Length');
    const n = Number(lengths[0]);
    if (!Number.isSafeInteger(n) || n > maxBytes) throw new Error('HTTP body exceeds 16 MiB');
    if (bytes.length < p + n) return null;
    body = bytes.subarray(p, p + n); p += n;
  } else if (req) body = new Uint8Array();
  else {
    if (!closed) return null;
    body = bytes.subarray(p); p = bytes.length;
  }
  message.bodyLength = body.length;
  message.bodyPreview = decoder.decode(body.subarray(0, 4096));
  if (body.length > 4096) message.previewTruncated = true;
  return {message, length: p};
}

export function dissectHttpSegment(payload, packet, context) {
  let sequence = (packet.sequence + ((packet.flags & 2) ? 1 : 0)) >>> 0;
  let gap = false;
  if (context.nextSequence !== null && packet.sequence !== undefined) {
    const delta = (sequence - context.nextSequence) | 0;
    if (delta < 0) {
      if (-delta >= payload.length) return {protocol: 'HTTP', info: 'HTTP TCP retransmission', messages: []};
      payload = payload.subarray(-delta); sequence = context.nextSequence;
    } else if (delta > 0) {context.pending = new Uint8Array(); gap = true;}
  }
  context.nextSequence = (sequence + payload.length) >>> 0;
  const result = {protocol: 'HTTP', messages: []};
  try {
    if (context.pending.length + payload.length > maxBytes) throw new Error('HTTP buffer exceeds 16 MiB');
    const bytes = new Uint8Array(context.pending.length + payload.length);
    bytes.set(context.pending); bytes.set(payload, context.pending.length);
    let offset = 0;
    while (offset < bytes.length) {
      const parsed = parseMessage(bytes.subarray(offset), Boolean(packet.flags & 1));
      if (!parsed) break;
      result.messages.push(parsed.message); offset += parsed.length;
    }
    context.pending = bytes.slice(offset);
    if (context.pending.length) result.pendingBytes = context.pending.length;
  } catch (error) {result.error = error.message; context.pending = new Uint8Array();}
  if (gap) result.error = 'TCP sequence gap; HTTP framing may be incomplete';
  result.info = result.messages.map(m => m.startLine).join('; ') || `HTTP continuation (${context.pending.length} buffered bytes)`;
  if (result.error) result.info += `; ${result.error}`;
  return result;
}

export default {
  name: 'http',
  flushOnFin: true,
  probe(bytes, packet) {
    if (packet.protocol !== 'TCP') return 0;
    const text = decoder.decode(bytes.subarray(0, 8192));
    const line = text.split('\r\n')[0];
    if (request.test(line) || response.test(line)) return 100;
    // Port hints only accept a plausible partial start line, avoiding TLS/binary data.
    if (ports.includes(packet.sport) || ports.includes(packet.dport)) {
      if (/^HTTP\/1\./.test(text) || new RegExp(`^${token}(?: [^\\r\\n]*)?$`).test(line)) return 1;
    }
    return 0;
  },
  createContext: () => ({pending: new Uint8Array(), nextSequence: null}),
  dissect: dissectHttpSegment,
};
