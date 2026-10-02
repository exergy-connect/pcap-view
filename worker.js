import {parsePcapng} from './parser.js';
let capture;
self.onmessage = async ({data}) => {
  const {id, command} = data;
  try {
    let result;
    if (command === 'open') {
      const buffer = data.input instanceof Blob ? await data.input.arrayBuffer() : data.input;
      capture = parsePcapng(buffer, data.options);
      let min = Infinity, max = -Infinity;
      for (const packet of capture.packets) if (packet.time !== null) {min = Math.min(min, packet.time); max = Math.max(max, packet.time);}
      result = {packetCount: capture.packets.length, streamCount: capture.streams.length,
        duration: min === Infinity ? null : max - min};
    } else if (command === 'packets') {
      if (!capture) throw new Error('No capture open');
      const {offset = 0, limit = 100, stream, source} = data.options ?? {};
      if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 0) {
        throw new TypeError('offset and limit must be nonnegative safe integers');
      }
      const packets = []; let total = 0;
      for (const packet of capture.packets) {
        if (stream !== undefined && packet.stream !== stream || source !== undefined && packet.source !== source) continue;
        if (total >= offset && packets.length < limit) packets.push(packet);
        total++;
      }
      result = {packets, total, offset};
    } else if (command === 'streams') {
      if (!capture) throw new Error('No capture open');
      result = capture.streams;
    } else if (command === undefined) {
      // Preserve the original worker message contract.
      result = parsePcapng(data instanceof ArrayBuffer ? data : data.buffer, data.options);
    } else throw new Error(`Unknown command: ${command}`);
    self.postMessage({id, result});
  } catch (error) {self.postMessage({id, error: error.message});}
};
