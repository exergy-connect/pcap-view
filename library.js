import workerSource from './worker.js?inline';

// Each capture owns a worker so terminating it also interrupts synchronous parsing.
export function open(input, {dissectors = 'all', signal} = {}) {
  return new Promise((resolve, reject) => {
    let worker, url, settled = false, nextId = 0;
    const pending = new Map();
    const abortError = () => new DOMException('Capture cancelled', 'AbortError');
    function dispose(error = new Error('Capture closed')) {
      worker?.terminate();
      if (url) {URL.revokeObjectURL(url); url = null;}
      signal?.removeEventListener('abort', abort);
      for (const request of pending.values()) request.reject(error);
      pending.clear();
      if (!settled) {settled = true; reject(error);}
      worker = null;
    }
    function abort() {dispose(abortError());}
    function request(command, args = {}, transfer = []) {
      if (!worker) return Promise.reject(new Error('Capture closed'));
      return new Promise((resolve, reject) => {
        const id = ++nextId; pending.set(id, {resolve, reject});
        try {worker.postMessage({id, command, ...args}, transfer);}
        catch (error) {pending.delete(id); reject(error);}
      });
    }
    if (signal?.aborted) {reject(abortError()); return;}
    try {
      if (!(input instanceof Blob) && !(input instanceof ArrayBuffer) && !ArrayBuffer.isView(input)) {
        throw new TypeError('Expected a File, Blob, ArrayBuffer, or typed array');
      }
      // Copy buffers to preserve caller ownership; Files/Blobs are read in the worker.
      const source = input instanceof Blob ? input : input instanceof ArrayBuffer
        ? input.slice(0) : input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
      url = URL.createObjectURL(new Blob([workerSource], {type: 'text/javascript'}));
      worker = new Worker(url);
      worker.onmessage = ({data}) => {
        const entry = pending.get(data.id); if (!entry) return;
        pending.delete(data.id);
        if (data.error) entry.reject(new Error(data.error)); else entry.resolve(data.result);
      };
      worker.onerror = event => {event.preventDefault?.(); dispose(new Error(event.message || 'Capture worker failed'));};
      worker.onmessageerror = () => dispose(new Error('Unable to receive capture data'));
      signal?.addEventListener('abort', abort, {once: true});
      request('open', {input: source, options: {dissectors}}, source instanceof ArrayBuffer ? [source] : [])
        .then(summary => {
          if (!worker) return;
          settled = true;
          resolve(Object.freeze({
            ...summary,
            getPackets: (options = {}) => request('packets', {options}),
            getStreams: () => request('streams'),
            close: () => dispose(),
          }));
        }, error => dispose(error));
    } catch (error) {dispose(error);}
  });
}

// Convenience API for clients that want the complete result in main-thread memory.
export async function parse(input, options) {
  const capture = await open(input, options);
  try {
    const [page, streams] = await Promise.all([
      capture.getPackets({limit: capture.packetCount}), capture.getStreams(),
    ]);
    return {packets: page.packets, streams};
  } finally {capture.close();}
}
