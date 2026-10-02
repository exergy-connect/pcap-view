import {test} from 'node:test';
import assert from 'node:assert/strict';
import {fixture} from './fixtures.js';
import {Worker as NodeWorker} from 'node:worker_threads';
import vm from 'node:vm';
import {build} from 'esbuild';

// Run the shipped browser worker in a real thread, adapting only browser transport.
const blobs = new Map(); let activeWorkers = 0;
class BrowserWorker {
  constructor(url) {
    activeWorkers++;
    this.ready = blobs.get(url).text().then(source => {
      if (this.closed) return;
      this.thread = new NodeWorker(`const {parentPort} = require('node:worker_threads');
        global.self = {postMessage: data => parentPort.postMessage(data)};
        ${source}\nparentPort.on('message', data => self.onmessage({data}));`, {eval: true});
      this.thread.on('message', data => this.onmessage?.({data}));
      this.thread.on('error', error => this.onerror?.({message: error.message}));
    });
  }
  postMessage(data, transfer) {this.ready.then(() => {if (!this.closed) this.thread.postMessage(data, transfer);});}
  terminate() {if (!this.closed) {this.closed = true; activeWorkers--; this.thread?.terminate();}}
}
const worker = await build({entryPoints: ['worker.js'], bundle: true, write: false, format: 'iife'});
const library = await build({entryPoints: ['library.js'], bundle: true, write: false, format: 'iife', globalName: 'PacketLens',
  plugins: [{name: 'worker', setup(b) {
    b.onResolve({filter: /\?inline$/}, () => ({path:'worker', namespace:'inline'}));
    b.onLoad({filter: /.*/, namespace:'inline'}, () => ({contents:worker.outputFiles[0].text, loader:'text'}));
  }}]});
const context = vm.createContext({Worker: BrowserWorker, Blob, ArrayBuffer, DOMException, URL: {
  createObjectURL(blob) {const url = String(Math.random()); blobs.set(url, blob); return url;},
  revokeObjectURL(url) {blobs.delete(url);},
}});
vm.runInContext(library.outputFiles[0].text, context);
const api = context.PacketLens;
test('worker library pages and filters captures, preserves buffers, and closes resources', async () => {
  const buffer = fixture(); const capture = await api.open(buffer);
  assert.equal(buffer.byteLength > 0,true); assert.equal(capture.packetCount,3); assert.equal(capture.streamCount,1);
  const page = await capture.getPackets({offset:1,limit:1});
  assert.equal(page.total,3); assert.equal(page.packets[0].number,2);
  const filtered = await capture.getPackets({source:'10.0.0.1',stream:0});
  assert.equal(filtered.total,2); assert.deepEqual(filtered.packets.map(p => p.number),[1,3]);
  assert.equal((await capture.getStreams())[0].count,3);
  await assert.rejects(capture.getPackets({limit:-1}),/nonnegative/);
  capture.close(); capture.close(); await assert.rejects(capture.getStreams(),/closed/);
  assert.equal(activeWorkers,0); assert.equal(blobs.size,0);
});
test('Blob convenience parsing and typed-array views return full dissection', async () => {
  const result = await api.parse(new Blob([fixture()])); assert.equal(result.packets.length,3);
  const input = new Uint8Array(fixture().byteLength + 10); input.set(new Uint8Array(fixture()),5);
  assert.equal((await api.parse(input.subarray(5,-5))).packets.length,3);
  assert.equal(activeWorkers,0); assert.equal(blobs.size,0);
});
test('errors and cancellation release workers and reject pending requests', async () => {
  await assert.rejects(api.open(new ArrayBuffer(0)),/Not a PCAPNG/);
  await assert.rejects(api.open('bad input'),/Expected/);
  const controller = new AbortController(); const pending = api.open(new Blob([fixture()]),{signal:controller.signal});
  controller.abort(); await assert.rejects(pending,{name:'AbortError'});
  await assert.rejects(api.open(fixture(),{signal:controller.signal}),{name:'AbortError'});
  const after = new AbortController(); const capture = await api.open(fixture(),{signal:after.signal});
  const request = capture.getPackets(); after.abort(); await assert.rejects(request,{name:'AbortError'});
  assert.equal(activeWorkers,0); assert.equal(blobs.size,0);
});
