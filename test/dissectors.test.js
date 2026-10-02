import {test} from 'node:test';
import assert from 'node:assert/strict';
import {registerDissector, loadDissectors, applyDissectors} from '../dissectors.js';

 test('applications can register and select their own dissectors', () => {
  const custom = {
    name: 'example',
    matches: packet => packet.protocol === 'TCP' && packet.dport === 12345,
    dissect: payload => payload[0] === 42 ? {protocol: 'EXAMPLE', info: 'Example message', value: payload[0], source: 'ignored'} : null,
  };
  registerDissector(custom);
  assert.ok(loadDissectors().includes(custom));
  assert.deepEqual(loadDissectors(['example', 'example']), [custom]);
  assert.deepEqual(loadDissectors([]), []);
  const packet = {protocol: 'TCP', source: '192.0.2.1', dport: 12345, stream: 7, info: 'TCP summary'};
  applyDissectors(packet, new Uint8Array([42]), loadDissectors(['example']));
  assert.equal(packet.protocol, 'EXAMPLE');
  assert.equal(packet.transport, 'TCP');
  assert.equal(packet.source, '192.0.2.1');
  assert.equal(packet.stream, 7);
  assert.equal(packet.application.value, 42);
  assert.throws(() => registerDissector(custom), /Duplicate dissector/);
  assert.throws(() => registerDissector({name: 'invalid'}), /Invalid dissector/);
  assert.throws(() => loadDissectors('bmp'), /array of names/);
});

test('nonmatching and declining dissectors leave transport decoding intact', () => {
  const packet = {protocol: 'TCP', dport: 12345, info: 'TCP summary'};
  const ignored = {matches: () => false, dissect: () => {throw new Error('must not run');}};
  const declining = {matches: () => true, dissect: () => null};
  applyDissectors(packet, new Uint8Array([0]), [ignored, declining]);
  assert.deepEqual(packet, {protocol: 'TCP', dport: 12345, info: 'TCP summary'});
});

test('payload confidence beats port hints and retains TCP continuation selection', () => {
  const contexts = new Map();
  const hint = {name: 'hint', matches: () => true, dissect: () => ({protocol: 'HINT'})};
  let probes = 0;
  const detected = {name: 'detected', probe: payload => {probes++; return payload[0] === 42 ? 100 : 0;},
    dissect: payload => ({protocol: 'DETECTED', value: payload[0]})};
  const packet = () => ({protocol: 'TCP', stream: 0});
  const first = packet();
  applyDissectors(first, new Uint8Array([42]), [hint, detected], contexts);
  assert.equal(first.protocol, 'DETECTED');
  const continuation = packet();
  applyDissectors(continuation, new Uint8Array([0]), [hint, detected], contexts);
  assert.equal(continuation.protocol, 'DETECTED');
  assert.equal(probes, 1);
  const other = packet();
  applyDissectors(other, new Uint8Array([0]), [hint, detected], new Map());
  assert.equal(other.protocol, 'HINT');
});

test('a declining high-confidence candidate allows fallback', () => {
  const packet = {protocol: 'UDP'};
  applyDissectors(packet, new Uint8Array([1]), [
    {name: 'decline', probe: () => 100, dissect: () => null},
    {name: 'fallback', matches: () => true, dissect: () => ({protocol: 'FALLBACK'})},
  ]);
  assert.equal(packet.protocol, 'FALLBACK');
});

test('BMP is detected on a nonstandard port and buffers continuation bytes', () => {
  const contexts = new Map();
  const packet = sequence => ({protocol: 'TCP', stream: 1, sport: 50000, dport: 50001, sequence, flags: 16});
  const first = packet(10);
  applyDissectors(first, new Uint8Array([3, 0, 0, 0, 10, 4]), loadDissectors(['bmp']), contexts);
  assert.equal(first.protocol, 'BMP');
  assert.equal(first.application.pendingBytes, 6);
  const next = packet(16);
  applyDissectors(next, new Uint8Array([0, 0, 0, 0]), loadDissectors(['bmp']), contexts);
  assert.equal(next.application.messages[0].name, 'Initiation');
  const unrelated = packet(0);
  applyDissectors(unrelated, new Uint8Array([1, 2, 3, 4, 5, 6]), loadDissectors(['bmp']), new Map());
  assert.equal(unrelated.protocol, 'TCP');
});
