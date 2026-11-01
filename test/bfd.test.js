import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dissectBfd} from '../dissectors/bfd.js';
import {applyDissectors, loadDissectors} from '../dissectors.js';
import {decode} from '../decode.js';

function control(authType) {
  const authLength = authType === 1 ? 7 : authType <= 3 ? 24 : 28;
  const bytes = new Uint8Array(24 + (authType ? authLength : 0));
  const view = new DataView(bytes.buffer);
  bytes.set([0x23, 0xfB | (authType ? 4 : 0), 3, bytes.length]);
  [123, 456, 100000, 200000, 300000].forEach((n, i) => view.setUint32(4 + i * 4, n));
  if (authType) {
    bytes.set([authType, authLength, 7, 0], 24);
    if (authType === 1) bytes.set([0x74, 0x65, 0x73, 0x74], 27);
    else {view.setUint32(28, 0xffffffff); bytes.fill(0xab, 32);}
  }
  return bytes;
}

test('BFD exposes state, diagnostics, flags, discriminators and microsecond timers', () => {
  const result = dissectBfd(control());
  assert.equal(result.error, undefined);
  assert.equal(result.version, 1);
  assert.equal(result.stateName, 'Up');
  assert.equal(result.diagnosticName, 'Neighbor Signaled Session Down');
  assert.deepEqual(result.flags, {poll: true, final: true, controlPlaneIndependent: true,
    authenticationPresent: false, demand: true, multipoint: true});
  assert.equal(result.myDiscriminator, 123);
  assert.equal(result.yourDiscriminator, 456);
  assert.equal(result.desiredMinTxInterval, 100000);
  assert.equal(result.requiredMinRxInterval, 200000);
  assert.equal(result.requiredMinEchoRxInterval, 300000);
  for (let state = 0; state < 4; state++) {
    const bytes = control(); bytes[1] = state << 6;
    assert.equal(dissectBfd(bytes).stateName, ['AdminDown', 'Down', 'Init', 'Up'][state]);
  }
});

test('BFD decodes password and all MD5/SHA1 authentication layouts', () => {
  for (let type = 1; type <= 5; type++) {
    const result = dissectBfd(control(type));
    assert.equal(result.error, undefined);
    assert.equal(result.authentication.type, type);
    assert.equal(result.authentication.keyId, 7);
    if (type === 1) assert.equal(result.authentication.password, '74657374');
    else {
      assert.equal(result.authentication.sequence, 0xffffffff);
      assert.equal(result.authentication.digest, 'ab'.repeat(type <= 3 ? 16 : 20));
    }
  }
});

test('BFD safely reports truncated and malformed headers and authentication', () => {
  for (const type of [undefined, 1, 2, 4]) {
    const bytes = control(type);
    for (let length = 0; length < bytes.length; length++) {
      assert.ok(dissectBfd(bytes.subarray(0, length)).error, `type ${type}, length ${length}`);
    }
  }
  for (const [offset, value, message] of [[0, 0x40, /version/], [3, 23, /length/],
    [2, 0, /multiplier/], [4, 0, /Discriminator/]]) {
    const bytes = control();
    if (offset === 4) bytes.fill(0, 4, 8); else bytes[offset] = value;
    assert.match(dissectBfd(bytes).error, message);
  }
  const bytes = control(2); bytes[25] = 23;
  assert.match(dissectBfd(bytes).error, /authentication length/);
  bytes[25] = 24; bytes[24] = 4;
  assert.match(dissectBfd(bytes).error, /digest length/);
  const padded = new Uint8Array(30); padded.set(control());
  assert.equal(dissectBfd(padded).error, undefined);
  const offset = new Uint8Array(28); offset.set(control(), 4);
  assert.equal(dissectBfd(offset.subarray(4)).myDiscriminator, 123);
});

test('BFD selection integrates with IP/UDP decoding and can be disabled', () => {
  for (const port of [3784, 4784]) {
    const bytes = new Uint8Array(52), view = new DataView(bytes.buffer);
    bytes[0] = 0x45; view.setUint16(2, 52); bytes[9] = 17;
    view.setUint16(20, 49152); view.setUint16(22, port); view.setUint16(24, 32);
    bytes.set(control(), 28);
    const packet = decode(bytes, 101);
    applyDissectors(packet, packet.payload, loadDissectors());
    assert.equal(packet.protocol, 'BFD');
    assert.equal(packet.transport, 'UDP');
    assert.equal(packet.application.myDiscriminator, 123);
    const disabled = decode(bytes, 101);
    applyDissectors(disabled, disabled.payload, loadDissectors(['udp']));
    assert.equal(disabled.protocol, 'UDP');
  }
  for (const protocol of ['UDP', 'TCP']) {
    const packet = {protocol, sport: 3784, dport: 12345};
    applyDissectors(packet, control(), loadDissectors(['bfd']));
    assert.equal(packet.protocol, protocol);
  }
  const echo = {protocol: 'UDP', dport: 3785};
  applyDissectors(echo, new Uint8Array([1, 2]), loadDissectors());
  assert.equal(echo.application.type, 'Echo');
  assert.equal(echo.application.data, '0102');
  const empty = {protocol: 'UDP', dport: 3784};
  applyDissectors(empty, new Uint8Array(), loadDissectors());
  assert.match(empty.application.error, /Truncated/);
});
