// BFD v1 Control packets (RFC 5880); UDP single-hop and multihop bindings.
const states = ['AdminDown', 'Down', 'Init', 'Up'];
const diagnostics = ['No Diagnostic', 'Control Detection Time Expired', 'Echo Function Failed',
  'Neighbor Signaled Session Down', 'Forwarding Plane Reset', 'Path Down',
  'Concatenated Path Down', 'Administratively Down', 'Reverse Concatenated Path Down'];
const authTypes = ['Reserved', 'Simple Password', 'Keyed MD5', 'Meticulous Keyed MD5',
  'Keyed SHA1', 'Meticulous Keyed SHA1'];
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

export function dissectBfd(bytes, packet = {}) {
  const result = {protocol: 'BFD', type: packet.dport === 3785 ? 'Echo' : 'Control'};
  const fail = error => ({...result, info: error, error});
  // Echo contents are implementation specific, not a BFD Control header.
  if (result.type === 'Echo') return {...result, data: hex(bytes), info: `BFD Echo Len=${bytes.length}`};
  if (bytes.length < 4) return fail('Truncated BFD header');
  Object.assign(result, {version: bytes[0] >> 5, diagnostic: bytes[0] & 31,
    state: bytes[1] >> 6, detectMultiplier: bytes[2], length: bytes[3]});
  result.diagnosticName = diagnostics[result.diagnostic] ?? `Unknown (${result.diagnostic})`;
  result.stateName = states[result.state];
  result.flags = Object.fromEntries(['poll', 'final', 'controlPlaneIndependent', 'authenticationPresent', 'demand', 'multipoint']
    .map((name, i) => [name, Boolean(bytes[1] & (32 >> i))]));
  if (result.version !== 1) return fail(`Unsupported BFD version ${result.version}`);
  if (result.length < 24) return fail('Invalid BFD length');
  if (bytes.length < 24) return fail('Truncated BFD control header');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  Object.assign(result, {myDiscriminator: view.getUint32(4), yourDiscriminator: view.getUint32(8),
    desiredMinTxInterval: view.getUint32(12), requiredMinRxInterval: view.getUint32(16),
    requiredMinEchoRxInterval: view.getUint32(20)});
  if (result.length > bytes.length) return fail('Truncated BFD control packet');
  if (result.flags.authenticationPresent) {
    if (result.length < 26) return fail('Truncated BFD authentication header');
    const type = bytes[24], length = bytes[25];
    const auth = result.authentication = {type, name: authTypes[type] ?? `Unknown (${type})`, length};
    if (length < 3 || 24 + length !== result.length) return fail('Invalid BFD authentication length');
    auth.keyId = bytes[26];
    if (type === 1) {
      if (length < 4 || length > 19) return fail('Invalid BFD password length');
      auth.password = hex(bytes.subarray(27, result.length));
    } else if (type >= 2 && type <= 5) {
      if (length !== (type <= 3 ? 24 : 28)) return fail('Invalid BFD digest length');
      auth.sequence = view.getUint32(28);
      auth.digest = hex(bytes.subarray(32, result.length));
    } else auth.data = hex(bytes.subarray(27, result.length));
  } else if (result.length !== 24) return fail('Invalid BFD unauthenticated length');
  if (!result.detectMultiplier) return fail('Invalid BFD detect multiplier');
  if (!result.myDiscriminator) return fail('Invalid BFD My Discriminator');
  result.info = `BFD Control ${result.stateName}, My Discriminator=${result.myDiscriminator}, Your Discriminator=${result.yourDiscriminator}, ${result.diagnosticName}`;
  return result;
}

export default {
  name: 'bfd',
  matches: packet => packet.protocol === 'UDP' && [3784, 3785, 4784].includes(packet.dport),
  dissect: dissectBfd,
};
