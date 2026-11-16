// draft-ietf-idr-multinexthop-attribute-05. The BGP path-attribute code is
// still TBD; RFC 2042 reserves 255 for development of new attributes.
export const mnhAttributeType = 255;

const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(' ');
const ipv4 = bytes => Array.from(bytes).join('.');
const behaviors = {16: 'End.DX6', 17: 'End.DX4', 18: 'End.DT6', 19: 'End.DT4', 20: 'End.DT46',
  21: 'End.DX2', 22: 'End.DX2V', 23: 'End.DT2U', 24: 'End.DT2M',
  60: 'uDX6 (End.DX6 with NEXT-CSID)', 61: 'uDX4 (End.DX4 with NEXT-CSID)',
  62: 'uDT6 (End.DT6 with NEXT-CSID)', 63: 'uDT4 (End.DT4 with NEXT-CSID)',
  64: 'uDT46 (End.DT46 with NEXT-CSID)', 65: 'uDX2 (End.DX2 with NEXT-CSID)',
  66: 'uDX2V (End.DX2V with NEXT-CSID)', 67: 'uDT2U (End.DT2U with NEXT-CSID)',
  68: 'uDT2M (End.DT2M with NEXT-CSID)', 65535: 'Opaque'};
const mnhTypes = {0: 'Reserved', 1: 'Primary forwarding path', 2: 'Backup forwarding path'};
const actions = {0: 'Reserved', 1: 'Forward', 2: 'Pop-And-Forward', 3: 'Swap', 4: 'Push', 5: 'Pop-And-Lookup', 6: 'Replicate'};
const argumentTypes = {0: 'Reserved', 1: 'Endpoint Identifier', 2: 'Path Constraints',
  3: 'Payload encapsulation info', 4: 'Endpoint attributes'};
const endpointTypes = {0: 'Reserved', 1: 'IPv4 Address', 2: 'IPv6 Address', 3: 'MPLS Label',
  4: 'Fwd Context RD', 5: 'Fwd Context RT'};
const constrainTypes = {0: 'Reserved', 1: 'Proximity check', 2: 'Transport Class ID', 3: 'Load balance factor'};
const encapTypes = {0: 'Reserved', 1: 'MPLS Label Info', 2: 'SR MPLS label Index Info', 3: 'SRv6 SID info', 4: 'DSCP code point'};
const metricTypes = {0: 'IGP Metric', 1: 'Min Unidirectional Link Delay'};

export function dissectMnh(bytes) {
  const result = {tlvs: []};
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const ipv6 = p => Array.from({length: 8}, (_, i) => view.getUint16(p + i * 2).toString(16)).join(':');
  const u64 = p => ((BigInt(view.getUint32(p)) << 32n) | BigInt(view.getUint32(p + 4))).toString();
  function rd(p) {
    const type = view.getUint16(p);
    if (type === 0) return `${view.getUint16(p + 2)}:${view.getUint32(p + 4)}`;
    if (type === 1) return `${ipv4(bytes.subarray(p + 2, p + 6))}:${view.getUint16(p + 6)}`;
    if (type === 2) return `${view.getUint32(p + 2)}:${view.getUint16(p + 6)}`;
    return undefined;
  }
  function structures(start, end, output) {
    let p = start;
    while (p < end) {
      if (end - p < 3) throw new Error('Truncated MNH SRv6 SID Structure header');
      const type = bytes[p], length = view.getUint16(p + 1), stop = p + 3 + length;
      if (stop > end) throw new Error('Truncated MNH SRv6 SID Structure value');
      const tlv = {type, length, raw: hex(bytes.subarray(p + 3, stop))};
      output.push(tlv); p += 3;
      if (type === 1) {
        if (length !== 6) throw new Error('Invalid MNH SRv6 SID Structure length');
        tlv.name = 'SRv6 SID Structure';
        Object.assign(tlv, {locatorBlockLength: bytes[p], locatorNodeLength: bytes[p + 1],
          functionLength: bytes[p + 2], argumentLength: bytes[p + 3],
          transpositionLength: bytes[p + 4], transpositionOffset: bytes[p + 5]});
      } else tlv.name = `Unknown SRv6 Sub-Sub-TLV ${type}`;
      p = stop;
    }
  }
  function sidInformation(start, end) {
    const sids = [];
    let p = start;
    while (p < end) {
      if (end - p < 3) throw new Error('Truncated MNH SRv6 SID header');
      const type = bytes[p], length = view.getUint16(p + 1), stop = p + 3 + length;
      if (stop > end) throw new Error('Truncated MNH SRv6 SID value');
      const tlv = {type, length, raw: hex(bytes.subarray(p + 3, stop))};
      sids.push(tlv); p += 3;
      if (type === 1) {
        if (length < 21) throw new Error('Invalid MNH SRv6 SID Information length');
        tlv.name = 'SRv6 SID Information';
        tlv.reserved1 = bytes[p];
        tlv.sid = ipv6(p + 1);
        tlv.flags = bytes[p + 17];
        tlv.endpointBehavior = view.getUint16(p + 18);
        tlv.endpointBehaviorName = behaviors[tlv.endpointBehavior] ?? `Unknown behavior ${tlv.endpointBehavior}`;
        tlv.reserved2 = bytes[p + 20];
        tlv.subTlvs = [];
        structures(p + 21, stop, tlv.subTlvs);
      } else tlv.name = `Unknown SRv6 Sub-TLV ${type}`;
      p = stop;
    }
    return sids;
  }
  function argumentsOf(start, end) {
    const args = [];
    let p = start;
    while (p < end) {
      if (end - p < 5) throw new Error('Truncated MNH Forwarding Argument header');
      const flags = bytes[p], type = view.getUint16(p + 1), length = view.getUint16(p + 3);
      const value = p + 5, stop = value + length;
      if (stop > end) throw new Error('Truncated MNH Forwarding Argument value');
      const arg = {flags, mandatory: !!(flags & 1), cumulative: !!(flags & 2), egress: !!(flags & 4),
        type, name: argumentTypes[type] ?? `Unknown Forwarding Argument ${type}`, length,
        raw: hex(bytes.subarray(value, stop))};
      args.push(arg);
      if (type === 1) {
        if (length < 2) throw new Error('Truncated MNH Endpoint Identifier');
        arg.endpointType = bytes[value];
        arg.endpointLength = bytes[value + 1];
        arg.endpointTypeName = endpointTypes[arg.endpointType] ?? `Unknown endpoint ${arg.endpointType}`;
        if (arg.endpointLength !== length - 2) throw new Error('Invalid MNH Endpoint Identifier length');
        const body = value + 2;
        if (arg.endpointType === 1) {
          if (arg.endpointLength !== 4) throw new Error('Invalid MNH IPv4 endpoint length');
          arg.address = ipv4(bytes.subarray(body, body + 4));
        } else if (arg.endpointType === 2) {
          if (arg.endpointLength !== 16) throw new Error('Invalid MNH IPv6 endpoint length');
          arg.address = ipv6(body);
        } else if (arg.endpointType === 3) {
          if (arg.endpointLength !== 4) throw new Error('Invalid MNH MPLS endpoint length');
          arg.value = view.getUint32(body);
          arg.label = arg.value & 0xfffff;
        } else if (arg.endpointType === 4 || arg.endpointType === 5) {
          if (arg.endpointLength !== 8) throw new Error('Invalid MNH forwarding-context endpoint length');
          const formatted = rd(body);
          if (formatted) arg[arg.endpointType === 4 ? 'routeDistinguisher' : 'routeTarget'] = formatted;
        }
      } else if (type === 2) {
        if (length < 2) throw new Error('Truncated MNH Path Constraints');
        arg.constraintType = bytes[value];
        arg.constraintLength = bytes[value + 1];
        arg.constraintTypeName = constrainTypes[arg.constraintType] ?? `Unknown constraint ${arg.constraintType}`;
        if (arg.constraintLength !== length - 2) throw new Error('Invalid MNH Path Constraints length');
        const body = value + 2;
        if (arg.constraintType === 1) {
          if (arg.constraintLength !== 2) throw new Error('Invalid MNH Proximity check length');
          arg.proximityFlags = view.getUint16(body);
          arg.singleHop = !!(arg.proximityFlags & 0x8000);
          arg.multiHop = !!(arg.proximityFlags & 0x4000);
        } else if (arg.constraintType === 2) {
          if (arg.constraintLength !== 4) throw new Error('Invalid MNH Transport Class length');
          arg.transportClass = view.getUint32(body);
        } else if (arg.constraintType === 3) {
          if (arg.constraintLength !== 2) throw new Error('Invalid MNH Load balance factor length');
          arg.balancePercentage = view.getUint16(body);
        }
      } else if (type === 3) {
        if (length < 3) throw new Error('Truncated MNH encapsulation info');
        arg.encapsulationType = bytes[value];
        arg.encapsulationLength = view.getUint16(value + 1);
        arg.encapsulationTypeName = encapTypes[arg.encapsulationType] ?? `Unknown encapsulation ${arg.encapsulationType}`;
        if (arg.encapsulationLength !== length - 3) throw new Error('Invalid MNH encapsulation length');
        const body = value + 3, encapEnd = body + arg.encapsulationLength;
        if (arg.encapsulationType === 1) {
          if (arg.encapsulationLength < 2 || (arg.encapsulationLength - 2) % 3) throw new Error('Invalid MNH MPLS Label Info length');
          arg.labelFlags = view.getUint16(body);
          arg.entropyLabelCapable = !!(arg.labelFlags & 0x8000);
          arg.labels = [];
          for (let q = body + 2; q < encapEnd; q += 3) {
            const word = (bytes[q] << 16) | (bytes[q + 1] << 8) | bytes[q + 2];
            arg.labels.push({label: word >>> 4, trafficClass: (word >>> 1) & 7, bottomOfStack: !!(word & 1)});
          }
        } else if (arg.encapsulationType === 2) {
          if (arg.encapsulationLength !== 7) throw new Error('Invalid MNH SR MPLS label index length');
          arg.reserved = bytes[body];
          arg.labelIndexFlags = view.getUint16(body + 1);
          arg.labelIndex = view.getUint32(body + 3);
        } else if (arg.encapsulationType === 3) arg.sids = sidInformation(body, encapEnd);
        else if (arg.encapsulationType === 4) {
          if (arg.encapsulationLength !== 1) throw new Error('Invalid MNH DSCP length');
          arg.ds = bytes[body];
          arg.dscp = bytes[body] >>> 2;
          arg.ecn = bytes[body] & 3;
        }
      } else if (type === 4) {
        if (!length) throw new Error('Truncated MNH Endpoint attributes');
        arg.attributeType = bytes[value];
        arg.attributeTypeName = {0: 'None', 1: 'Endpoint Bandwidth', 2: 'Accumulated Metric'}[arg.attributeType]
          ?? `Unknown endpoint attribute ${arg.attributeType}`;
        if (arg.attributeType === 1) {
          if (length !== 10 || bytes[value + 1] !== 8) throw new Error('Invalid MNH Endpoint Bandwidth length');
          arg.bandwidth = u64(value + 2);
        } else if (arg.attributeType === 2) {
          if (length < 3) throw new Error('Truncated MNH Accumulated Metric');
          arg.metricType = bytes[value + 1];
          arg.metricLength = bytes[value + 2];
          arg.metricTypeName = metricTypes[arg.metricType] ?? `Unknown metric ${arg.metricType}`;
          if (length !== 3 + arg.metricLength) throw new Error('Invalid MNH Accumulated Metric length');
          if ([0, 1].includes(arg.metricType) && arg.metricLength !== 4) throw new Error('Invalid MNH Accumulated Metric length');
          if (arg.metricLength === 4) arg.metric = view.getUint32(value + 3);
        } else if (arg.attributeType !== 0) {
          if (length < 2) throw new Error('Truncated MNH Endpoint attributes');
          arg.attributeLength = bytes[value + 1];
          if (arg.attributeLength !== length - 2) throw new Error('Invalid MNH Endpoint attributes length');
        }
      }
      p = stop;
    }
    return args;
  }
  try {
    if (!bytes.length) throw new Error('Truncated MNH header');
    result.version = bytes[0] >> 6;
    result.mnhFlags = bytes[0] & 0x3f;
    result.mandatory = !!(bytes[0] & 1);
    if (bytes.length >= 5) result.routerId = ipv4(bytes.subarray(1, 5));
    if (result.version !== 0) throw new Error(`Unsupported MNH version ${result.version}`);
    if (bytes.length < 5) throw new Error('Truncated MNH header');
    let p = 5;
    while (p < bytes.length) {
      if (bytes.length - p < 4) throw new Error('Truncated MNH TLV header');
      const flags = bytes[p], type = bytes[p + 1], length = view.getUint16(p + 2);
      const value = p + 4, stop = value + length;
      if (stop > bytes.length) throw new Error('Truncated MNH TLV value');
      const tlv = {flags, mandatory: !!(flags & 1), type, name: mnhTypes[type] ?? `Unknown MNH TLV ${type}`,
        length, raw: hex(bytes.subarray(value, stop))};
      result.tlvs.push(tlv);
      if (length < 3) throw new Error('Truncated MNH Nexthop Forwarding Information');
      const numNexthops = view.getUint16(value + 1);
      tlv.nfi = {flags: bytes[value], mandatory: !!(bytes[value] & 1), numNexthops, instructions: []};
      if (!numNexthops) throw new Error('Invalid MNH Num-Nexthops 0');
      let q = value + 3;
      for (let i = 0; i < numNexthops; i++) {
        if (stop - q < 6) throw new Error('Truncated MNH Forwarding Instruction header');
        const instructionFlags = bytes[q], preference = view.getUint16(q + 1), action = bytes[q + 3];
        const argLength = view.getUint16(q + 4), argStart = q + 6, argEnd = argStart + argLength;
        if (argEnd > stop) throw new Error('Truncated MNH Forwarding Instruction value');
        const instruction = {flags: instructionFlags, mandatory: !!(instructionFlags & 1), preference, action,
          actionName: actions[action] ?? `Unknown forwarding action ${action}`, length: argLength};
        tlv.nfi.instructions.push(instruction);
        instruction.arguments = argumentsOf(argStart, argEnd);
        q = argEnd;
      }
      if (q !== stop) throw new Error('Invalid MNH Nexthop Forwarding Information length');
      p = stop;
    }
  } catch (error) {result.error = error.message;}
  return result;
}
