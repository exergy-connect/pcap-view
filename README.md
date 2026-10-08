# pcap-view

A dependency-free, single-page PCAPNG viewer. Files are parsed locally in a web worker; nothing is uploaded to a server.

Open the hosted web page to use the viewer. No local installation is required.

For development, install Node.js 24+ and run `npm install`. Run `npm test` to check the parser and `npm run build` to rebuild the browser bundles.

`npm run build` uses esbuild to generate `docs/app.min.js`, the single minified JavaScript bundle loaded by `docs/index.html`. The parser worker is bundled into that file and started from a local Blob URL. Rebuild after editing JavaScript sources.

Drop a `.pcapng` file or use the file picker. Choose a TCP stream in the dropdown, or click a stream number in the packet table. The table displays 100 packets per page.

IPv4 and IPv6 hostname mappings embedded in PCAPNG Name Resolution Blocks appear in the packet table and stream selector. The first supplied name is displayed; hover over an address cell to see its IP and all aliases. Mappings apply throughout their section, including packets before the mapping block. Unmapped addresses remain numeric. No DNS requests are made, and TCP grouping continues to use numeric addresses. Record decoding follows the [PCAPNG Name Resolution Block format](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.5).

Supports little- and big-endian sections, multiple interfaces, enhanced/simple/legacy packet blocks, interface timestamp resolution and offsets, Ethernet/VLAN, raw IP, Linux cooked capture, IPv4, IPv6, TCP, UDP, and ICMP. Unknown link types and truncated network headers remain visible with limited details. Malformed PCAPNG blocks produce an error without replacing the previous capture.

TCP streams are assigned in capture order using bidirectional address/port pairs scoped to the section and interface. A new SYN after an established or closed connection starts a new stream. This is a lightweight heuristic; it does not promise Wireshark-identical stream numbering. IP fragments are not reassembled. Large files must fit in browser memory.

Format reference: [IETF PCAPNG specification](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/).

Application dissectors run after transport decoding and retain TCP stream grouping. BMP v3 is enabled by default and recognized by its common header, with TCP port 11019 as a fallback hint. It decodes common and per-peer headers, message types, initiation/termination TLVs, and basic BGP, statistics and peer notification fields following [RFC 7854](https://www.rfc-editor.org/rfc/rfc7854.html). Multiple messages per packet and BMP messages spanning contiguous TCP segments are decoded. Buffers are independent per stream direction, handle retransmission overlap and sequence wrap, and flag sequence gaps. Missing or out-of-order segments are not recovered; pending bytes are shown while awaiting more data. Messages above 16 MiB are rejected by the stream decoder. Embedded BGP OPEN, UPDATE, NOTIFICATION, KEEPALIVE, and ROUTE-REFRESH messages expose nested fields. UPDATE decoding includes IPv4 prefixes, common path attributes, AS paths and communities; unsupported attributes retain raw bytes.

Standalone BGP is also enabled by default and can be selected with `['bgp']`. It recognizes BGP headers on any TCP port, with port 179 as a fallback hint, and exposes decoded messages under `packet.application.messages`. It buffers contiguous TCP segments and handles multiple messages, retransmission overlap, sequence wrap, and sequence gaps. Standalone AS_PATH decoding checks the complete segment encoding for two-byte and four-byte ASNs and decodes structurally unambiguous paths. Ambiguous paths retain raw bytes with a warning; negotiation across peers is not tracked. BMP retains its explicit per-peer ASN width.

VXLAN and cleartext HTTP/1.0–1.1 are also enabled by default. VXLAN recognizes UDP ports 4789 and 8472 (or a standard header on another port), exposes flags and the 24-bit VNI, and decodes the inner Ethernet/VLAN, IP and transport fields under `packet.application.inner`, preserving outer endpoints. Inner IP addresses also receive section-scoped capture hostname mappings under `inner.sourceNames` and `inner.destinationNames`; the VXLAN summary displays the first supplied names while retaining numeric addresses in the decoded fields. Truncated or invalid headers remain inspectable. Enabled dissectors also decode inner application payloads under `inner.application`, including ARP, HTTP, BMP and nested VXLAN. Inner TCP continuations are buffered independently by capture section/interface, tunnel direction, VNI and inner endpoints; inner connections do not create selectable TCP streams. Nested dissection stops after eight inner layers. Hostname mappings apply recursively. VXLAN extensions are not decoded. Header layout follows [RFC 7348](https://www.rfc-editor.org/rfc/rfc7348.html).

HTTP detects request/response start lines on any TCP port, with partial-start-line hints on ports 80, 8000 and 8080. `packet.application.messages` contains start lines, request methods/targets or response statuses, ordered headers, body lengths, and body previews capped at 4096 bytes. It supports contiguous TCP segments, overlapping retransmissions, pipelined messages, Content-Length, chunked bodies with trailers, and close-delimited responses completed by a captured FIN, following [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html). Pending messages are capped at 16 MiB; malformed framing and sequence gaps report errors. Previews are byte-oriented text, without decompression or charset conversion. TLS, HTTP/2, request/response correlation (including HEAD response framing), and upgraded/tunnel protocols are not supported. Missing FINs leave close-delimited responses pending. Select `['vxlan', 'http']` to enable only these dissectors.

ARP is enabled by default and can be selected with `['arp']`. It decodes hardware/protocol types, declared address lengths, operation, and sender/target hardware and protocol addresses following [RFC 826](https://www.rfc-editor.org/rfc/rfc826.html). Requests and replies have readable summaries; unknown operations and nonstandard address types remain inspectable. Ethernet, VLAN, and Linux cooked captures are supported. Sender and target protocol addresses populate packet endpoints and receive capture hostname mappings. Truncated headers/addresses and invalid zero address lengths report errors under `packet.application`.

OSPF and IS-IS are enabled by default and can be selected with `['ospf', 'isis']`. OSPFv2/v3 over IP protocol 89 exposes common headers, Hello neighbors/timers, Database Description fields and LSA headers, Link State Requests, Link State Updates, and acknowledgments. IS-IS over Ethernet/VLAN LLC or Linux cooked capture exposes LAN/point-to-point Hello, LSP, CSNP and PSNP headers and TLVs, including dynamic hostnames. Unsupported IS-IS system ID lengths and versions report errors. Unknown LSA bodies and TLVs retain raw bytes; checksums and authentication are displayed without verification.

SRv6 locator advertisements are interpreted in IS-IS TLV 27 following [RFC 9352](https://www.rfc-editor.org/rfc/rfc9352.html#section-7.1) and OSPFv3 SRv6 Locator LSAs (function code 42) following [RFC 9513](https://www.rfc-editor.org/rfc/rfc9513.html#section-7). Decoded fields include the IPv6 locator prefix, prefix length, metric, algorithm, flags/options, IS-IS topology ID, OSPF route type, and raw nested sub-TLVs. Prefixes mask unused trailing bits and respect each protocol's padding rules. Locators appear under `packet.application.locators` and in packet summaries. SID behaviors and SID structure sub-TLVs are retained as raw data; locator boundaries are not inferred from arbitrary IPv6 addresses. Truncated or invalid routing data reports an error under `packet.application`.

LLDP is enabled by default and can be selected with `['lldp']`. It recognizes EtherType `0x88cc` on Ethernet, VLAN and Linux cooked captures, and decodes chassis/port identifiers, TTL, port/system descriptions, system capabilities, and IPv4/IPv6 management addresses under `packet.application`. Ordered TLVs retain raw values; organizational TLVs expose OUI, subtype and raw data. Ethernet source/destination MAC addresses are preserved. Malformed lengths, mandatory TLV order, duplicate mandatory TLVs and missing end markers report errors; padding after the end marker is ignored. Vendor extension bodies remain raw. LLDP follows [IEEE 802.1AB](https://www.ieee802.org/1/pages/802.1ab.html).

Multipath Reliable Connection (MRC) is enabled by default and selectable with `['mrc']`. The dissector follows [OCP MRC 1.0](https://www.opencompute.org/documents/ocp-mrc-1-0-pdf), sections 6.2.2 and 7.5.5–7.5.6. It detects MRC BTH opcodes over UDP on any port; truncated-header hints use RoCEv2 port 4791 and port 4971 as printed in the specification. Ordinary RoCE opcodes are not claimed. Decoded fields include BTH QP/PSN and retransmission flags, METH, optional TSETH, per-packet RETH, immediate data, AETH, SACK bitmap/signed offsets and congestion state, NACK reasons, reliability probes and endpoint messages. Payload previews are capped at 256 bytes; 64-bit addresses and bitmaps are strings. Unknown congestion state retains raw bytes. Captured iCRC is exposed without validation. Decoding is packet-local, with no RDMA message reconstruction, connection tracking, trim DSCP interpretation or loss/congestion analysis. Truncated fixed headers report errors; a shortened write payload cannot be identified without an external length hint.

RoCE is enabled by default and selectable with `['roce']`. RoCEv1 uses EtherType `0x8915` on Ethernet/VLAN and Linux cooked captures; RoCEv2 uses UDP destination port 4791 over IPv4 or IPv6. Both expose `packet.application.version`, BTH fields (QP, PSN, padding and congestion bits), and packet-local payload previews capped at 256 bytes. RoCEv1 also decodes GRH/GIDs and uses its payload length to exclude Ethernet padding. Supported transports are RC, UC, UD and CNP, including send/write/read, immediate and invalidate fields, acknowledgments, and compare-swap/fetch-add atomics. Extended header stacks follow the [Linux RDMA implementation](https://github.com/torvalds/linux/blob/master/drivers/infiniband/sw/rxe/rxe_opcode.c). Unsupported opcodes retain raw data with an error. MRC opcodes remain owned by the MRC dissector. Captured iCRC is exposed without validation; RDMA messages are not reconstructed. RD, XRC, flush, atomic-write and vendor extensions are not decoded. RoCEv2 custom ports are not detected automatically.

Applications importing the parser can select dissectors explicitly:

```js
import {parsePcapng} from './parser.js';
parsePcapng(buffer);                         // All registered dissectors (default)
parsePcapng(buffer, {dissectors: ['bmp']});   // Only BMP
parsePcapng(buffer, {dissectors: []});        // Transport decoding only
```

The bundled viewer accepts the same selection through `globalThis.packetLensOptions = {dissectors: ['bmp']}` before loading a capture. The worker accepts `{buffer, options: {dissectors: ['bmp']}}` as well as the original bare ArrayBuffer message.

To add a dissector, place it in its own source module and register it with `registerDissector` from `dissectors.js` before parsing (built-in modules are imported and registered there). Modules provide `name`, `matches(packet)`, and `dissect(payload, packet)`, returning `{protocol, info, ...details}` or `null`. Names must be unique; unknown selections fail explicitly. Modules may provide a pure `probe(payload, packet)` returning a positive confidence score (zero rejects) instead of `matches`; legacy matches score 1. Candidates run in descending confidence, with caller order breaking ties, until one returns a result. Successful TCP selection stays attached to that stream direction for continuation segments. Results appear under `packet.application`; the registry owns application protocol and summary updates while preserving transport fields. Custom registrations for the bundled viewer must be included in the worker's module graph, then rebuilt.

Filter by source address using the Source dropdown (resolved names are shown beside addresses). Source and TCP stream filters combine. Click a packet, or focus its row and press Enter or Space, to inspect its fields and application dissection in expandable groups.

## Deployment

Deploy the contents of `docs/` to any static web host. This directory contains the sample `index.html`, its `style.css` and `app.min.js`, and standalone `pcap-view.min.js` and `pcap-view.min.mjs` library bundles. Asset URLs are relative, so the sample works when hosted under a subdirectory. Source modules, tests, and build scripts remain outside the deployment directory.

Run `npm run build` before deployment to refresh all minified bundles. Edit the sample page and stylesheet directly in `docs/`. From a page hosted beside the library, use `<script src="pcap-view.min.js"></script>`.

## Standalone browser library

Include `docs/pcap-view.min.js` on any page; it exposes `PacketLens` and requires no viewer HTML, CSS, dependencies, or separate worker file. The worker and all built-in dissectors are embedded. Alternatively import `{open, parse}` from `docs/pcap-view.min.mjs`.

```html
<script src="docs/pcap-view.min.js"></script>
<input id="capture" type="file" accept=".pcapng">
<script>
  let capture;
  const input = document.querySelector('#capture');
  input.onchange = async () => {
    const file = input.files[0];
    if (!file) return;
    capture?.close();
    try {
      capture = await PacketLens.open(file);
      console.log(capture.packetCount, capture.streamCount, capture.duration);
      const {packets, total} = await capture.getPackets({offset: 0, limit: 100});
      console.log(packets, total);
      console.log(await capture.getStreams());
    } catch (error) {
      console.error(error);
    }
  };
  window.addEventListener('pagehide', () => capture?.close());
</script>
```

`PacketLens.open(input, {dissectors = 'all', signal} = {})` returns a Promise for a capture handle. Inputs may be a File, Blob, ArrayBuffer, or typed-array/DataView. Buffers are copied before transfer, preserving caller ownership; Files and Blobs are read inside the worker. Dissector selection matches the source parser API. An AbortSignal cancels opening or closes an already-open capture, rejecting pending requests with `AbortError`.

Capture handles expose:

- `packetCount`, `streamCount`, `duration` (seconds, or null when timestamps are absent).
- `getPackets({offset = 0, limit = 100, stream, source} = {})`: Promise of `{packets, total, offset}`. `stream` is a numeric TCP stream ID, `source` is a numeric IP address string; filters combine. Offset applies after filtering. Packet numbers retain capture order. `total` counts all matching packets. Each request scans the capture in worker memory.
- `getStreams()`: Promise of the complete stream array.
- `close()`: terminates the worker and releases its capture. Safe to call repeatedly; subsequent requests reject.

Packets retain the source parser structure, including `application.messages` for BMP and nested BGP fields. Each handle owns its worker; always close handles when finished. Errors reject Promises.

For smaller captures, `await PacketLens.parse(input, options)` returns the complete `{packets, streams}` result and closes its worker automatically. The bundled viewer uses this convenience API.

For large captures, prefer `open()` and bounded pages: parsing, filtering, and retained packet data stay in the worker, keeping the page responsive and avoiding cloning the entire result to the main thread. This is an in-memory parser, not a streaming or disk-backed index: the full file and decoded capture must fit in available browser memory. `parse()` additionally clones the entire result to the main thread. No progress events are provided during parsing.

Serve the bundle over HTTP(S). Sites with Content Security Policy must permit Blob workers (`worker-src blob:`) and the library script under their `script-src` policy. No capture data is uploaded.

Copyright © 2026 Exergy ∞ LLC.
