# pcap-view

A dependency-free, single-page PCAPNG viewer. Files are parsed locally in a web worker; nothing is uploaded to a server.

Run `npm install`, then `npm start` and open http://localhost:5173. Requires Node.js 24+ and Python 3 for the static server. Run `npm test` to check the parser.

`npm run build` uses esbuild to generate `docs/app.min.js`, the single minified JavaScript bundle loaded by `docs/index.html`. The parser worker is bundled into that file and started from a local Blob URL. `npm start` rebuilds automatically and serves only `docs/`; rebuild after editing JavaScript sources.

Drop a `.pcapng` file or use the file picker. Choose a TCP stream in the dropdown, or click a stream number in the packet table. The table displays 100 packets per page.

IPv4 and IPv6 hostname mappings embedded in PCAPNG Name Resolution Blocks appear in the packet table and stream selector. The first supplied name is displayed; hover over an address cell to see its IP and all aliases. Mappings apply throughout their section, including packets before the mapping block. Unmapped addresses remain numeric. No DNS requests are made, and TCP grouping continues to use numeric addresses. Record decoding follows the [PCAPNG Name Resolution Block format](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html#section-4.5).

Supports little- and big-endian sections, multiple interfaces, enhanced/simple/legacy packet blocks, interface timestamp resolution and offsets, Ethernet/VLAN, raw IP, Linux cooked capture, IPv4, IPv6, TCP, UDP, and ICMP. Unknown link types and truncated network headers remain visible with limited details. Malformed PCAPNG blocks produce an error without replacing the previous capture.

TCP streams are assigned in capture order using bidirectional address/port pairs scoped to the section and interface. A new SYN after an established or closed connection starts a new stream. This is a lightweight heuristic; it does not promise Wireshark-identical stream numbering. IP fragments are not reassembled. Large files must fit in browser memory.

Format reference: [IETF PCAPNG specification](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/).

Application dissectors run after transport decoding and retain TCP stream grouping. BMP v3 is enabled by default and recognized by its common header, with TCP port 11019 as a fallback hint. It decodes common and per-peer headers, message types, initiation/termination TLVs, and basic BGP, statistics and peer notification fields following [RFC 7854](https://www.rfc-editor.org/rfc/rfc7854.html). Multiple messages per packet and BMP messages spanning contiguous TCP segments are decoded. Buffers are independent per stream direction, handle retransmission overlap and sequence wrap, and flag sequence gaps. Missing or out-of-order segments are not recovered; pending bytes are shown while awaiting more data. Messages above 16 MiB are rejected by the stream decoder. Embedded BGP OPEN, UPDATE, NOTIFICATION, KEEPALIVE, and ROUTE-REFRESH messages expose nested fields. UPDATE decoding includes IPv4 prefixes, common path attributes, AS paths and communities; unsupported attributes retain raw bytes.

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
