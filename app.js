import {parse} from './library.js';
const $ = id => document.getElementById(id);
let capture = {packets: [], streams: []}, filtered = [], page = 0, controller, generation = 0;
const pageSize = 100;
function render() {
  filtered = capture.packets.filter(p => ($('stream').value === 'all' || String(p.stream) === $('stream').value) && ($('source').value === 'all' || p.source === $('source').value));
  const start = page * pageSize, shown = filtered.slice(start, start+pageSize), fragment = document.createDocumentFragment();
  for (const p of shown) {
    const tr = document.createElement('tr');
    tr.tabIndex = 0; tr.title = 'View packet dissection';
    tr.onclick = () => showDetails(p);
    tr.onkeydown = e => {if (e.target === tr && (e.key === 'Enter' || e.key === ' ')) {e.preventDefault(); showDetails(p);}};
    const values = [p.number,p.relativeTime === null ? '—' : p.relativeTime.toFixed(6),p.sourceNames[0] || p.source,p.destinationNames[0] || p.destination,p.protocol,p.length,p.stream === null ? '—' : p.stream,p.info];
    values.forEach((value,i) => {
      const td = document.createElement('td');
      if (i === 2 || i === 3) {
        const address = i === 2 ? p.source : p.destination;
        const names = i === 2 ? p.sourceNames : p.destinationNames;
        td.title = [address, ...names].join('\n');
      }
      if (i === 4) {const badge = document.createElement('span'); badge.className = `badge ${p.protocol}`; badge.textContent = value; td.append(badge);}
      else if (i === 6 && p.stream !== null) {const button = document.createElement('button'); button.className = 'stream-link'; button.textContent = value; button.title = `Filter TCP stream ${value}`; button.onclick = e => {e.stopPropagation(); $('stream').value = String(p.stream); page=0; render();}; td.append(button);}
      else td.textContent = value;
      tr.append(td);
    }); fragment.append(tr);
  }
  $('rows').replaceChildren(fragment); $('empty').hidden = filtered.length > 0;
  $('visible-count').textContent = filtered.length.toLocaleString();
  $('range').textContent = filtered.length ? `${start+1}–${Math.min(start+pageSize,filtered.length)} of ${filtered.length.toLocaleString()} packets` : 'No packets to display';
  $('prev').disabled = page === 0; $('next').disabled = start + pageSize >= filtered.length;
  $('list-caption').textContent = capture.packets.length ? ($('stream').value === 'all' ? 'All packets in capture order' : `Following TCP stream ${$('stream').value}`) : 'Your capture will appear here';
}
function showDetails(packet) {
  $('detail-title').textContent = `Packet ${packet.number} · ${packet.protocol}`;
  const root = document.createDocumentFragment();
  function field(name, value, parent) {
    if (value !== null && typeof value === 'object') {
      const group = document.createElement('details'); group.open = true;
      const title = document.createElement('summary'); title.textContent = name; group.append(title);
      for (const [key, child] of Object.entries(value)) field(key, child, group);
      parent.append(group);
    } else {
      const row = document.createElement('div'); row.className = 'detail-field';
      const label = document.createElement('strong'); label.textContent = `${name}: `;
      row.append(label, document.createTextNode(value === null ? '—' : String(value))); parent.append(row);
    }
  }
  for (const [name, value] of Object.entries(packet)) field(name, value, root);
  $('dissection').replaceChildren(root); $('packet-details').hidden = false;
  $('packet-details').scrollIntoView({behavior: 'smooth', block: 'nearest'});
}
async function load(file) {
  if (!file) return;
  const token = ++generation; controller?.abort();
  $('status').className = '';
  if (!file.name.toLowerCase().endsWith('.pcapng')) {$('status').className='error'; $('status').textContent='Please choose a .pcapng file.'; return;}
  $('status').textContent = `Reading ${file.name}…`;
  try {
    controller = new AbortController();
    const result = await parse(file, {signal: controller.signal, dissectors: globalThis.packetLensOptions?.dissectors ?? 'all'});
    if (token !== generation) return; capture = result; page=0;
    $('filename').textContent = file.name; $('count').textContent = result.packets.length.toLocaleString(); $('streams').textContent = result.streams.length.toLocaleString();
    let min = Infinity, max = -Infinity; for (const p of result.packets) if (p.time !== null) {min=Math.min(min,p.time); max=Math.max(max,p.time);}
    $('duration').textContent = min === Infinity ? '—' : `${(max-min).toFixed(3)} s`;
    $('stream').replaceChildren(new Option('All packets','all'));
    for (const s of result.streams) $('stream').add(new Option(`Stream ${s.id} · ${s.sourceNames[0] || s.source}:${s.sport} ↔ ${s.destinationNames[0] || s.destination}:${s.dport} · ${s.count} packets`,String(s.id)));
    $('stream').disabled = !result.streams.length;
    $('source').replaceChildren(new Option('All sources', 'all'));
    for (const address of [...new Set(result.packets.map(p => p.source))].sort()) {
      const names = result.packets.find(p => p.source === address).sourceNames;
      $('source').add(new Option(names.length ? `${names[0]} (${address})` : address, address));
    }
    $('source').disabled = !result.packets.length;
    $('packet-details').hidden = true;
    $('status').textContent = result.packets.length ? 'Capture loaded. Select a TCP stream or click a stream number to filter.' : 'This capture contains no packets.'; render();
  } catch (error) {if (token !== generation) return; controller?.abort(); $('status').className='error'; $('status').textContent=error.message;}
}
$('file').onchange = e => {load(e.target.files[0]); e.target.value='';};
$('source').onchange = () => {page=0;render();};
$('close-details').onclick = () => {$('packet-details').hidden = true;};
$('stream').onchange = () => {page=0;render();};
$('prev').onclick = () => {page--;render();}; $('next').onclick = () => {page++;render();};
$('dropzone').onkeydown = e => {if (e.key==='Enter' || e.key===' ') {e.preventDefault();$('file').click();}};
for (const name of ['dragenter','dragover']) $('dropzone').addEventListener(name,e => {e.preventDefault();$('dropzone').classList.add('drag');});
for (const name of ['dragleave','drop']) $('dropzone').addEventListener(name,e => {e.preventDefault();$('dropzone').classList.remove('drag');});
$('dropzone').addEventListener('drop',e => load(e.dataTransfer.files[0]));
render();
