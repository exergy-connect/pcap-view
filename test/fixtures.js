export function fixture(little=true) {
  function block(type,body) {const b=new Uint8Array(body.length+12),v=new DataView(b.buffer);v.setUint32(0,type,little);v.setUint32(4,b.length,little);b.set(body,8);v.setUint32(b.length-4,b.length,little);return b;}
  const section=new Uint8Array(16),s=new DataView(section.buffer);s.setUint32(0,0x1a2b3c4d,little);s.setUint16(4,1,little);s.setBigInt64(8,-1n,little);
  const iface=new Uint8Array(8),i=new DataView(iface.buffer);i.setUint16(0,1,little);i.setUint32(4,65535,little);
  const parts=[block(0x0a0d0d0a,section),block(1,iface)];
  for (let n=0;n<3;n++) {
    const packet=new Uint8Array(54),v=new DataView(packet.buffer);v.setUint16(12,0x0800);packet[14]=0x45;v.setUint16(16,40);packet[23]=6;
    packet.set(n===1?[10,0,0,2]:[10,0,0,1],26);packet.set(n===1?[10,0,0,1]:[10,0,0,2],30);
    v.setUint16(34,n===1?443:50000);v.setUint16(36,n===1?50000:443);packet[46]=0x50;packet[47]=n===0?2:16;
    const body=new Uint8Array(76),b=new DataView(body.buffer);b.setUint32(8,1000000+n*1000,little);b.setUint32(12,54,little);b.setUint32(16,54,little);body.set(packet,20);parts.push(block(6,body));
  }
  const out=new Uint8Array(parts.reduce((sum,p)=>sum+p.length,0));let pos=0;for(const p of parts){out.set(p,pos);pos+=p.length;}return out.buffer;
}
