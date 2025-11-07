#!/usr/bin/env python3
# nmap_netviz_pyramid_draggable_autogrow.py
# Scan (or parse XML) → standalone HTML with pyramid layout, draggable nodes, and auto-expanding canvas.

import sys, os, json, tempfile, subprocess, shlex, time, xml.etree.ElementTree as ET

def prompt_target():
    try:
        t = input("Target (IP or CIDR, e.g. 10.0.2.15 or 10.0.2.0/24): ").strip()
    except KeyboardInterrupt:
        print(); sys.exit(1)
    if not t:
        print("No target provided."); sys.exit(2)
    return t

def run_nmap(target, xml_out):
    cmd = ["nmap", "-Pn", "-sS", "-sV", "-p-", "-T4", "-oX", xml_out, target]
    if os.geteuid() != 0:
        cmd.insert(0, "sudo")
    print(f"[*] Running: {' '.join(shlex.quote(c) for c in cmd)}")
    subprocess.run(cmd, check=True)

def parse_nmap(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []
    for host in root.findall('host'):
        st = host.find('status')
        if st is not None and st.get('state') != 'up':
            continue
        ip, mac, vendor = "", "", ""
        for a in host.findall('address'):
            if a.get('addrtype') in ('ipv4','ipv6'):
                ip = a.get('addr')
            if a.get('addrtype') == 'mac':
                mac = a.get('addr'); vendor = a.get('vendor','')
        hostname = ""
        hns = host.find('hostnames')
        if hns is not None:
            hn = hns.find('hostname')
            if hn is not None: hostname = hn.get('name','')
        os_name = ""
        os_el = host.find('os')
        if os_el is not None:
            match = os_el.find('osmatch')
            if match is not None:
                os_name = match.get('name','')
            else:
                oc = os_el.find('osclass')
                if oc is not None:
                    os_name = " ".join(filter(None, [oc.get('vendor',''), oc.get('osfamily',''), oc.get('type','')]))
        entries = []
        ports = host.find('ports')
        if ports is not None:
            for p in ports.findall('port'):
                state_el = p.find('state')
                state = (state_el.get('state') if state_el is not None else '').lower()
                if state not in ('open','open|filtered'):
                    continue
                portid = p.get('portid',''); proto = p.get('protocol','')
                svc = p.find('service')
                name = svc.get('name','') if svc is not None else ''
                prod = svc.get('product','') if svc is not None else ''
                ver  = svc.get('version','') if svc is not None else ''
                if not name: name = f"port:{portid}/{proto}"
                entries.append({"port":portid,"proto":proto,"state":state,"service":name,"product":prod,"version":ver})
        hosts.append({"display": hostname or ip or "unknown","ip": ip,"mac": mac,"vendor": vendor,"os": os_name,"entries": entries})
    return hosts

HTML = r"""<!doctype html>
<html><head><meta charset="utf-8">
<title>NetWeaver (pyramid • draggable • autogrow)</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial;margin:0;color:#0f172a}
  header{background:#0b2948;color:#fff;padding:10px 14px;display:flex;align-items:center;gap:12px}
  header h1{font-size:16px;margin:0}
  #wrap{display:flex;height:calc(100vh - 52px)}
  #svgwrap{flex:1;background:#f7fafc;overflow:auto;padding:8px} /* overflow:auto gives scrollbars when SVG grows */
  #side{width:360px;border-left:1px solid #e6eef6;padding:12px;box-sizing:border-box;overflow:auto}
  .muted{color:#64748b;font-size:13px}
  .info{font-size:13px;margin-bottom:8px}
  .section-title{font-weight:700;margin-top:8px;margin-bottom:6px}
  .dot{cursor:grab; stroke:#fff; stroke-width:1.6}
  .dot:active{cursor:grabbing}
  .subnet{fill:#0ea5a4}
  .host{fill:#2563eb}
  .port{fill:#f97316}
  .small{font-size:12px;color:#475569}
  table{width:100%;border-collapse:collapse;margin-top:6px}
  th,td{padding:6px 8px;border-bottom:1px solid #eef2f6;text-align:left;font-size:13px}
  th{background:#fbfdff}
  .hint{font-size:12px;color:#64748b}
  line{stroke-linecap:round; pointer-events:none;} /* edges never intercept clicks */
  @media(max-width:900px){#side{width:100%;height:36vh;border-left:none;border-top:1px solid #e6eef6}#wrap{flex-direction:column}}
</style>
</head><body>
<header><h1>NetWeaver</h1><div class="muted">Pyramid layout. Drag dots. Canvas autogrows when you hit the edge.</div></header>
<div id="wrap">
  <div id="svgwrap"><svg id="svg" width="1600" height="1100" viewBox="0 0 1600 1100" xmlns="http://www.w3.org/2000/svg"></svg></div>
  <aside id="side"><div id="details"><div class="hint">Click or drag a subnet / host / port to view details.</div></div></aside>
</div>
<script>
const DATA = __DATA__;

function escapeHtml(s){ return String(s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m])); }
function create(tag){ return document.createElementNS('http://www.w3.org/2000/svg', tag); }

const svg = document.getElementById('svg');
const side = document.getElementById('details');
const wrap = document.getElementById('svgwrap');

// --- Canvas sizing state ---
let CANVAS_W = parseFloat(svg.getAttribute('width')) || 1600;
let CANVAS_H = parseFloat(svg.getAttribute('height')) || 1100;
const EDGE_PAD = 80;   // how close to the edge before we expand
const GROW_CHUNK = 600; // how much to grow by each expansion

function setCanvasSize(w, h){
  CANVAS_W = Math.max(CANVAS_W, w);
  CANVAS_H = Math.max(CANVAS_H, h);
  svg.setAttribute('width', CANVAS_W);
  svg.setAttribute('height', CANVAS_H);
  svg.setAttribute('viewBox', `0 0 ${CANVAS_W} ${CANVAS_H}`);
}

function ensureBounds(x, y){
  let grew = false;
  if (x > CANVAS_W - EDGE_PAD) { setCanvasSize(x + GROW_CHUNK, CANVAS_H); grew = true; }
  if (y > CANVAS_H - EDGE_PAD) { setCanvasSize(CANVAS_W, y + GROW_CHUNK); grew = true; }
  // (Optional) handle negative drags: for simplicity we clamp at 0; feel free to add left/top growth if you need it.
  if (grew) {
    // Keep following the drag by auto-scrolling a bit toward the new space
    wrap.scrollLeft = Math.max(0, x - wrap.clientWidth/2);
    wrap.scrollTop  = Math.max(0, y - wrap.clientHeight/2);
  }
}

// ------- group by /24 -------
function subnet24(ip){
  const parts = (ip||'').split('.');
  if (parts.length===4 && parts.every(p=>/^\d+$/.test(p))) return parts.slice(0,3).join('.')+'.0/24';
  return 'other';
}
const clusters = {};
(DATA.hosts||[]).forEach(h=>{
  const sn = subnet24(h.ip);
  (clusters[sn] ||= []).push(h);
});
const subnetKeys = Object.keys(clusters).sort();

// ------- model for drag bookkeeping -------
const model = { subnets: {}, hosts: [], ports: [] };

// ------- pyramid layout per subnet -------
const cols = Math.min(subnetKeys.length, 5) || 1;     // up to 5 subnets per row
const colW = CANVAS_W / cols;
const rowH = 320;
const baseTop = 80;

subnetKeys.forEach((sn, idx)=>{
  const col = idx % cols;
  const row = Math.floor(idx / cols);
  const centerX = Math.round(colW*col + colW/2);
  const topY    = baseTop + row*rowH;

  // Subnet node (group)
  const sg = create('g');
  const sc = create('circle'); sc.setAttribute('r',32); sc.setAttribute('class','dot subnet');
  const st = create('text');   st.setAttribute('class','small'); st.setAttribute('text-anchor','middle'); st.textContent = sn.split('/')[0];

  sc.setAttribute('cx', centerX); sc.setAttribute('cy', topY);
  st.setAttribute('x',  centerX); st.setAttribute('y',  topY+5);

  const sh = create('circle'); sh.setAttribute('cx', centerX); sh.setAttribute('cy', topY); sh.setAttribute('r', 40);
  sh.setAttribute('fill','transparent'); sh.style.pointerEvents='all';

  sg.appendChild(sh); sg.appendChild(sc); sg.appendChild(st); svg.appendChild(sg);

  const subnetObj = { key: sn, g: sg, c: sc, t: st, h: sh, cx:centerX, cy:topY, hostObjs: [] };
  model.subnets[sn] = subnetObj;

  // Hosts row
  const hosts = clusters[sn];
  const hostRowY = topY + 100;
  const hostSpacing = 70;
  const totalHostWidth = (hosts.length-1)*hostSpacing;
  const hostStartX = centerX - totalHostWidth/2;

  hosts.forEach((h, i)=>{
    const hx = Math.round(hostStartX + i*hostSpacing);
    const hy = hostRowY;

    // edge subnet->host
    const hl = create('line'); hl.setAttribute('x1', centerX); hl.setAttribute('y1', topY+32);
    hl.setAttribute('x2', hx); hl.setAttribute('y2', hy-22); hl.setAttribute('stroke','#cfe3ff'); hl.setAttribute('stroke-width','2');
    svg.appendChild(hl);

    // host group
    const hg = create('g');
    const hc = create('circle'); hc.setAttribute('r',22); hc.setAttribute('class','dot host');
    const ht = create('text');   ht.setAttribute('class','small'); ht.setAttribute('text-anchor','middle');
    const label = (h.display||h.ip||'host'); ht.textContent = label.length>12 ? (label.slice(0,11)+'…') : label;

    hc.setAttribute('cx', hx); hc.setAttribute('cy', hy);
    ht.setAttribute('x',  hx); ht.setAttribute('y',  hy+7);

    const hh = create('circle'); hh.setAttribute('cx', hx); hh.setAttribute('cy', hy); hh.setAttribute('r', 30);
    hh.setAttribute('fill','transparent'); hh.style.pointerEvents='all';

    hg.appendChild(hh); hg.appendChild(hc); hg.appendChild(ht); svg.appendChild(hg);

    const hostObj = { data:h, g:hg, c:hc, t:ht, h:hh, cx:hx, cy:hy, lineToSubnet:hl, ports: [], subnet: subnetObj };
    subnetObj.hostObjs.push(hostObj);
    model.hosts.push(hostObj);

    // Ports row
    const ports = h.entries || [];
    const portRowY = hy + 90;
    const portSpacing = 44;
    const totalPortsW = (ports.length-1)*portSpacing;
    const portStartX = hx - (totalPortsW/2);

    ports.forEach((p, j)=>{
      const px = Math.round(portStartX + j*portSpacing);
      const py = portRowY;

      // edge host->port
      const pl = create('line'); pl.setAttribute('x1', hx); pl.setAttribute('y1', hy+22);
      pl.setAttribute('x2', px); pl.setAttribute('y2', py-14); pl.setAttribute('stroke','#ffdca8'); pl.setAttribute('stroke-width','1.8');
      svg.appendChild(pl);

      // port group
      const pg = create('g');
      const pc = create('circle'); pc.setAttribute('r',14); pc.setAttribute('class','dot port');
      const pt = create('text');   pt.setAttribute('class','small'); pt.setAttribute('text-anchor','middle'); pt.textContent = p.port;

      pc.setAttribute('cx', px); pc.setAttribute('cy', py);
      pt.setAttribute('x',  px); pt.setAttribute('y',  py+5);

      const ph = create('circle'); ph.setAttribute('cx', px); ph.setAttribute('cy', py); ph.setAttribute('r', 22);
      ph.setAttribute('fill', 'transparent'); ph.style.pointerEvents='all';

      pg.appendChild(ph); pg.appendChild(pc); pg.appendChild(pt); svg.appendChild(pg);

      const portObj = { data:p, g:pg, c:pc, t:pt, h:ph, cx:px, cy:py, lineToHost:pl, host:hostObj };
      hostObj.ports.push(portObj);
      model.ports.push(portObj);

      // click + drag for port
      makeDraggableGroup(pg, (dx,dy)=>{
        portObj.cx += dx; portObj.cy += dy;
        pc.setAttribute('cx', portObj.cx); pc.setAttribute('cy', portObj.cy);
        pt.setAttribute('x',  portObj.cx); pt.setAttribute('y',  portObj.cy+5);
        ph.setAttribute('cx', portObj.cx); ph.setAttribute('cy', portObj.cy);
        portObj.lineToHost.setAttribute('x2', portObj.cx);
        portObj.lineToHost.setAttribute('y2', portObj.cy-14);
        ensureBounds(portObj.cx, portObj.cy);
      }, ()=> showPort(h, p));
    });

    // click + drag for host (moves its ports and adjusts lines)
    makeDraggableGroup(hg, (dx,dy)=>{
      hostObj.cx += dx; hostObj.cy += dy;
      hc.setAttribute('cx', hostObj.cx); hc.setAttribute('cy', hostObj.cy);
      ht.setAttribute('x',  hostObj.cx); ht.setAttribute('y',  hostObj.cy+7);
      hh.setAttribute('cx', hostObj.cx); hh.setAttribute('cy', hostObj.cy);

      hostObj.lineToSubnet.setAttribute('x2', hostObj.cx);
      hostObj.lineToSubnet.setAttribute('y2', hostObj.cy-22);

      hostObj.ports.forEach(po=>{
        po.cx += dx; po.cy += dy;
        po.c.setAttribute('cx', po.cx); po.c.setAttribute('cy', po.cy);
        po.t.setAttribute('x',  po.cx); po.t.setAttribute('y',  po.cy+5);
        po.h.setAttribute('cx', po.cx); po.h.setAttribute('cy', po.cy);
        po.lineToHost.setAttribute('x1', hostObj.cx);
        po.lineToHost.setAttribute('y1', hostObj.cy+22);
        po.lineToHost.setAttribute('x2', po.cx);
        po.lineToHost.setAttribute('y2', po.cy-14);
        ensureBounds(po.cx, po.cy);
      });
      ensureBounds(hostObj.cx, hostObj.cy);
    }, ()=> showHost(h));
  });

  // click + drag for subnet (moves only the subnet node + starts of host edges)
  makeDraggableGroup(sg, (dx,dy)=>{
    subnetObj.cx += dx; subnetObj.cy += dy;
    sc.setAttribute('cx', subnetObj.cx); sc.setAttribute('cy', subnetObj.cy);
    st.setAttribute('x',  subnetObj.cx); st.setAttribute('y',  subnetObj.cy+5);
    sh.setAttribute('cx', subnetObj.cx); sh.setAttribute('cy', subnetObj.cy);
    subnetObj.hostObjs.forEach(h=>{
      h.lineToSubnet.setAttribute('x1', subnetObj.cx);
      h.lineToSubnet.setAttribute('y1', subnetObj.cy+32);
    });
    ensureBounds(subnetObj.cx, subnetObj.cy);
  }, ()=> showSubnet(sn));
});

// ---- interactivity (details) ----
function showSubnet(sn){
  const hosts = clusters[sn]||[];
  let html = `<div class="section-title">Subnet: ${escapeHtml(sn)}</div>`;
  html += `<div class="info small">Hosts: ${hosts.length}</div>`;
  html += `<table><thead><tr><th>Host</th><th>IP</th><th>#open</th></tr></thead><tbody>`;
  hosts.forEach(h=>{
    html += `<tr onclick="(function(){showHostClient('${escapeHtml(JSON.stringify(h))}')})()"><td>${escapeHtml(h.display)}</td><td>${escapeHtml(h.ip)}</td><td>${(h.entries||[]).length}</td></tr>`;
  });
  html += `</tbody></table>`;
  side.innerHTML = html;
}
window.showHostClient = (hjson)=>{ try{ showHost(JSON.parse(hjson)); }catch(e){} };

function showHost(h){
  let html = `<div class="section-title">Host: ${escapeHtml(h.display)}</div>`;
  html += `<div class="info small">IP: ${escapeHtml(h.ip||'')}</div>`;
  html += `<div class="info small">OS: ${escapeHtml(h.os||'unknown')}${h.vendor?(' • Vendor: '+escapeHtml(h.vendor)):''}</div>`;
  const ports = h.entries||[];
  html += `<div class="section-title" style="margin-top:8px">Open ports (${ports.length})</div>`;
  if (!ports.length){ html += `<div class="hint">No open ports.</div>`; side.innerHTML = html; return; }
  html += `<table><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>`;
  ports.forEach(p=>{
    html += `<tr onclick="(function(){showPortClient('${escapeHtml(JSON.stringify(h))}','${escapeHtml(JSON.stringify(p))}')})()"><td>${escapeHtml(p.port)}</td><td>${escapeHtml(p.proto)}</td><td>${escapeHtml(p.state)}</td><td>${escapeHtml(p.service||'')}</td><td>${escapeHtml(p.product||'')}</td><td>${escapeHtml(p.version||'')}</td></tr>`;
  });
  html += `</tbody></table>`;
  side.innerHTML = html;
}
window.showPortClient = (hjson,pjson)=>{ try{ showPort(JSON.parse(hjson), JSON.parse(pjson)); }catch(e){} };

function showPort(h,p){
  let html = `<div class="section-title">Port ${escapeHtml(p.port)} on ${escapeHtml(h.display)}</div>`;
  html += `<div class="info small">IP: ${escapeHtml(h.ip||'')}</div>`;
  html += `<div class="info small">Proto: ${escapeHtml(p.proto||'')}</div>`;
  html += `<div class="info small">State: ${escapeHtml(p.state||'')}</div>`;
  html += `<div class="info small">Service: ${escapeHtml(p.service||'')}</div>`;
  if (p.product) html += `<div class="info small">Product: ${escapeHtml(p.product)}</div>`;
  if (p.version) html += `<div class="info small">Version: ${escapeHtml(p.version)}</div>`;
  side.innerHTML = html;
}

// ---- drag helpers (attach to GROUP) ----
function makeDraggableGroup(groupEl, ondrag, onclick){
  let dragging = false, moved = false, last = null;

  function svgPoint(evt){
    const pt = svg.createSVGPoint();
    pt.x = evt.clientX; pt.y = evt.clientY;
    const ctm = svg.getScreenCTM().inverse();
    const p = pt.matrixTransform(ctm);
    return {x:p.x, y:p.y};
  }
  function mousedown(evt){
    dragging = true; moved = false; last = svgPoint(evt);
    evt.preventDefault(); evt.stopPropagation();
  }
  function mousemove(evt){
    if (!dragging) return;
    const p = svgPoint(evt);
    const dx = p.x - last.x, dy = p.y - last.y;
    if (Math.abs(dx) > 0.5 || Math.abs(dy) > 0.5) moved = true;
    ondrag(dx, dy);
    last = p;
  }
  function mouseup(evt){
    if (!dragging) return;
    dragging = false;
    if (!moved && typeof onclick === 'function') onclick();
    moved = false;
  }

  // Expand the group's click target by placing an invisible rect around its bbox
  try {
    const r = create('rect');
    const bb = groupEl.getBBox();
    r.setAttribute('x', bb.x - 8); r.setAttribute('y', bb.y - 8);
    r.setAttribute('width', bb.width + 16); r.setAttribute('height', bb.height + 16);
    r.setAttribute('fill', 'transparent'); r.style.pointerEvents = 'all';
    groupEl.insertBefore(r, groupEl.firstChild);
  } catch(e){}

  groupEl.addEventListener('mousedown', mousedown);
  window.addEventListener('mousemove', mousemove);
  window.addEventListener('mouseup', mouseup);
}
</script>
</body></html>
"""

def main():
    args = sys.argv[1:]
    if not args:
        target = prompt_target()
        out_html = f"netweaver_{int(time.time())}.html"
        xml_tmp = os.path.join(tempfile.gettempdir(), f"nmap_{os.getpid()}_{int(time.time())}.xml")
        run_nmap(target, xml_tmp)
        in_xml = xml_tmp
    elif args[0] == '-x':
        if len(args) < 2:
            print("Usage: -x scan.xml [out.html]", file=sys.stderr); sys.exit(2)
        in_xml = args[1]
        if not os.path.isfile(in_xml):
            print(f"[!] XML not found: {in_xml}", file=sys.stderr); sys.exit(1)
        out_html = args[2] if len(args) > 2 else f"netweaver_{int(time.time())}.html"
    else:
        target = args[0]
        out_html = args[1] if len(args) > 1 else f"netweaver_{int(time.time())}.html"
        xml_tmp = os.path.join(tempfile.gettempdir(), f"nmap_{os.getpid()}_{int(time.time())}.xml")
        run_nmap(target, xml_tmp)
        in_xml = xml_tmp

    hosts = parse_nmap(in_xml)
    data = {"hosts": hosts}
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(HTML.replace("__DATA__", json.dumps(data)))
    print(f"[+] Wrote {out_html} (hosts: {len(hosts)})")

if __name__ == "__main__":
    main()
