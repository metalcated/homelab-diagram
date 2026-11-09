"""Automatic inventory layout using the original project's palette and folder-card design.

The upstream build.py example remains hand-placed. This layout reads the local
discovery database and grows to fit multiple hosts and their reported guests.
"""
import argparse
from contextlib import closing
import html
import ipaddress
import json
import math
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET

import asset_inventory

ROOT=Path(__file__).resolve().parent
BG='#0b0f15'; PANEL='#111821'; TILE='#161f2b'; BORDER='#253042'
TEXT='#e6edf3'; MUTED='#8d9aab'; BLUE='#79c0ff'; HARDWARE='#c08a5c'
COLORS=('#58a6ff','#f0883e','#bc8cff','#3fb950','#e3b341','#39c5cf','#f85149')
PARTS={'CPU','Memory module','Storage controller','Disk'}
KNOWN={'Router','Switch','Router / switch','Proxmox host','Physical server','TrueNAS','UPS','PDU','VM','Container','Access point','Storage pool','Storage share','Proxmox storage'}
W=2400; LEFT=48; SIDE=380; X=460; MAIN=W-X-48


def esc(value):return html.escape(re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]','',str(value or '')),quote=True)
def clip(value,limit=45):
    value=str(value or '')
    return value if len(value)<=limit else value[:limit-1]+'…'
def number(value):
    try:
        result=float(value or 0)
        return result if math.isfinite(result) and result>0 else 0
    except (TypeError,ValueError):return 0
def memory(value):
    amount=number(value)
    return f'{amount/1024**3:.0f} GiB' if amount else 'Memory not reported'
def key(asset):return asset.get('id') or asset.get('address')


class Drawing:
    def __init__(self):self.items=[];self.wires=[]
    def text(self,x,y,value,size=16,color=TEXT,weight=400,mono=False,max_width=None):
        family='Fira Code, Menlo, monospace' if mono else 'Fira Sans, Avenir Next, Helvetica Neue, sans-serif'
        clipping=''
        if max_width is not None:
            ident='clip-'+str(len(self.items))
            self.items.append(f'<defs><clipPath id="{ident}"><rect x="{x}" y="{y-size-3}" width="{max_width}" height="{size+8}"/></clipPath></defs>')
            clipping=f' clip-path="url(#{ident})"'
        self.items.append(f'<text x="{x}" y="{y}" fill="{color}" font-family="{family}" font-size="{size}" font-weight="{weight}"{clipping}>{esc(value)}</text>')
    def rect(self,x,y,w,h,fill=PANEL,stroke=BORDER,rx=12):
        self.items.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>')
    def folder(self,x,y,w,h,title,kind,color):
        # Same folder-tab silhouette as build.py; generous bounded labels fit any font fallback.
        tab=min(w-28,30+len(clip(title,30))*11+len(clip(kind,20))*8)
        self.items.append(f'<path d="M{x},{y+h-12} L{x},{y-25} Q{x},{y-34} {x+9},{y-34} L{x+tab-16},{y-34} C{x+tab-5},{y-34} {x+tab-5},{y} {x+tab+8},{y} L{x+w-12},{y} Q{x+w},{y} {x+w},{y+12} L{x+w},{y+h-12} Q{x+w},{y+h} {x+w-12},{y+h} L{x+12},{y+h} Q{x},{y+h} {x},{y+h-12} Z" fill="{PANEL}" stroke="{color}" stroke-width="1.6"/>')
        self.items.append(f'<title>{esc(title)} / {esc(kind)}</title>')
        self.text(x+18,y-11,clip(title,30),20,TEXT,700)
        self.text(x+28+len(clip(title,30))*11,y-11,'· '+clip(kind,20),14,MUTED,600)
    def icon(self,name,x,y,size=30):
        if name not in {'cpu','ram','nic','hdd','shield'}:return
        root=ET.fromstring((ROOT/'icons'/('glyph-'+name+'.svg')).read_text())
        for attr,value in {'x':x,'y':y,'width':size,'height':size}.items():root.set(attr,str(value))
        self.items.append(ET.tostring(root,encoding='unicode'))
    def render(self,height,title):
        return f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{height}" viewBox="0 0 {W} {height}" role="img" aria-label="{esc(title)}"><title>{esc(title)}</title><defs><pattern id="dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1.5" cy="1.5" r="1.3" fill="#151c26"/></pattern></defs><rect width="{W}" height="{height}" fill="{BG}"/><rect width="{W}" height="{height}" fill="url(#dots)"/>'+''.join(self.wires)+''.join(self.items)+'</svg>'


def render(state,site_id,redacted=False):
    site=next((s for s in state.get('sites',[]) if s['id']==site_id),None)
    if not site:raise ValueError('Choose an existing site for the diagram.')
    assets=sorted((a for a in state.get('assets',[]) if a['site']==site_id),key=lambda a:(str(a.get('name') or a.get('hostname') or a.get('address') or '').casefold(),str(key(a))))
    if len(assets)>10000:raise ValueError('This site is too large for one diagram. Split it into smaller sites.')
    links=[l for l in state.get('asset_links',[]) if l['site']==site_id]
    by_id={key(a):a for a in assets}; indices={key(a):i+1 for i,a in enumerate(assets)}
    role=lambda a:a.get('role') or a.get('auto_role') or ''
    def shown_role(a):return (role(a) if role(a) in KNOWN else 'Asset') if redacted else a.get('role') or role(a) or 'Unverified'
    def name(a):return f'{shown_role(a)} {indices[key(a)]}' if redacted else a.get('name') or a.get('hostname') or a.get('address') or a.get('mac') or 'Unidentified asset'
    def address(a):return 'Address hidden' if redacted else a.get('address') or 'No IP reported'
    def model(a):return 'Hardware details hidden' if redacted else a.get('manual_model') or a.get('model') or a.get('vendor') or 'Model not reported'
    scopes=[]
    for target in site.get('targets',[]):
        try:scopes.append(ipaddress.ip_network(target,strict=False))
        except ValueError:pass
    def color(a):
        for raw in a.get('addresses') or [a.get('address')]:
            try:ip=ipaddress.ip_address(raw)
            except (ValueError,TypeError):continue
            for i,net in enumerate(scopes):
                if ip.version==net.version and ip in net:return COLORS[i%len(COLORS)]
        return '#3a475a'
    def address_color(a):return MUTED if color(a)=='#3a475a' else color(a)
    children={}
    for link in links:
        if link['kind']=='hosts' and link['src'] in by_id and link['dst'] in by_id:
            children.setdefault(link['src'],set()).add(link['dst'])
    hosts=[a for a in assets if role(a)=='Proxmox host' or key(a) in children]
    placed={guest for values in children.values() for guest in values}
    parts={key(a) for a in assets if role(a) in PARTS}
    host_ids={key(a) for a in hosts}
    guests=[a for a in assets if role(a) in ('VM','Container') and key(a) not in placed]
    network=[a for a in assets if key(a) not in host_ids|placed|parts and role(a) in ('Router','Switch','Router / switch','TrueNAS','Physical server','UPS','PDU','Access point')]
    covered=host_ids|placed|parts|{key(a) for a in guests+network}
    remaining=[a for a in assets if key(a) not in covered]
    d=Drawing(); title='Lab inventory' if redacted else site['label']
    d.text(LEFT,65,title,40,TEXT,700)
    d.text(LEFT,96,'Original-style diagram · generated from collected inventory',17,MUTED)
    d.text(LEFT,123,f'{len(assets)} assets · {len(hosts)} hosts · {sum(role(a)=="VM" for a in assets)} VMs · {sum(role(a)=="Container" for a in assets)} containers · {len(links)} reported relationships',15,MUTED)
    badge='Simulated inventory' if state.get('demo') or state.get('simulated') else 'Names and addresses hidden' if redacted else 'Private inventory snapshot'
    d.text(W-400,65,badge,16,BLUE,600)
    observed=max((str(a.get('last_seen') or '') for a in assets),default='')
    d.text(W-400,94,('Observed '+observed[:19].replace('T',' ')+' UTC') if observed else 'No observations yet',13,MUTED)
    side_height=82+max(1,len(scopes))*62
    d.rect(LEFT,165,SIDE,side_height);d.text(LEFT+20,198,'Networks',20,TEXT,600)
    for i,net in enumerate(scopes):
        y=220+i*62; c=COLORS[i%len(COLORS)]
        d.rect(LEFT+16,y,SIDE-32,49,TILE,BORDER,6);d.rect(LEFT+16,y,4,49,c,c,1)
        d.text(LEFT+30,y+21,f'Network {i+1}' if redacted else str(net),16,c,600,True)
        d.text(LEFT+30,y+40,'Configured discovery scope',12,MUTED)
    if not scopes:d.text(LEFT+20,240,'No saved network scopes',14,MUTED)
    y=185+side_height
    d.rect(LEFT,y,SIDE,235);d.text(LEFT+20,y+34,'Reading this diagram',20,TEXT,600)
    for i,text in enumerate(('Folder tabs identify physical hosts.','Guests sit inside their reported host.','Card color follows the observed IP network.','No-IP guests remain in their host group.','Physical cables require manual evidence.','Network reports do not prove direct cables.','Unknown roles remain unverified.')):d.text(LEFT+20,y+66+i*22,text,13,MUTED)
    d.rect(LEFT,y+255,SIDE,126);d.text(LEFT+20,y+289,'Connection evidence',18,TEXT,600)
    for i,(kind,label) in enumerate((('physical','Confirmed network cables'),('neighbor','Reported neighbors'),('learned','Forwarding / ARP reports'))):
        count=sum(l['kind']==kind and (kind!='physical' or l['source']=='manual') for l in links)
        d.text(LEFT+20,y+317+i*22,f'{label}: {count}',13,MUTED)
    bottom=y+400; y=200;positions={}
    d.text(X,y-25,'Infrastructure',21,TEXT,600)
    if not network:
        d.rect(X,y,MAIN,85);d.text(X+22,y+34,'No infrastructure roles reported yet',18,TEXT,600);d.text(X+22,y+61,'Collect from your router, hypervisor, storage and power systems to identify them.',14,MUTED);y+=145
    else:
        cols=3;cw=(MAIN-2*24)/3
        for i,a in enumerate(network):
            cx=X+(i%cols)*(cw+24);cy=y+(i//cols)*190
            positions[key(a)]=(cx+cw,cy+58)
            d.folder(cx,cy,cw,118,name(a),shown_role(a),color(a));d.icon('nic' if 'Router' in role(a) or role(a)=='Switch' else 'hdd' if role(a)=='TrueNAS' else 'cpu',cx+18,cy+22,40)
            d.text(cx+74,cy+34,clip(model(a),54),16,TEXT,500);d.text(cx+74,cy+62,clip(address(a),50),14,address_color(a),500,True)
            version=a.get('details',{}).get('version','') if not redacted else ''
            d.text(cx+74,cy+89,clip(version or shown_role(a),57),13,MUTED)
        y+=math.ceil(len(network)/cols)*190+25

    def host_panel(host,items,unplaced=False):
        nonlocal y
        header='Guests without a reported host' if unplaced else name(host)
        rows=max(1,math.ceil(len(items)/4));height=max(230,142+rows*90)
        c=BORDER if unplaced else color(host)
        if host:positions[key(host)]=(X+MAIN,y+44)
        d.folder(X,y,MAIN,height,header,'Host not reported' if unplaced else shown_role(host),c)
        if not unplaced:
            d.icon('cpu',X+20,y+18,45);d.text(X+78,y+36,clip(model(host),90),18,TEXT,600);d.text(X+78,y+63,address(host),14,address_color(host),500,True)
            details=host.get('details',{});cpu=details.get('cpu') or {};cpu=cpu if isinstance(cpu,dict) else {}
            d.rect(X+20,y+88,260,height-108,TILE,BORDER,8);d.rect(X+21,y+100,4,height-132,HARDWARE,HARDWARE,1)
            d.text(X+40,y+115,'Hardware',15,HARDWARE,600)
            d.text(X+40,y+143,clip('Details hidden' if redacted else cpu.get('model') or 'CPU not reported',27),14,TEXT,500)
            d.text(X+40,y+169,memory(details.get('memory_bytes')),14,MUTED)
            count=number(details.get('cpu_count') or cpu.get('cpus'))
            d.text(X+40,y+195,f'{int(count)} logical CPUs' if count else 'CPU count not reported',13,MUTED)
        else:d.text(X+22,y+40,'Guests were discovered, but their host relationship is unavailable.',16,MUTED)
        gx=X+304;cw=(MAIN-324-3*16)/4
        for i,a in enumerate(items):
            ax=gx+(i%4)*(cw+16);ay=y+88+(i//4)*90
            d.rect(ax,ay,cw,74,TILE,color(a),7);d.items.append(f'<title>{esc(name(a))}</title>')
            d.text(ax+12,ay+23,clip(name(a),42),15,TEXT,600,max_width=cw-24)
            vmid=a.get('details',{}).get('vmid','')
            badge=('CT' if role(a)=='Container' else 'VM')+(' '+str(vmid) if vmid and not redacted else '')
            d.text(ax+cw-90,ay+64,clip(badge,12),11,MUTED,500,True,max_width=78)
            d.text(ax+12,ay+46,clip(address(a),42),12,address_color(a),500,True,max_width=cw-24)
            status=a.get('details',{}).get('status','')
            status=status if status in ('running','stopped','paused','online','offline') else ''
            d.text(ax+12,ay+64,(status+' · ' if status else '')+shown_role(a),11,MUTED,max_width=cw-114)
        if not items:d.text(gx,y+125,'No guests reported for this host.',15,MUTED)
        y+=height+75

    for host in hosts:host_panel(host,[a for a in assets if key(a) in children.get(key(host),set())])
    if guests:host_panel(None,guests,True)
    if not hosts:
        d.rect(X,y,MAIN,98);d.text(X+22,y+36,'Proxmox hosts and guests',21,TEXT,600);d.text(X+22,y+68,'Connect Proxmox to populate host hardware, VMs, containers and their placement automatically.',16,MUTED);y+=145
    if remaining:
        d.text(X,y,'Additional discovered assets',22,TEXT,600);y+=18
        cols=4;cw=(MAIN-3*16)/cols;rows=math.ceil(len(remaining)/cols)
        d.rect(X,y,MAIN,rows*58+28)
        for i,a in enumerate(remaining):
            ax=X+18+(i%cols)*(cw+16);ay=y+30+(i//cols)*58
            d.text(ax,ay,clip(name(a),40),14,TEXT,500)
            d.text(ax,ay+21,clip(address(a)+' · '+shown_role(a),49),11,address_color(a),400,True)
        y+=rows*58+65
    y=max(y,bottom)
    drawn=set()
    for link in sorted(links,key=lambda l:0 if l['kind']=='physical' and l['source']=='manual' else 1 if l['kind']=='neighbor' else 2):
        pair=tuple(sorted((link['src'],link['dst'])))
        if pair in drawn or link['src'] not in positions or link['dst'] not in positions:continue
        if link['kind'] not in ('physical','neighbor','learned'):continue
        solid=link['kind']=='physical' and link['source']=='manual'
        # A reported relation stays dashed; it is never promoted to a confirmed cable.
        a,b=positions[link['src']],positions[link['dst']];lane=W-25
        dash='' if solid else ' stroke-dasharray="5 5"'
        label=('Confirmed cable' if solid else 'Reported '+link['kind'])+': '+name(by_id[link['src']])+' → '+name(by_id[link['dst']])
        d.wires.append(f'<path d="M{a[0]},{a[1]} H{lane} V{b[1]} H{b[0]}" fill="none" stroke="{BLUE if solid else MUTED}" stroke-width="{2.4 if solid else 1.4}" opacity="0.7"{dash}><title>{esc(label)}</title></path>')
        drawn.add(pair)
    d.text(LEFT,y+12,'Placement and colors summarize inventory. Reported network neighbors and forwarding entries are evidence, not inferred physical cables.',14,MUTED)
    d.text(LEFT,y+38,f'Host placement: {len(placed)} guests · Hardware components: {len(parts)} · Unknown roles: {sum(not a.get("role") for a in assets)}',13,MUTED)
    return d.render(y+70,title+' · original-style inventory diagram')


def png(svg):
    binary=shutil.which('rsvg-convert')
    if not binary:raise ValueError('PNG export is unavailable on this Mac. Download the SVG instead.')
    root=ET.fromstring(svg);width=int(root.get('width'));height=int(root.get('height'))
    width=min(width,max(1,int(math.sqrt(16_000_000*width/max(height,1)))))
    try:result=subprocess.run([binary,'--width',str(width)],input=svg.encode(),capture_output=True,timeout=30,check=False)
    except (OSError,subprocess.SubprocessError):raise ValueError('The PNG could not be generated. Download the SVG instead.') from None
    if result.returncode or not result.stdout.startswith(b'\x89PNG\r\n\x1a\n'):raise ValueError('The PNG could not be generated. Download the SVG instead.')
    return result.stdout


def main(argv=None):
    parser=argparse.ArgumentParser(description='Render the original-style layout from collected inventory.')
    parser.add_argument('--discovered-db',type=Path,required=True);parser.add_argument('--site',required=True)
    parser.add_argument('--out',type=Path,default=ROOT/'out');parser.add_argument('--redacted',action='store_true')
    parser.add_argument('--svg-only',action='store_true');args=parser.parse_args(argv)
    path=args.discovered_db.expanduser().resolve()
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
        db.row_factory=sqlite3.Row
        sites=[{**dict(s),'targets':json.loads(s['targets'])} for s in db.execute('SELECT * FROM sites')]
        state={**asset_inventory.state(db),'sites':sites}
    svg=render(state,args.site,args.redacted)
    # Site IDs are validated independently before using them in an output filename.
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}',args.site):parser.error('Invalid site ID.')
    args.out.mkdir(parents=True,exist_ok=True)
    stem=args.site+'-original-style'+('-redacted' if args.redacted else '-private')
    (args.out/(stem+'.svg')).write_text(svg)
    if not args.svg_only:(args.out/(stem+'.png')).write_bytes(png(svg))
    print(str(args.out/stem)+(' .svg' if args.svg_only else ' .svg + .png'))
    return 0


if __name__=='__main__':raise SystemExit(main())
