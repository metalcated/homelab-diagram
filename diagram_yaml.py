"""Editable YAML documents and runs of the original build.py renderer.

Discovery remains read-only input. Documents, revisions and render receipts live
in SQLite; each build receives its own inventory.yaml and output directory.
"""
from contextlib import closing
from datetime import datetime, timezone
import copy
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import sqlite3
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parent
SCHEMA='''
CREATE TABLE IF NOT EXISTS diagram_documents(site TEXT PRIMARY KEY,revision TEXT NOT NULL,yaml TEXT NOT NULL,baseline TEXT NOT NULL,updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS diagram_versions(site TEXT NOT NULL,revision TEXT PRIMARY KEY,yaml TEXT NOT NULL,baseline TEXT NOT NULL,updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS diagram_builds(id TEXT PRIMARY KEY,site TEXT NOT NULL,revision TEXT NOT NULL,redacted INTEGER NOT NULL,status TEXT NOT NULL,message TEXT NOT NULL,started TEXT NOT NULL,finished TEXT,renderer_sha256 TEXT NOT NULL,yaml_sha256 TEXT NOT NULL);
'''
COLORS=['#58a6ff','#f0883e','#bc8cff','#3fb950','#e3b341','#39c5cf','#f85149']
MAX_YAML=1_048_576


def now():return datetime.now(timezone.utc).isoformat(timespec='seconds')
def digest(data):return hashlib.sha256(data).hexdigest()
def text(value,limit=200):return re.sub(r'[\x00-\x1f]',' ',str(value or ''))[:limit]
def flag(value):return value is True or value in ('true','yes',1)
def amount(value):
    try:
        result=float(value or 0)
        return result if math.isfinite(result) and result>=0 else 0
    except (TypeError,ValueError):return 0

def yaml_module():
    try:import yaml;return yaml
    except ImportError:raise ValueError('The YAML workflow needs the project Python environment. Run start-labmap.command after renderer setup.') from None

def dump(document):return yaml_module().safe_dump(document,allow_unicode=True,sort_keys=False,width=100)

def load(contents):
    if not isinstance(contents,str) or len(contents.encode())>MAX_YAML:raise ValueError('YAML must be text no larger than 1 MiB.')
    y=yaml_module()
    try:
        for token in y.scan(contents):
            if isinstance(token,(y.tokens.AliasToken,y.tokens.AnchorToken)):raise ValueError('YAML aliases and anchors are not supported. Use explicit values.')
        data=y.safe_load(contents)
    except y.YAMLError as error:
        mark=getattr(error,'problem_mark',None)
        raise ValueError('Invalid YAML'+(f' at line {mark.line+1}, column {mark.column+1}' if mark else '')+'. Correct the syntax and save again.') from None
    validate(data)
    return data

def validate(document):
    if not isinstance(document,dict):raise ValueError('The original renderer needs a YAML mapping.')
    collected=document.get('layout')=='collected'
    if document.get('layout') not in (None,'collected'):raise ValueError('Choose the original fixed layout or layout: collected for multiple hosts.')
    count=0
    def walk(value,depth=0):
        nonlocal count
        count+=1
        if depth>20 or count>100000:raise ValueError('The YAML document is too deeply nested or too large.')
        if isinstance(value,dict):
            for key,item in value.items():
                if not isinstance(key,str):raise ValueError('YAML field names must be text.')
                if key in ('icon','icons'):
                    for name in item if isinstance(item,list) else [item]:
                        if not isinstance(name,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}',name):raise ValueError('Icon names must be local icon names without paths.')
                if key=='color' and (not isinstance(item,str) or not re.fullmatch(r'#[0-9a-fA-F]{6}',item)):raise ValueError('Colors must use #RRGGBB format.')
                walk(item,depth+1)
        elif isinstance(value,list):
            for item in value:walk(item,depth+1)
        elif isinstance(value,str):
            if len(value)>4096 or any(ord(c)<32 and c not in '\n\t' for c in value):raise ValueError('A YAML text value is too long or contains control characters.')
        elif value is not None and not isinstance(value,(bool,int,float)):raise ValueError('Use plain text, numbers, lists and mappings in YAML.')
        elif isinstance(value,(int,float)) and (abs(value)>1e30 or not math.isfinite(value)):raise ValueError('YAML numbers must be finite and within the supported range.')
    walk(document)
    sections=[('meta',dict),('redact',dict),('vlans',list),('devices',dict)]
    sections+= [('servers',list),('connections',list),('unplaced_assets',list)] if collected else [('internet',dict),('fritzbox',dict),('opnsense',dict),('switch',dict),('ssids',list),('remote',dict),('port_forwards',list),('terra',dict)]
    for name,kind in sections:
        if not isinstance(document.get(name),kind):raise ValueError(f'Keep the {name} section as a '+('list.' if kind is list else 'mapping.'))
    for key in ('title','title_redacted','domain','date','watermark'):
        if not isinstance(document['meta'].get(key),str):raise ValueError('The meta section needs text fields: title, title_redacted, domain, date and watermark.')
    if not collected:return
    if len(document['servers'])>100 or len(document['devices'])>500 or len(document['unplaced_assets'])>10000:raise ValueError('Split this diagram into smaller sites.')
    seen=set()
    for vlan in document['vlans']:
        if not isinstance(vlan,dict) or not all(isinstance(vlan.get(k),str) for k in ('key','tag','name','subnet','color','note')):raise ValueError('Each network needs key, tag, name, subnet, color and note text fields.')
        if vlan['key'] in seen:raise ValueError('Network keys must be unique.')
        seen.add(vlan['key'])
    def device(item):
        if not isinstance(item,dict) or not all(isinstance(item.get(k),str) for k in ('asset_id','name','type','model','ip','os')):raise ValueError('Each device/server needs asset_id, name, type, model, ip and os text fields.')
        if not isinstance(item.get('hw',[]),list) or not isinstance(item.get('ports',[]),list):raise ValueError('Device hardware and ports must be lists.')
        for hw in item.get('hw',[]):
            if not isinstance(hw,dict) or not all(isinstance(hw.get(k),str) for k in ('icon','label','value','sub')):raise ValueError('Hardware tiles need icon, label, value and sub text fields.')
    for item in document['devices'].values():device(item)
    for server in document['servers']:
        device(server)
        if not isinstance(server.get('dmz_groups'),list) or not isinstance(server.get('storage'),list):raise ValueError('Each server needs dmz_groups and storage lists.')
        for group in server['dmz_groups']:
            if not isinstance(group,dict) or not isinstance(group.get('name'),str) or not isinstance(group.get('guests'),list):raise ValueError('Each guest group needs a name and guests list.')
            for guest in group['guests']:
                if not isinstance(guest,dict) or not all(isinstance(guest.get(k),str) for k in ('asset_id','name','ip','note','kind')) or not isinstance(guest.get('icons'),list) or not isinstance(guest.get('id'),(str,int)):raise ValueError('Guests need asset_id, name, id, kind, ip, note and icons.')
                if guest.get('kind') not in ('VM','CT'):raise ValueError('Guest kind must be VM or CT.')
                if 'apps' in guest and (not isinstance(guest['apps'],list) or len(guest['apps'])>50):raise ValueError('Guest apps must be a list with at most 50 rows.')
    for link in document['connections']:
        if not isinstance(link,dict) or link.get('kind') not in ('physical','neighbor','logical','power'):raise ValueError('Connections must state physical, neighbor, logical or power evidence.')
        if link['kind']=='physical' and link.get('source')!='manual':raise ValueError('Only manually confirmed connections can be physical cables.')


def generated(state,site_id):
    site=next((s for s in state['sites'] if s['id']==site_id),None)
    if not site:raise ValueError('Choose an existing site.')
    assets=sorted((a for a in state.get('assets',[]) if a['site']==site_id),key=lambda a:(a.get('name','').casefold(),a['id']))
    by_id={a['id']:a for a in assets};links=[l for l in state.get('asset_links',[]) if l['site']==site_id]
    scopes=[ipaddress.ip_network(s) for s in site['targets']]
    networks=[];known=set()
    for a in assets:
        details=a.get('details',{});interfaces={i.get('name'):i for i in details.get('interfaces',[]) if 'name' in i}
        for row in details.get('addresses',[]):
            if flag(row.get('disabled')):continue
            try:net=ipaddress.ip_interface(row['address']).network
            except (KeyError,ValueError):continue
            if not any(net.version==n.version and net.subnet_of(n) for n in scopes) or str(net) in known:continue
            known.add(str(net));iface=row.get('interface','');vid=interfaces.get(iface,{}).get('vlan-id')
            # A reported VLAN ID is authoritative; a subnet's octet is not a VLAN ID.
            label=text(iface);key='network-'+digest(str(net).encode())[:10]
            networks.append({'key':key,'tag':'VLAN '+str(vid) if vid else 'Network','name':label,'subnet':str(net),'color':COLORS[len(networks)%len(COLORS)],'note':'Reported by '+text(a.get('name')),'vlan_id':str(vid or '')})
    for scope in scopes:
        if any(ipaddress.ip_network(n['subnet']).subnet_of(scope) for n in networks if ipaddress.ip_network(n['subnet']).version==scope.version):continue
        networks.append({'key':'network-'+digest(str(scope).encode())[:10],'tag':'Scope','name':'Discovery scope','subnet':str(scope),'color':COLORS[len(networks)%len(COLORS)],'note':'VLAN details not reported','vlan_id':''})
    def net_for(a):
        matches=[]
        for raw in a.get('addresses',[]):
            try:ip=ipaddress.ip_address(raw)
            except ValueError:continue
            for n in networks:
                net=ipaddress.ip_network(n['subnet'])
                if ip.version==net.version and ip in net:matches.append((net.prefixlen,n['key']))
        return max(matches,default=(0,'unknown'))[1]
    children={}
    for link in links:
        if link['kind']=='hosts' and link['src'] in by_id and link['dst'] in by_id:children.setdefault(link['src'],set()).add(link['dst'])
    hosts=[a for a in assets if a.get('role')=='Proxmox host' or a['id'] in children]
    host_ids={a['id'] for a in hosts};guest_ids={v for values in children.values() for v in values}
    storage_ids={a['id'] for a in assets if a.get('role') in ('Proxmox storage','Storage pool','Storage share')}
    neighbor_ids={end for link in links if link['kind'] in ('physical','neighbor') for end in (link['src'],link['dst'])}
    physical=[a for a in assets if a['id'] not in host_ids|guest_ids|storage_ids and (a.get('role') in ('Router','Switch','Router / switch','Physical server','TrueNAS','UPS','PDU','Access point') or a['id'] in neighbor_ids)]
    def base(a):
        details=a.get('details',{});cpu=details.get('cpu');cpu=cpu if isinstance(cpu,dict) else {}
        hw=[]
        if cpu.get('model') or isinstance(details.get('cpu'),str):hw.append({'icon':'glyph-cpu','label':'CPU','value':text(cpu.get('model') or details['cpu']), 'sub':str(cpu.get('cpus') or details.get('cpu_count') or details.get('cpu-count') or '?')+' logical CPUs'})
        mem=amount(details.get('memory_bytes') or details.get('total-memory'))
        if mem:hw.append({'icon':'glyph-ram','label':'MEMORY','value':f'{mem/1024**3:.0f} GiB','sub':'Reported usable memory'})
        interfaces=details.get('interfaces',[])
        if interfaces:hw.append({'icon':'glyph-nic','label':'NETWORK','value':str(len(interfaces))+' reported interfaces','sub':text(', '.join(i.get('iface') or i.get('name','') for i in interfaces[:3]),45)})
        ports=[]
        for i in interfaces:
            if i.get('type') not in ('ether','eth'):continue
            name=i.get('name') or i.get('iface','');tagged=[];untagged=''
            for v in details.get('vlans',[]):
                nk=next((n['key'] for n in networks if n['vlan_id'] and n['vlan_id']==str(v.get('vlan-ids'))),'')
                if name in str(v.get('tagged','')).split(',') and nk:tagged.append(nk)
                if name in str(v.get('untagged','')).split(',') and nk:untagged=nk
            ports.append({'name':text(name),'tagged':tagged,'untagged':untagged,'speed':text(i.get('speed')),'running':flag(i.get('running') or i.get('active'))})
        return {'asset_id':a['id'],'name':text(a.get('name') or a.get('address') or 'Unidentified device'),'type':text(a.get('role') or 'Neighbor device'),'model':text(a.get('manual_model') or a.get('model') or 'Model not reported'),'ip':text(a.get('address') or 'No IP reported'),'os':text(details.get('version') or ('Proxmox VE' if a['id'] in host_ids else '')),'vlan':net_for(a),'icons':['proxmox' if a['id'] in host_ids else 'mikrotik-l' if a.get('source')=='routeros' else 'glyph-nic'],'hw':hw,'ports':ports}
    devices={a['id']:base(a) for a in physical};servers=[]
    for a in hosts:
        server=base(a);groups={}
        for ident in sorted(children.get(a['id'],set()),key=lambda k:by_id[k].get('name','')):
            g=by_id[ident];details=g.get('details',{});nk=net_for(g)
            group=groups.setdefault(nk,{'asset_id':a['id']+':network:'+nk,'name':next((n['name'] for n in networks if n['key']==nk),'Network not reported'),'vlan':nk,'guests':[]})
            group['guests'].append({'asset_id':ident,'id':str(details.get('vmid','?')),'kind':'CT' if g.get('role')=='Container' else 'VM','name':text(g.get('name')),'ip':text(g.get('address') or 'No IP reported'),'internal':'','note':text(details.get('status') or ''),'icons':['glyph-cpu'],'vlan':nk})
        server['dmz_groups']=list(groups.values());server['storage']=[]
        for link in links:
            if link['kind']=='storage' and link['src']==a['id'] and link['dst'] in storage_ids:
                s=by_id[link['dst']];server['storage'].append({'asset_id':s['id'],'name':text(s.get('name')),'note':text(s.get('role')),'icon':'glyph-hdd'})
        servers.append(server)
    covered=set(devices)|host_ids|guest_ids|storage_ids
    unplaced=[{'asset_id':a['id'],'name':text(a.get('name') or a.get('address') or a.get('mac') or 'Unidentified'),'ip':text(a.get('address') or 'No IP reported'),'type':text(a.get('role') or 'Unverified')} for a in assets if a['id'] not in covered]
    connections=[{k:text(l.get(k)) for k in ('src','dst','src_port','dst_port','kind','source','label')} for l in links if l['kind'] in ('physical','neighbor','power') and l['src'] in devices and l['dst'] in devices]
    doc={'layout':'collected','meta':{'title':site['label'],'title_redacted':'My Homelab','domain':'','date':datetime.now().strftime('%B %Y'),'watermark':''},'redact':{'domain':True,'domain_placeholder':'redacted.com','ssid_names':True,'names':True,'addresses':True},'vlans':networks,'internet':{'note':'WAN details not confirmed'},'devices':devices,'servers':servers,'connections':connections,'unplaced_assets':unplaced,'layout_options':{'show_unplaced':True},'source':{'site':site_id,'assets':len(assets),'guests':len(guest_ids),'simulated':bool(state.get('demo') or state.get('simulated'))}}
    validate(doc)
    return doc


def merge(old,edited,new):
    """Three-way refresh: preserve user edits, add newly discovered identities."""
    if edited==old:return copy.deepcopy(new)
    if isinstance(old,dict) and isinstance(edited,dict) and isinstance(new,dict):
        result={}
        for key in dict.fromkeys([*edited,*new]):
            if key not in edited:
                if key not in old:result[key]=copy.deepcopy(new[key])
            elif key not in old:result[key]=copy.deepcopy(edited[key])
            elif key not in new:result[key]=copy.deepcopy(edited[key])
            else:result[key]=merge(old[key],edited[key],new[key])
        return result
    if isinstance(old,list) and isinstance(edited,list) and isinstance(new,list):
        def identity(item):return item.get('asset_id') or item.get('key') or item.get('name') if isinstance(item,dict) else None
        if all(identity(i) for i in old+edited+new):
            om={identity(i):i for i in old};em={identity(i):i for i in edited};nm={identity(i):i for i in new}
            return list(merge(om,em,nm).values())
    return copy.deepcopy(edited)


class Documents:
    def __init__(self,store):
        self.store=store;self.lock=threading.Lock();self.threads=[];self.process_lock=threading.Lock();self.processes=set();self.stopping=False
        with closing(store.connect()) as db,db:
            db.executescript(SCHEMA)
            db.execute("UPDATE diagram_builds SET status='interrupted',message='App stopped during build.py. Generate the PNG again.',finished=? WHERE status='running'",(now(),))
    def summary(self):
        with closing(self.store.connect()) as db:
            docs={r['site']:{'revision':r['revision'],'updated':r['updated'],'builds':[]} for r in db.execute('SELECT site,revision,updated FROM diagram_documents')}
            for row in db.execute('SELECT * FROM diagram_builds ORDER BY rowid DESC'):
                if row['site'] in docs and len(docs[row['site']]['builds'])<10:docs[row['site']]['builds'].append(dict(row))
        return docs
    def get(self,site):
        self.store.get_site(site)
        with closing(self.store.connect()) as db:
            row=db.execute('SELECT * FROM diagram_documents WHERE site=?',(site,)).fetchone()
            versions=[dict(r) for r in db.execute('SELECT revision,updated FROM diagram_versions WHERE site=? ORDER BY rowid DESC LIMIT 20',(site,))]
            builds=[dict(r) for r in db.execute('SELECT * FROM diagram_builds WHERE site=? ORDER BY rowid DESC LIMIT 10',(site,))]
        contents=row['yaml'] if row else dump(generated(self.store.state(),site))
        doc=load(contents)
        servers=doc.get('servers',[doc.get('terra',{})]);guests=sum(len(g['guests']) for s in servers for g in s.get('dmz_groups',[]))+sum(len(s.get('other_guests',{})) for s in servers)
        return {'site':site,'revision':row['revision'] if row else '', 'yaml':contents,'meta':doc['meta'],'summary':{'hosts':len(servers),'guests':guests,'devices':len(doc['devices']),'unplaced':len(doc.get('unplaced_assets',[]))},'versions':versions,'builds':builds,'saved':bool(row)}
    def save(self,payload,refresh=False,baseline_override=None):
        site=self.store.get_site(payload.get('site'))['id'];contents=payload.get('yaml');doc=load(contents)
        for key,value in (payload.get('metadata_changes') or {}).items():
            if key not in ('title','title_redacted','domain','date','watermark') or not isinstance(value,str):raise ValueError('Invalid diagram metadata edit.')
            doc['meta'][key]=text(value)
        validate(doc)
        with closing(self.store.connect()) as db,db:
            row=db.execute('SELECT * FROM diagram_documents WHERE site=?',(site,)).fetchone()
            if payload.get('revision','')!=(row['revision'] if row else ''):raise ValueError('This YAML was changed in another window. Reopen the editor before saving; your text is still in this window.')
            baseline=baseline_override if baseline_override is not None else json.loads(row['baseline']) if row else generated(self.store.state(),site)
            if refresh:
                if doc.get('layout')!='collected':raise ValueError('The original fixed-layout YAML can be edited and rendered here. Inventory refresh applies to the collected multi-host YAML layout.')
                fresh=generated(self.store.state(),site);doc=merge(baseline,doc,fresh);baseline=fresh;validate(doc)
            contents=dump(doc);rev=secrets.token_hex(12);updated=now();base=json.dumps(baseline)
            db.execute('INSERT INTO diagram_documents VALUES (?,?,?,?,?) ON CONFLICT(site) DO UPDATE SET revision=excluded.revision,yaml=excluded.yaml,baseline=excluded.baseline,updated=excluded.updated',(site,rev,contents,base,updated))
            db.execute('INSERT INTO diagram_versions VALUES (?,?,?,?,?)',(site,rev,contents,base,updated))
        return self.get(site)
    def restore(self,payload):
        site=self.store.get_site(payload.get('site'))['id']
        with closing(self.store.connect()) as db:row=db.execute('SELECT yaml,baseline FROM diagram_versions WHERE site=? AND revision=?',(site,payload.get('restore_revision'))).fetchone()
        if not row:raise ValueError('Choose an existing saved YAML revision.')
        return self.save({**payload,'yaml':row['yaml']},baseline_override=json.loads(row['baseline']))
    def render(self,payload):
        if self.stopping:raise ValueError('The local app is stopping. Reopen it before generating a PNG.')
        site=self.store.get_site(payload.get('site'))['id']
        if not isinstance(payload.get('redacted',False),bool):raise ValueError('Invalid redaction option.')
        with closing(self.store.connect()) as db:
            row=db.execute('SELECT * FROM diagram_documents WHERE site=?',(site,)).fetchone()
        if not row or row['revision']!=payload.get('revision'):raise ValueError('Save the current YAML before generating the PNG.')
        with self.lock:
            script=(ROOT/'build.py').read_bytes()
            with closing(self.store.connect()) as db,db:
                if db.execute("SELECT 1 FROM diagram_builds WHERE status='running'").fetchone():raise ValueError('A diagram build is already running. Wait for it to finish.')
                ident=secrets.token_hex(12);stamp=now()
                db.execute('INSERT INTO diagram_builds VALUES (?,?,?,?,?,?,?,?,?,?)',(ident,site,row['revision'],int(payload.get('redacted',False)),'running','Running build.py',stamp,None,digest(script),digest(row['yaml'].encode())))
            thread=threading.Thread(target=self.worker,args=(ident,site,row['yaml'],payload.get('redacted',False),script),daemon=True);self.threads.append(thread);thread.start()
        return {'build':ident}
    def worker(self,ident,site,contents,redacted,script):
        status='failed';message='The original renderer could not finish. Check YAML and renderer setup.'
        folder=self.store.path.parent/'diagrams'/site/ident
        try:
            folder.mkdir(parents=True,mode=0o700)
            (folder/'inventory.yaml').write_text(contents);(folder/'inventory.yaml').chmod(0o600)
            (folder/'build.py').write_bytes(script);(folder/'build.py').chmod(0o600)
            (folder/'icons').symlink_to(ROOT/'icons',target_is_directory=True)
            env=os.environ.copy();fonts=ROOT/'private'/'renderer-assets'/'fonts.conf'
            if fonts.exists():env['FONTCONFIG_FILE']=str(fonts)
            command=[sys.executable,str(folder/'build.py'),'--inventory',str(folder/'inventory.yaml'),'--out',str(folder/'out')]
            if not redacted:command.append('--unredacted')
            with self.process_lock:
                if self.stopping:raise ValueError('App stopped before build.py started.')
                process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
                self.processes.add(process)
            try:
                try:stdout,stderr=process.communicate(timeout=60)
                except subprocess.TimeoutExpired:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    process.communicate(timeout=5)
                    raise
                result=subprocess.CompletedProcess(command,process.returncode,stdout,stderr)
            finally:
                with self.process_lock:self.processes.discard(process)
            stem='homelab' if redacted else 'homelab-unredacted'
            png=folder/'out'/(stem+'.png');svg=folder/'out'/(stem+'.svg')
            if result.returncode:
                errors=result.stderr.decode(errors='replace')
                match=re.search(r'(?:AssertionError|ValueError): ([^\n]{1,160})',errors)
                if match:message='build.py: '+text(match.group(1),160)
                elif 'missing icon' in errors:message='build.py needs a local icon named in the YAML. Check the icon names or run renderer setup.'
                elif 'No module named' in errors:message='The original renderer needs its Python dependencies. Run renderer setup.'
            elif not png.exists() or not svg.exists() or not png.read_bytes().startswith(b'\x89PNG\r\n\x1a\n'):message='build.py did not produce valid SVG and PNG files.'
            else:
                ET.fromstring(svg.read_bytes());status='complete';message='PNG generated by build.py from saved YAML.'
        except subprocess.TimeoutExpired:message='build.py exceeded 60 seconds. Reduce the diagram size and retry.'
        except (OSError,ValueError,ET.ParseError):pass
        if self.stopping:status='interrupted';message='App stopped during build.py. Generate the PNG again.'
        with closing(self.store.connect()) as db,db:db.execute('UPDATE diagram_builds SET status=?,message=?,finished=? WHERE id=?',(status,message,now(),ident))
    def stop(self):
        self.stopping=True
        with self.process_lock:
            for process in list(self.processes):
                if process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
        for thread in self.threads:thread.join(timeout=5)
        with self.process_lock:
            for process in list(self.processes):
                if process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
        for thread in self.threads:
            if thread.is_alive():thread.join(timeout=2)
    def artifact(self,site,ident,kind):
        self.store.get_site(site)
        if kind not in ('png','svg','yaml') or not re.fullmatch(r'[a-f0-9]{24}',str(ident or '')):raise ValueError('Invalid diagram artifact.')
        with closing(self.store.connect()) as db:row=db.execute('SELECT * FROM diagram_builds WHERE site=? AND id=?',(site,ident)).fetchone()
        if not row or row['status']!='complete':raise ValueError('Choose a completed diagram build.')
        folder=self.store.path.parent/'diagrams'/site/ident
        path=folder/'inventory.yaml' if kind=='yaml' else folder/'out'/(('homelab' if row['redacted'] else 'homelab-unredacted')+'.'+kind)
        return path.read_bytes()
