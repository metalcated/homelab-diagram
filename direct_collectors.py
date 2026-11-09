"""Read-only platform adapters and numeric-OID SNMP discovery."""
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.parse import quote, urlencode

from asset_inventory import mac, text
from collector_transport import CollectorError, HTTPS, TrueNASWebSocket, endpoint, fingerprint, resolve_scoped
from scan_events import quiet

CATALOG={
 'routeros':{'name':'RouterOS','transport':'HTTPS REST','auth':'basic'},
 'proxmox':{'name':'Proxmox VE','transport':'HTTPS API token','auth':'token'},
 'truenas':{'name':'TrueNAS 25.04+','transport':'WSS JSON-RPC','auth':'api_key'},
 'idrac':{'name':'Dell iDRAC / Redfish','transport':'HTTPS Redfish','auth':'basic'},
 'snmp':{'name':'SNMP discovery / auto-detect','transport':'SNMP GET / GETBULK','auth':'snmp'},
 'apc':{'name':'APC UPS','transport':'SNMP GET / GETBULK','auth':'snmp'},
 'cyberpower':{'name':'CyberPower UPS','transport':'SNMP GET / GETBULK','auth':'snmp'},
}


def validate_config(kind,payload):
    if kind not in CATALOG:raise CollectorError('Choose a supported collector.')
    cfg={'endpoint':str(payload.get('endpoint') or '').strip(), 'username':text(payload.get('username'),200),
         'fingerprint':fingerprint(payload.get('fingerprint')), 'snmp_version':str(payload.get('snmp_version','3')),
         'security_level':str(payload.get('security_level','authPriv')), 'auth_protocol':str(payload.get('auth_protocol','SHA')),
         'privacy_protocol':str(payload.get('privacy_protocol','AES'))}
    try:cfg['snmp_port']=int(payload.get('snmp_port',161))
    except (ValueError,TypeError):raise CollectorError('Enter a valid SNMP UDP port.') from None
    if not 1<=cfg['snmp_port']<=65535:raise CollectorError('Enter a valid SNMP UDP port.')
    if any(c in cfg['username'] for c in ('\r','\n','\x00')):raise CollectorError('Invalid username.')
    if CATALOG[kind]['auth']=='snmp':
        if cfg['endpoint']:
            try:cfg['endpoint']=str(ipaddress.ip_address(cfg['endpoint']))
            except ValueError:raise CollectorError('SNMP endpoint must be an IP address, or blank for site-wide discovery.') from None
        if kind!='snmp' and not cfg['endpoint']:raise CollectorError('Enter the UPS management IP, or use SNMP discovery to find agents across the site.')
        if cfg['snmp_version'] not in ('2c','3') or cfg['security_level'] not in ('noAuthNoPriv','authNoPriv','authPriv'):
            raise CollectorError('Choose SNMPv2c or a valid SNMPv3 security level.')
        if cfg['auth_protocol'] not in ('SHA','MD5') or cfg['privacy_protocol'] not in ('AES','DES'):
            raise CollectorError('Choose a supported Net-SNMP authentication/privacy protocol.')
        if cfg['snmp_version']=='3' and not cfg['username']:raise CollectorError('SNMPv3 requires a security name.')
    else:
        endpoint(cfg['endpoint'])
        if not cfg['username']:raise CollectorError('Enter the management username, API-key username, or Proxmox user@realm!tokenid.')
    return cfg


def inside(value,nets):
    try:
        addr=ipaddress.ip_interface(str(value)).ip
        return str(addr) if any(addr.version==n.version and addr in n for n in nets) else ''
    except ValueError:return ''


class Batch:
    def __init__(self,nets):self.nets=nets;self.assets={};self.links=[];self.warnings=[]
    def asset(self,ref,**fields):
        item=self.assets.setdefault(ref,{'ref':ref,'addresses':[],'macs':[],'details':{}})
        for key,value in fields.items():
            if key=='addresses':item[key]=list(dict.fromkeys(item[key]+[v for a in value if (v:=inside(a,self.nets))]))
            elif key=='macs':item[key]=list(dict.fromkeys(item[key]+[v for a in value if (v:=mac(a))]))
            elif key=='details':item[key].update(value)
            elif value:item[key]=text(value)
        return ref
    def link(self,src,dst,kind='neighbor',**fields):
        if src!=dst:self.links.append({'src':src,'dst':dst,'kind':kind,**fields})
    def result(self):return {'assets':list(self.assets.values()),'links':self.links,'warnings':list(dict.fromkeys(self.warnings))}
    def optional(self,client,path,default):
        try:return client.get(path)
        except CollectorError as error:
            self.warnings.append(f'{path.split("?")[0]}: read unavailable ({error.code or "connection"}).')
            return default


def basic(config,secret):
    if not secret.get('password'):raise CollectorError('Enter a password or API token for this connection.')
    raw=f'{config["username"]}:{secret["password"]}'.encode()
    return {'Authorization':'Basic '+base64.b64encode(raw).decode()}


def routeros(config,secret,address,nets,stop=lambda:False,client=None,emit=None):
    http=client or HTTPS(config,address,basic(config,secret),stop,emit=emit)
    b=Batch(nets)
    def get(path,properties,required=False):
        url='/rest/'+path+'?'+urlencode({'.proplist':','.join(properties)})
        data=http.get(url) if required else b.optional(http,url,[])
        if not isinstance(data,list) or any(not isinstance(row,dict) for row in data):raise CollectorError('Unexpected RouterOS response shape.')
        return data
    identity=get('system/identity',['name'],True)
    resource=get('system/resource',['board-name','version','cpu','cpu-count','total-memory'])
    r=resource[0] if resource else {}
    root=b.asset('routeros:'+address,addresses=[address],name=identity[0].get('name') if identity else '',role='Router / switch',vendor='MikroTik',model=r.get('board-name'),
                 details={k:r[k] for k in ('version','cpu','cpu-count','total-memory') if k in r})
    interfaces=get('interface',['name','type','mac-address','mtu','running'])
    ips=get('ip/address',['address','interface','disabled'])
    b.asset(root,macs=[i.get('mac-address') for i in interfaces],addresses=[i.get('address') for i in ips if i.get('disabled')!='true'],
            details={'interfaces':interfaces,'addresses':ips})
    neighbors=get('ip/neighbor',['address','address4','address6','identity','mac-address','interface','interface-name','platform','board','discovered-by'])
    for row in neighbors:
        remote=inside(row.get('address4') or row.get('address') or row.get('address6'),nets)
        m=mac(row.get('mac-address'))
        if not remote and not m:continue
        ref=b.asset('neighbor:'+(m or remote),addresses=[remote],macs=[m],name=row.get('identity'),vendor=row.get('platform'),model=row.get('board'))
        b.link(root,ref,'neighbor',src_port=text(row.get('interface')),dst_port=text(row.get('interface-name')),label=text(row.get('discovered-by') or 'Neighbor report'))
    for path,props in [('ip/arp',['address','mac-address','interface','status']),('ip/dhcp-server/lease',['address','mac-address','host-name','status'])]:
        for row in get(path,props):
            ip=inside(row.get('address'),nets);m=mac(row.get('mac-address'))
            if not ip or not m:continue
            ref=b.asset('network-device:'+m,addresses=[ip],macs=[m],name=row.get('host-name'))
            if row.get('interface'):b.link(root,ref,'learned',src_port=text(row['interface']),label='ARP interface; not proof of a direct cable')
    for row in get('interface/bridge/host',['mac-address','on-interface','vid','local']):
        m=mac(row.get('mac-address'))
        if not m or row.get('local')=='true':continue
        ref=b.asset('network-device:'+m,macs=[m])
        b.link(root,ref,'learned',src_port=text(row.get('on-interface')),label='Forwarding table / VLAN '+text(row.get('vid')))
    vlans=get('interface/bridge/vlan',['vlan-ids','tagged','untagged','bridge'])
    ports=get('interface/bridge/port',['interface','bridge','pvid','hw','disabled'])
    routes=get('ip/route',['dst-address','gateway','active','routing-table'])
    b.asset(root,details={'vlans':vlans,'bridge_ports':ports,'routes':routes})
    return b.result()


def proxmox(config,secret,address,nets,stop=lambda:False,client=None,emit=None):
    token=secret.get('password','')
    if not token:raise CollectorError('Enter the Proxmox API token secret.')
    http=client or HTTPS(config,address,{'Authorization':f'PVEAPIToken={config["username"]}={token}'},stop,emit=emit)
    b=Batch(nets)
    def get(path,optional=False,default=None):
        payload=b.optional(http,'/api2/json'+path,{'data':default}) if optional else http.get('/api2/json'+path)
        if not isinstance(payload,dict) or 'data' not in payload:raise CollectorError('Unexpected Proxmox API response.')
        return payload['data']
    resources=get('/cluster/resources')
    if not isinstance(resources,list):raise CollectorError('Proxmox did not return a resource list.')
    status=get('/cluster/status',True,[])
    cluster=next((text(r.get('name')) for r in status if r.get('type')=='cluster'),'')
    prefix='pve:'+str(config.get('id') or address)+':'
    nodes={}
    for resource in resources:
        if resource.get('type')!='node':continue
        node=text(resource.get('node'))
        if not node:continue
        known=next((r for r in status if r.get('type')=='node' and r.get('name')==node),{})
        ips=[known.get('ip')]
        if known.get('local') in (1,True):ips.append(address)
        ref=b.asset(prefix+'node:'+node,name=node,role='Proxmox host',addresses=ips,details={'cluster':cluster,'status':resource.get('status'),'memory_bytes':resource.get('maxmem'),'cpu_count':resource.get('maxcpu')})
        nodes[node]=ref
        nodepath='/nodes/'+quote(node,safe='')
        info=get(nodepath+'/status',True,{}) or {}
        interfaces=get(nodepath+'/network',True,[]) or []
        b.asset(ref,addresses=[i.get(k) for i in interfaces for k in ('address','address6')],macs=[i.get('hwaddress') for i in interfaces],
                details={'cpu':info.get('cpuinfo',{}),'memory':info.get('memory',{}),'interfaces':[{k:i[k] for k in ('iface','type','address','address6','bridge_ports','bond_slaves','vlan-id') if k in i} for i in interfaces]})
    def storage(node,name):
        ref=b.asset(prefix+'storage:'+node+':'+name,name=name,role='Proxmox storage',details={'node':node,'storage_id':name})
        if node in nodes:b.link(nodes[node],ref,'storage',label='Proxmox storage resource')
        return ref
    for r in resources:
        kind=r.get('type');node=text(r.get('node'))
        if kind=='storage':storage(node,text(r.get('storage') or str(r.get('id','')).rsplit('/',1)[-1]));continue
        if kind not in ('qemu','lxc'):continue
        vmid=str(r.get('vmid',''))
        if not vmid.isdecimal() or not node:continue
        ref=b.asset(prefix+kind+':'+vmid,name=r.get('name') or kind+' '+vmid,role='VM' if kind=='qemu' else 'Container',details={'vmid':vmid,'status':r.get('status'),'node':node,'memory_bytes':r.get('maxmem'),'cpu_count':r.get('maxcpu')})
        if node in nodes:b.link(nodes[node],ref,'hosts',label='Proxmox reports this guest on '+node)
        conf=get('/nodes/'+quote(node,safe='')+'/'+kind+'/'+vmid+'/config',True,{}) or {}
        macs,ips,bridges=[],[],[]
        for key,value in conf.items():
            if not isinstance(value,str):continue
            if re.fullmatch(r'net\d+|ipconfig\d+',key):
                fields=dict(part.split('=',1) for part in value.split(',') if '=' in part)
                macs.extend(fields.get(k) for k in ('virtio','e1000','vmxnet3','rtl8139','hwaddr'))
                ips.extend(fields.get(k) for k in ('ip','ip6'))
                if fields.get('bridge'):bridges.append({k:fields[k] for k in ('bridge','tag','trunks','name') if k in fields})
            if re.fullmatch(r'(?:rootfs|mp\d+|scsi\d+|sata\d+|virtio\d+|ide\d+)',key):
                volume=value.split(',',1)[0]
                if ':' in volume:
                    pool=storage(node,volume.split(':',1)[0]);b.link(ref,pool,'storage',label='Guest volume '+key)
        match=re.search(r'(?:^|,)uuid=([^,]+)',str(conf.get('smbios1','')))
        b.asset(ref,macs=macs,addresses=ips,uuid=match.group(1) if match else '',details={'networks':bridges})
    return b.result()


def truenas(config,secret,address,nets,stop=lambda:False,client=None,emit=None):
    b=Batch(nets)
    ws=client or TrueNASWebSocket(config,address,stop,emit=emit)
    try:
        key=secret.get('password','')
        if not key:raise CollectorError('Enter the TrueNAS API key.')
        try:
            result=ws.call('auth.login_ex',[{'mechanism':'API_KEY_PLAIN','username':config['username'],'api_key':key,'login_options':{'user_info':False}}])
            authenticated=isinstance(result,dict) and result.get('response_type')=='SUCCESS'
        except CollectorError as error:
            if error.code!=-32601:raise
            authenticated=ws.call('auth.login_with_api_key',[key]) is True
        if not authenticated:raise CollectorError('TrueNAS API-key authentication was denied.')
        info=ws.call('system.info')
        if not isinstance(info,dict):raise CollectorError('Unexpected TrueNAS system information.')
        root=b.asset('truenas:'+address,addresses=[address],name=info.get('hostname'),role='TrueNAS',model=info.get('system_product'),vendor=info.get('system_manufacturer'),serial=info.get('system_serial'),
                     details={k:info[k] for k in ('version','physmem','model','cores') if k in info})
        def optional(method):
            try:return ws.call(method) or []
            except CollectorError as error:b.warnings.append(method+': read unavailable ('+str(error.code or 'connection')+').');return []
        for interface in optional('interface.query'):
            state=interface.get('state') or {}
            aliases=(state.get('aliases') or [])+(interface.get('aliases') or [])
            b.asset(root,macs=[state.get('link_address')],addresses=[a.get('address') for a in aliases],details={'interface:'+text(interface.get('name') or interface.get('id')):{'mac':state.get('link_address'),'aliases':[a.get('address') for a in aliases]}})
        for pool in optional('pool.query'):
            ref=b.asset('truenas-pool:'+str(pool.get('guid') or str(address)+':'+str(pool.get('id'))),name=pool.get('name'),role='Storage pool',details={k:pool[k] for k in ('status','size','allocated','free','topology') if k in pool})
            b.link(root,ref,'storage',label='TrueNAS pool')
        for disk in optional('disk.query'):
            ref=b.asset('truenas-disk:'+address+':'+str(disk.get('identifier') or disk.get('name')),name=disk.get('name'),role='Disk',model=disk.get('model'),serial=disk.get('serial'),vendor='Disk',details={k:disk[k] for k in ('size','type','bus','rotationrate') if k in disk})
            b.link(root,ref,'contains',label='TrueNAS disk inventory')
        for method,protocol in (('sharing.smb.query','SMB'),('sharing.nfs.query','NFS')):
            for share in optional(method):
                ref=b.asset('truenas-share:'+address+':'+protocol+':'+str(share.get('id')),name=share.get('name') or protocol+' share '+str(share.get('id')),role='Storage share',details={'protocol':protocol,'path':share.get('path')})
                b.link(root,ref,'storage',label=protocol+' share')
        return b.result()
    finally:ws.close()


def idrac(config,secret,address,nets,stop=lambda:False,client=None,emit=None):
    http=client or HTTPS(config,address,basic(config,secret),stop,emit=emit)
    b=Batch(nets)
    def members(path,optional=True):
        if not str(path).startswith('/redfish/v1/'):raise CollectorError('Invalid Redfish resource link.')
        payload=b.optional(http,path,{}) if optional else http.get(path)
        if not isinstance(payload,dict):raise CollectorError('Unexpected Redfish collection response.')
        return payload.get('Members') or []
    for member in members('/redfish/v1/Systems',False):
        path=member.get('@odata.id','')
        if not path.startswith('/redfish/v1/Systems/'):raise CollectorError('Invalid Redfish system link.')
        system=http.get(path)
        ref=b.asset('redfish:'+str(system.get('UUID') or address+':'+system.get('Id','')),addresses=[address],name=system.get('HostName') or system.get('Name'),role='Physical server',model=system.get('Model'),vendor=system.get('Manufacturer') or 'Dell',serial=system.get('SerialNumber'),uuid=system.get('UUID'),
                    details={k:system[k] for k in ('PowerState','ProcessorSummary','MemorySummary','BiosVersion','Status') if k in system})
        ethernet=(system.get('EthernetInterfaces') or {}).get('@odata.id') or path+'/EthernetInterfaces'
        for item in members(ethernet):
            link=item.get('@odata.id','')
            if not link.startswith('/redfish/v1/Systems/'):raise CollectorError('Invalid Redfish interface link.')
            nic=b.optional(http,link,{})
            b.asset(ref,macs=[nic.get('MACAddress'),nic.get('PermanentMACAddress')],addresses=[i.get('Address') for k in ('IPv4Addresses','IPv6Addresses') for i in nic.get(k,[])],
                    details={'nic:'+text(nic.get('Id')):{k:nic[k] for k in ('Name','MACAddress','SpeedMbps','LinkStatus') if k in nic}})
        for component,role in (('Processors','CPU'),('Memory','Memory module'),('Storage','Storage controller')):
            target=(system.get(component) or {}).get('@odata.id') or path+'/'+component
            for item in members(target):
                link=item.get('@odata.id','')
                if not link.startswith('/redfish/v1/Systems/'):raise CollectorError('Invalid Redfish component link.')
                part=b.optional(http,link,{})
                child=b.asset('redfish-part:'+address+':'+link,name=part.get('Name') or part.get('Id'),role=role,model=part.get('Model') or part.get('PartNumber'),serial=part.get('SerialNumber'),vendor=part.get('Manufacturer'),details={k:part[k] for k in ('CapacityMiB','TotalCores','TotalThreads','MemoryDeviceType','Status') if k in part})
                b.link(ref,child,'contains',label='Redfish '+component)
                for drive_link in part.get('Drives') or []:
                    drive_path=drive_link.get('@odata.id','')
                    if not drive_path.startswith('/redfish/v1/'):raise CollectorError('Invalid Redfish drive link.')
                    drive=b.optional(http,drive_path,{})
                    disk=b.asset('redfish-drive:'+address+':'+drive_path,name=drive.get('Name') or drive.get('Id'),role='Disk',vendor=drive.get('Manufacturer'),model=drive.get('Model'),serial=drive.get('SerialNumber'),details={k:drive[k] for k in ('CapacityBytes','MediaType','Protocol','Status') if k in drive})
                    b.link(ref,disk,'contains',label='Redfish drive')
    if not b.assets:raise CollectorError('Redfish returned no systems visible to this account.')
    return b.result()


SYS={ 'description':'.1.3.6.1.2.1.1.1.0','object_id':'.1.3.6.1.2.1.1.2.0','name':'.1.3.6.1.2.1.1.5.0','location':'.1.3.6.1.2.1.1.6.0'}
UPS={ 'manufacturer':'.1.3.6.1.2.1.33.1.1.1.0','model':'.1.3.6.1.2.1.33.1.1.2.0','battery_status':'.1.3.6.1.2.1.33.1.2.1.0','runtime_minutes':'.1.3.6.1.2.1.33.1.2.3.0','battery_percent':'.1.3.6.1.2.1.33.1.2.4.0','load_percent':'.1.3.6.1.2.1.33.1.4.4.1.5.1'}
VENDOR_UPS={
 'apc':{'model':'.1.3.6.1.4.1.318.1.1.1.1.1.1.0','serial':'.1.3.6.1.4.1.318.1.1.1.1.2.3.0','battery_percent':'.1.3.6.1.4.1.318.1.1.1.2.2.1.0','load_percent':'.1.3.6.1.4.1.318.1.1.1.4.2.3.0'},
 'cyberpower':{'model':'.1.3.6.1.4.1.3808.1.1.1.1.1.1.0','serial':'.1.3.6.1.4.1.3808.1.1.1.1.2.3.0','runtime_seconds':'.1.3.6.1.4.1.3808.1.1.1.2.2.4.0','load_percent':'.1.3.6.1.4.1.3808.1.1.1.4.2.3.0'}
}
IF_NAME='.1.3.6.1.2.1.31.1.1.1.1'
IF_MAC='.1.3.6.1.2.1.2.2.1.6'
IF_SPEED='.1.3.6.1.2.1.31.1.1.1.15'
LLDP_REMOTE='.1.0.8802.1.1.2.1.4.1.1'
LLDP_LOCAL='.1.0.8802.1.1.2.1.3.7.1.3'


def parse_snmp(output):
    rows={}
    for line in output.splitlines():
        match=re.match(r'^\s*(\.\d+(?:\.\d+)*)\s*=\s*(.*)$',line)
        if not match:continue
        oid,value=match.groups()
        if any(s in value for s in ('No Such','No more variables','End of MIB')):continue
        value=re.sub(r'^[A-Za-z0-9 -]+:\s*','',value).strip()
        if len(value)>=2 and value[0]==value[-1]=='"':value=value[1:-1]
        rows[oid]=value
    return rows


class SNMP:
    def __init__(self,config,secret,address,runner=subprocess.run,emit=None):
        self.address=address;self.runner=runner;self.config=config
        self.emit=emit or quiet
        self.temp=tempfile.TemporaryDirectory(prefix='labmap-snmp-')
        def token(value):
            value=str(value)
            if any(ord(c)<32 for c in value) or '\\' in value or '"' in value:
                raise CollectorError('SNMP credential fields cannot contain control characters, quotes or backslashes.')
            return '"'+value+'"'
        try:
            lines=['defVersion '+config['snmp_version'],'persistentDir '+self.temp.name]
            if config['snmp_version']=='2c':
                if not secret.get('community'):raise CollectorError('Enter an SNMPv2c community.')
                lines.append('defCommunity '+token(secret['community']))
            else:
                lines+=['defSecurityName '+token(config['username']),'defSecurityLevel '+config['security_level'],
                        'defAuthType '+config['auth_protocol'],'defPrivType '+config['privacy_protocol']]
                for level,key,directive in [('auth','auth_password','defAuthPassphrase'),('priv','privacy_password','defPrivPassphrase')]:
                    required=(level=='auth' and config['security_level']!='noAuthNoPriv') or (level=='priv' and config['security_level']=='authPriv')
                    if required and len(secret.get(key,''))<8:raise CollectorError('SNMPv3 authentication/privacy passphrases must be at least 8 characters.')
                    if required:lines.append(directive+' '+token(secret[key]))
            file=Path(self.temp.name)/'snmp.conf'
            fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as out:out.write('\n'.join(lines)+'\n')
            self.env={k:v for k,v in os.environ.items() if k not in ('SNMP_PERSISTENT_FILE',)}
            self.env.update({'SNMPCONFPATH':self.temp.name,'SNMP_PERSISTENT_DIR':self.temp.name,'MIBS':''})
        except BaseException:self.close();raise
    def close(self):self.temp.cleanup()
    def query(self,oids,walk=False):
        binary=shutil.which('snmpbulkwalk' if walk else 'snmpget')
        if not binary:raise CollectorError('Net-SNMP command tools are not installed on this Mac.')
        port=str(self.config.get('snmp_port',161))
        target=('udp6:['+self.address+']:'+port) if ':' in self.address else ('udp:'+self.address+':'+port)
        oids=list(oids)
        command=[binary,'-m','','-On','-Oe','-Ot','-t','1','-r','0']+(['-Cr16'] if walk else [])+[target]+oids
        operation='SNMP GETBULK' if walk else 'SNMP GET'
        self.emit('request',operation+' '+', '.join(oids))
        started=time.monotonic()
        try:result=self.runner(command,capture_output=True,text=True,timeout=12 if walk else 4,check=False,env=self.env)
        except (OSError,ValueError,subprocess.SubprocessError):
            self.emit('error',operation+' failed or timed out. Command diagnostics are hidden.')
            raise CollectorError('SNMP request failed or timed out.') from None
        if len(result.stdout)>4*1024*1024:raise CollectorError('SNMP table exceeded its response limit.')
        # Never include stderr: Net-SNMP diagnostics may echo configuration tokens.
        rows=parse_snmp(result.stdout)
        self.emit('warning' if result.returncode or not rows else 'response',
                  operation+f': {len(rows)} values / exit {result.returncode}',
                  {'duration_ms':round((time.monotonic()-started)*1000),'result':rows})
        return rows


def snmp_device(config,secret,address,nets,stop=lambda:False,runner=subprocess.run,client=None,emit=None):
    snmp=client or SNMP(config,secret,address,runner,emit=emit)
    b=Batch(nets)
    try:
        raw=snmp.query(SYS.values())
        info={k:raw.get(oid,'') for k,oid in SYS.items()}
        if not info['object_id'] and not info['description']:return b.result()
        oid=info['object_id']
        detected='apc' if oid.startswith('.1.3.6.1.4.1.318.') or oid=='.1.3.6.1.4.1.318' else 'cyberpower' if oid.startswith('.1.3.6.1.4.1.3808') else 'routeros' if oid.startswith('.1.3.6.1.4.1.14988') else 'idrac' if oid.startswith('.1.3.6.1.4.1.674') else 'snmp'
        if config.get('kind') in ('apc','cyberpower') and detected!=config['kind']:
            b.warnings.append('SNMP enterprise identity does not match the selected UPS vendor; classification uses reported data.')
        vendor={'apc':'APC','cyberpower':'CyberPower','routeros':'MikroTik','idrac':'Dell'}.get(detected,'')
        role='UPS' if detected in ('apc','cyberpower') else 'Router / switch' if detected=='routeros' else 'Managed device'
        root=b.asset('snmp:'+address,addresses=[address],name=info['name'],vendor=vendor,role=role,details={'snmp':info})
        if detected in ('apc','cyberpower'):
            fields={**UPS,**VENDOR_UPS[detected]}
            values=snmp.query(fields.values())
            values={k:values[oid] for k,oid in fields.items() if oid in values}
            b.asset(root,model=values.get('model'),serial=values.get('serial'),role='UPS' if values.get('model') else 'Power device',details={'ups':values})
        tables={}
        for name,oid in [('name',IF_NAME),('mac',IF_MAC),('speed_mbps',IF_SPEED),('class','.1.3.6.1.2.1.47.1.1.1.1.5'),('model','.1.3.6.1.2.1.47.1.1.1.1.13'),('serial','.1.3.6.1.2.1.47.1.1.1.1.11')]:
            if stop():raise CollectorError('Collection stopped.')
            tables[name]={key[len(oid)+1:]:value for key,value in snmp.query([oid],True).items() if key.startswith(oid+'.')}
        b.asset(root,macs=list(tables['mac'].values()),details={'interfaces':[{ 'index':i,'name':v,'mac':mac(tables['mac'].get(i)),'speed_mbps':tables['speed_mbps'].get(i)} for i,v in tables['name'].items()]})
        chassis=next((i for i,value in tables['class'].items() if value in ('3','11')),None)
        if chassis:
            if not b.assets[root].get('model'):b.asset(root,model=tables['model'].get(chassis))
            if not b.assets[root].get('serial'):b.asset(root,serial=tables['serial'].get(chassis))
        ip_table='.1.3.6.1.2.1.4.20.1.1'
        b.asset(root,addresses=list(snmp.query([ip_table],True).values()))
        local=snmp.query([LLDP_LOCAL],True)
        remote=snmp.query([LLDP_REMOTE],True)
        neighbors={}
        for key,value in remote.items():
            parts=key[len(LLDP_REMOTE)+1:].split('.') if key.startswith(LLDP_REMOTE+'.') else []
            if len(parts)<4:continue
            neighbors.setdefault(tuple(parts[1:]),{})[parts[0]]=value
        for index,row in neighbors.items():
            chassis=mac(row.get('5')) if row.get('4')=='4' else ''
            if not chassis:continue
            ref=b.asset('lldp:'+chassis,macs=[chassis],name=row.get('9'),details={'lldp_description':row.get('10','')})
            port=local.get(LLDP_LOCAL+'.'+index[1],index[1])
            b.link(root,ref,'neighbor',src_port=port,dst_port=row.get('7',''),label='LLDP report')
        bridge_index='.1.3.6.1.2.1.17.1.4.1.2'
        bridge_ports={oid[len(bridge_index)+1:]:value for oid,value in snmp.query([bridge_index],True).items() if oid.startswith(bridge_index+'.')}
        fdb='.1.3.6.1.2.1.17.4.3.1.2'
        for oid,port in snmp.query([fdb],True).items():
            suffix=oid[len(fdb)+1:].split('.') if oid.startswith(fdb+'.') else []
            if len(suffix)!=6:continue
            try:m=mac(''.join(f'{int(part):02x}' for part in suffix))
            except ValueError:continue
            if not m:continue
            child=b.asset('fdb:'+m,macs=[m])
            b.link(root,child,'learned',src_port=tables['name'].get(bridge_ports.get(port,''),port),label='Forwarding table; may be behind another switch')
        return b.result()
    finally:snmp.close()


ADAPTERS={'routeros':routeros,'proxmox':proxmox,'truenas':truenas,'idrac':idrac,
          'snmp':snmp_device,'apc':snmp_device,'cyberpower':snmp_device}


def connection_targets(connection,nets):
    config=connection['config'];kind=connection['kind']
    if CATALOG[kind]['auth']=='snmp':
        if config['endpoint']:
            value=inside(config['endpoint'],nets)
            if not value:raise CollectorError('SNMP target is outside the saved site scope.')
            return [value]
        # Collapse overlap before enumerating, including explicit IPv6 host targets.
        return [str(ip) for version in (4,6) for net in ipaddress.collapse_addresses(n for n in nets if n.version==version) for ip in (list(net.hosts()) if net.num_addresses>2 else list(net))]
    host,port=endpoint(config['endpoint'])
    return resolve_scoped(host,port,nets)[:1]
