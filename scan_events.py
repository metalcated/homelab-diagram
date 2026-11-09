"""Private, bounded scan events. Only sanitized inventory previews reach SQLite."""
import base64
from contextlib import closing
from datetime import datetime, timezone
import json
import math
import re
from urllib.parse import quote

MAX_EVENTS = 5000
MAX_DETAILS = 6000
SCHEMA = '''
CREATE TABLE IF NOT EXISTS job_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL, observed TEXT NOT NULL,
 collector TEXT NOT NULL, target TEXT NOT NULL, level TEXT NOT NULL,
 message TEXT NOT NULL, details TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS job_events_job_id ON job_events(job,id);
'''
SENSITIVE = re.compile(r'password|passwd|passphrase|secret|token|credential|authorization|cookie|community|privatekey|apikey|sshkey|chap|certificate|session', re.I)
FIELDS = set('''data result items hosts targets addresses macs ref name hostname identity role vendor model serial uuid type id node vmid status version cpu cpucount totalmemory memory memorybytes maxmem maxcpu cpuinfo cores sockets mhz total free used physmem systemproduct systemmanufacturer systemserial boardname interface interfaces iface address address4 address6 macaddress hwaddress mtu running disabled platform board discoveredby interfacename hostname oninterface vid local vlanids tagged untagged bridge pvid hw dstaddress gateway active routingtable bridgeports bondslaves vlanid netmask aliases state linkaddress guid size allocated topology disk disks identifier bus rotationrate path protocol linkstatus speedmbps permanentmacaddress ipv4addresses ipv6addresses members odataid manufacturer serialnumber powerstate processorsummary memorysummary biosversion health healthrollup count capacitymib capacitybytes totalcores totalthreads memorydevicetype mediatype partnumber processortype memorysizegib drives nodes storage response_type warnings assets links kind duration_ms bytes records code omitted result_count'''.split())
FIELDS.update({'odataid','membersodatacount'})
FIELDS={re.sub(r'[^a-z0-9]','',field) for field in FIELDS}


def quiet(*args, **kwargs):pass


class Redactor:
    def __init__(self, values=()):
        secrets=set()
        for value in values:
            if not isinstance(value,str) or not value:continue
            secrets.update((value,quote(value,safe=''),json.dumps(value)[1:-1]))
        self.secrets=sorted(secrets,key=len,reverse=True)

    @classmethod
    def connection(cls, config, secret):
        values=list(secret.values())
        username=config.get('username','');password=secret.get('password','')
        if username and password:
            values.append(base64.b64encode((username+':'+password).encode()).decode())
            values.append('PVEAPIToken='+username+'='+password)
        return cls(values)

    def text(self, value, limit=500):
        value=str(value)
        for secret in self.secrets:value=value.replace(secret,'[hidden]')
        value=re.sub(r'-----BEGIN [^-]+-----.*?-----END [^-]+-----','[hidden]',value,flags=re.S)
        value=re.sub(r'(?i)\b(?:Basic|Bearer|PVEAPIToken)\s*[= ]\s*\S+','[hidden]',value)
        value=re.sub(r'(?i)(?:password|passwd|passphrase|secret|token|api[_-]?key|community|authorization|cookie)\s*[=:]\s*[^\s,;]+','[hidden]',value)
        value=re.sub(r'(?i)(https?|wss?)://[^/\s]*@',r'\1://[hidden]@',value)
        return ''.join(c for c in value if c in '\n\t' or ord(c)>=32)[:limit]

    def preview(self, value):
        budget=[160]
        def project(item,depth=0):
            budget[0]-=1
            if depth>6 or budget[0]<0:return '[preview limit]'
            if isinstance(item,dict):
                result={};omitted=0
                for key,child in item.items():
                    normal=re.sub(r'[^a-z0-9]','',str(key).lower())
                    if SENSITIVE.search(normal):result[self.text(key,80)]='[hidden]'
                    elif normal in FIELDS or re.fullmatch(r'(?:net|ipconfig|scsi|sata|virtio|ide|mp)\d+|rootfs|smbios1',normal) or re.fullmatch(r'\.?\d+(?:\.\d+)+',str(key)):
                        result[self.text(key,100)]='[non-inventory scalar omitted]' if normal in ('data','result') and isinstance(child,str) else project(child,depth+1)
                    else:omitted+=1
                    if len(result)>=30:omitted+=max(0,len(item)-len(result)-omitted);break
                if omitted:result['_other_fields_omitted']=omitted
                return result
            if isinstance(item,(list,tuple)):
                result=[project(child,depth+1) for child in item[:8]]
                if len(item)>8:result.append(f'[{len(item)-8} more records]')
                return result
            if isinstance(item,str):return self.text(item,400)
            if isinstance(item,float) and not math.isfinite(item):return '[non-finite value]'
            if item is None or isinstance(item,(bool,int,float)):return item
            return '[unsupported value]'
        text=json.dumps(project(value) if isinstance(value,(dict,list,tuple)) else '[non-inventory scalar omitted]',ensure_ascii=True,allow_nan=False)
        return text if len(text)<=MAX_DETAILS else text[:MAX_DETAILS]+'\n[preview truncated]'


class Events:
    def __init__(self,store,job,collector='',target='',redactor=None):
        self.store=store;self.job=job;self.collector=collector;self.target=target
        self.redactor=redactor or Redactor()

    def __call__(self,level,message,details=None):
        if not self.job:return
        if level!='complete' and self.job in self.store._limited_output_jobs:return
        if level not in ('info','request','response','warning','error','complete'):level='info'
        message=self.redactor.text(message)
        payload=self.redactor.preview(details) if details is not None else ''
        with closing(self.store.connect()) as db,db:
            db.execute('BEGIN IMMEDIATE')
            # The limit notice and final outcome remain available without deleting history.
            count=db.execute('SELECT count(*) FROM job_events WHERE job=?',(self.job,)).fetchone()[0]
            if count>=MAX_EVENTS+1 and level!='complete':return
            if count==MAX_EVENTS and level!='complete':
                level='warning';message='Output limit reached. Further request details are omitted; collection continues.';payload=''
            db.execute('INSERT INTO job_events(job,observed,collector,target,level,message,details) VALUES (?,?,?,?,?,?,?)',
                       (self.job,datetime.now(timezone.utc).isoformat(timespec='milliseconds'),self.redactor.text(self.collector,200),self.redactor.text(self.target,100),level,message,payload))
        if count>=MAX_EVENTS and level!='complete':self.store._limited_output_jobs.add(self.job)


def read_events(store,site,job,after=0):
    store.get_site(site)
    if not isinstance(job,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',job):raise ValueError('Choose a scan from this site.')
    try:after=int(after)
    except (ValueError,TypeError):raise ValueError('Invalid output cursor.') from None
    if not 0<=after<=9223372036854775807:raise ValueError('Invalid output cursor.')
    with closing(store.connect()) as db:
        row=db.execute('SELECT id,status,message FROM jobs WHERE id=? AND site=?',(job,site)).fetchone()
        if row is None:raise ValueError('Scan not found in this site.')
        events=[dict(r) for r in db.execute('SELECT * FROM job_events WHERE job=? AND id>? ORDER BY id LIMIT 251',(job,after))]
    return {'job':dict(row),'events':events[:250],'next':events[min(len(events),250)-1]['id'] if events else after,'has_more':len(events)>250}
