"""Saved source configuration and explicitly reviewed collection jobs."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from datetime import datetime, timezone
import json
import secrets
import shutil
import time
import threading

import asset_inventory
from collector_secrets import Vault
from collector_transport import CollectorError
from direct_collectors import ADAPTERS, CATALOG, connection_targets, validate_config
from scan_events import Events, Redactor


def now():return datetime.now(timezone.utc).isoformat(timespec='seconds')


class CollectorManager:
    def __init__(self,workspace,scope_parser):
        self.scope_parser=scope_parser
        self.workspace=workspace
        self.store=workspace.store
        self.vault=Vault()

    def connections(self,site=None):
        with closing(self.store.connect()) as db:
            rows=db.execute('SELECT * FROM collector_connections'+(' WHERE site=?' if site else '')+' ORDER BY label',(site,) if site else ()).fetchall()
        result=[]
        for row in rows:
            item=dict(row);item['config']=json.loads(item['config']);item['enabled']=bool(item['enabled'])
            item['credential_status']='Saved in Keychain' if item['secret_mode']=='keychain' else 'Available this session' if item['id'] in self.vault.memory else 'Needs credentials'
            if item['config'].get('snmp_version')=='3' and item['config'].get('security_level')=='noAuthNoPriv' and CATALOG[item['kind']]['auth']=='snmp':item['credential_status']='No secret required'
            result.append(item)
        return result

    def save(self,payload):
        site=self.store.get_site(payload.get('site'))['id']
        kind=payload.get('kind')
        config=validate_config(kind,payload.get('config') or {})
        key=payload.get('id') or secrets.token_hex(12)
        if not isinstance(key,str) or len(key)>64 or not key.isalnum():raise ValueError('Invalid collector connection ID.')
        with closing(self.store.connect()) as db:
            old=db.execute('SELECT * FROM collector_connections WHERE id=?',(key,)).fetchone()
        if old and old['site']!=site:raise ValueError('Collector belongs to another site.')
        if not isinstance(payload.get('enabled',True),bool):raise ValueError('Enabled must be true or false.')
        secret_values=payload.get('credentials') or {}
        changed_account=bool(old and (old['kind']!=kind or json.loads(old['config']).get('username')!=config.get('username')))
        if changed_account and not any(secret_values.values()):
            raise ValueError('Re-enter credentials when changing the collector type or account.')
        if old and not changed_account and any(secret_values.values()):
            try:previous=self.vault.get(key,old['secret_mode'])
            except ValueError:previous={}
            secret_values={**previous,**{k:v for k,v in secret_values.items() if v}}
        mode=self.vault.put(key,secret_values,payload.get('save_keychain') is True)
        mode=mode or (old['secret_mode'] if old else 'session')
        with closing(self.store.connect()) as db,db:
            db.execute('''INSERT INTO collector_connections(id,site,label,kind,config,secret_mode,enabled,revision)
              VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET label=excluded.label,kind=excluded.kind,
              config=excluded.config,secret_mode=excluded.secret_mode,enabled=excluded.enabled,revision=excluded.revision''',
              (key,site,asset_inventory.text(payload.get('label')) or CATALOG[kind]['name'],kind,json.dumps(config),mode,int(payload.get('enabled',True)),secrets.token_hex(12)))
        return {'saved':True,'id':key}

    def credential(self,connection):
        cfg=connection['config']
        snmp=CATALOG[connection['kind']]['auth']=='snmp'
        if snmp and cfg['snmp_version']=='3' and cfg['security_level']=='noAuthNoPriv':return {}
        value=self.vault.get(connection['id'],connection['secret_mode'])
        if not snmp and not value.get('password'):raise ValueError('Enter the password or API token secret for this collector.')
        if snmp and cfg['snmp_version']=='2c' and not value.get('community'):raise ValueError('Enter the read-only SNMP community.')
        if snmp and cfg['snmp_version']=='3':
            if cfg['security_level']!='noAuthNoPriv' and len(value.get('auth_password',''))<8:raise ValueError('Enter an SNMPv3 authentication passphrase of at least 8 characters.')
            if cfg['security_level']=='authPriv' and len(value.get('privacy_password',''))<8:raise ValueError('Enter an SNMPv3 privacy passphrase of at least 8 characters.')
        return value

    def plan(self,site,selected=None):
        saved=self.store.get_site(site)
        nets=self.scope_parser(saved['targets'],saved['allow_public'])
        connections=[c for c in self.connections(site) if c['enabled']]
        if selected is not None:
            if not isinstance(selected,list) or not selected or any(not isinstance(key,str) for key in selected):
                raise ValueError('Choose all enabled collectors or at least one collector for this site.')
            if not set(selected).issubset({c['id'] for c in connections}):
                raise ValueError('Choose enabled collectors belonging to this site. Refresh the list and review again.')
            connections=[c for c in connections if c['id'] in selected]
        if not connections:raise ValueError('Add and enable at least one collector for this site.')
        targets=[];summaries=[]
        for c in connections:
            self.credential(c)
            if CATALOG[c['kind']]['auth']=='snmp' and not all(shutil.which(name) for name in ('snmpget','snmpbulkwalk')):
                raise ValueError('Net-SNMP tools are missing. Install them separately before using SNMP collectors.')
            addresses=connection_targets(c,nets)
            targets.append({'id':c['id'],'revision':c['revision'],'addresses':addresses})
            summaries.append(f"{c['label']} / {CATALOG[c['kind']]['transport']} / {len(addresses)} management targets")
        plan={'kind':'collectors','site':site,'targets':saved['targets'],'allow_public':saved['allow_public'],
              'addresses':sum(len(t['addresses']) for t in targets),'connections':targets,'summaries':summaries,
              'commands':['Read-only '+s for s in summaries]}
        self.workspace.register_plan(plan)
        return plan

    def validate_plan(self,plan):
        saved=self.store.get_site(plan['site'])
        if saved['targets']!=plan['targets'] or saved['allow_public']!=plan['allow_public']:
            raise ValueError('Site scope changed. Review collection again.')
        current={c['id']:c for c in self.connections(plan['site'])}
        for target in plan['connections']:
            c=current.get(target['id'])
            if not c or not c['enabled'] or c['revision']!=target['revision']:raise ValueError('Collector configuration changed. Review collection again.')
            self.credential(c)

    def collect(self,plan,job=None):
        self.validate_plan(plan)
        nets=self.scope_parser(plan['targets'],plan['allow_public'])
        current={c['id']:c for c in self.connections(plan['site'])}
        total=0;failures=[];warnings=[]
        for target in plan['connections']:
            connection=current[target['id']]
            secret=self.credential(connection)
            cfg={**connection['config'],'id':connection['id'],'kind':connection['kind']}
            redactor=Redactor.connection(cfg,secret)
            emit=Events(self.store,job,connection['label'],redactor=redactor)
            emit('info',f'Starting collector / {len(target["addresses"])} management targets.')
            successes=0;source_warnings=[];errors=0
            deadline=time.monotonic()+1800
            rate_lock=threading.Lock()
            next_start=[time.monotonic()]
            def one(address):
                if self.workspace.stopping or time.monotonic()>deadline:raise CollectorError('Collection stopped or reached its time limit.')
                if CATALOG[connection['kind']]['auth']=='snmp':
                    with rate_lock:
                        wait=max(0,next_start[0]-time.monotonic())
                        next_start[0]=max(next_start[0],time.monotonic())+0.25
                    if wait:time.sleep(wait)
                adapter=ADAPTERS[connection['kind']]
                output=Events(self.store,job,connection['label'],address,redactor)
                output('info','Connecting to management target.')
                kwargs={'stop':lambda:self.workspace.stopping,'emit':output}
                if CATALOG[connection['kind']]['auth']=='snmp':kwargs['runner']=self.workspace.execute_command
                try:
                    batch=adapter(cfg,secret,address,nets,**kwargs)
                    output('info',f'Discovered {len(batch["assets"])} assets and {len(batch["links"])} relationships.',{'assets':batch['assets']})
                    return batch
                except CollectorError as error:
                    output('error',str(error),{'code':error.code})
                    raise
                except Exception:
                    output('error','Target failed. Check protocol support, connectivity and read permissions. Unexpected diagnostics are hidden.')
                    raise
            # A shared SNMP profile finds agents across explicit scopes without per-asset assignments.
            workers=4 if CATALOG[connection['kind']]['auth']=='snmp' else 1
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures={executor.submit(one,address):address for address in target['addresses']}
                for future in as_completed(futures):
                    try:
                        batch=future.result()
                        if batch['assets']:
                            with closing(self.store.connect()) as db,db:
                                count=asset_inventory.ingest(db,plan['site'],connection['kind'],batch,now())
                                db.execute('INSERT INTO runs(site,source,observed,hosts) VALUES (?,?,?,?)',(plan['site'],connection['kind'],now(),count))
                            successes+=1;total+=count
                            Events(self.store,job,connection['label'],futures[future],redactor)('info',f'Saved {count} asset observations. Existing corrections were preserved.')
                        for warning in batch.get('warnings',[]):
                            warning=redactor.text(warning)
                            source_warnings.append(warning)
                            Events(self.store,job,connection['label'],futures[future],redactor)('warning',warning)
                    except CollectorError as error:
                        errors+=1
                        if len(source_warnings)<10:source_warnings.append(redactor.text(error))
                    except Exception:
                        # Unexpected libraries/HTTP diagnostics can contain secrets. Never persist their text.
                        errors+=1
                        if len(source_warnings)<10:source_warnings.append('A target could not be collected. Check its protocol version, permissions and connectivity.')
            if not successes:failures.append(connection['label'])
            if errors or source_warnings:warnings.append(connection['label'])
            summary=f'{successes} responding targets; {errors} failed targets. '+(' / '.join(dict.fromkeys(source_warnings))[:1000] if source_warnings else '')
            if not successes and not errors:summary+='No SNMP agents responded. Verify the profile, scope, UDP/161 reachability and read permissions.'
            with closing(self.store.connect()) as db,db:
                db.execute('UPDATE collector_connections SET last_collected=?,last_result=? WHERE id=?',(now(),redactor.text(summary,1500),connection['id']))
            emit('warning' if errors or source_warnings or not successes else 'info','Collector finished. '+summary)
        status='failed' if failures and not total else 'partial' if failures or warnings else 'complete'
        message=f'Collected {total} asset observations. Existing inventory and manual corrections were preserved.'
        if failures or warnings:message+=' Review collector results for missing permissions, unsupported fields or unreachable targets.'
        return status,message
