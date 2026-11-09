from contextlib import closing
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import sqlite3
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

import asset_inventory as inventory
import collector_transport as transport
from collector_secrets import Vault
import direct_collectors as dc
import labmap
import test_labmap as base_tests

NETS=[ipaddress.ip_network('10.20.0.0/24')]
SECRET={'password':'example-test-secret'}
CFG={'endpoint':'https://10.20.0.1','username':'readonly','id':'example','kind':'routeros'}
PVE_CFG={**CFG,'username':'readonly@pve!inventory','kind':'proxmox'}
PVE_SECRET={'password':'d3f55ff9-d386-4071-9870-fd81a7d57b03'}


class FakeHTTP:
    def __init__(self,responses):self.responses=responses;self.paths=[]
    def get(self,path):
        self.paths.append(path)
        path=path.split('?')[0]
        if path not in self.responses:raise transport.CollectorError('Read unavailable.',404)
        value=self.responses[path]
        if isinstance(value,Exception):raise value
        return value


def pve_fixture():
    resources=[{'type':'node','node':'pve-a','status':'online','maxmem':68719476736},
               {'type':'qemu','node':'pve-a','vmid':100,'name':'vm-no-ip','status':'running'},
               {'type':'lxc','node':'pve-a','vmid':101,'name':'web-ct','status':'running'}]
    return FakeHTTP({
      '/api2/json/cluster/resources':{'data':resources},
      '/api2/json/cluster/status':{'data':[{'type':'node','name':'pve-a','ip':'10.20.0.10','local':1}]},
      '/api2/json/nodes/pve-a/status':{'data':{'cpuinfo':{'model':'Example CPU'},'memory':{'total':68719476736}}},
      '/api2/json/nodes/pve-a/network':{'data':[{'iface':'eno1','type':'eth','address':'10.20.0.10','hwaddress':'00:11:22:33:44:10'}]},
      '/api2/json/nodes/pve-a/qemu/100/config':{'data':{'net0':'virtio=00:11:22:33:44:64,bridge=vmbr0,tag=20','smbios1':'uuid=12345678-1234-1234-1234-123456789abc','scsi0':'local-zfs:vm-100-disk-0','cipassword':'DO-NOT-STORE-THIS'}},
      '/api2/json/nodes/pve-a/lxc/101/config':{'data':{'net0':'name=eth0,hwaddr=00:11:22:33:44:65,ip=10.20.0.101/24,bridge=vmbr0','rootfs':'local-zfs:subvol-101-disk-0'}}
    })


def redfish_fixture():
    root='/redfish/v1/Systems/1'
    return FakeHTTP({
      '/redfish/v1/Systems':{'Members':[{'@odata.id':root}]},
      root:{'Id':'1','HostName':'pve-a','Model':'PowerEdge example','Manufacturer':'Dell Inc.','SerialNumber':'EXAMPLE-SERIAL','UUID':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'},
      root+'/EthernetInterfaces':{'Members':[{'@odata.id':root+'/EthernetInterfaces/NIC1'}]},
      root+'/EthernetInterfaces/NIC1':{'Id':'NIC1','MACAddress':'00:11:22:33:44:10','IPv4Addresses':[{'Address':'10.20.0.10'}],'SpeedMbps':10000},
      root+'/Processors':{'Members':[]},root+'/Memory':{'Members':[]},root+'/Storage':{'Members':[]}
    })


class AdapterTests(unittest.TestCase):
    def test_proxmox_requires_the_full_token_id_without_persisting_a_header_or_token_value(self):
        for value in ('readonly','root@pam','root@pam!','root@pam!token=value','PVEAPIToken=root@pam!token','root@pam!token\nextra'):
            with self.subTest(value=value),self.assertRaisesRegex(transport.CollectorError,'user@realm!tokenid'):
                dc.validate_config('proxmox',{**CFG,'username':value})
        self.assertEqual(dc.validate_config('proxmox',PVE_CFG)['username'],PVE_CFG['username'])

    def test_proxmox_empty_visibility_explains_token_and_user_permissions(self):
        with self.assertRaisesRegex(transport.CollectorError,'no visible inventory'):
            dc.proxmox(PVE_CFG,PVE_SECRET,'10.20.0.10',NETS,client=FakeHTTP({'/api2/json/cluster/resources':{'data':[]}}))

    def test_routeros_singleton_objects_and_optional_bad_table_keep_collected_inventory(self):
        http=FakeHTTP({'/rest/system/identity':{'name':'real-format-router'},'/rest/system/resource':{'board-name':'Example router','version':'7.x'},'/rest/interface':[{'name':'ether1'}],'/rest/ip/neighbor':{'unexpected':'not-a-table'}})
        result=dc.routeros(CFG,SECRET,'10.20.0.1',NETS,client=http)
        self.assertTrue(any(a.get('name')=='real-format-router' and a.get('model')=='Example router' for a in result['assets']))
        self.assertTrue(any('/rest/ip/neighbor' in warning for warning in result['warnings']))

    def test_bad_required_routeros_response_identifies_the_exact_endpoint(self):
        for value in ('not-a-record',{'error':'not-an-identity'},[None]):
            with self.subTest(value=value),self.assertRaisesRegex(transport.CollectorError,'/rest/system/identity'):
                dc.routeros(CFG,SECRET,'10.20.0.1',NETS,client=FakeHTTP({'/rest/system/identity':value}))

    def test_routeros_collects_many_devices_and_keeps_forwarding_as_reported(self):
        http=FakeHTTP({
          '/rest/system/identity':[{'name':'core'}],'/rest/system/resource':[{'board-name':'Example switch','version':'7.x'}],
          '/rest/interface':[{'name':'ether1','mac-address':'00:11:22:33:44:01'}],'/rest/ip/address':[{'address':'10.20.0.1/24'}],
          '/rest/ip/neighbor':[{'mac-address':'00:11:22:33:44:02','identity':'neighbor-without-ip','interface':'ether2','discovered-by':'lldp'}],
          '/rest/ip/arp':[{'address':'10.20.0.101','mac-address':'00:11:22:33:44:65','interface':'bridge'}],
          '/rest/ip/dhcp-server/lease':[{'address':'10.20.0.101','mac-address':'00:11:22:33:44:65','host-name':'web-ct'}],
          '/rest/interface/bridge/host':[{'mac-address':'00:11:22:33:44:65','on-interface':'ether3','vid':'20'}]
        })
        result=dc.routeros(CFG,SECRET,'10.20.0.1',NETS,client=http)
        self.assertGreaterEqual(len(result['assets']),3)
        self.assertTrue(any(a.get('name')=='neighbor-without-ip' and not a['addresses'] for a in result['assets']))
        self.assertTrue(any(l['kind']=='learned' for l in result['links']))
        self.assertFalse(any(l['kind']=='physical' for l in result['links']))
        self.assertNotIn('wireguard',str(http.paths))

    def test_proxmox_automatically_assigns_hosts_guests_and_storage_without_ips(self):
        result=dc.proxmox(PVE_CFG,PVE_SECRET,'10.20.0.10',NETS,client=pve_fixture())
        vm=next(a for a in result['assets'] if a.get('name')=='vm-no-ip')
        self.assertEqual(vm['role'],'VM')
        self.assertEqual(vm['addresses'],[])
        self.assertTrue(any(l['kind']=='hosts' and l['dst']==vm['ref'] for l in result['links']))
        self.assertTrue(any(l['kind']=='storage' and l['src']==vm['ref'] for l in result['links']))
        self.assertNotIn('DO-NOT-STORE-THIS',json.dumps(result))

    def test_proxmox_permission_failure_is_partial_and_preserves_visible_guests(self):
        http=pve_fixture();http.responses['/api2/json/nodes/pve-a/qemu/100/config']=transport.CollectorError('Denied',403)
        result=dc.proxmox(PVE_CFG,PVE_SECRET,'10.20.0.10',NETS,client=http)
        self.assertTrue(result['warnings'])
        self.assertTrue(any(a.get('name')=='vm-no-ip' for a in result['assets']))

    def test_truenas_collects_system_interfaces_pools_disks_and_shares(self):
        ws=Mock()
        responses={
          'auth.login_ex':{'response_type':'SUCCESS'},'system.info':{'hostname':'nas','system_product':'Example chassis','system_manufacturer':'Dell Inc.','system_serial':'NAS-SERIAL','version':'25.10'},
          'interface.query':[{'name':'eno1','state':{'link_address':'00:11:22:33:44:20','aliases':[{'address':'10.20.0.20'}]}}],
          'pool.query':[{'guid':'pool-guid','name':'tank','status':'ONLINE'}],
          'disk.query':[{'identifier':'disk1','name':'sda','serial':'DISK-SERIAL','model':'Example disk','size':1000000}],
          'sharing.smb.query':[{'id':1,'name':'media','path':'/mnt/tank/media'}],'sharing.nfs.query':[]}
        ws.call.side_effect=lambda method,*args:responses[method]
        result=dc.truenas(CFG,SECRET,'10.20.0.20',NETS,client=ws)
        self.assertEqual({a.get('role') for a in result['assets']},{'TrueNAS','Storage pool','Disk','Storage share'})
        ws.close.assert_called_once()
        self.assertNotIn(SECRET['password'],json.dumps(result))

    def test_truenas_authentication_failure_does_not_collect_inventory(self):
        ws=Mock();ws.call.return_value={'response_type':'AUTH_ERR'}
        with self.assertRaises(transport.CollectorError):dc.truenas(CFG,SECRET,'10.20.0.20',NETS,client=ws)
        self.assertEqual(ws.call.call_count,1);ws.close.assert_called_once()

    def test_idrac_discovers_system_path_and_nic_identity(self):
        result=dc.idrac(CFG,SECRET,'10.20.0.11',NETS,client=redfish_fixture())
        root=result['assets'][0]
        self.assertEqual(root['model'],'PowerEdge example')
        self.assertIn('10.20.0.10',root['addresses'])
        self.assertIn('00:11:22:33:44:10',root['macs'])
        self.assertEqual(root['serial'],'EXAMPLE-SERIAL')

    def test_redfish_cannot_redirect_resource_collection_to_another_origin(self):
        http=FakeHTTP({'/redfish/v1/Systems':{'Members':[{'@odata.id':'https://evil.example/redfish/v1/Systems/1'}]}})
        with self.assertRaises(transport.CollectorError):dc.idrac(CFG,SECRET,'10.20.0.11',NETS,client=http)
        self.assertEqual(http.paths,['/redfish/v1/Systems'])

    def test_snmp_auto_detects_apc_and_cyberpower_from_enterprise_identity(self):
        for kind,enterprise in [('apc','318'),('cyberpower','3808')]:
            fake=Mock()
            def query(oids,walk=False):
                if walk:return {}
                if dc.SYS['object_id'] in oids:return {dc.SYS['name']:'UPS example',dc.SYS['object_id']:'.1.3.6.1.4.1.'+enterprise+'.1',dc.SYS['description']:'UPS'}
                return {dc.VENDOR_UPS[kind]['model']:'Example UPS',dc.VENDOR_UPS[kind]['serial']:'UPS-SERIAL'}
            fake.query.side_effect=query
            result=dc.snmp_device({'kind':'snmp'}, {}, '10.20.0.30',NETS,client=fake)
            root=result['assets'][0]
            self.assertEqual(root['role'],'UPS');self.assertEqual(root['model'],'Example UPS')
            self.assertEqual(root['vendor'],'APC' if kind=='apc' else 'CyberPower')
            self.assertEqual(result['links'],[])  # No guessed UPS-to-server power feed.

    def test_snmp_credentials_are_not_in_process_arguments_and_temp_is_private(self):
        cfg=dc.validate_config('snmp',{'snmp_version':'2c'})
        captured=[]
        def runner(command,**kwargs):
            directory=Path(kwargs['env']['SNMPCONFPATH']);file=directory/'snmp.conf'
            self.assertEqual(file.stat().st_mode&0o777,0o600)
            self.assertIn('example-private-community',file.read_text())
            self.assertNotIn('example-private-community',' '.join(command))
            self.assertNotIn('snmpset',' '.join(command));captured.append(directory)
            return Mock(returncode=0,stdout=dc.SYS['name']+' = STRING: "example"\n')
        client=dc.SNMP(cfg,{'community':'example-private-community'},'10.20.0.1',runner)
        self.assertTrue(client.query(dc.SYS.values()));client.close()
        self.assertFalse(captured[0].exists())

    def test_snmp_config_injection_and_unknown_versions_are_rejected(self):
        cfg=dc.validate_config('snmp',{'snmp_version':'2c'})
        with self.assertRaises(transport.CollectorError):dc.SNMP(cfg,{'community':'x\ndefCommunity public'},'10.20.0.1')
        with self.assertRaises(transport.CollectorError):dc.validate_config('snmp',{'snmp_version':'1'})

    def test_single_cluster_connection_discovers_fifty_guests(self):
        http=pve_fixture()
        http.responses['/api2/json/cluster/resources']['data']=[{'type':'node','node':'pve-a'}]+[{'type':'qemu','node':'pve-a','vmid':i,'name':'guest-'+str(i)} for i in range(100,150)]
        result=dc.proxmox(PVE_CFG,PVE_SECRET,'10.20.0.10',NETS,client=http)
        self.assertEqual(len([a for a in result['assets'] if a.get('role')=='VM']),50)
        self.assertEqual(len([l for l in result['links'] if l['kind']=='hosts']),50)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.store=labmap.Store(Path(self.temp.name)/'map.sqlite')
        self.store.save_site({'id':'home','targets':['10.20.0.0/24']})
    def ingest(self,source,batch):
        with closing(self.store.connect()) as db,db:return inventory.ingest(db,'home',source,batch,labmap.now())

    def test_enrich_existing_address_and_preserve_user_corrections(self):
        self.store.ingest('home','nmap',[{'address':'10.20.0.10','network':'10.20.0.0/24','hostname':'old','mac':'00:11:22:33:44:10','vendor':'Dell','model':''}],[],labmap.now())
        self.store.annotate({'site':'home','address':'10.20.0.10','name':'Keep this name','role':'My role'})
        self.ingest('proxmox',dc.proxmox(PVE_CFG,PVE_SECRET,'10.20.0.10',NETS,client=pve_fixture()))
        self.ingest('idrac',dc.idrac(CFG,SECRET,'10.20.0.11',NETS,client=redfish_fixture()))
        assets=self.store.state()['assets']
        physical=next(a for a in assets if '10.20.0.10' in a['addresses'])
        self.assertEqual(physical['name'],'Keep this name');self.assertEqual(physical['role'],'My role')
        self.assertEqual(physical['model'],'PowerEdge example');self.assertIn('10.20.0.11',physical['addresses'])
        self.assertEqual(len([a for a in assets if '10.20.0.10' in a['addresses']]),1)
        self.assertEqual(len(self.store.state()['hosts']),1)  # Legacy rows are preserved.

    def test_placeholder_addresses_merge_without_deleting_legacy_assets(self):
        for ip in ('10.20.0.10','10.20.0.11'):
            self.store.ingest('home','nmap',[{'address':ip,'network':'10.20.0.0/24','hostname':'','mac':'','vendor':'','model':''}],[],labmap.now())
        self.ingest('idrac',dc.idrac(CFG,SECRET,'10.20.0.11',NETS,client=redfish_fixture()))
        self.assertEqual(len(self.store.state()['assets']),1)
        self.assertEqual(len(self.store.state()['hosts']),2)
        with closing(self.store.connect()) as db:self.assertGreater(db.execute("SELECT count(*) FROM assets WHERE merged_into!=''").fetchone()[0],0)

    def test_conflicting_serials_or_guest_host_mac_reuse_never_silently_merge(self):
        for ref,serial,role in [('a','ONE','Physical server'),('b','TWO','Physical server'),('vm','THREE','VM')]:
            self.ingest('idrac',{'assets':[{'ref':ref,'uuid':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','serial':serial,'vendor':'Dell','role':role,'macs':['00:11:22:33:44:10']}],'links':[]})
        self.assertEqual(len(self.store.state()['assets']),3)
        self.assertTrue(any(a['review'] for a in self.store.state()['assets']))

    def test_guest_with_no_ip_has_stable_identity_and_host_relationship(self):
        for _ in range(2):self.ingest('proxmox',dc.proxmox(PVE_CFG,PVE_SECRET,'10.20.0.10',NETS,client=pve_fixture()))
        state=self.store.state();vms=[a for a in state['assets'] if a['role']=='VM']
        self.assertEqual(len(vms),1);self.assertEqual(vms[0]['addresses'],[])
        self.assertTrue(any(l['kind']=='hosts' and l['dst']==vms[0]['id'] for l in state['asset_links']))
        labmap.ET.fromstring(labmap.diagram(state))

    def test_old_schema_upgrade_keeps_rows_and_creates_recoverable_backup(self):
        path=Path(self.temp.name)/'old.sqlite'
        with closing(sqlite3.connect(path)) as db:
            db.executescript(labmap.SCHEMA)
            db.execute("INSERT INTO hosts VALUES ('home','10.20.0.10','10.20.0.0/24','old-host','','','','nmap','old','old')")
            db.execute("INSERT INTO annotations VALUES ('home','10.20.0.10','saved-name','saved-role','','')");db.commit()
        upgraded=labmap.Store(path)
        self.assertEqual(upgraded.state()['assets'][0]['name'],'saved-name')
        backups=list((path.parent/'backups').glob('old-before-collectors-*.sqlite'))
        self.assertEqual(len(backups),1)
        with closing(sqlite3.connect(backups[0])) as db:
            self.assertEqual(db.execute('SELECT hostname FROM hosts').fetchone()[0],'old-host')
            self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='assets'").fetchone())


class ManagerTests(unittest.TestCase):
    setUp=InventoryTests.setUp

    def test_legacy_proxmox_user_account_is_rejected_before_keychain_or_network_access(self):
        app=labmap.Workspace(self.store)
        saved=app.collectors.save({'site':'home','kind':'proxmox','config':PVE_CFG,'credentials':PVE_SECRET})
        with closing(self.store.connect()) as db,db:
            db.execute('UPDATE collector_connections SET config=? WHERE id=?',(json.dumps({**PVE_CFG,'username':'root@pam'}),saved['id']))
        with patch.object(app.collectors.vault,'get') as credential,patch('collector_workspace.connection_targets') as resolve:
            with self.assertRaisesRegex(ValueError,'user@realm!tokenid'):app.collectors.plan('home')
            credential.assert_not_called();resolve.assert_not_called()

    def test_all_collectors_only_includes_enabled_connections_in_this_site(self):
        app=labmap.Workspace(self.store)
        enabled=[app.collectors.save({'site':'home','kind':'routeros','label':label,'config':CFG,'credentials':SECRET})['id'] for label in ('Core','Edge')]
        app.collectors.save({'site':'home','kind':'routeros','enabled':False,'config':CFG})
        self.store.save_site({'id':'dc','targets':['10.20.0.0/24']})
        app.collectors.save({'site':'dc','kind':'routeros','config':CFG})
        plan=app.collectors.plan('home')
        self.assertCountEqual([c['id'] for c in plan['connections']],enabled)

    def test_one_collector_does_not_need_credentials_from_unselected_sources(self):
        app=labmap.Workspace(self.store)
        saved=app.collectors.save({'site':'home','kind':'routeros','config':CFG,'credentials':SECRET})['id']
        app.collectors.save({'site':'home','kind':'proxmox','config':PVE_CFG})
        with self.assertRaises(ValueError):app.collectors.plan('home')
        plan=app.collectors.plan('home',[saved])
        self.assertEqual([c['id'] for c in plan['connections']],[saved])

    def test_invalid_or_unavailable_selection_is_rejected_before_target_resolution(self):
        app=labmap.Workspace(self.store)
        saved=app.collectors.save({'site':'home','kind':'routeros','config':CFG,'credentials':SECRET})['id']
        disabled=app.collectors.save({'site':'home','kind':'routeros','enabled':False,'config':CFG})['id']
        self.store.save_site({'id':'dc','targets':['10.20.0.0/24']})
        foreign=app.collectors.save({'site':'dc','kind':'routeros','config':CFG})['id']
        with patch('collector_workspace.connection_targets') as resolve:
            for selected in ([],saved,{},[None],[{}],['unknown'],[saved,'unknown'],[disabled],[foreign]):
                with self.subTest(selected=selected),self.assertRaises(ValueError):app.collectors.plan('home',selected)
            resolve.assert_not_called()
        self.assertEqual(app.plans,{})

    def test_saved_config_never_contains_credentials_and_plan_revalidation_blocks_edits(self):
        app=labmap.Workspace(self.store)
        result=app.collectors.save({'site':'home','kind':'routeros','label':'Core','config':CFG,'credentials':SECRET})
        connection=app.collectors.connections()[0]
        self.assertNotIn(SECRET['password'],json.dumps(connection))
        plan=app.collectors.plan('home')
        self.assertNotIn(SECRET['password'],json.dumps(plan))
        app.collectors.save({'id':result['id'],'site':'home','kind':'routeros','label':'Changed','config':CFG})
        with self.assertRaises(ValueError):app.start({'plan_id':plan['id'],'confirmed':True})
        self.assertEqual(self.store.state()['jobs'],[])

    def test_direct_collection_runs_without_import_or_manual_assignment(self):
        app=labmap.Workspace(self.store)
        app.collectors.save({'site':'home','kind':'proxmox','config':PVE_CFG,'credentials':PVE_SECRET})
        batch=dc.proxmox(PVE_CFG,PVE_SECRET,'10.20.0.10',NETS,client=pve_fixture())
        with patch.dict(dc.ADAPTERS,{'proxmox':Mock(return_value=batch)}):
            plan=app.collectors.plan('home');app.start({'plan_id':plan['id'],'confirmed':True});app.thread.join(timeout=5)
        self.assertEqual(self.store.state()['jobs'][0]['status'],'complete')
        self.assertGreater(len(self.store.state()['assets']),2)
        self.assertTrue(self.store.state()['asset_links'])

    def test_unexpected_transport_exception_cannot_persist_credential_text(self):
        app=labmap.Workspace(self.store)
        app.collectors.save({'site':'home','kind':'routeros','config':CFG,'credentials':SECRET})
        with patch.dict(dc.ADAPTERS,{'routeros':Mock(side_effect=RuntimeError(SECRET['password']))}):
            plan=app.collectors.plan('home');app.start({'plan_id':plan['id'],'confirmed':True});app.thread.join(timeout=5)
        self.assertNotIn(SECRET['password'],json.dumps(app.collectors.connections()))
        self.assertNotIn(SECRET['password'],json.dumps(self.store.state()))

    def test_invalid_snmp_profile_is_rejected_before_fanning_out_to_targets(self):
        app=labmap.Workspace(self.store)
        app.collectors.save({'site':'home','kind':'snmp','config':{'username':'readonly'},'credentials':{'auth_password':'valid-auth-only'}})
        with self.assertRaisesRegex(ValueError,'privacy passphrase'):app.collectors.plan('home')
        self.assertEqual(self.store.state()['jobs'],[])

    def test_partial_snmp_credential_edit_preserves_the_other_saved_passphrase(self):
        app=labmap.Workspace(self.store)
        config={'snmp_version':'3','username':'readonly','endpoint':'10.20.0.1'}
        saved=app.collectors.save({'site':'home','kind':'snmp','config':config,'credentials':{'auth_password':'original-auth','privacy_password':'original-private'}})
        app.collectors.save({'id':saved['id'],'site':'home','kind':'snmp','config':config,'credentials':{'auth_password':'changed-auth','privacy_password':''}})
        creds=app.collectors.credential(app.collectors.connections()[0])
        self.assertEqual(creds['auth_password'],'changed-auth')
        self.assertEqual(creds['privacy_password'],'original-private')


class CollectorHTTPTests(unittest.TestCase):
    setUp=base_tests.HTTPTests.setUp
    request=base_tests.HTTPTests.request
    auth=base_tests.HTTPTests.auth

    def test_single_and_all_selection_execute_only_the_reviewed_collectors(self):
        auth=self.auth()
        self.request('/api/sites',{'id':'home','targets':['10.20.0.0/24']},auth)
        ids=[]
        for name,address in [('Core','10.20.0.1'),('Edge','10.20.0.2')]:
            payload={'site':'home','kind':'routeros','label':name,'config':{**CFG,'endpoint':'https://'+address},'credentials':SECRET}
            code,body,_=self.request('/api/collectors/save',payload,auth)
            self.assertEqual(code,200);ids.append(json.loads(body)['id'])
        calls=[]
        def fake(config,secret,address,nets,**kwargs):
            calls.append(config['id'])
            return {'assets':[{'ref':config['id'],'addresses':[address],'name':address,'role':'Router'}],'links':[],'warnings':[]}
        for selected,expected in [([ids[0]],[ids[0]]),(None,ids)]:
            with self.subTest(selected=selected),patch.dict(dc.ADAPTERS,{'routeros':fake}):
                calls.clear()
                code,body,_=self.request('/api/collectors/plan',{'site':'home','connections':selected},auth)
                self.assertEqual(code,200);plan=json.loads(body)
                self.assertCountEqual([c['id'] for c in plan['connections']],expected)
                self.assertEqual(self.request('/api/scan',{'plan_id':plan['id'],'confirmed':True},auth)[0],200)
                self.app.thread.join(timeout=5)
                self.assertFalse(self.app.thread.is_alive())
                self.assertCountEqual(calls,expected)
                self.assertEqual(self.app.store.state()['jobs'][0]['status'],'complete')
                collected={c['id'] for c in self.app.collectors.connections() if c['last_collected']}
                self.assertEqual(collected,set(expected))
        self.assertEqual(len(self.app.store.state()['assets']),2)

    def test_webui_apis_save_collect_and_return_automatically_classified_assets(self):
        auth=self.auth()
        self.request('/api/sites',{'id':'home','targets':['10.20.0.0/24']},auth)
        payload={'site':'home','kind':'proxmox','label':'Cluster','config':PVE_CFG,'credentials':PVE_SECRET}
        code,body,_=self.request('/api/collectors/save',payload,auth)
        self.assertEqual(code,200)
        state=json.loads(self.request('/api/state')[1])
        self.assertEqual(len(state['collectors']),1)
        self.assertNotIn(PVE_SECRET['password'],json.dumps(state))
        code,body,_=self.request('/api/collectors/plan',{'site':'home'},auth)
        self.assertEqual(code,200)
        plan=json.loads(body)
        batch=dc.proxmox(PVE_CFG,PVE_SECRET,'10.20.0.10',NETS,client=pve_fixture())
        with patch.dict(dc.ADAPTERS,{'proxmox':Mock(return_value=batch)}):
            code,_,_=self.request('/api/scan',{'plan_id':plan['id'],'confirmed':True},auth)
            self.assertEqual(code,200);self.app.thread.join(timeout=5)
        state=json.loads(self.request('/api/state')[1])
        self.assertEqual(state['jobs'][0]['status'],'complete')
        self.assertTrue(any(a['role']=='VM' for a in state['assets']))
        self.assertTrue(any(l['kind']=='hosts' for l in state['asset_links']))

    def test_collector_save_requires_the_same_csrf_guard_as_other_writes(self):
        self.assertEqual(self.request('/api/collectors/save',{'site':'home','kind':'snmp'})[0],403)

    def test_one_shared_snmp_profile_discovers_agents_without_per_asset_assignments(self):
        auth=self.auth()
        self.request('/api/sites',{'id':'home','targets':['10.20.0.0/30']},auth)
        p={'site':'home','kind':'snmp','config':{'snmp_version':'2c'},'credentials':{'community':'example-only'}}
        self.assertEqual(self.request('/api/collectors/save',p,auth)[0],200)
        plan=json.loads(self.request('/api/collectors/plan',{'site':'home'},auth)[1])
        self.assertEqual(plan['addresses'],2)
        def fake(config,secret,address,nets,**kwargs):
            return {'assets':[{'ref':'snmp:'+address,'addresses':[address],'name':'UPS '+address,'role':'UPS','vendor':'APC'}],'links':[],'warnings':[]}
        with patch.dict(dc.ADAPTERS,{'snmp':fake}):
            self.request('/api/scan',{'plan_id':plan['id'],'confirmed':True},auth);self.app.thread.join(timeout=5)
        state=json.loads(self.request('/api/state')[1])
        self.assertEqual(len(state['assets']),2)
        self.assertTrue(all(a['role']=='UPS' for a in state['assets']))


class TransportTests(unittest.TestCase):
    def test_endpoint_and_dns_scope_guards(self):
        for value in ('http://10.20.0.1','https://user:secret@10.20.0.1','https://10.20.0.1/unsafe'):
            with self.assertRaises(transport.CollectorError):transport.endpoint(value)
        resolver=Mock(return_value=[(None,None,None,None,('203.0.113.1',443))])
        with self.assertRaises(transport.CollectorError):transport.resolve_scoped('example',443,NETS,resolver)
        self.assertEqual(transport.resolve_scoped('10.20.0.1',443,NETS),['10.20.0.1'])

    def test_certificate_pin_is_checked_before_any_http_credentials(self):
        raw=Mock();tls=Mock();tls.getpeercert.return_value=b'example-cert'
        http=transport.HTTPS({**CFG,'fingerprint':'0'*64},'10.20.0.1',{'Authorization':'secret'})
        with patch.object(transport.socket,'create_connection',return_value=raw),patch.object(transport.ssl,'create_default_context') as context:
            context.return_value.wrap_socket.return_value=tls
            with self.assertRaises(transport.CollectorError):http.get('/rest/system/identity')
        tls.sendall.assert_not_called();tls.close.assert_called()

    def test_https_redirect_is_not_followed(self):
        conn=Mock();response=Mock(status=302);response.read.return_value=b'';conn.getresponse.return_value=response
        with patch.object(transport,'PinnedHTTPS',return_value=conn):
            with self.assertRaises(transport.CollectorError):transport.HTTPS(CFG,'10.20.0.1',{'Authorization':'secret'}).get('/rest/system/identity')
        self.assertEqual(conn.request.call_count,1)
        self.assertEqual(conn.request.call_args.args[0],'GET')

    def test_websocket_frames_are_masked_and_inventory_method_allowlist_is_enforced(self):
        ws=object.__new__(transport.TrueNASWebSocket);ws.socket=Mock();ws.counter=0
        ws.send_frame(1,b'hello')
        frame=ws.socket.sendall.call_args.args[0]
        self.assertTrue(frame[1]&128);mask=frame[2:6]
        self.assertEqual(bytes(v^mask[i%4] for i,v in enumerate(frame[6:])),b'hello')
        with self.assertRaises(transport.CollectorError):ws.call('pool.delete',[1])

    def test_websocket_fragmentation_and_ping_are_handled_without_unbounded_messages(self):
        ws=object.__new__(transport.TrueNASWebSocket);ws.socket=Mock();ws.stop=lambda:False
        frames=bytearray(b'\x01\x05{"id"'+b'\x89\x01x'+b'\x80\x03:1}')
        def read(size):result=bytes(frames[:size]);del frames[:size];return result
        ws.socket.recv.side_effect=read
        self.assertEqual(ws.receive(),{'id':1})
        self.assertTrue(ws.socket.sendall.called)

    def test_vault_session_storage_and_keychain_opt_in(self):
        vault=Vault();vault.keychain=Mock();vault.keychain.operation.return_value=SECRET
        self.assertEqual(vault.put('example',SECRET),'session');vault.keychain.operation.assert_not_called()
        self.assertEqual(vault.get('example','session'),SECRET)
        self.assertEqual(vault.put('saved',SECRET,True),'keychain')
        self.assertEqual(vault.keychain.operation.call_args_list,[unittest.mock.call('saved',SECRET),unittest.mock.call('saved')])


if __name__=='__main__':unittest.main()
