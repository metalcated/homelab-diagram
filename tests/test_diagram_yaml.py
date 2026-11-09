from contextlib import closing
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import asset_inventory
import diagram_yaml as dy
import direct_collectors as dc
import labmap
import test_labmap as base_tests
from test_collectors import pve_fixture,PVE_CFG,PVE_SECRET,NETS


class YamlTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.store=labmap.Store(Path(self.temp.name)/'map.sqlite')
        self.store.save_site({'id':'home','label':'Private Lab','targets':['10.20.0.0/24']})
        batch=dc.proxmox(PVE_CFG,PVE_SECRET,'10.20.0.10',NETS,client=pve_fixture())
        with closing(self.store.connect()) as db,db:asset_inventory.ingest(db,'home','proxmox',batch,labmap.now())
        self.manager=dy.Documents(self.store)
    def payload(self,document=None):
        doc=self.manager.get('home')
        return {'site':'home','revision':doc['revision'],'yaml':dy.dump(document) if document else doc['yaml']}
    def test_all_discovered_guests_and_hosts_flow_into_yaml_without_credentials_or_inventory_writes(self):
        before=self.store.state();data=self.manager.get('home');doc=dy.load(data['yaml'])
        self.assertEqual(data['summary']['hosts'],1);self.assertEqual(data['summary']['guests'],2)
        guests=[g for s in doc['servers'] for group in s['dmz_groups'] for g in group['guests']]
        self.assertEqual({g['kind'] for g in guests},{'VM','CT'});self.assertIn('No IP reported',{g['ip'] for g in guests})
        self.assertNotIn(PVE_SECRET['password'],data['yaml']);self.assertEqual(before,self.store.state())
        self.assertEqual(doc['layout'],'collected');self.assertIn('hw',doc['servers'][0])
    def test_fifty_guests_are_assigned_without_manual_yaml_entries(self):
        http=pve_fixture();http.responses['/api2/json/cluster/resources']['data']=[{'type':'node','node':'pve-a'}]+[{'type':'qemu','node':'pve-a','vmid':i,'name':'guest-'+str(i)} for i in range(200,250)]
        batch=dc.proxmox(PVE_CFG,PVE_SECRET,'10.20.0.10',NETS,client=http)
        with closing(self.store.connect()) as db,db:asset_inventory.ingest(db,'home','proxmox',batch,labmap.now())
        self.assertEqual(self.manager.get('home')['summary']['guests'],52)
    def test_edit_reopen_refresh_and_restore_keep_edits_and_history(self):
        first=self.manager.save(self.payload());doc=dy.load(first['yaml']);doc['meta']['title']='Edited in UI';doc['servers'][0]['dmz_groups'][0]['name']='Custom group';doc['servers'][0]['dmz_groups'][0]['guests'][0]['name']='Custom guest'
        saved=self.manager.save(self.payload(doc));self.assertEqual(dy.load(self.manager.get('home')['yaml'])['meta']['title'],'Edited in UI')
        fresh=copy.deepcopy(dy.generated(self.store.state(),'home'));fresh['servers'][0]['dmz_groups'][0]['guests'].append({'asset_id':'new-guest','id':'999','kind':'VM','name':'New guest','ip':'No IP reported','note':'stopped','icons':['glyph-cpu'],'vlan':'unknown'})
        with patch('diagram_yaml.generated',return_value=fresh):merged=self.manager.save(self.payload(),refresh=True)
        document=dy.load(merged['yaml']);self.assertEqual(document['meta']['title'],'Edited in UI');group=document['servers'][0]['dmz_groups'][0]
        self.assertEqual(group['name'],'Custom group');self.assertIn('Custom guest',{g['name'] for g in group['guests']});self.assertIn('New guest',{g['name'] for g in group['guests']})
        restored=self.manager.restore({'site':'home','revision':merged['revision'],'restore_revision':first['revision']})
        self.assertEqual(dy.load(restored['yaml'])['meta']['title'],'Private Lab');self.assertNotEqual(restored['revision'],first['revision']);self.assertEqual(len(restored['versions']),4)
    def test_conflicting_saves_and_invalid_yaml_preserve_saved_revision(self):
        saved=self.manager.save(self.payload())
        with self.assertRaisesRegex(ValueError,'another window'):self.manager.save({'site':'home','revision':'old','yaml':saved['yaml']})
        for contents in ['meta: [','!!python/object/apply:os.system [echo bad]','x: &a [1]\ny: *a',saved['yaml'].replace('glyph-cpu','../secret')]:
            with self.subTest(contents=contents[:30]),self.assertRaises(ValueError):self.manager.save({'site':'home','revision':saved['revision'],'yaml':contents})
        self.assertEqual(self.manager.get('home')['revision'],saved['revision'])
    def test_unknown_metadata_and_unconfirmed_physical_cables_are_rejected(self):
        payload=self.payload();payload['metadata_changes']={'unexpected':'bad'}
        with self.assertRaisesRegex(ValueError,'metadata'):self.manager.save(payload)
        doc=dy.load(payload['yaml']);doc['connections']=[{'kind':'physical','source':'routeros','src':'x','dst':'y'}]
        with self.assertRaisesRegex(ValueError,'manually confirmed'):dy.load(dy.dump(doc))

    def test_original_example_yaml_is_accepted_without_conversion_to_collected_layout(self):
        original=(dy.ROOT/'inventory.yaml').read_text();doc=dy.load(original);self.assertNotIn('layout',doc)
        saved=self.manager.save({**self.payload(),'yaml':original})
        self.assertEqual(dy.load(saved['yaml'])['terra']['name'],doc['terra']['name'])
        with self.assertRaisesRegex(ValueError,'fixed-layout'):self.manager.save(self.payload(),refresh=True)

    def test_stopping_the_app_terminates_its_owned_renderer_and_marks_interrupted(self):
        saved=self.manager.save(self.payload())
        root=Path(self.temp.name)/'slow-renderer';root.mkdir();(root/'build.py').write_text('import time\ntime.sleep(30)\n');(root/'icons').mkdir()
        with patch('diagram_yaml.ROOT',root):
            self.manager.render({'site':'home','revision':saved['revision']})
            deadline=time.monotonic()+3
            while not self.manager.processes and time.monotonic()<deadline:time.sleep(.02)
            self.assertTrue(self.manager.processes);self.manager.stop()
        self.assertFalse(any(t.is_alive() for t in self.manager.threads))
        self.assertEqual(self.manager.get('home')['builds'][0]['status'],'interrupted')

    @unittest.skipUnless(shutil.which('rsvg-convert'),'PNG converter unavailable')
    def test_actual_build_py_uses_saved_yaml_and_failure_preserves_previous_output(self):
        saved=self.manager.save({**self.payload(),'metadata_changes':{'title':'UI title reached original renderer'}})
        receipt=self.manager.render({'site':'home','revision':saved['revision'],'redacted':False});self.manager.threads[-1].join(timeout=65)
        build=self.manager.get('home')['builds'][0];self.assertEqual(build['status'],'complete',build['message'])
        self.assertEqual(build['renderer_sha256'],hashlib.sha256((dy.ROOT/'build.py').read_bytes()).hexdigest());self.assertEqual(build['yaml_sha256'],hashlib.sha256(saved['yaml'].encode()).hexdigest())
        source=self.manager.artifact('home',receipt['build'],'yaml').decode();self.assertEqual(source,saved['yaml'])
        svg=self.manager.artifact('home',receipt['build'],'svg').decode();self.assertIn('UI title reached original renderer',svg);self.assertIn('glyph',source);ET.fromstring(svg)
        self.assertTrue(self.manager.artifact('home',receipt['build'],'png').startswith(b'\x89PNG\r\n\x1a\n'))
        broken=dy.load(source);broken['servers'][0]['dmz_groups'][0]['guests'][0]['icons']=['missing-local-icon']
        edited=self.manager.save(self.payload(broken));self.manager.render({'site':'home','revision':edited['revision']});self.manager.threads[-1].join(timeout=65)
        self.assertEqual(self.manager.get('home')['builds'][0]['status'],'failed');self.assertTrue(self.manager.artifact('home',receipt['build'],'png').startswith(b'\x89PNG'))
        with self.assertRaises(ValueError):self.manager.artifact('other',receipt['build'],'png')
    @unittest.skipUnless(shutil.which('rsvg-convert'),'PNG converter unavailable')
    def test_redacted_original_build_hides_private_names_and_addresses(self):
        saved=self.manager.save(self.payload());self.manager.render({'site':'home','revision':saved['revision'],'redacted':True});self.manager.threads[-1].join(timeout=65)
        build=self.manager.get('home')['builds'][0];self.assertEqual(build['status'],'complete',build['message']);svg=self.manager.artifact('home',build['id'],'svg').decode()
        for value in ['Private Lab','pve-a','vm-no-ip','web-ct','10.20.0.']:self.assertNotIn(value,svg)
        self.assertIn('My Homelab',svg)


class YamlHTTPTests(unittest.TestCase):
    setUp=base_tests.HTTPTests.setUp
    request=base_tests.HTTPTests.request
    auth=base_tests.HTTPTests.auth
    def test_document_workflow_obeys_site_origin_revision_and_csrf_controls(self):
        self.app.store.save_site({'id':'home','targets':['10.20.0.0/24']})
        code,body,_=self.request('/api/diagram-document?site=home');self.assertEqual(code,200);draft=json.loads(body)
        payload={'site':'home','revision':draft['revision'],'yaml':draft['yaml']}
        self.assertEqual(self.request('/api/diagram-document/save',payload)[0],403)
        code,body,_=self.request('/api/diagram-document/save',payload,self.auth());self.assertEqual(code,200);saved=json.loads(body)
        self.assertEqual(self.request('/api/diagram-document/save',payload,self.auth())[0],400)
        code,body,headers=self.request('/api/diagram-document?site=home&format=yaml');self.assertEqual(code,200);self.assertEqual(body.decode(),saved['yaml']);self.assertIn('application/yaml',headers['Content-Type'])
        self.assertEqual(self.request('/api/diagram-document?site=missing')[0],400)
        self.assertEqual(self.request('/api/diagram-document?site=home',headers={'Origin':'https://evil.example'})[0],403)
        self.assertEqual(self.request('/api/diagram-artifact?site=home&build=../../secret&format=png')[0],400)
        self.assertEqual(self.request('/api/original-diagram.png?site=home')[0],400)
        self.assertEqual(self.request('/api/diagram-document/render',{'site':'home','revision':'wrong'},self.auth())[0],400)
