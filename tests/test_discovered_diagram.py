from contextlib import closing
import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import asset_inventory
import discovered_diagram as diagram
import labmap
import test_labmap as base_tests

NS={'s':'http://www.w3.org/2000/svg'}

def asset(ident,name,role,address='',site='home',**extra):
    return {'id':ident,'site':site,'name':name,'role':role,'auto_role':role,'address':address,'addresses':[address] if address else [],'details':{},**extra}

def fixture():
    assets=[asset('router','private-router','Router','10.20.0.1'),asset('host','private-host','Proxmox host','10.20.0.10',model='private-model',details={'cpu':{'model':'private-cpu'},'memory_bytes':34359738368}),asset('vm','private-vm','VM',details={'vmid':100,'status':'running'}),asset('ct','private-container','Container','10.20.0.31')]
    links=[{'site':'home','src':'host','dst':k,'kind':'hosts','source':'proxmox'} for k in ('vm','ct')]
    return {'sites':[{'id':'home','label':'private-site','targets':['10.20.0.0/24']}],'assets':assets,'asset_links':links}


class DiagramTests(unittest.TestCase):
    def test_host_guest_placement_and_no_ip_guests_are_drawn_without_changing_inventory(self):
        state=fixture();before=copy.deepcopy(state);svg=diagram.render(state,'home');root=ET.fromstring(svg)
        self.assertEqual(state,before)
        text=' '.join(root.itertext())
        for expected in ('private-host','private-vm','private-container','No IP reported','Host placement: 2 guests','32 GiB'):self.assertIn(expected,text)
        self.assertIn('1 hosts · 1 VMs · 1 containers',text)
        self.assertNotIn('Guests without a reported host',text)
        self.assertEqual(root.get('width'),'2400')

    def test_manual_roles_names_and_models_are_preserved(self):
        state=fixture();state['assets'][0].update(name='Custom switch',role='Switch',manual_model='Custom hardware')
        svg=diagram.render(state,'home');text=' '.join(ET.fromstring(svg).itertext())
        self.assertIn('Custom switch',text);self.assertIn('Custom hardware',text)
        state['assets'].append(asset('corrected','Corrected guest','VM',auto_role='Unknown'))
        self.assertIn('Guests without a reported host',diagram.render(state,'home'))

    def test_fifty_guests_grow_the_page_and_keep_each_placement(self):
        state=fixture();state['assets']=state['assets'][:2];state['asset_links']=[]
        for i in range(50):
            ident='guest-'+str(i);state['assets'].append(asset(ident,ident,'VM'))
            state['asset_links'].append({'site':'home','src':'host','dst':ident,'kind':'hosts','source':'proxmox'})
        root=ET.fromstring(diagram.render(state,'home'));text=' '.join(root.itertext())
        for i in range(50):self.assertIn('guest-'+str(i),text)
        self.assertIn('Host placement: 50 guests',text);self.assertGreater(int(root.get('height')),1400)

    def test_redaction_removes_names_networks_models_cpu_and_unknown_role_text(self):
        state=fixture();state['assets'].append(asset('private-id','private-unknown','private-custom-role','10.20.0.90'))
        svg=diagram.render(state,'home',True)
        for secret in ('private-','10.20.0.','private-cpu'):self.assertNotIn(secret,svg)
        self.assertIn('Network 1',svg);self.assertIn('Address hidden',svg)
        self.assertIn('Host placement: 2 guests',svg)

    def test_sites_are_isolated_and_invalid_site_is_rejected(self):
        state=fixture();state['assets'].append(asset('other','Other-site-secret','Router','10.50.0.1','other'))
        self.assertNotIn('Other-site-secret',diagram.render(state,'home'))
        with self.assertRaisesRegex(ValueError,'existing site'):diagram.render(state,'absent')

    def test_labels_are_xml_escaped_and_never_executable(self):
        state=fixture();name='router <script>alert("x")</script> & cabling';state['assets'][0]['name']=name
        root=ET.fromstring(diagram.render(state,'home'));self.assertEqual(root.findall('.//s:script',NS),[])
        self.assertIn(name,' '.join(root.itertext()))
        self.assertEqual(root.findall('.//s:image',NS),[])

    def test_connections_require_evidence_and_neighbor_report_remains_dashed(self):
        state=fixture();svg=diagram.render(state,'home');self.assertNotIn('stroke-dasharray',svg)
        state['asset_links'].append({'site':'home','src':'router','dst':'host','kind':'neighbor','source':'routeros'})
        root=ET.fromstring(diagram.render(state,'home'))
        wires=[p for p in root.findall('s:path',NS) if p.find('s:title',NS) is not None]
        self.assertEqual(len(wires),1);self.assertEqual(wires[0].get('stroke-dasharray'),'5 5')
        state['asset_links'].append({'site':'home','src':'host','dst':'router','kind':'physical','source':'manual'})
        root=ET.fromstring(diagram.render(state,'home'));wires=[p for p in root.findall('s:path',NS) if p.find('s:title',NS) is not None]
        self.assertEqual(len(wires),1);self.assertIsNone(wires[0].get('stroke-dasharray'))
        self.assertIn('Confirmed cable',wires[0].find('s:title',NS).text)

    def test_empty_inventory_simulation_and_invalid_numeric_hardware(self):
        state=fixture();state['assets'][1]['details']={'cpu_count':'NaN','memory_bytes':'Infinity'}
        ET.fromstring(diagram.render(state,'home'))
        state.update(assets=[],asset_links=[],demo=True)
        text=' '.join(ET.fromstring(diagram.render(state,'home')).itertext())
        self.assertIn('No infrastructure roles reported yet',text);self.assertIn('Simulated inventory',text)

    @unittest.skipUnless(shutil.which('rsvg-convert'),'native PNG converter is unavailable')
    def test_real_png_conversion_has_valid_dimensions(self):
        result=diagram.png(diagram.render(fixture(),'home'));self.assertTrue(result.startswith(b'\x89PNG\r\n\x1a\n'))
        width,height=struct.unpack('>II',result[16:24]);self.assertGreater(width,0);self.assertLessEqual(width*height,16_000_000)

    def test_missing_png_converter_has_actionable_error(self):
        with patch('discovered_diagram.shutil.which',return_value=None),self.assertRaisesRegex(ValueError,'SVG instead'):diagram.png('<svg/>')

    def test_original_build_entrypoint_reads_database_without_modifying_it(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'inventory.sqlite';store=labmap.Store(path);store.save_site({'id':'home','label':'CLI site','targets':['10.20.0.0/24']})
            store.ingest('home','nmap',[{'address':'10.20.0.10','network':'10.20.0.0/24','hostname':'CLI host','mac':'','vendor':'','model':''}],[],labmap.now())
            before=hashlib.sha256(path.read_bytes()).digest()
            result=subprocess.run([sys.executable,str(diagram.ROOT/'build.py'),'--discovered-db',str(path),'--site','home','--out',temp,'--svg-only'],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(hashlib.sha256(path.read_bytes()).digest(),before)
            self.assertIn('CLI host',(Path(temp)/'home-original-style-private.svg').read_text())


class DiagramHTTPTests(unittest.TestCase):
    setUp=base_tests.HTTPTests.setUp
    request=base_tests.HTTPTests.request

    def test_download_scope_query_validation_and_origin_guards(self):
        self.app.store.save_site({'id':'home','targets':['10.20.0.0/24']})
        code,body,headers=self.request('/api/original-diagram.svg?site=home&redacted=1')
        self.assertEqual(code,200);ET.fromstring(body);self.assertIn('image/svg+xml',headers['Content-Type']);self.assertEqual(headers['Cache-Control'],'no-store')
        for query in ('site=missing','site=home&redacted=x','site=home&site=home','site=home&unknown=1'):
            self.assertEqual(self.request('/api/original-diagram.svg?'+query)[0],400)
        self.assertEqual(self.request('/api/original-diagram.svg?site=home',headers={'Origin':'https://evil.example'})[0],403)
        self.assertEqual(self.request('/api/original-diagram.svg?site=home',headers={'Host':'evil.example'})[0],403)
        with patch('discovered_diagram.png',return_value=b'\x89PNG\r\n\x1a\nfixture'):
            code,body,headers=self.request('/api/original-diagram.png?site=home')
            self.assertEqual(code,200);self.assertEqual(headers['Content-Type'],'image/png');self.assertTrue(body.startswith(b'\x89PNG'))
        with patch('discovered_diagram.shutil.which',return_value=None):
            self.assertFalse(json.loads(self.request('/api/state')[1])['png_available'])
            code,body,_=self.request('/api/original-diagram.png?site=home');self.assertEqual(code,400);self.assertIn('SVG instead',body.decode())
