from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import base64
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import collector_transport as transport
import direct_collectors as collectors
import labmap
import scan_events as output
import test_labmap as base_tests


class EventTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.store=labmap.Store(Path(temp.name)/'inventory.sqlite')
        self.store.save_site({'id':'home','targets':['10.20.0.0/24']})
        with closing(self.store.connect()) as db,db:
            db.execute("INSERT INTO jobs VALUES ('run-one','home','running','now',NULL,'working','[]')")

    def test_response_projection_hides_credentials_and_unknown_fields_before_storage(self):
        secret='sentinel-password-123'
        config={'username':'readonly','endpoint':'https://10.20.0.1'}
        redactor=output.Redactor.connection(config,{'password':secret,'community':'sentinel-community'})
        encoded=base64.b64encode(('readonly:'+secret).encode()).decode()
        emit=output.Events(self.store,'run-one','Example',redactor=redactor)
        emit('response','Authorization: Basic '+encoded,{'data':[{'name':'router '+secret,'password':'unknown-password','api_key':'unknown-key','private_key':'unknown-private','CiPassword':'unknown-cloud','opaque':'unknown-opaque','interfaces':[{'name':'ether1','address':'10.20.0.1'}]}]})
        records=output.read_events(self.store,'home','run-one')['events']
        text=json.dumps(records)
        for value in (secret,encoded,'unknown-password','unknown-key','unknown-private','unknown-cloud','unknown-opaque'):
            self.assertNotIn(value,text)
            self.assertNotIn(value.encode(),self.store.path.read_bytes())
        self.assertIn('ether1',text);self.assertIn('[hidden]',text)

    def test_output_is_bounded_and_keeps_limit_notice_and_final_outcome(self):
        emit=output.Events(self.store,'run-one')
        with patch.object(output,'MAX_EVENTS',3):
            for _ in range(10):emit('response','Response',{'data':[{'name':'x'*2000}]*100})
            emit('complete','Complete')
        rows=output.read_events(self.store,'home','run-one')['events']
        self.assertEqual(len(rows),5)
        self.assertIn('Output limit reached',rows[-2]['message'])
        self.assertEqual(rows[-1]['level'],'complete')
        self.assertLessEqual(len(rows[0]['details']),output.MAX_DETAILS+30)

    def test_concurrent_target_events_have_stable_order_and_cursor_without_duplicates(self):
        def write(index):output.Events(self.store,'run-one','SNMP',str(index))('info','Responded')
        with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(write,range(30)))
        data=output.read_events(self.store,'home','run-one')
        ids=[e['id'] for e in data['events']]
        self.assertEqual(len(ids),30);self.assertEqual(ids,sorted(set(ids)))
        self.assertEqual(output.read_events(self.store,'home','run-one',data['next'])['events'],[])

    def test_http_transport_records_status_and_preview_without_headers_or_query_parameters(self):
        emit=output.Events(self.store,'run-one')
        response=Mock(status=200);response.read.return_value=b'{"name":"example","password":"do-not-save"}'
        connection=Mock();connection.getresponse.return_value=response
        with patch.object(transport,'PinnedHTTPS',return_value=connection):
            transport.HTTPS({'endpoint':'https://10.20.0.1'},'10.20.0.1',{'Authorization':'header-do-not-save'},emit=emit).get('/rest/system/identity?token=query-do-not-save')
        rows=output.read_events(self.store,'home','run-one')['events']
        self.assertEqual([r['level'] for r in rows],['request','response'])
        self.assertIn('HTTP 200',rows[-1]['message'])
        self.assertIn('duration_ms',json.loads(rows[-1]['details']))
        for secret in ('header-do-not-save','query-do-not-save','do-not-save'):self.assertNotIn(secret,json.dumps(rows))

    def test_authentication_responses_and_error_bodies_are_never_previewed(self):
        emit=output.Events(self.store,'run-one')
        ws=object.__new__(transport.TrueNASWebSocket);ws.counter=0;ws.emit=emit
        ws.send_frame=Mock();ws.receive=Mock(return_value={'id':1,'result':{'response_type':'SUCCESS','token':'hidden-auth-result'}})
        ws.call('auth.login_ex',[{'api_key':'hidden-request-key'}])
        response=Mock(status=403);response.read.return_value=b'{"error":"hidden-error-body"}'
        connection=Mock();connection.getresponse.return_value=response
        with patch.object(transport,'PinnedHTTPS',return_value=connection),self.assertRaises(transport.CollectorError):
            transport.HTTPS({'endpoint':'https://10.20.0.1'},'10.20.0.1',emit=emit).get('/redfish/v1/Systems')
        rows=output.read_events(self.store,'home','run-one')['events']
        for secret in ('hidden-auth-result','hidden-request-key','hidden-error-body'):self.assertNotIn(secret,json.dumps(rows))
        self.assertTrue(any(r['level']=='error' and '403' in r['details'] for r in rows))

    def test_snmp_logs_oid_responses_but_never_stderr_environment_or_command_credentials(self):
        secret={'community':'community-not-for-output'}
        emit=output.Events(self.store,'run-one',redactor=output.Redactor.connection({},secret))
        runner=Mock(return_value=Mock(returncode=1,stdout=collectors.SYS['name']+' = STRING: "example"\n',stderr='secret-snmp-diagnostic'))
        client=collectors.SNMP(collectors.validate_config('snmp',{'snmp_version':'2c'}),secret,'10.20.0.1',runner=runner,emit=emit)
        try:self.assertTrue(client.query([collectors.SYS['name']]))
        finally:client.close()
        text=json.dumps(output.read_events(self.store,'home','run-one'))
        self.assertIn('example',text);self.assertIn('SNMP GET',text)
        self.assertNotIn(secret['community'],text);self.assertNotIn('secret-snmp-diagnostic',text)

    def test_events_arrive_before_target_finishes_and_remain_available_after_restart(self):
        app=labmap.Workspace(self.store)
        config={'endpoint':'https://10.20.0.1','username':'readonly'}
        saved=app.collectors.save({'site':'home','kind':'routeros','label':'Core','config':config,'credentials':{'password':'private-sentinel'}})
        arrived=threading.Event();release=threading.Event()
        def fake(config,secret,address,nets,emit,**kwargs):
            emit('request','GET /rest/system/identity')
            emit('response','HTTP 200',{'name':'example','password':secret['password']})
            arrived.set();release.wait(5)
            return {'assets':[{'ref':'core','addresses':[address],'name':'example','role':'Router'}],'links':[],'warnings':[]}
        try:
            with patch.dict(collectors.ADAPTERS,{'routeros':fake}):
                plan=app.collectors.plan('home',[saved['id']]);job=app.start({'plan_id':plan['id'],'confirmed':True})['job']
                self.assertTrue(arrived.wait(3))
                data=output.read_events(self.store,'home',job)
                self.assertEqual(data['job']['status'],'running')
                self.assertTrue(any(r['level']=='response' for r in data['events']))
                self.assertNotIn('private-sentinel',json.dumps(data))
                release.set();app.thread.join(5)
        finally:release.set();app.thread.join(5)
        restarted=labmap.Store(self.store.path)
        data=output.read_events(restarted,'home',job)
        self.assertEqual(data['job']['status'],'complete');self.assertEqual(data['events'][-1]['level'],'complete')
        self.assertEqual(len(restarted.state()['assets']),1)

    def test_failed_target_redacts_exception_in_events_and_existing_collector_summary(self):
        app=labmap.Workspace(self.store)
        app.collectors.save({'site':'home','kind':'routeros','config':{'endpoint':'https://10.20.0.1','username':'readonly'},'credentials':{'password':'never-persist-this'}})
        with patch.dict(collectors.ADAPTERS,{'routeros':Mock(side_effect=transport.CollectorError('Denied never-persist-this',403))}):
            plan=app.collectors.plan('home');job=app.start({'plan_id':plan['id'],'confirmed':True})['job'];app.thread.join(5)
        data=output.read_events(self.store,'home',job)
        self.assertEqual(data['job']['status'],'failed')
        self.assertTrue(any(r['level']=='error' for r in data['events']))
        self.assertNotIn('never-persist-this',json.dumps(data)+json.dumps(app.collectors.connections()))

    def test_network_discovery_records_parsed_results_and_explains_invalid_responses(self):
        app=labmap.Workspace(self.store)
        for xml,status in ((base_tests.xml(),'complete'),('<nmaprun/>','failed')):
            with self.subTest(status=status),patch.object(app,'execute_command',return_value=Mock(returncode=0,stdout=xml)):
                plan=app.plan('home');job=app.start({'plan_id':plan['id'],'confirmed':True})['job'];app.thread.join(5)
                data=output.read_events(self.store,'home',job)
                self.assertEqual(data['job']['status'],status)
                self.assertTrue(any(r['level']=='request' for r in data['events']))
                if status=='complete':self.assertTrue(any(r['level']=='response' for r in data['events']))
                else:self.assertTrue(any('invalid, incomplete' in r['message'] for r in data['events']))
                self.assertFalse(app.running)


class OutputHTTPTests(unittest.TestCase):
    setUp=base_tests.HTTPTests.setUp
    request=base_tests.HTTPTests.request
    auth=base_tests.HTTPTests.auth

    def test_output_requires_local_origin_token_and_job_site_match(self):
        self.app.store.save_site({'id':'home','targets':['10.20.0.0/24']})
        self.app.store.save_site({'id':'dc','targets':['10.30.0.0/24']})
        with closing(self.app.store.connect()) as db,db:db.execute("INSERT INTO jobs VALUES ('run','home','complete','now','now','done','[]')")
        output.Events(self.app.store,'run')('info','Example event')
        url='/api/events?site=home&job=run'
        self.assertEqual(self.request(url)[0],403)
        self.assertEqual(self.request(url,headers={**self.auth(),'Origin':'https://example.com'})[0],403)
        self.assertEqual(self.request(url,headers={**self.auth(),'Host':'evil.example'})[0],403)
        self.assertEqual(self.request('/api/events?site=dc&job=run',headers=self.auth())[0],400)
        for suffix in ('&after=-1','&after=invalid','&after=999999999999999999999','&job=duplicate'):
            self.assertEqual(self.request(url+suffix,headers=self.auth())[0],400)
        code,body,headers=self.request(url,headers=self.auth())
        self.assertEqual(code,200);self.assertEqual(len(json.loads(body)['events']),1)
        self.assertEqual(headers['Cache-Control'],'no-store')

    def test_old_jobs_have_no_invented_output_and_cursor_pages_are_bounded(self):
        self.app.store.save_site({'id':'home','targets':['10.20.0.0/24']})
        with closing(self.app.store.connect()) as db,db:
            db.execute("INSERT INTO jobs VALUES ('old','home','complete','now','now','done','[]')")
            db.execute("INSERT INTO jobs VALUES ('new','home','running','now',NULL,'working','[]')")
        self.assertEqual(json.loads(self.request('/api/events?site=home&job=old',headers=self.auth())[1])['events'],[])
        for _ in range(260):output.Events(self.app.store,'new')('info','Event')
        first=json.loads(self.request('/api/events?site=home&job=new',headers=self.auth())[1])
        second=json.loads(self.request('/api/events?site=home&job=new&after='+str(first['next']),headers=self.auth())[1])
        self.assertEqual(len(first['events']),250);self.assertTrue(first['has_more'])
        self.assertEqual(len(second['events']),10);self.assertFalse(second['has_more'])
        self.assertTrue(set(r['id'] for r in first['events']).isdisjoint(r['id'] for r in second['events']))
