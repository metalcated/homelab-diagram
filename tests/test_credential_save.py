from contextlib import closing
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from collector_secrets import Vault
import labmap
import test_labmap as base_tests

FIRST='12345678-1234-1234-1234-123456789abc'
SECOND='87654321-4321-4321-4321-cba987654321'
CONFIG={'endpoint':'https://10.20.0.1:8006','username':'inventory@pve!labmap'}


class MemoryKeychain:
    def __init__(self):self.values={};self.calls=[]
    def operation(self,key,values=None):
        self.calls.append((key,values is not None))
        if values is not None:self.values[key]=dict(values)
        return dict(self.values[key]) if key in self.values else None


class CredentialSaveTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.store=labmap.Store(Path(temp.name)/'test.sqlite')
        self.store.save_site({'id':'home','targets':['10.20.0.0/24']})

    def test_keychain_write_is_checked_before_session_cache_is_updated(self):
        vault=Vault();vault.keychain=MemoryKeychain()
        values={'password':FIRST}
        self.assertEqual(vault.put('source',values,True),'keychain')
        self.assertEqual(vault.keychain.calls,[('source',True),('source',False)])
        values['password']='caller changed its own object'
        self.assertEqual(vault.get('source','keychain'),{'password':FIRST})

    def test_keychain_mismatch_never_reports_success_or_populates_new_cache(self):
        vault=Vault();vault.keychain=Mock()
        vault.keychain.operation.return_value={'password':'unexpected-value'}
        with self.assertRaisesRegex(ValueError,'read-back did not match') as error:vault.put('source',{'password':FIRST},True)
        self.assertNotIn(FIRST,str(error.exception));self.assertNotIn('source',vault.memory)

    def test_proxmox_uuid_edit_survives_a_fresh_vault_and_metadata_edits_retain_it(self):
        app=labmap.Workspace(self.store);keychain=MemoryKeychain();app.collectors.vault.keychain=keychain
        payload={'site':'home','kind':'proxmox','config':CONFIG,'credentials':{'password':FIRST},'save_keychain':True}
        saved=app.collectors.save(payload);self.assertTrue(saved['credential_storage_checked'])
        app.collectors.save({**payload,'id':saved['id'],'credentials':{'password':SECOND}})
        fresh=Vault();fresh.keychain=keychain
        self.assertEqual(fresh.get(saved['id'],'keychain'),{'password':SECOND})
        retained=app.collectors.save({**payload,'id':saved['id'],'label':'Renamed','credentials':{'password':''}})
        self.assertFalse(retained['credential_updated'])
        self.assertEqual(fresh.get(saved['id'],'keychain'),{'password':SECOND})

    def test_non_uuid_proxmox_entry_is_rejected_before_storage(self):
        app=labmap.Workspace(self.store);app.collectors.vault.keychain=MemoryKeychain()
        for value in ('ordinary-credential','[hidden]','PVEAPIToken=inventory@pve!labmap='+FIRST):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'UUID value'):
                app.collectors.save({'site':'home','kind':'proxmox','config':CONFIG,'credentials':{'password':value},'save_keychain':True})
        self.assertEqual(app.collectors.vault.keychain.calls,[])
        self.assertEqual(app.collectors.connections(),[])

    def test_hidden_snmp_fields_cannot_satisfy_api_credential_change_requirement(self):
        app=labmap.Workspace(self.store)
        saved=app.collectors.save({'site':'home','kind':'proxmox','config':CONFIG,'credentials':{'password':FIRST}})
        with self.assertRaisesRegex(ValueError,'Re-enter credentials'):
            app.collectors.save({'id':saved['id'],'site':'home','kind':'proxmox','config':{**CONFIG,'username':'another@pve!labmap'},'credentials':{'password':'','community':'unrelated-autofill'}})


class CredentialHTTPTests(unittest.TestCase):
    setUp=base_tests.HTTPTests.setUp
    request=base_tests.HTTPTests.request
    auth=base_tests.HTTPTests.auth

    def test_save_response_reports_storage_comparison_without_reflecting_secret(self):
        self.app.store.save_site({'id':'home','targets':['10.20.0.0/24']})
        self.app.collectors.vault.keychain=MemoryKeychain()
        payload={'site':'home','kind':'proxmox','config':CONFIG,'credentials':{'password':FIRST},'save_keychain':True}
        code,body,_=self.request('/api/collectors/save',payload,self.auth())
        self.assertEqual(code,200);result=json.loads(body)
        self.assertTrue(result['credential_storage_checked']);self.assertNotIn(FIRST,body.decode())
        self.assertNotIn(FIRST,self.request('/api/state')[1].decode())
        self.assertEqual(self.app.collectors.vault.keychain.values[result['id']],{'password':FIRST})

    def test_invalid_token_value_returns_inline_error_and_preserves_existing_configuration(self):
        self.app.store.save_site({'id':'home','targets':['10.20.0.0/24']})
        payload={'site':'home','kind':'proxmox','label':'Keep','config':CONFIG,'credentials':{'password':FIRST}}
        saved=json.loads(self.request('/api/collectors/save',payload,self.auth())[1])
        code,body,_=self.request('/api/collectors/save',{**payload,'id':saved['id'],'label':'Should not change','credentials':{'password':'autofill-value'}},self.auth())
        self.assertEqual(code,400);self.assertIn('UUID value',body.decode());self.assertNotIn('autofill-value',body.decode())
        self.assertEqual(self.app.collectors.connections()[0]['label'],'Keep')
        self.assertEqual(self.app.collectors.vault.get(saved['id'],'session'),{'password':FIRST})
