import http.client
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("labmap", Path(__file__).resolve().parents[1] / "labmap.py")
labmap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(labmap)


def xml(address="10.20.0.10", hostname="example-host", timestamp="1700000000", exit_="success"):
    return f'''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap">
    <host><status state="up"/><address addr="{address}" addrtype="{'ipv6' if ':' in address else 'ipv4'}"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example vendor"/>
    <hostnames><hostname name="{hostname}"/></hostnames></host>
    <runstats><finished time="{timestamp}" exit="{exit_}"/></runstats></nmaprun>'''


class DataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = labmap.Store(Path(self.temp.name) / "private" / "map.sqlite")
        self.store.save_site({"id":"home", "label":"Example home", "targets":["10.20.0.0/24"]})

    def import_host(self, **kwargs):
        return self.store.import_data("home", "nmap", xml(**kwargs))

    def test_scope_validation_and_no_implicit_expansion(self):
        for targets in (["10.20.0.7/24"], ["--script=all"], ["example.org"], ["10.0.0.0/8"], ["127.0.0.1"], ["224.0.0.1"], []):
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                labmap.make_plan("home", targets)
        with self.assertRaises(ValueError):
            labmap.make_plan("home", ["8.8.8.8"])
        self.assertEqual(labmap.make_plan("home", ["8.8.8.8"], True)["addresses"], 1)

    def test_multiple_scopes_families_and_duplicate_count(self):
        plan = labmap.make_plan("home", ["10.20.0.0/24", "10.20.0.10", "fd00::10"])
        self.assertEqual(plan["addresses"], 257)
        self.assertEqual(len(plan["commands"]), 2)
        self.assertIn("-6", plan["commands"][1])
        for command in plan["commands"]:
            self.assertIn("-sn", command)
            self.assertIn("-n", command)
            self.assertIn("--unprivileged", command)
            self.assertNotIn("-sV", command)
            self.assertNotIn("-A", command)
            self.assertNotIn("--script", command)

    def test_scans_preserve_annotations_and_previous_devices(self):
        self.import_host()
        self.store.annotate({"site":"home","address":"10.20.0.10","name":"My Dell","role":"Proxmox host","model":"PowerEdge","notes":"Confirmed"})
        self.import_host(hostname="changed-dns", timestamp="1700001000")
        self.import_host(address="10.20.0.20", timestamp="1700002000")
        state = self.store.state()
        self.assertEqual(len(state["hosts"]), 2)
        host = next(h for h in state["hosts"] if h["address"]=="10.20.0.10")
        self.assertEqual(host["name"], "My Dell")
        self.assertEqual(host["role"], "Proxmox host")
        self.assertEqual(host["hostname"], "changed-dns")
        self.assertEqual(state["links"], [])  # Neither IP proximity nor traceroute invents a cable.

    def test_older_import_cannot_replace_newer_observation(self):
        self.import_host(hostname="new", timestamp="1700001000")
        self.import_host(hostname="old", timestamp="1700000000")
        self.assertEqual(self.store.state()["hosts"][0]["hostname"], "new")

    def test_same_address_in_different_sites_is_separate(self):
        self.store.save_site({"id":"dc", "targets":["10.20.0.0/24"]})
        self.import_host()
        self.store.import_data("dc", "nmap", xml(hostname="different-host"))
        self.assertEqual(len(self.store.state()["hosts"]), 2)

    def test_bad_or_out_of_scope_imports_are_atomic(self):
        for contents in ("<broken", xml(exit_="error"), xml(address="10.21.0.1"),
                         xml(timestamp="99999999999999999999999"), xml(timestamp="9999999999"),
                         '<!DOCTYPE x [<!ENTITY a "x">]>'+xml()):
            with self.subTest(contents=contents[:60]), self.assertRaises(ValueError):
                self.store.import_data("home", "nmap", contents)
        self.assertEqual(self.store.state()["hosts"], [])
        self.assertEqual(self.store.state()["runs"], [])

    def test_down_host_is_not_imported_as_observed(self):
        self.store.import_data("home", "nmap", xml().replace('state="up"', 'state="down"'))
        self.assertEqual(self.store.state()["hosts"], [])

    def test_routeros_neighbor_is_reported_not_confirmed_physical(self):
        data = json.dumps([{"address":"10.20.0.10", "identity":"example-pve", "interface":"ether3,bridge", "discovered-by":"lldp", "platform":"Dell"}])
        self.store.import_data("home", "routeros", data, "10.20.0.1")
        self.assertEqual(len(self.store.state()["hosts"]), 2)
        link = self.store.state()["links"][0]
        self.assertEqual(link["kind"], "neighbor")
        self.assertEqual(link["source"], "routeros")
        self.assertEqual(link["src_port"], "ether3,bridge")
        with self.assertRaises(ValueError):
            self.store.import_data("home", "routeros", '[{"identity":"no-address"}]', "10.20.0.1")

    def test_confirmed_connections_require_known_devices_and_can_be_updated(self):
        self.import_host()
        p={"site":"home","src":"10.20.0.1","dst":"10.20.0.10","kind":"physical","label":"1G"}
        with self.assertRaises(ValueError): self.store.link(p)
        self.import_host(address="10.20.0.1")
        self.store.link(p)
        self.store.link({**p,"label":"10G"})
        self.assertEqual(len(self.store.state()["links"]),1)
        self.assertEqual(self.store.state()["links"][0]["label"],"10G")
        self.assertEqual(self.store.state()["links"][0]["source"],"manual")

    def test_failed_or_partial_scans_do_not_save_inventory(self):
        plan=labmap.make_plan("home",["10.20.0.0/24", "fd00::10"])
        runner=Mock(side_effect=[Mock(returncode=0,stdout=xml()),Mock(returncode=1,stdout="")])
        with patch.object(labmap.shutil,"which",return_value="/usr/bin/nmap"),self.assertRaises(ValueError):
            labmap.run_scan(plan,self.store,runner)
        self.assertEqual(self.store.state()["hosts"],[])

    def test_scanner_runs_fixed_arguments_without_shell(self):
        runner=Mock(return_value=Mock(returncode=0,stdout=xml()))
        with patch.object(labmap.shutil,"which",return_value="/usr/bin/nmap"):
            count=labmap.run_scan(labmap.make_plan("home",["10.20.0.0/24"]),self.store,runner)
        self.assertEqual(count,1)
        self.assertNotIn("shell",runner.call_args.kwargs)
        self.assertEqual(runner.call_args.kwargs["timeout"],600)

    def test_diagram_is_valid_xml_and_escapes_device_labels(self):
        self.import_host()
        self.store.annotate({"site":"home","address":"10.20.0.10","name":'<script>alert("x")</script>'})
        svg=labmap.diagram(self.store.state())
        labmap.ET.fromstring(svg)
        self.assertNotIn("<script>",svg)
        self.assertIn("&lt;script&gt;",svg)
        self.assertIn("No connection evidence yet",svg)

    def test_new_database_is_private(self):
        self.assertEqual(self.store.path.stat().st_mode & 0o777,0o600)

    def test_restarting_marks_unfinished_jobs_interrupted(self):
        with closing(self.store.connect()) as db, db:
            db.execute("INSERT INTO jobs VALUES ('x','home','running','old',NULL,'working','[]')")
        app=labmap.Workspace(self.store)
        self.assertFalse(app.running)
        self.assertEqual(self.store.state()["jobs"][0]["status"],"interrupted")

    def test_plan_requires_confirmation_and_rejects_changed_scope(self):
        app=labmap.Workspace(self.store)
        plan=app.plan("home")
        with self.assertRaises(ValueError):app.start({"plan_id":plan["id"]})
        self.store.save_site({"id":"home","targets":["10.21.0.0/24"]})
        with self.assertRaises(ValueError):app.start({"plan_id":plan["id"],"confirmed":True})
        self.assertEqual(self.store.state()["jobs"],[])


    def test_worker_completion_failure_and_retry_are_durable(self):
        app=labmap.Workspace(self.store)
        with patch.object(labmap,"run_scan",return_value=2):
            plan=app.plan("home")
            app.start({"plan_id":plan["id"],"confirmed":True})
            app.thread.join(timeout=3)
        self.assertEqual(self.store.state()["jobs"][0]["status"],"complete")
        with patch.object(labmap,"run_scan",side_effect=ValueError("simulated failure")):
            plan=app.plan("home")
            app.start({"plan_id":plan["id"],"confirmed":True})
            app.thread.join(timeout=3)
        self.assertEqual(self.store.state()["jobs"][0]["status"],"failed")
        with patch.object(labmap,"run_scan",return_value=1):
            plan=app.plan("home")
            app.start({"plan_id":plan["id"],"confirmed":True})
            app.thread.join(timeout=3)
        self.assertEqual(self.store.state()["jobs"][0]["status"],"complete")
        self.assertFalse(app.running)

    def test_shutdown_terminates_its_active_child(self):
        app=labmap.Workspace(self.store)
        process=Mock()
        process.poll.return_value=None
        app.process=process
        app.stop()
        process.terminate.assert_called_once_with()
        self.assertTrue(app.stopping)

    def test_stopped_app_cannot_spawn_another_scan(self):
        app=labmap.Workspace(self.store)
        app.stop()
        with patch.object(labmap.subprocess,"Popen") as popen,self.assertRaises(ValueError):
            app.execute_command(["nmap"],timeout=600)
        popen.assert_not_called()


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        store=labmap.Store(Path(self.temp.name)/"map.sqlite")
        self.app=labmap.Workspace(store)
        self.server=labmap.ThreadingHTTPServer(("127.0.0.1",0),labmap.Handler)
        self.server.workspace=self.app
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self,path,body=None,headers=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=3)
        self.addCleanup(conn.close)
        conn.request("POST" if body is not None else "GET",path,json.dumps(body) if body is not None else None,headers or {})
        r=conn.getresponse()
        return r.status,r.read(),dict(r.headers)

    def auth(self):
        return {"Content-Type":"application/json","X-Labmap-Token":self.app.token}

    def test_ui_bootstrap_and_api_are_served(self):
        code,body,headers=self.request("/")
        self.assertEqual(code,200)
        self.assertIn(self.app.token.encode(),body)
        self.assertIn("frame-ancestors 'none'",headers["Content-Security-Policy"])
        for path in ("/app.js","/style.css","/api/state","/api/diagram.svg"):
            self.assertEqual(self.request(path)[0],200)

    def test_cross_origin_missing_token_and_rebinding_host_are_rejected(self):
        p={"id":"home","targets":["10.20.0.0/24"]}
        self.assertEqual(self.request("/api/sites",p)[0],403)
        self.assertEqual(self.request("/api/sites",p,{**self.auth(),"Origin":"https://example.com"})[0],403)
        self.assertEqual(self.request("/api/state",headers={"Host":"evil.example"})[0],403)
        self.assertEqual(self.app.store.state()["sites"],[])

    def test_edit_reopen_import_plan_cancel_and_retry_paths(self):
        auth=self.auth()
        p={"id":"home","label":"Home","targets":["10.20.0.0/24"]}
        self.assertEqual(self.request("/api/sites",p,auth)[0],200)
        self.assertEqual(self.request("/api/import",{"site":"home","format":"nmap","contents":xml()},auth)[0],200)
        edit={"site":"home","address":"10.20.0.10","name":"Dell host","role":"Proxmox"}
        self.assertEqual(self.request("/api/annotate",edit,auth)[0],200)
        self.assertEqual(json.loads(self.request("/api/state")[1])["hosts"][0]["name"],"Dell host")
        self.assertEqual(self.request("/api/plan",{"site":"home"},auth)[0],200)
        # Closing a plan is a client action; creating it never starts a subprocess or job.
        self.assertEqual(self.app.store.state()["jobs"],[])
        self.assertEqual(self.request("/api/import",{"site":"home","format":"nmap","contents":"bad"},auth)[0],400)
        self.assertEqual(self.request("/api/import",{"site":"home","format":"nmap","contents":xml()},auth)[0],200)
        self.assertEqual(self.app.store.state()["hosts"][0]["name"],"Dell host")

    def test_demo_cannot_start_live_scan(self):
        labmap.seed_demo(self.app.store)
        plan=self.app.plan("example-home")
        code,body,_=self.request("/api/scan",{"plan_id":plan["id"],"confirmed":True},self.auth())
        self.assertEqual(code,400)
        self.assertIn(b"disabled",body)
        self.assertEqual(self.app.store.state()["jobs"],[])

    def test_unknown_paths_and_file_traversal_are_rejected(self):
        for path in ("/private/map.sqlite","/../labmap.py","/api/nope"):
            self.assertEqual(self.request(path)[0],404)


if __name__ == "__main__":
    unittest.main()
