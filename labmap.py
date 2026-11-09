#!/usr/bin/env python3
"""Local discovery workspace. Python standard library only; see DISCOVERY.md."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import hmac
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import sqlite3
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

import asset_inventory
from collector_workspace import CollectorManager
from direct_collectors import CATALOG
from scan_events import Events, quiet, read_events, SCHEMA as EVENT_SCHEMA
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
MAX_INPUT = 4 * 1024 * 1024
MAX_ADDRESSES = 4096
PRIVATE = tuple(ipaddress.ip_network(s) for s in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean(value, limit=200):
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def site_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}", value):
        raise ValueError("Site ID must be 1–40 letters, numbers, hyphens or underscores.")
    return value


def scopes(values, allow_public=False):
    if not isinstance(values, list) or not values or len(values) > 128:
        raise ValueError("Enter one or more explicit IP addresses or CIDR networks (up to 128 entries).")
    nets = []
    for value in values:
        try:
            net = ipaddress.ip_network(value, strict=True)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid network: {clean(value)}. Use a network address such as 10.20.0.0/24.") from None
        if net.is_multicast or net.is_loopback or net.is_link_local or net.is_unspecified:
            raise ValueError("Multicast, loopback, link-local and unspecified targets are not supported.")
        if not allow_public and not any(net.version == p.version and net.subnet_of(p) for p in PRIVATE):
            raise ValueError("Non-private targets require the explicit public-address option.")
        nets.append(net)
    nets = sorted(set(nets), key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    count = sum(n.num_addresses for version in (4, 6)
                for n in ipaddress.collapse_addresses(n for n in nets if n.version == version))
    if count > MAX_ADDRESSES:
        raise ValueError(f"This plan contains {count:,} addresses; split it into plans of at most {MAX_ADDRESSES:,}.")
    return nets


def scoped_address(value, nets):
    try:
        addr = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise ValueError("Invalid device IP address.") from None
    if not any(addr.version == n.version and addr in n for n in nets):
        raise ValueError(f"Address {addr} is outside the selected site's scope. Nothing was imported.")
    return str(addr)


def network_for(address, nets):
    addr = ipaddress.ip_address(address)
    return str(max((n for n in nets if n.version == addr.version and addr in n), key=lambda n: n.prefixlen))


def make_plan(site, targets, allow_public=False):
    site_id(site)
    if not isinstance(allow_public, bool):
        raise ValueError("Public-address option must be true or false.")
    nets = scopes(targets, allow_public)
    commands = []
    for version in (4, 6):
        family = [str(n) for n in nets if n.version == version]
        if family:
            commands.append(["nmap", "-sn", "-n", "--unprivileged", "-T3", "--max-rate", "20",
                             "--max-retries", "1", "--host-timeout", "10s", "-oX", "-"]
                            + (["-6"] if version == 6 else []) + family)
    return {"site": site, "targets": [str(n) for n in nets], "allow_public": allow_public,
            "commands": commands, "addresses": sum(n.num_addresses for version in (4, 6)
                for n in ipaddress.collapse_addresses(n for n in nets if n.version == version))}


def parse_nmap(text, nets):
    if len(text.encode()) > MAX_INPUT or "<!ENTITY" in text.upper():
        raise ValueError("XML is too large or contains an unsupported entity declaration.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise ValueError("Invalid or incomplete Nmap XML. Nothing was imported.") from None
    finished = root.find("runstats/finished")
    if root.tag != "nmaprun" or root.get("scanner") != "nmap" or finished is None or finished.get("exit") != "success":
        raise ValueError("Import requires a complete, successful Nmap XML result.")
    try:
        observed = datetime.fromtimestamp(int(finished.get("time", "")), timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OverflowError, OSError):
        raise ValueError("Nmap result has an invalid completion time.") from None
    if observed > now():
        raise ValueError("Nmap completion time is in the future. Check the scanner clock.")
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        mac = next((a for a in host.findall("address") if a.get("addrtype") == "mac"), None)
        hostname = host.find("hostnames/hostname")
        for address in host.findall("address"):
            if address.get("addrtype") not in ("ipv4", "ipv6"):
                continue
            ip = scoped_address(address.get("addr"), nets)
            hosts.append({"address": ip, "network": network_for(ip, nets),
                          "hostname": clean(hostname.get("name")) if hostname is not None else "",
                          "mac": clean(mac.get("addr"), 40) if mac is not None else "",
                          "vendor": clean(mac.get("vendor")) if mac is not None else "", "model": ""})
    return hosts, [], observed


def parse_routeros(text, nets, observer):
    observer = scoped_address(observer, nets)
    if len(text.encode()) > MAX_INPUT:
        raise ValueError("Neighbor JSON is too large.")
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        raise ValueError("Invalid RouterOS neighbor JSON.") from None
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("Expected the JSON array returned by GET /rest/ip/neighbor.")
    hosts = [{"address": observer, "network": network_for(observer, nets), "hostname": "",
              "mac": "", "vendor": "", "model": ""}]
    links, skipped = [], 0
    for row in rows:
        address = row.get("address4") or row.get("address") or row.get("address6")
        if not address:
            skipped += 1
            continue
        remote = scoped_address(address, nets)
        hosts.append({"address": remote, "network": network_for(remote, nets),
                      "hostname": clean(row.get("identity")), "mac": clean(row.get("mac-address"), 40),
                      "vendor": clean(row.get("platform")), "model": clean(row.get("board"))})
        if remote != observer:
            links.append({"src": observer, "dst": remote, "src_port": clean(row.get("interface"), 100),
                          "dst_port": clean(row.get("interface-name"), 100), "kind": "neighbor",
                          "label": clean(row.get("discovered-by") or "RouterOS neighbor"), "source": "routeros"})
    if skipped:
        raise ValueError(f"{skipped} neighbor entries have no usable IP address. Add an address or remove those entries from a copy before importing; no partial import was saved.")
    return hosts, links, now()


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sites (id TEXT PRIMARY KEY, label TEXT NOT NULL, targets TEXT NOT NULL, allow_public INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, site TEXT NOT NULL, source TEXT NOT NULL, observed TEXT NOT NULL, hosts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS hosts (
 site TEXT NOT NULL, address TEXT NOT NULL, network TEXT NOT NULL, hostname TEXT NOT NULL,
 mac TEXT NOT NULL, vendor TEXT NOT NULL, model TEXT NOT NULL, source TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(site,address));
CREATE TABLE IF NOT EXISTS annotations (
 site TEXT NOT NULL, address TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT '',
 model TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', PRIMARY KEY(site,address));
CREATE TABLE IF NOT EXISTS links (
 site TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, src_port TEXT NOT NULL, dst_port TEXT NOT NULL,
 kind TEXT NOT NULL, label TEXT NOT NULL, source TEXT NOT NULL, observed TEXT NOT NULL,
 PRIMARY KEY(site,src,dst,src_port,dst_port,kind,source));
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, site TEXT NOT NULL, status TEXT NOT NULL, started TEXT NOT NULL, finished TEXT,
 message TEXT NOT NULL, targets TEXT NOT NULL);
"""


class Store:
    def __init__(self, path):
        self.path = Path(path).expanduser().resolve()
        self._limited_output_jobs=set()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        with closing(self.connect()) as db:
            legacy = db.execute("SELECT 1 FROM sqlite_master WHERE name='hosts'").fetchone()
            upgraded = db.execute("SELECT 1 FROM sqlite_master WHERE name='assets'").fetchone()
            if legacy and not upgraded:
                folder=self.path.parent/'backups'
                folder.mkdir(exist_ok=True,mode=0o700)
                backup=folder/(self.path.stem+'-before-collectors-'+secrets.token_hex(6)+'.sqlite')
                handle=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600);os.close(handle)
                with closing(sqlite3.connect(backup)) as destination:
                    db.backup(destination)
            db.executescript(SCHEMA+asset_inventory.SCHEMA+EVENT_SCHEMA)
            migrated=db.execute("SELECT 1 FROM settings WHERE key='asset_migration_v1'").fetchone()
            if not migrated:
                with db:
                    asset_inventory.migrate_legacy(db)
                    db.execute("INSERT INTO settings VALUES ('asset_migration_v1','complete')")

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def save_site(self, payload):
        site = site_id(payload.get("id"))
        plan = make_plan(site, payload.get("targets"), payload.get("allow_public", False))
        label = clean(payload.get("label")) or site
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO sites VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET label=excluded.label, targets=excluded.targets, allow_public=excluded.allow_public",
                       (site, label, json.dumps(plan["targets"]), int(plan["allow_public"])))
        return plan

    def get_site(self, site):
        with closing(self.connect()) as db:
            row = db.execute("SELECT * FROM sites WHERE id=?", (site_id(site),)).fetchone()
        if row is None:
            raise ValueError("Save a site and its scope first.")
        return {**dict(row), "targets": json.loads(row["targets"]), "allow_public": bool(row["allow_public"])}

    def ingest(self, site, source, hosts, links, observed):
        with closing(self.connect()) as db, db:
            for host in hosts:
                db.execute("""INSERT INTO hosts VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(site,address) DO UPDATE SET
                  network=excluded.network, hostname=CASE WHEN excluded.hostname!='' THEN excluded.hostname ELSE hosts.hostname END,
                  mac=CASE WHEN excluded.mac!='' THEN excluded.mac ELSE hosts.mac END,
                  vendor=CASE WHEN excluded.vendor!='' THEN excluded.vendor ELSE hosts.vendor END,
                  model=CASE WHEN excluded.model!='' THEN excluded.model ELSE hosts.model END,
                  source=excluded.source, last_seen=excluded.last_seen
                  WHERE excluded.last_seen >= hosts.last_seen""",
                  (site, host["address"], host["network"], host["hostname"], host["mac"], host["vendor"], host["model"], source, observed, observed))
            for link in links:
                db.execute("""INSERT INTO links VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(site,src,dst,src_port,dst_port,kind,source)
                  DO UPDATE SET label=excluded.label, observed=excluded.observed WHERE excluded.observed>=links.observed""",
                  (site, link["src"], link["dst"], link["src_port"], link["dst_port"], link["kind"], link["label"], link["source"], observed))
            asset_inventory.ingest(db,site,source,asset_inventory.legacy_batch(hosts,links),observed)
            db.execute("INSERT INTO runs(site,source,observed,hosts) VALUES (?,?,?,?)", (site, source, observed, len({h["address"] for h in hosts})))

    def import_data(self, site, format_, text, observer=""):
        saved = self.get_site(site)
        nets = scopes(saved["targets"], saved["allow_public"])
        if format_ == "nmap":
            data = parse_nmap(text, nets)
        elif format_ == "routeros":
            data = parse_routeros(text, nets, observer)
        else:
            raise ValueError("Choose Nmap XML or RouterOS neighbor JSON.")
        self.ingest(site, format_, *data)
        return len({h["address"] for h in data[0]})

    def annotate(self, p):
        with closing(self.connect()) as db, db:
            if p.get('asset_id'):
                asset_inventory.annotate(db,p)
                return
            if not db.execute("SELECT 1 FROM hosts WHERE site=? AND address=?", (p.get("site"), p.get("address"))).fetchone():
                raise ValueError("Device not found in this site.")
            db.execute("""INSERT INTO annotations VALUES (?,?,?,?,?,?) ON CONFLICT(site,address) DO UPDATE SET
              name=excluded.name, role=excluded.role, model=excluded.model, notes=excluded.notes""",
              (p["site"], p["address"], clean(p.get("name")), clean(p.get("role")), clean(p.get("model")), clean(p.get("notes"), 1000)))
            match=db.execute("SELECT asset_id FROM asset_keys WHERE site=? AND kind='ip' AND value=?",(p['site'],p['address'])).fetchone()
            if match:asset_inventory.annotate(db,{**p,'asset_id':match[0]})

    def link(self, p):
        site = site_id(p.get("site"))
        kind = p.get("kind")
        if kind not in ("physical", "power", "hosts", "storage", "vpn", "contains"):
            raise ValueError("Choose a valid connection type.")
        if p.get("src") == p.get("dst"):
            raise ValueError("A connection must join two different devices.")
        with closing(self.connect()) as db, db:
            identities=[db.execute("SELECT id FROM assets WHERE site=? AND id=?",(site,p.get(end))).fetchone() for end in ('src','dst')]
            if all(identities):
                asset_inventory.save_relation(db,site,p['src'],p['dst'],p,'manual',now())
                return
            for addr in (p.get("src"), p.get("dst")):
                if not db.execute("SELECT 1 FROM hosts WHERE site=? AND address=?", (site, addr)).fetchone():
                    raise ValueError("Both devices must exist in the selected site.")
            db.execute("""INSERT INTO links VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(site,src,dst,src_port,dst_port,kind,source)
              DO UPDATE SET label=excluded.label, observed=excluded.observed""",
              (site, p["src"], p["dst"], clean(p.get("src_port"), 100), clean(p.get("dst_port"), 100), kind, clean(p.get("label")), "manual", now()))

    def state(self):
        with closing(self.connect()) as db:
            sites = [dict(r) for r in db.execute("SELECT * FROM sites ORDER BY label")]
            hosts = [dict(r) for r in db.execute("""SELECT h.*,a.name,a.role,a.model AS manual_model,a.notes
              FROM hosts h LEFT JOIN annotations a ON a.site=h.site AND a.address=h.address ORDER BY h.site,h.address""")]
            links = [dict(r) for r in db.execute("SELECT * FROM links ORDER BY site,src,dst")]
            jobs = [dict(r) for r in db.execute("SELECT * FROM jobs ORDER BY started DESC, rowid DESC LIMIT 20")]
            runs = [dict(r) for r in db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 20")]
            demo = db.execute("SELECT value FROM settings WHERE key='demo'").fetchone()
            inventory=asset_inventory.state(db)
        for site in sites:
            site["targets"] = json.loads(site["targets"])
            site["allow_public"] = bool(site["allow_public"])
        return {**inventory,"sites": sites, "hosts": hosts, "links": links, "jobs": jobs, "runs": runs,
                "demo": bool(demo), "nmap_available": shutil.which("nmap") is not None}


def run_scan(plan, store, runner=subprocess.run,emit=quiet):
    nets = scopes(plan["targets"], plan["allow_public"])
    if not shutil.which("nmap"):
        emit('error','Nmap is not installed. Install it separately or import an existing result.')
        raise ValueError("Nmap is not installed. Install it separately, or import existing XML.")
    results = []
    for command in plan["commands"]:
        emit('request','Nmap host discovery started. Waiting for the scan response.',{'targets':plan['targets']})
        try:result = runner(command, capture_output=True, text=True, timeout=600, check=False)
        except (OSError,ValueError,subprocess.SubprocessError):
            emit('error','Nmap could not run, timed out, or was stopped. No partial inventory was saved.')
            raise
        if result.returncode:
            emit('error',f'Nmap exited with status {result.returncode}. Command diagnostics are hidden.')
            raise ValueError("Nmap could not complete the scan. Check target reachability and local network permissions; no partial inventory was saved.")
        try:results.append(parse_nmap(result.stdout, nets))
        except ValueError:
            emit('error','Nmap response was invalid, incomplete or outside the saved scope. No partial inventory was saved.')
            raise
        emit('response',f'Nmap returned {len(results[-1][0])} responding addresses.',{'hosts':results[-1][0]})
    # All address families must succeed before the single database transaction.
    hosts = [h for result in results for h in result[0]]
    observed = max(result[2] for result in results)
    store.ingest(plan["site"], "nmap", hosts, [], observed)
    return len({h["address"] for h in hosts})


def esc(value):
    return html.escape(str(value or ""), quote=True)


def diagram(state, selected=None):
    sites = [s for s in state["sites"] if selected is None or s["id"] == selected]
    blocks, y = [], 135
    for site in sites:
        devices = sorted((h for h in state.get("assets",state["hosts"]) if h["site"] == site["id"]), key=lambda h: h.get("name") or h.get("hostname") or h.get("address",""))
        rows = max(1, (len(devices) + 2) // 3)
        height = 85 + rows * 150
        blocks.append(f'<rect x="24" y="{y}" width="1152" height="{height}" rx="14" fill="#111f2d" stroke="#354859"/>')
        blocks.append(f'<text x="48" y="{y+34}" class="site">{esc(site["label"])}</text>')
        blocks.append(f'<text x="48" y="{y+58}" class="muted">{esc(" / ".join(site["targets"]))}</text>')
        if not devices:
            blocks.append(f'<text x="48" y="{y+112}" class="muted">No observations yet. Review a scan plan or import a result.</text>')
        for i, host in enumerate(devices):
            x, top = 48 + (i % 3) * 376, y + 82 + (i // 3) * 150
            lines = [host.get("name") or host["hostname"] or host["address"] or host.get("mac") or "Unidentified asset", host["address"] or "No IP reported",
                     host.get("role") or "Device type unverified", host.get("manual_model") or host["model"] or host["vendor"] or "Model unknown",
                     f'{host["source"]} / {host["last_seen"][:16]} UTC']
            blocks.append(f'<rect x="{x}" y="{top}" width="352" height="132" rx="8" fill="#192c3c" stroke="#486276"/>')
            for j, line in enumerate(lines):
                blocks.append(f'<text x="{x+16}" y="{top+25+j*22}" class="{"name" if j==0 else "muted"}" ><title>{esc(line)}</title>{esc(line[:43] + ("…" if len(line)>43 else ""))}</text>')
        y += height + 24
    links = [l for l in state.get("asset_links",state["links"]) if selected is None or l["site"] == selected]
    labels={h["id"]:h.get("name") or h["address"] for h in state.get("assets",[])}
    blocks.append(f'<text x="32" y="{y+22}" class="site">Reported and confirmed connections</text>')
    y += 50
    if not links:
        blocks.append(f'<text x="32" y="{y}" class="muted">No connection evidence yet. Import neighbors or add a confirmed connection.</text>')
        y += 34
    for link in links:
        label = f'{link["site"]}: {labels.get(link["src"],link["src"])} {link["src_port"]} → {labels.get(link["dst"],link["dst"])} {link["dst_port"]}'
        detail = f'{link["kind"]} / {link["source"]} / {link["label"]} / observed {link["observed"][:16]} UTC'
        blocks.append(f'<rect x="24" y="{y}" width="1152" height="64" rx="8" fill="#192c3c"/><text x="40" y="{y+25}" class="name">{esc(label)}</text><text x="40" y="{y+47}" class="muted">{esc(detail[:155])}</text>')
        y += 76
    title = "Lab map — simulated preview" if state["demo"] else "Lab map — discovery inventory"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="{y+30}" viewBox="0 0 1200 {y+30}">'
            '<style>text{font-family:Helvetica,Arial,sans-serif;fill:#e7edf4}.site{font-size:20px;font-weight:600}.name{font-size:15px;font-weight:600}.muted{font-size:12px;fill:#a6bacb}</style>'
            f'<rect width="1200" height="{y+30}" fill="#0c1722"/><text x="32" y="44" font-size="28" font-weight="700">{esc(title)}</text>'
            '<text x="32" y="73" class="muted">Cards group devices by site; position does not imply physical cabling. Neighbor reports require review.</text>'
            '<text x="32" y="96" class="muted">Observations are snapshots. Missing responses do not prove a device is offline.</text>' + ''.join(blocks) + '</svg>')


class Workspace:
    def __init__(self, store):
        self.store = store
        self.token = secrets.token_urlsafe(32)
        self.plans = {}
        self.lock = threading.Lock()
        self.running = False
        self.process_lock = threading.Lock()
        self.process = None
        self.processes = set()
        self.stopping = False
        self.thread = None
        self.collectors=CollectorManager(self,scopes)
        with closing(store.connect()) as db, db:
            db.execute("UPDATE jobs SET status='interrupted',finished=?,message='App stopped before completion. Review and retry the scan.' WHERE status='running'", (now(),))

    def plan(self, site):
        saved = self.store.get_site(site)
        plan = make_plan(site, saved["targets"], saved["allow_public"])
        self.register_plan(plan)
        return plan

    def register_plan(self,plan):
        nonce = secrets.token_urlsafe(24)
        plan["id"] = hmac.new(self.token.encode(), nonce.encode(), hashlib.sha256).hexdigest()
        with self.lock:
            self.plans = {k: v for k, v in self.plans.items() if v[0] > time.monotonic()}
            self.plans[plan["id"]] = (time.monotonic() + 600, plan)
        return plan

    def start(self, payload):
        if self.store.state()["demo"]:
            raise ValueError("Live scans are disabled in the simulated preview.")
        with self.lock:
            item = self.plans.get(payload.get("plan_id"))
            if payload.get("confirmed") is not True or item is None or item[0] < time.monotonic():
                raise ValueError("Review a fresh scan plan and confirm it before scanning.")
            if self.running:
                raise ValueError("A scan is already running. Wait for it to finish.")
            plan = item[1]
            saved = self.store.get_site(plan["site"])
            if plan.get("kind")=="collectors":
                self.collectors.validate_plan(plan)
            elif make_plan(saved["id"], saved["targets"], saved["allow_public"])["commands"] != plan["commands"]:
                raise ValueError("Site scope changed. Review a fresh plan.")
            job = secrets.token_hex(8)
            with closing(self.store.connect()) as db, db:
                db.execute("INSERT INTO jobs VALUES (?,?, 'running',?,NULL,?,?)", (job, plan["site"], now(), "Collecting direct inventory" if plan.get("kind")=="collectors" else "Discovering responding hosts", json.dumps(plan["targets"])))
            self.running = True
            self.plans.pop(plan["id"])
        self.thread = threading.Thread(target=self.worker, args=(job, plan), daemon=True)
        self.thread.start()
        return {"job": job}

    def execute_command(self, command, **options):
        with self.process_lock:
            if self.stopping:
                raise ValueError("Discovery stopped with the app.")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,env=options.get("env"))
            self.process = process
            self.processes.add(process)
        try:
            try:
                stdout, stderr = process.communicate(timeout=options["timeout"])
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise ValueError("Discovery timed out. Split the scope into smaller plans and retry.") from None
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        finally:
            with self.process_lock:
                self.processes.discard(process)
                self.process = next(iter(self.processes),None)

    def stop(self):
        with self.process_lock:
            self.stopping = True
            processes=self.processes|({self.process} if self.process is not None else set())
            for process in processes:
                if process.poll() is None:process.terminate()
        if self.thread is not None:
            self.thread.join(timeout=3)
            if self.thread.is_alive():
                for process in processes:
                    if process.poll() is None:process.kill()
                self.thread.join(timeout=10)

    def worker(self, job, plan):
        try:
            emit=Events(self.store,job)
            try:
                emit('info','Scan started. Credentials and authentication payloads are hidden.',{'kind':plan.get('kind','nmap'),'targets':plan['targets']})
                if plan.get("kind")=="collectors":
                    status,message=self.collectors.collect(plan,job)
                else:
                    count = run_scan(plan, self.store, self.execute_command,emit=Events(self.store,job,'Network discovery'))
                    status, message = "complete", f"Observed {count} addresses. Existing labels and earlier observations were preserved."
            except Exception:
                status, message = "failed", "Scan could not complete. Review Live output, connectivity and read permissions before retrying."
                emit('error','Scan failed. Unexpected exception text and command diagnostics are hidden.')
            emit('complete',status.capitalize()+': '+message)
            with closing(self.store.connect()) as db, db:
                db.execute("UPDATE jobs SET status=?,finished=?,message=? WHERE id=?", (status, now(), message, job))
        finally:
            with self.lock:
                self.running = False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Request bodies and private inventory never go to access logs.

    def allowed(self, write=False):
        expected = f"127.0.0.1:{self.server.server_port}"
        if self.headers.get("Host") != expected:
            return False
        if self.headers.get("Origin") not in (None, f"http://{expected}"):
            return False
        return not write or (self.headers.get("X-Labmap-Token") == self.server.workspace.token
                             and self.headers.get("Content-Type", "").split(";")[0] == "application/json")

    def send(self, code, data, content_type="application/json"):
        body = (json.dumps(data) if content_type == "application/json" else data).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.allowed():
            return self.send(403, {"error": "Use the local URL printed by the app."})
        if self.path == "/api/state":
            app=self.server.workspace
            return self.send(200,{**app.store.state(),"collectors":app.collectors.connections(),"collector_catalog":CATALOG,"keychain_available":app.collectors.vault.keychain is not None})
        if urlsplit(self.path).path == '/api/events':
            if self.headers.get('X-Labmap-Token')!=self.server.workspace.token:
                return self.send(403,{'error':'Refresh the local app to view scan output.'})
            try:
                params=parse_qs(urlsplit(self.path).query,keep_blank_values=True)
                if set(params)-{'site','job','after'} or any(len(v)!=1 for v in params.values()):raise ValueError('Invalid output request.')
                return self.send(200,read_events(self.server.workspace.store,params.get('site',[''])[0],params.get('job',[''])[0],params.get('after',['0'])[0]))
            except ValueError as error:return self.send(400,{'error':clean(error,200)})
        if self.path == "/api/diagram.svg":
            return self.send(200, diagram(self.server.workspace.store.state()), "image/svg+xml")
        assets = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
        if self.path not in assets:
            return self.send(404, {"error": "Not found"})
        name, mime = assets[self.path]
        data = (ROOT / "web" / name).read_text()
        if name == "index.html":
            data = data.replace("__LABMAP_TOKEN__", self.server.workspace.token)
        self.send(200, data, mime)

    def do_POST(self):
        if not self.allowed(write=True):
            return self.send(403, {"error": "Refresh the local app before making changes."})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_INPUT:
                raise ValueError("Request is empty or too large (4 MiB maximum).")
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ValueError("Expected a JSON object.")
            app = self.server.workspace
            if self.path == "/api/sites":
                result = app.store.save_site(payload)
            elif self.path == "/api/collectors/save":
                result=app.collectors.save(payload)
            elif self.path == "/api/collectors/plan":
                result=app.collectors.plan(payload.get("site"),payload.get("connections"))
            elif self.path == "/api/plan":
                result = app.plan(payload.get("site"))
            elif self.path == "/api/scan":
                result = app.start(payload)
            elif self.path == "/api/import":
                if not isinstance(payload.get("contents"), str):
                    raise ValueError("Choose a result file first.")
                result = {"hosts": app.store.import_data(payload.get("site"), payload.get("format"), payload["contents"], payload.get("observer", ""))}
            elif self.path == "/api/annotate":
                app.store.annotate(payload)
                result = {"saved": True}
            elif self.path == "/api/link":
                app.store.link(payload)
                result = {"saved": True}
            else:
                return self.send(404, {"error": "Not found"})
            self.send(200, result)
        except (ValueError, TypeError, KeyError) as exc:
            self.send(400, {"error": clean(str(exc), 500)})
        except (sqlite3.Error, OSError):
            self.send(500, {"error": "Could not save the change. Check database permissions and free disk space, then retry."})


def seed_demo(store):
    if store.state()["sites"]:
        raise ValueError("Demo mode requires an empty, separate database.")
    with closing(store.connect()) as db, db:
        db.execute("INSERT INTO settings VALUES ('demo','true')")
    store.save_site({"id": "example-home", "label": "Example home lab", "targets": ["10.20.0.0/24"]})
    devices = [("10.20.0.1", "example-router", "MikroTik", "RouterOS router"),
               ("10.20.0.2", "example-switch", "MikroTik", "Core switch"),
               ("10.20.0.10", "example-pve", "Dell", "Proxmox host"),
               ("10.20.0.20", "example-storage", "", "TrueNAS"),
               ("10.20.0.30", "example-ups", "APC", "UPS")]
    hosts = [{"address": ip, "network": "10.20.0.0/24", "hostname": name, "mac": "", "vendor": vendor, "model": model} for ip, name, vendor, model in devices]
    store.ingest("example-home", "simulated", hosts, [], now())
    store.link({"site": "example-home", "src": "10.20.0.2", "dst": "10.20.0.10", "src_port": "ether3", "dst_port": "eno1", "kind": "physical", "label": "Simulated cable"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=ROOT / "private" / "labmap.sqlite")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--demo", action="store_true", help="Seed simulated data into a separate, empty database; disables live scans")
    parser.add_argument("--plan", action="store_true", help="Print a discovery plan and exit without probing or creating a database")
    parser.add_argument("--site", default="lab")
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--allow-public", action="store_true")
    args = parser.parse_args()
    try:
        if args.plan:
            plan = make_plan(args.site, args.target, args.allow_public)
            print(json.dumps({**plan, "commands": [shlex.join(c) for c in plan["commands"]]}, indent=2))
            return
        if not 0 <= args.port <= 65535:
            raise ValueError("Port must be between 0 and 65535.")
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
        store = Store(args.db)
        if args.demo:
            seed_demo(store)
        app = Workspace(store)
        server.workspace = app
        print(f"Lab map: http://127.0.0.1:{server.server_port}", flush=True)
        print(f"Database: {store.path}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            app.stop()
            server.server_close()
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
