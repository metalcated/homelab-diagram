"""Additive asset identity and provenance; legacy inventory remains recoverable."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
 id TEXT PRIMARY KEY, site TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT '',
 model TEXT NOT NULL DEFAULT '', vendor TEXT NOT NULL DEFAULT '', serial TEXT NOT NULL DEFAULT '',
 details TEXT NOT NULL DEFAULT '{}', source TEXT NOT NULL, priority INTEGER NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, merged_into TEXT NOT NULL DEFAULT '', review TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS asset_keys (
 site TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, asset_id TEXT NOT NULL,
 PRIMARY KEY(site,kind,value));
CREATE TABLE IF NOT EXISTS asset_key_conflicts (site TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(site,kind,value));
CREATE TABLE IF NOT EXISTS asset_overrides (
 asset_id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT '',
 model TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS asset_relations (
 site TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, kind TEXT NOT NULL,
 src_port TEXT NOT NULL DEFAULT '', dst_port TEXT NOT NULL DEFAULT '', label TEXT NOT NULL DEFAULT '',
 source TEXT NOT NULL, observed TEXT NOT NULL,
 PRIMARY KEY(site,src,dst,kind,src_port,dst_port,source));
CREATE TABLE IF NOT EXISTS asset_observations (
 asset_id TEXT NOT NULL, source TEXT NOT NULL, identity TEXT NOT NULL, observed TEXT NOT NULL,
 attributes TEXT NOT NULL, PRIMARY KEY(asset_id,source,identity));
CREATE TABLE IF NOT EXISTS collector_connections (
 id TEXT PRIMARY KEY, site TEXT NOT NULL, label TEXT NOT NULL, kind TEXT NOT NULL,
 config TEXT NOT NULL, secret_mode TEXT NOT NULL, enabled INTEGER NOT NULL,
 revision TEXT NOT NULL, last_collected TEXT NOT NULL DEFAULT '', last_result TEXT NOT NULL DEFAULT '');
"""


def text(value, limit=300):
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def mac(value):
    raw = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    if len(raw) != 12 or raw in ("000000000000", "ffffffffffff"):
        return ""
    return ':'.join(raw[i:i+2] for i in range(0,12,2))


def keys_for(record):
    keys = [("provider", text(record["ref"], 500))]
    for kind in ("uuid", "serial"):
        value = text(record.get(kind)).lower()
        if kind=='uuid' and value:
            try:
                value=str(uuid.UUID(value))
                if uuid.UUID(value).int in (0,(1<<128)-1):continue
            except ValueError:continue
        if value and value not in ("unknown", "none", "n/a", "default string", "to be filled by o.e.m."):
            if kind == "serial":
                vendor=re.sub(r'[^a-z0-9]','',text(record.get('vendor')).lower())
                if vendor.startswith('dell'):vendor='dell'
                value = vendor + ':' + value
            keys.append((kind, value))
    keys.extend(("mac", value) for value in {mac(m) for m in record.get("macs", [])} if value)
    for address in record.get("addresses", []):
        try:
            keys.append(("ip", str(ipaddress.ip_address(address))))
        except ValueError:
            pass
    return list(dict.fromkeys(keys))


def resolve(db, asset_id):
    for _ in range(100):
        row = db.execute("SELECT merged_into FROM assets WHERE id=?", (asset_id,)).fetchone()
        if row is None or not row[0]:
            return asset_id
        asset_id = row[0]
    raise ValueError("Asset identity cycle needs repair from the saved backup.")


def strong_conflict(db, asset_id, keys):
    existing = {}
    for row in db.execute("SELECT kind,value FROM asset_keys WHERE asset_id=? AND kind IN ('uuid','serial')", (asset_id,)):
        existing.setdefault(row[0],set()).add(row[1])
    for kind in ("uuid", "serial"):
        incoming = {value for k,value in keys if k == kind}
        if incoming and existing.get(kind) and incoming.isdisjoint(existing[kind]):
            return True
    return False


def merge_placeholder(db, old, target):
    if old == target:
        return True
    row = db.execute("SELECT priority FROM assets WHERE id=?", (old,)).fetchone()
    manual = db.execute("SELECT * FROM asset_overrides WHERE asset_id=?", (old,)).fetchone()
    known=db.execute("SELECT role FROM assets WHERE id=?",(old,)).fetchone()
    strong=db.execute("SELECT 1 FROM asset_keys WHERE asset_id=? AND kind IN ('uuid','serial')",(old,)).fetchone()
    if row is None or (row[0]>2 and (strong or known[0] not in ('','Managed device'))) or (manual and any(manual[k] for k in ("name","role","model","notes"))):
        return False
    db.execute("UPDATE assets SET merged_into=? WHERE id=?", (target,old))
    db.execute("UPDATE asset_keys SET asset_id=? WHERE asset_id=?", (target,old))
    return True


def ingest(db, site, source, batch, observed):
    references = {}
    priority = {"nmap":1,"legacy":1,"routeros-arp":2,"snmp":5,"apc":5,"cyberpower":5,"routeros":6,
                "proxmox":8,"truenas":8,"idrac":9}.get(source,3)
    for record in batch.get("assets", []):
        keys = keys_for(record)
        matches = {}
        ambiguous=set()
        for kind,value in keys:
            if db.execute("SELECT 1 FROM asset_key_conflicts WHERE site=? AND kind=? AND value=?",(site,kind,value)).fetchone():
                ambiguous.add((kind,value))
                continue
            row = db.execute("SELECT asset_id FROM asset_keys WHERE site=? AND kind=? AND value=?", (site,kind,value)).fetchone()
            if row:
                matches.setdefault(kind,set()).add(resolve(db,row[0]))
        preferred = matches.get("uuid",set()) or matches.get("serial",set()) or matches.get("mac",set()) or matches.get("provider",set()) or matches.get("ip",set())
        candidate = next(iter(preferred)) if len(preferred) == 1 else None
        conflict=bool(candidate and strong_conflict(db,candidate,keys))
        if candidate:
            oldrole=db.execute("SELECT role FROM assets WHERE id=?",(candidate,)).fetchone()[0]
            incomingrole=record.get('role','')
            if (oldrole in ('Physical server','Proxmox host') and incomingrole in ('VM','Container')) or (incomingrole in ('Physical server','Proxmox host') and oldrole in ('VM','Container')):conflict=True
            oldmacs={r[0] for r in db.execute("SELECT value FROM asset_keys WHERE asset_id=? AND kind='mac'",(candidate,))}
            newmacs={v for k,v in keys if k=='mac'}
            if source=='nmap' and oldmacs and newmacs and oldmacs.isdisjoint(newmacs):conflict=True
        if conflict:candidate=None
        identity = next((f'{k}:{v}' for k,v in keys if k in ("uuid","serial")), record["ref"])
        if conflict or any(k in ('uuid','serial') for k,v in ambiguous):identity=record['ref']+':'+str([(k,v) for k,v in keys if k in ('uuid','serial','mac')])
        asset_id = candidate or hashlib.sha256(f'{site}:{identity}'.encode()).hexdigest()[:24]
        review = "Shared identity needs review; ambiguous keys were excluded from matching." if ambiguous else ""
        for other in set().union(*matches.values()) if matches else set():
            if other != asset_id and not merge_placeholder(db,other,asset_id):
                review = "Identity overlaps another asset. Verify MAC, serial, or address reuse; no manual correction was overwritten."
        current = db.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        values = {key:text(record.get(key)) for key in ("name","role","model","vendor","serial")}
        details = dict(json.loads(current["details"])) if current else {}
        # Collectors construct these attributes explicitly; raw credentials/config responses never enter here.
        details.update(record.get("details", {}))
        details["reported_roles"]=sorted(set(details.get("reported_roles",[]))|({values["role"]} if values["role"] else set()))
        if current:
            newer = observed >= current["last_seen"]
            for key in values:
                if not values[key] or (priority < current["priority"] and current[key]) or not newer:
                    values[key] = current[key]
            new_priority = max(priority,current["priority"])
            new_source = source if priority >= current["priority"] and newer else current["source"]
            db.execute("""UPDATE assets SET name=?,role=?,model=?,vendor=?,serial=?,details=?,source=?,priority=?,last_seen=?,review=? WHERE id=?""",
                       (*values.values(),json.dumps(details),new_source,new_priority,max(observed,current["last_seen"]),review or current["review"],asset_id))
        else:
            db.execute("INSERT INTO assets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (asset_id,site,*values.values(),json.dumps(details),source,priority,observed,observed,"",review))
        for kind,value in keys:
            old = db.execute("SELECT asset_id FROM asset_keys WHERE site=? AND kind=? AND value=?", (site,kind,value)).fetchone()
            if old is not None and resolve(db,old[0])!=asset_id:
                db.execute("INSERT OR IGNORE INTO asset_key_conflicts VALUES (?,?,?)",(site,kind,value))
                db.execute("UPDATE assets SET review=? WHERE id=?",("Shared identity needs review; it is excluded from future automatic matching.",resolve(db,old[0])))
            if old is None or resolve(db,old[0]) == asset_id:
                db.execute("INSERT INTO asset_keys VALUES (?,?,?,?) ON CONFLICT(site,kind,value) DO UPDATE SET asset_id=excluded.asset_id", (site,kind,value,asset_id))
        db.execute("""INSERT INTO asset_observations VALUES (?,?,?,?,?) ON CONFLICT(asset_id,source,identity)
          DO UPDATE SET observed=excluded.observed,attributes=excluded.attributes WHERE excluded.observed>=asset_observations.observed""",
                   (asset_id,source,record["ref"],observed,json.dumps({**values,"details":record.get("details",{})})))
        references[record["ref"]] = asset_id
    for link in batch.get("links", []):
        src,dst = references.get(link["src"]),references.get(link["dst"])
        if not src or not dst or src == dst:
            continue
        save_relation(db,site,src,dst,link,source,observed)
    return len(set(references.values()))


def save_relation(db, site, src, dst, link, source, observed):
    db.execute("""INSERT INTO asset_relations VALUES (?,?,?,?,?,?,?,?,?)
      ON CONFLICT(site,src,dst,kind,src_port,dst_port,source) DO UPDATE SET label=excluded.label,observed=excluded.observed
      WHERE excluded.observed>=asset_relations.observed""",
      (site,src,dst,text(link.get("kind") or "neighbor"),text(link.get("src_port")),text(link.get("dst_port")),text(link.get("label")),source,observed))


def legacy_batch(hosts, links=()):
    return {"assets":[{"ref":"ip:"+h["address"],"addresses":[h["address"]],"macs":[h.get("mac","")],
                       "name":h.get("hostname",""),"model":h.get("model",""),"vendor":h.get("vendor","")} for h in hosts],
            "links":[{**dict(l),"src":"ip:"+l["src"],"dst":"ip:"+l["dst"]} for l in links]}


def migrate_legacy(db):
    for host in db.execute("SELECT * FROM hosts").fetchall():
        ingest(db,host["site"],"legacy",legacy_batch([dict(host)]),host["last_seen"])
    for note in db.execute("SELECT * FROM annotations").fetchall():
        row=db.execute("SELECT asset_id FROM asset_keys WHERE site=? AND kind='ip' AND value=?",(note["site"],note["address"])).fetchone()
        if row:
            db.execute("INSERT OR IGNORE INTO asset_overrides VALUES (?,?,?,?,?)",(resolve(db,row[0]),note["name"],note["role"],note["model"],note["notes"]))


def annotate(db, payload):
    asset_id = resolve(db,text(payload.get("asset_id")))
    if not db.execute("SELECT 1 FROM assets WHERE id=?",(asset_id,)).fetchone():
        raise ValueError("Asset not found.")
    db.execute("""INSERT INTO asset_overrides VALUES (?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET
       name=excluded.name,role=excluded.role,model=excluded.model,notes=excluded.notes""",
       (asset_id,text(payload.get("name")),text(payload.get("role")),text(payload.get("model")),text(payload.get("notes"),1000)))


def state(db):
    assets = []
    for row in db.execute("SELECT a.*,o.name AS manual_name,o.role AS manual_role,o.model AS manual_model,o.notes FROM assets a LEFT JOIN asset_overrides o ON o.asset_id=a.id WHERE a.merged_into='' ORDER BY a.site,a.role,a.name"):
        item=dict(row)
        item["hostname"]=item["name"]
        item["name"]=item.pop("manual_name") or item["name"]
        item["auto_role"]=item["role"]
        item["role"]=item.pop("manual_role") or item["role"]
        item["details"]=json.loads(item["details"])
        keys=db.execute("SELECT kind,value FROM asset_keys WHERE asset_id=?",(item["id"],)).fetchall()
        item["addresses"]=sorted({r[1] for r in keys if r[0]=="ip"})
        item["macs"]=sorted({r[1] for r in keys if r[0]=="mac"})
        item["address"]=next(iter(item["addresses"]),"")
        item["mac"]=next(iter(item["macs"]),"")
        assets.append(item)
    relations={}
    for link in db.execute("SELECT * FROM asset_relations"):
        item=dict(link)
        item["src"],item["dst"]=resolve(db,item["src"]),resolve(db,item["dst"])
        if item["src"]!=item["dst"]:
            relations[tuple(item[k] for k in ("site","src","dst","kind","src_port","dst_port","source"))]=item
    for link in db.execute("SELECT * FROM links"):
        item=dict(link)
        for end in ("src","dst"):
            match=db.execute("SELECT asset_id FROM asset_keys WHERE site=? AND kind='ip' AND value=?",(item["site"],item[end])).fetchone()
            item[end]=resolve(db,match[0]) if match else item[end]
        relations[tuple(item[k] for k in ("site","src","dst","kind","src_port","dst_port","source"))]=item
    return {"assets":assets,"asset_links":list(relations.values())}
