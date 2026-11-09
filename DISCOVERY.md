# Local discovery workspace

Run the WebUI on your Mac with Python 3.10 or newer:

```sh
python3 labmap.py
```

Open the printed `http://127.0.0.1:8765` URL. The server binds only to loopback.
No Python packages, Node packages, Docker containers, or external web services are
needed for this interface. Nmap must already be installed to run live discovery;
existing result files can be imported without it. Stop the app with Ctrl+C; its active Nmap child process is stopped as well.

## Workflow

1. Add a site and its explicit networks or individual addresses. Use as many sites
   as needed; the same IP in different sites remains a separate inventory record.
2. Select **Review scan**. Check the address count, targets, and exact commands in
   the modal. Nothing is probed until **Start discovery** is selected.
3. Inspect the discovered addresses on the canvas and in Devices. Set meaningful
   names, roles, hardware models, and notes using the device modal.
4. Import RouterOS neighbor reports or add connections you have verified. Reported
   neighbors appear separately from user-confirmed physical cables. Logical,
   hosting, power, storage, and VPN connections can also be recorded.
5. Export an SVG snapshot. Rescans update observations while preserving corrections
   and older devices. A missed response never deletes a device or marks it offline.

Site scopes are inputs, not facts inferred from the Mac's current interface. No
customer-specific addresses, hostnames, or credentials are built into the tool.
Targets must be explicit IPs/CIDRs, with at most 4,096 unique addresses per plan.
IPv4 and IPv6 are supported in separate Nmap invocations. IPv6 discovery needs
small prefixes or known addresses; sweeping an entire /64 is not supported.
Non-private targets require the explicit ownership/permission checkbox.

Nmap runs `-sn -n --unprivileged -T3 --max-rate 20 --max-retries 1
--host-timeout 10s -oX -`. There is no service scan, OS detection, NSE, traceroute,
sudo, or configuration write. Unprivileged host discovery uses TCP connection
probes to ports 80/443; filtering can hide devices. MAC/vendor fields are only
available when present in imported Nmap or neighbor results. DNS lookup is disabled
for live scans. Each Nmap invocation has a ten-minute timeout; unsuccessful or
partial results are not merged into inventory. Failed jobs can be retried through
a fresh review plan. Interrupted jobs are identified on app restart.

## Importing existing observations

Choose **Import results** and select a local file or paste its contents. Nmap imports require complete,
successful `-oX` XML output. RouterOS imports accept the JSON array returned by
`GET /rest/ip/neighbor`; enter the reporting router's IP as well. This optional import path accepts an existing response; use the direct
RouterOS collector for automatic collection.
Do not enable services or change neighbor settings just for an import.

Every imported IP, including the observer, must be in the saved site scope. The
import is atomic. Neighbor entries without usable IPs need a cleaned copy or a
later MAC-only asset collector. RouterOS may report a bridge, a physical interface,
or multiple interface names; the tool preserves the report and does not certify
it as a physical cable. Ports, link speed, and power feeds are never guessed from
IP addresses, vendor names, or proximity on the canvas.

Only selected inventory fields are saved. Nmap script output, service banners,
API secrets, and complete raw responses are not retained. Address observations remain scoped by site. The asset layer adds provider,
hardware and MAC identities; review conflicts and DHCP address reuse.
Connections remain as timestamped evidence when a later import omits them; their
continued presence is not proof that a connection still exists.

## Storage and privacy

SQLite defaults to `private/labmap.sqlite`; `--db /path/to/inventory.sqlite` selects
another database. New database files use mode 0600 and new containing directories
use mode 0700. The `private/` and `out/` directories are ignored by Git. Keep custom
database paths and exported diagrams out of public commits. Exported SVG is a
private snapshot and is **not redacted**. It contains observed IPs and names.

The app does not use localStorage. Browser requests that change data require a
per-launch token, and mismatched Host/Origin requests are refused. Direct collector credentials can be kept for the session or explicitly saved
in macOS Keychain; they are never stored in SQLite. The existing `inventory.yaml`, `build.py`,
and icon workflow remain unchanged; the original hand-placed renderer does not
consume the discovery database yet.

## Preview and checks

Use a separate empty database for simulated demo data:

```sh
python3 labmap.py --demo --db /tmp/labmap-demo.sqlite --port 8766
python3 -m unittest discover -s tests -v
```

Demo databases are clearly marked and cannot start live scans. To reopen an
existing demo database, omit `--demo`; its simulated marker remains in SQLite.
Tests use synthetic data, mocked Nmap execution, and temporary loopback servers.
They do not scan the lab.

A terminal-only plan is also available and does not create a database or send
network probes:

```sh
python3 labmap.py --plan --site example --target 10.20.0.0/24 --target 10.30.0.0/24
```

## Direct collectors

### Live output

Starting a scan opens the **Live output** tab below the canvas. It refreshes every
second and shows the collector, target, UTC time, requests, response status,
warnings, errors, and saved discovery counts. Expand **Response details** to
inspect a sanitized inventory preview. **Follow latest output** controls automatic
scrolling; turn it off to read an earlier entry while events continue arriving.
The **Scan** menu reopens recorded output for the site's recent jobs, including
failed or interrupted runs. In **History**, **View output** opens the matching run
directly. New failure summaries identify the collector and its first reported
problem, including the request path when available. Older jobs created before this feature have no
detailed output. Output continues refreshing while a device/collector modal is open.

HTTPS responses show status, size and timing. TrueNAS shows its WebSocket and
JSON-RPC reads; SNMP shows requested numeric OIDs, parsed values and command status.
Network discovery shows scan start and its parsed response when Nmap finishes;
Nmap XML is buffered until completion, so it is not a line-by-line terminal stream.

Events are stored locally in SQLite, rather than browser storage. Authorization
headers, query parameters, authentication request/response bodies, cookies,
command environments and stderr are excluded. Response previews use an inventory
field allowlist, hide sensitive fields and known credential values before saving,
and limit nesting, rows and string length. These are diagnostic previews, not
complete raw responses. Each preview is bounded to about 6 KiB and each job to
5,000 events plus its output-limit notice and final result. Reaching this limit
does not stop discovery or erase earlier events. The existing local-origin guards
also apply to output; its endpoint additionally requires the app's per-launch token.

### Configure and collect

Open **Collectors**, add a connection, then select **Collect inventory**. In the
review modal, **Collectors to scan** lets you choose **All enabled collectors**
for the current site or one named collector. Changing this choice prepares a new
review; check the listed collectors and targets before selecting **Start collection**.
Disabled collectors are excluded. A single-collector run only needs that
collector's credentials and leaves other collectors untouched.
One connection can discover many assets; guests, storage and hardware
parts do not need manually assigned roles. The optional importer is not part of
the normal direct-collection workflow.

| Collector | Read protocol | Automatically records |
| --- | --- | --- |
| RouterOS 7 REST | HTTPS GET | Identity, board, interfaces, addresses, neighbors, ARP/DHCP identities, bridge forwarding entries, VLANs, ports, routes |
| Proxmox VE | HTTPS API token | Cluster nodes, VMs, containers, CPU/memory information, network configuration, guest placement and storage dependencies |
| TrueNAS 25.04+ | WSS JSON-RPC | System hardware, interfaces, pools, disks, SMB/NFS shares and storage relationships |
| Dell iDRAC with Redfish | HTTPS GET | System model, serial, UUID, host NICs, processors, memory and storage inventory |
| APC / CyberPower | SNMP GET / GETBULK | Enterprise identity, UPS model/serial and supported battery/runtime/load values |
| SNMP discovery / auto-detect | SNMPv2c or SNMPv3 | Responding agents across the site scope, names, chassis identity, interface MACs/speeds, LLDP and forwarding-table observations |

For a shared SNMP profile, leave its management IP blank and select **SNMP
discovery / auto-detect**. The profile queries the explicit site scope directly;
it does not depend on a successful TCP/Nmap discovery first. This finds
SNMP-only agents and automatically classifies supported vendors. SNMP ports are
configurable (default UDP/161); IPv4 and IPv6 use their respective transports.
Four agent collections can run concurrently, with starts paced at four agents per
second. Each command has a timeout, and
per-source failures remain visible. Unavailable optional read endpoints produce a
partial result rather than erasing the facts that were successfully collected.

An API endpoint must resolve into the site's saved scope. Its resolved address is
pinned into the review plan. Collection does not automatically follow discovered
routes into new subnets. A saved site or connection change invalidates its old
plan. Newly reported out-of-scope addresses are not treated as authorized scan
targets. SNMP uses the saved networks directly and never issues SET requests.

### Accounts and credentials

Use existing accounts with inventory/read permissions. No collector creates an
account, enables a management service, changes router settings, controls a UPS,
or starts/stops guests. Proxmox expects `user@realm!tokenid` plus the token secret;
permissions depend on both user and token ACLs. TrueNAS expects the API-key user
and key (READONLY_ADMIN for the general hardware inventory, with optional methods
subject to their own roles). RouterOS/iDRAC use username and password. SNMPv3
supports noAuthNoPriv, authNoPriv, and authPriv with the SHA/MD5 and AES/DES
protocols supported by the installed Net-SNMP client; choose SHA/AES where the
agent supports it. SNMPv2c communities are not encrypted on the wire.

Credentials stay in memory for the app session unless **Save entered credentials
in macOS Keychain** is explicitly selected. Keychain storage uses native Security
framework calls; secrets are not passed to the `security` command. SQLite stores
connection settings and a Keychain/session reference, never the credentials.
Credentials are not returned in state/plan responses. Blank credential fields
retain the existing secret on edits; updating one SNMPv3 passphrase preserves the
other. Re-enter credentials if the account or collector type changes.

Net-SNMP reads credentials from a short-lived mode-0600 config inside a private
temporary directory. Its arguments contain no community or passphrases. The
config is cleaned up after each agent collection, and Net-SNMP diagnostics are
not copied into the inventory or job history. Password fields are cleared after
a successful save. Synthetic tests do not create real Keychain entries.

HTTPS/WSS uses normal certificate and hostname verification. For an existing
self-signed management certificate, an independently verified SHA-256 fingerprint
can be entered for that connection. The pin is checked before credentials are
sent; a mismatch aborts collection. There is no general insecure-TLS option.
HTTP redirects and cross-origin Redfish resource links are not followed.

### Asset matching and evidence

The asset layer supports records without IP addresses and correlates provider
IDs, hardware UUIDs, vendor serials, MACs and scoped IPs. It enriches the original
address observations rather than replacing them. Matching guest/physical hardware
conflicts are flagged for review, and hostname similarity alone never merges
assets. Manual overrides survive refreshes. Low-information placeholders can be
redirected to the enriched asset without deleting their underlying records.

Proxmox supplies host/guest placement and storage relationships directly. RouterOS
and SNMP supply reported neighbors and learned forwarding relationships. A learned
MAC or ARP entry is not certified as a direct physical cable. Serial/UUID/MAC/IP
matching depends on what the device actually exposes; conflicting or reused
identities need review. A VM's IP can be learned from container configuration or
correlated MAC/address evidence, but a VM with no reported address still appears
under its host. Missing optional methods or fields are shown in collector results.

Hardware parts can be shown with **Hardware parts** on the canvas. Select a device
and expand **Discovered hardware and source data** to see its attributes and review
notes. UPS battery values never imply which server is connected to which outlet.
Power feeds require independent evidence or user confirmation. USB-only UPS units
need an existing network/SNMP agent; this version does not install one. Older
TrueNAS REST-only systems and non-Redfish iDRAC generations are not supported by
those direct API adapters; generic SNMP can still collect fields they expose.

### Existing inventory and recovery

The first upgrade creates a mode-0600 SQLite backup in `private/backups/` before
adding asset tables. Existing sites, host observations, annotations, connections,
runs and jobs are preserved. The original host tables and YAML renderer remain
available. A code rollback to the previous commit can use the original tables;
the saved pre-upgrade database is also available for explicit restoration. Stop
the app before replacing a database, and do not overwrite a newer backup.

Local tests cover protocol fixtures, fifty-guest discovery, saved edits, partial
permissions, credential handling, TLS/redirect guards, matching conflicts,
legacy-data preservation, and the installed Net-SNMP command against a synthetic
loopback agent. Real management devices and credentials must be validated through
the configured WebUI connections; fixture tests do not establish live-provider
compatibility.

Protocol references: [RouterOS REST](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API),
[Proxmox API](https://pve.proxmox.com/wiki/Proxmox_VE_API),
[TrueNAS API](https://api.truenas.com/),
[Dell Redfish examples](https://github.com/dell/iDRAC-Redfish-Scripting),
[Net-SNMP config](https://www.net-snmp.org/docs/man/snmp.conf.html),
[standard UPS MIB](https://www.rfc-editor.org/rfc/rfc1628), and
[CyberPower/APC MIB support](https://github.com/networkupstools/nut/tree/master/drivers).
