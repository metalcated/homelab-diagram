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
`GET /rest/ip/neighbor`; enter the reporting router's IP as well. This first
version imports an existing response rather than connecting to RouterOS itself.
Do not enable services or change neighbor settings just for an import.

Every imported IP, including the observer, must be in the saved site scope. The
import is atomic. Neighbor entries without usable IPs need a cleaned copy or a
later MAC-only asset collector. RouterOS may report a bridge, a physical interface,
or multiple interface names; the tool preserves the report and does not certify
it as a physical cable. Ports, link speed, and power feeds are never guessed from
IP addresses, vendor names, or proximity on the canvas.

Only selected inventory fields are saved. Nmap script output, service banners,
API secrets, and complete raw responses are not retained. Device identity in this
first version is site + IP; review manual labels after DHCP address reuse.
Connections remain as timestamped evidence when a later import omits them; their
continued presence is not proof that a connection still exists.

## Storage and privacy

SQLite defaults to `private/labmap.sqlite`; `--db /path/to/inventory.sqlite` selects
another database. New database files use mode 0600 and new containing directories
use mode 0700. The `private/` and `out/` directories are ignored by Git. Keep custom
database paths and exported diagrams out of public commits. Exported SVG is a
private snapshot and is **not redacted**. It contains observed IPs and names.

The app does not use localStorage. Browser requests that change data require a
per-launch token, and mismatched Host/Origin requests are refused. No credentials
are needed or stored in this version. The existing `inventory.yaml`, `build.py`,
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

## Current boundary and next collectors

This is an initial discovery inventory and review workspace. It does not yet
authenticate to Proxmox, TrueNAS, iDRAC/Redfish, UPS SNMP/NUT, or RouterOS, and it
does not yet correlate multiple NICs/IPs into a physical asset, track MAC-only or
USB-only equipment, or connect devices across sites. Those need version-checked,
read-only collectors and evidence-based identity matching. A network sweep alone
cannot establish which VM runs on which Dell, which storage pool backs it, or
which UPS outlet powers it.

Protocol references: [Nmap host discovery](https://nmap.org/book/man-host-discovery.html),
[Nmap XML](https://nmap.org/book/output-formats-xml-output.html),
[RouterOS neighbor fields](https://manual.mikrotik.com/docs/cli-reference/ip/neighbor/),
and [RouterOS REST](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API).
