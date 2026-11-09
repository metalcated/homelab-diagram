#!/usr/bin/env python3
"""Render the homelab diagram (r/homelab style) from inventory.yaml.

Usage: python3 build.py [--unredacted]   → out/homelab.svg + out/homelab.png
                                            (--unredacted → out/homelab-unredacted.*)
Content comes from inventory.yaml; the layout (positions of every box and line) is
hand-placed in this file for one specific network, so expect to move things around.
Line width encodes link speed (SPEED_W); trunks are drawn as a light cable with a dark core.
Written with Claude (Anthropic) in Claude Code, see README.md.
"""
import argparse
import base64
import html
import pathlib
import subprocess
import sys

if '--discovered-db' in sys.argv:
    from diagram_yaml_cli import main as yaml_main
    raise SystemExit(yaml_main(sys.argv[1:]))

import yaml

ROOT = pathlib.Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--inventory', type=pathlib.Path, default=ROOT / 'inventory.yaml')
parser.add_argument('--out', type=pathlib.Path, default=ROOT / 'out')
parser.add_argument('--unredacted', action='store_true')
parser.add_argument('--svg-only', action='store_true')
args = parser.parse_args()
INV = yaml.safe_load(args.inventory.read_text())
ICONS = ROOT / "icons"
OUT = args.out
COLLECTED = INV.get('layout') == 'collected'

UNREDACTED = "--unredacted" in sys.argv
RED = INV["redact"]
DOMAIN = INV["meta"]["domain"]
SHOWN_DOMAIN = DOMAIN if (UNREDACTED or not RED["domain"]) else RED["domain_placeholder"]

W, H = 2400, 2326

# ---------------------------------------------------------------- palette
BG = "#0b0f15"
GRID = "#151c26"
PANEL = "#111821"
PANEL2 = "#161f2b"
CHIP = "#19222e"
BORDER = "#253042"
TEXT = "#e6edf3"
MUTED = "#8d9aab"
FAINT = "#5d6a7c"
TRUNK = "#d5dde6"
TRUNK_BORDER = "#3a475a"   # border for devices on a tagged trunk (not in a single VLAN)
LINK = "#79c0ff"
REDDIT = "#ff5722"
DISK = "#1d2734"
DISK_EDGE = "#5a6b82"
PROTO = {"TCP": "#79c0ff", "UDP": "#39c5cf"}
SPEED_W = {"10G": 9.5, "2.5G": 3.8, "1G": 2.4, "100M": 1.4}   # access-line widths
VLAN = {v["key"]: v for v in INV["vlans"]}
C = {k: v["color"] for k, v in VLAN.items()}
SANS = "Fira Sans"
MONO = "Fira Code"


def trunk_w(speed):
    return SPEED_W[speed] + 3.4


def sub(s):
    """Fill {domain} placeholders and apply redaction."""
    s = str(s).replace("{domain}", SHOWN_DOMAIN)
    if not UNREDACTED and RED["domain"] and DOMAIN:
        s = s.replace(DOMAIN, SHOWN_DOMAIN)
    return s


def esc(s):
    return html.escape(sub(s), quote=True)


def tw(s, size, mono=False):
    """Rough text width for layout decisions."""
    return len(sub(s)) * size * (0.6 if mono else 0.53)


def _font_file(pattern):
    """Path of an installed font via fontconfig (fc-match), or None."""
    try:
        out = subprocess.run(["fc-match", "-f", "%{file}", pattern], capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None
    except Exception:
        return None


try:
    from PIL import ImageFont
    _FONTS = {700: _font_file("Fira Sans:bold"), 600: _font_file("Fira Sans:semibold")}
    if not all(_FONTS.values()):
        raise RuntimeError("Fira Sans not found")
    _FCACHE = {}

    def measure(s, size, weight=700):
        key = (weight, size)
        if key not in _FCACHE:
            _FCACHE[key] = ImageFont.truetype(_FONTS[weight], size=size * 8)
        return _FCACHE[key].getlength(s) / 8
except Exception:          # no Pillow / font file: rough estimate
    def measure(s, size, weight=700):
        return tw_title(s, size)


def tw_title(s, size):
    """Width estimate for bold title text (capitals are wider than lowercase)."""
    return sum(0.68 if c.isupper() else 0.58 if c.isdigit() else 0.5 for c in s) * size


def fqdn(h):
    return f"{h}.{SHOWN_DOMAIN}"


class SVG:
    def __init__(self):
        self.p = []
        self._icon_cache = {}

    def add(self, s):
        self.p.append(s)

    def rect(self, x, y, w, h, rx=10, fill=PANEL, stroke=BORDER, sw=1.2, op=1, dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}" opacity="{op}"{d}/>')

    def text(self, x, y, s, size=14, fill=TEXT, weight=400, anchor="start", mono=False, ls=0, op=1):
        fam = MONO if mono else SANS
        lsa = f' letter-spacing="{ls}"' if ls else ""
        self.add(f'<text x="{x:.1f}" y="{y:.1f}" font-family="{fam}" font-size="{size}" fill="{fill}" '
                 f'font-weight="{weight}" text-anchor="{anchor}" opacity="{op}"{lsa}>{esc(s)}</text>')

    def icon(self, name, x, y, size):
        if name not in self._icon_cache:
            f = ICONS / f"{name}.svg"
            if not f.exists():
                raise SystemExit(f"missing icon '{name}' – run: python3 fetch_icons.py")
            self._icon_cache[name] = base64.b64encode(f.read_bytes()).decode()
        self.add(f'<image x="{x:.1f}" y="{y:.1f}" width="{size}" height="{size}" '
                 f'href="data:image/svg+xml;base64,{self._icon_cache[name]}"/>')

    def line(self, pts, color, sw=3, dash=None, r=10, op=1, cap="round"):
        self.add(f'<path d="{rounded(pts, r)}" fill="none" stroke="{color}" stroke-width="{sw}" '
                 f'stroke-linecap="{cap}" stroke-linejoin="round" opacity="{op}"'
                 + (f' stroke-dasharray="{dash}"' if dash else "") + "/>")

    def trunk(self, pts, r=12, sw=7):
        """Tagged trunk: light cable with a dark core."""
        self.line(pts, TRUNK, sw=sw, r=r)
        self.line(pts, BG, sw=sw - 4.4, r=r)

    def arrow(self, pts, color=MUTED, sw=1.8, dash=None, r=8):
        """Line with an arrowhead at the last point."""
        self.line(pts, color, sw, dash=dash, r=r)
        (x0, y0), (x1, y1) = pts[-2], pts[-1]
        dx, dy = x1 - x0, y1 - y0
        ln = max(abs(dx), abs(dy)) or 1
        ux, uy = dx / ln, dy / ln
        a, b = 8, 4.5
        p1 = (x1 - ux * a - uy * b, y1 - uy * a + ux * b)
        p2 = (x1 - ux * a + uy * b, y1 - uy * a - ux * b)
        self.add(f'<path d="M{x1},{y1} L{p1[0]:.1f},{p1[1]:.1f} L{p2[0]:.1f},{p2[1]:.1f} Z" fill="{color}"/>')

    def pill(self, x, y, s, color, size=12, fill=None, mono=False, anchor="start", h=None, pad=8, tcolor=None, weight=600):
        w = tw(s, size, mono) + pad * 2
        h = h or size + 10
        if anchor == "middle":
            x -= w / 2
        elif anchor == "end":
            x -= w
        self.rect(x, y, w, h, rx=h / 2, fill=fill or color + "22", stroke=color + "88", sw=1)
        self.text(x + w / 2, y + h / 2 + size * 0.36, s, size, tcolor or color, weight, "middle", mono)
        return w

    def label(self, x, y, s, color=MUTED, size=12, anchor="middle", mono=False, bg=BG):
        """Text on a line, with a background knock-out."""
        w = tw(s, size, mono) + 12
        bx = x - w / 2 if anchor == "middle" else (x if anchor == "start" else x - w)
        self.rect(bx, y - size - 2, w, size + 9, rx=5, fill=bg, stroke=bg, sw=0)
        self.text(bx + w / 2, y + 1, s, size, color, 500, "middle", mono)

    def render(self):
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">'
                + "".join(self.p) + "</svg>")


def rounded(pts, r):
    """Orthogonal polyline with rounded corners."""
    if len(pts) == 2:
        return f"M{pts[0][0]},{pts[0][1]} L{pts[1][0]},{pts[1][1]}"
    d = f"M{pts[0][0]},{pts[0][1]}"
    for i in range(1, len(pts) - 1):
        (x0, y0), (x1, y1), (x2, y2) = pts[i - 1], pts[i], pts[i + 1]
        l1 = max(abs(x1 - x0), abs(y1 - y0))
        l2 = max(abs(x2 - x1), abs(y2 - y1))
        rr = min(r, l1 / 2, l2 / 2)
        ax = x1 - (x1 - x0) / l1 * rr if l1 else x1
        ay = y1 - (y1 - y0) / l1 * rr if l1 else y1
        bx = x1 + (x2 - x1) / l2 * rr if l2 else x1
        by = y1 + (y2 - y1) / l2 * rr if l2 else y1
        d += f" L{ax:.1f},{ay:.1f} Q{x1},{y1} {bx:.1f},{by:.1f}"
    d += f" L{pts[-1][0]},{pts[-1][1]}"
    return d


S = SVG()


# ---------------------------------------------------------------- shared pieces
def hostname(g):
    """(text, color) for the second address line: public host, or <name>.internal."""
    if g.get("hostname"):
        return g["hostname"], None
    if g.get("host"):
        return fqdn(g["host"]), LINK
    if g.get("internal"):
        return f"{g['internal']}.internal", None
    return None, None


def addr(x, y, ip, g, color, size=12):
    """Address line under a card's name (like the switch): IP · hostname, in the VLAN color
    (a public Traefik hostname is blue)."""
    S.text(x, y, ip, size, color, 500, mono=True)
    name, ncol = hostname(g)
    if name:
        cw_ = size * 0.6                      # Fira Code advance width
        dx = x + len(ip) * cw_ + cw_ * 0.6
        S.text(dx, y, "·", size, MUTED, 400, mono=True)
        S.text(dx + cw_ * 1.6, y, name, size, ncol or color, 400, mono=True, op=1 if ncol else 0.85)


def card(x, y, w, h, color=None, title=None, icons=None, sub_=None, isz=34, tsize=19):
    """Panel with a colored left accent, icons, title and subtitle."""
    S.rect(x, y, w, h, rx=14, fill=PANEL, stroke=(color + "aa") if color else BORDER, sw=1.6)
    if color:
        S.add(f'<rect x="{x+1}" y="{y+14}" width="4" height="{h-28}" rx="2" fill="{color}"/>')
    ix = x + 18
    for ic in icons or []:
        S.icon(ic, ix, y + 16, isz)
        ix += isz + 6
    tx_ = ix + 4 if icons else x + 18
    if title:
        S.text(tx_, y + 16 + isz * 0.5 - (2 if sub_ else -6), title, tsize, TEXT, 600)
    if sub_:
        S.text(tx_, y + 16 + isz * 0.5 + 17, sub_, 13, MUTED, 400)
    return tx_


HWC = "#c08a5c"   # "physical hardware" accent (same tan as the HARDWARE labels)


def hw_bar(x, y, h):
    """Left accent bar = this card is a physical box / hardware part."""
    S.add(f'<rect x="{x+1}" y="{y+12}" width="4" height="{h-24}" rx="2" fill="{HWC}"/>')


TAB = 34   # height of the folder tab on physical-device cards


def tab_width(g):
    """Tab fits 'name · type' (name 20px bold, type 14px semibold), measured from the font."""
    return 16 + measure(g["name"], 20, 700) + 7 + measure("·", 20, 700) + 7 + measure(g["type"], 14, 600) + 18


def folder(x, y, w, h, tab_w, fill, stroke, sw):
    """Card body at (x, y, w, h) with a folder tab on its top-left edge, tab_w wide and TAB high."""
    t = y - TAB
    r, rt, sl = 12, 9, 16
    d = (f"M{x},{y+h-r} L{x},{t+rt} Q{x},{t} {x+rt},{t} L{x+tab_w-sl:.1f},{t} "
         f"C{x+tab_w-sl/3:.1f},{t} {x+tab_w-sl/3:.1f},{y} {x+tab_w+sl/2:.1f},{y} "
         f"L{x+w-r},{y} Q{x+w},{y} {x+w},{y+r} L{x+w},{y+h-r} Q{x+w},{y+h} {x+w-r},{y+h} "
         f"L{x+r},{y+h} Q{x},{y+h} {x},{y+h-r} Z")
    S.add(f'<path d="{d}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')


def device_card(x, y, w, h, icons, g, color, fill=PANEL, stroke=None, sw=1.6):
    """Physical device: folder tab 'name · type'; body = icon, full device name, IP · hostname, OS."""
    folder(x, y, w, h, tab_width(g), fill, stroke or color + "aa", sw)
    S.add(f'<text x="{x+16}" y="{y-10}" font-family="{SANS}" fill="{TEXT}">'
          f'<tspan font-size="20" font-weight="700">{esc(g["name"])}</tspan>'
          f'<tspan dx="7" font-size="20" font-weight="700" fill-opacity="0.6">·</tspan>'
          f'<tspan dx="7" font-size="14" font-weight="600">{esc(g["type"])}</tspan></text>')
    ix = x + 14
    for ic in icons:                      # icon spans the three body lines (full name … OS)
        S.icon(ic, ix, y + 15, 54)
        ix += 58
    tx_ = ix + 8
    dy = 0 if g.get("os") else 8          # no OS line → center the two lines on the icon
    S.text(tx_, y + 28 + dy, g.get("model") or "custom build", 14, TEXT if g.get("model") else MUTED, 500)
    addr(tx_, y + 48 + dy, g["ip"], g, color)
    if g.get("os"):
        S.text(tx_, y + 66, g["os"], 12, MUTED, 400)
    if g.get("config"):                   # optional 4th line: how the device is set up
        S.text(tx_, y + 84, g["config"], 12, FAINT, 400)


def jack(x, y, w, h, fill, stroke, sfp=False):
    S.rect(x, y, w, h, rx=5, fill=fill, stroke=stroke, sw=1.4)
    if sfp:
        S.rect(x + 8, y + 9, w - 16, h - 18, rx=2, fill="#0b0f15", stroke="none", sw=0)
    else:
        S.add(f'<path d="M{x+10},{y+h-8} v-14 h6 v-5 h{w-32} v5 h6 v14 z" fill="#0b0f15"/>')


def ticks(cx, y, untagged=None, tagged=(), up=False):
    """VLAN indicator bars for a port: tall = untagged, short = tagged. up=True grows upwards."""
    vk = ([untagged] if untagged else []) + list(tagged)
    x0 = cx - (len(vk) * 7) / 2
    for j, k in enumerate(vk):
        hh = 8 if k == untagged else 5
        yy = y - hh if up else y
        S.add(f'<rect x="{x0 + j*7:.1f}" y="{yy}" width="5" height="{hh}" rx="1" fill="{C[k]}"/>')


def vlan_tag(vkey):
    v = VLAN[vkey]
    return f"{v['tag']} · {v['name']}" if v["tag"].startswith("VLAN") else v["name"]


if not COLLECTED:
    # ---------------------------------------------------------------- background + header
    S.add(f'<defs><pattern id="dots" width="24" height="24" patternUnits="userSpaceOnUse">'
          f'<circle cx="1.5" cy="1.5" r="1.3" fill="{GRID}"/></pattern></defs>')
    S.rect(0, 0, W, H, rx=0, fill=BG, stroke=BG, sw=0)
    S.rect(0, 0, W, H, rx=0, fill="url(#dots)", stroke="none", sw=0)

    meta = INV["meta"]
    title = meta["title"] if (UNREDACTED or not RED["domain"]) else meta["title_redacted"]
    S.text(40, 86, title, 46, TEXT, 700, ls=-0.5)
    S.text(W - 40, 74, meta["watermark"], 21, REDDIT, 700, "end")
    S.text(W - 40, 100, meta["date"], 16, MUTED, 400, "end")

    # ================================================================ TOP: edge chain
    CX = 1200
    cy0 = 172
    fy, fh = 324, 104                          # Fritzbox (body; tab above)
    ox, oy, ow, oh = 670, 468, 850, 430         # OPNsense (hardware list left, services right)
    bx, by, bw, bh = 620, 990, 1000, 112       # switch
    SB = by + bh
    PX0, PITCH = bx + 320, 58
    ALL_VLANS = ["10", "20", "30", "40", "99"]



def port_x(i):
    """Center x of switch port i (0-7 RJ45, 8-9 SFP+)."""
    return PX0 + i * PITCH + 24 if i < 8 else PX0 + 8 * PITCH + 22 + (i - 8) * 70 + 30

if not COLLECTED:


    # Remote access: reaches home over the internet (dotted = logical, not a cable).
    rw = INV["remote"]
    rx_, ry_ = 700, 150
    S.line([(rx_ + 300, ry_ + 42), (CX - 100, ry_ + 42)], C["vpn"], 1.8, dash="2 5", r=0)

    # Internet cloud (circles: outline trick)
    blobs = [(-95, 18, 42), (-45, -8, 56), (25, -18, 62), (90, 6, 48), (130, 26, 30), (-130, 30, 28)]
    for dx, dy, r in blobs:
        S.add(f'<circle cx="{CX+dx}" cy="{cy0+dy}" r="{r+2.5}" fill="#3a4a60"/>')
    S.add(f'<rect x="{CX-150}" y="{cy0+12}" width="300" height="46" rx="23" fill="#3a4a60"/>')
    for dx, dy, r in blobs:
        S.add(f'<circle cx="{CX+dx}" cy="{cy0+dy}" r="{r}" fill="#1a2433"/>')
    S.add(f'<rect x="{CX-147.5}" y="{cy0+14.5}" width="295" height="41" rx="20.5" fill="#1a2433"/>')
    S.text(CX, cy0 + 14, "Internet", 26, TEXT, 600, "middle")
    S.text(CX, cy0 + 40, "semi-static public IPv4", 13, MUTED, 400, "middle")

    S.rect(rx_, ry_, 300, 84, rx=12, fill=PANEL, stroke=C["vpn"] + "aa", sw=1.6)
    S.icon("wireguard", rx_ + 16, ry_ + 22, 38)
    S.text(rx_ + 66, ry_ + 38, rw["name"], 18, TEXT, 600)
    S.text(rx_ + 66, ry_ + 60, rw["note"], 13, MUTED, 400)

    csx, csy = 1790, 146
    for i, cs in enumerate(INV["internet"]["cloud_services"]):
        y = csy + i * 54
        S.rect(csx, y, 570, 44, rx=10, fill=PANEL2, stroke=BORDER)
        S.icon(cs["icon"], csx + 10, y + 9, 26)
        S.text(csx + 46, y + 20, cs["name"], 14, TEXT, 600)
        S.text(csx + 46, y + 36, cs["note"], 12, MUTED, 400)
    S.line([(CX + 130, 168), (csx, 168)], FAINT, 1.6, dash="2 5", r=0)
    S.line([(CX + 150, 222), (csx, 222)], FAINT, 1.6, dash="2 5", r=0)

    # Fritzbox: owns the internet uplink, NATs as usual, OPNsense is its exposed host
    fb = INV["fritzbox"]
    ISPD = INV["internet"]["speed"]
    S.label(CX - 10, (cy0 + 58 + fy - TAB) / 2 + 5, "↓ " + ISPD["down"], "#c3cdd9", 12, anchor="end", mono=True)
    S.label(CX + 10, (cy0 + 58 + fy - TAB) / 2 + 5, "↑ " + ISPD["up"], "#c3cdd9", 12, anchor="start", mono=True)
    FBX, FBW = CX - 302, 620                   # coax port sits right under the internet line (x = CX)
    device_card(FBX, fy, FBW, fh, ["fritzbox"], fb, C["wan"])
    COAX_X = FBX + 302
    S.line([(CX, cy0 + 58), (CX, fy + 28)], "#6b7a90", 3)
    FB_PORTS = [("Cable", None)] + [(sp, None) for sp in fb["lan_ports"]]
    for i, (lbl, _) in enumerate(FB_PORTS):
        if i == 0:
            cx_ = COAX_X
            S.rect(cx_ - 22, fy + 28, 44, 36, rx=5, fill="#2a3443", stroke=TRUNK, sw=1.4)
            S.add(f'<circle cx="{cx_}" cy="{fy+46}" r="11" fill="#0b0f15" stroke="#5a6b82" stroke-width="2"/>'
                  f'<circle cx="{cx_}" cy="{fy+46}" r="2.5" fill="{TRUNK}"/>')
            S.label(cx_, fy + 20, "Cable", MUTED, 11, mono=True, bg=PANEL)   # the internet line passes behind it
            S.text(cx_, fy + fh - 9, "internet", 10.5, MUTED, 500, "middle")
            continue
        cx_ = FBX + 366 + (i - 1) * 52
        used = (i - 1) == fb["opnsense_port"]
        jack(cx_ - 22, fy + 28, 44, 36, (C["wan"] + "55") if used else "#1b222c", C["wan"] if used else "#3a475a")
        S.text(cx_, fy + 21, lbl, 11, MUTED, 500, "middle", mono=True)
        if used:
            WANX = cx_
            ticks(cx_, fy + 69, untagged="wan")
            S.text(cx_, fy + fh - 9, "exposed host", 10.5, C["wan"], 600, "middle")

    # OPNsense card (jacks: em0 on top where the WAN comes in, the dual NIC at the bottom above switch ports 1+2)
    opn = INV["opnsense"]
    device_card(ox, oy, ow, oh, ["opnsense"], opn, C["99"], stroke=TRUNK_BORDER)
    S.text(ox + 20, oy + 96, "HARDWARE", 11.5, HWC, 700, ls=1.4)
    S.text(916, oy + 96, "SERVICES", 11.5, HWC, 700, ls=1.4)
    for i, hwi in enumerate(opn["hw"]):
        x, y = ox + 16, oy + 106 + i * 64
        S.rect(x, y, 200, 58, rx=11, fill="#151d29", stroke="#2e3a4c", sw=1.2)
        hw_bar(x, y, 58)
        S.icon(hwi["icon"], x + 12, y + 15, 28)
        S.text(x + 50, y + 17, hwi["label"], 10, "#c08a5c", 700, ls=1.3)
        S.text(x + 50, y + 35, hwi["value"], 15.5, TEXT, 700)
        S.text(x + 50, y + 50, hwi["sub"], 10.5, MUTED, 400)
    sw_, sh_ = 190, 50
    for i, sv in enumerate(opn["services"]):
        col, row = i % 3, i // 3
        x = 914 + col * (sw_ + 9)
        y = oy + 106 + row * (sh_ + 8)
        S.rect(x, y, sw_, sh_, rx=9, fill=CHIP, stroke=BORDER, sw=1)
        S.icon(sv["icon"], x + 9, y + 12, 26)
        S.text(x + 44, y + 22, sv["name"], 14, TEXT, 600)
        S.text(x + 44, y + 39, sv["note"], 11.5, MUTED, 400)

    # WAN cable into the onboard port, uplink cables into the dual NIC (cables first, jacks on top)
    S.line([(WANX, fy + fh), (WANX, oy + 30)], C["wan"], SPEED_W["1G"])
    for i in (0, 1):
        S.trunk([(port_x(i), by), (port_x(i), oy + oh - 20)], sw=trunk_w("2.5G"))
    jack(WANX - 24, oy + 14, 48, 36, C["wan"] + "55", C["wan"])
    ticks(WANX, oy + 55, untagged="wan")
    S.label(WANX + 6, (fy + fh + oy + 14) / 2 + 4, "1G", C["wan"], 11, anchor="start", mono=True)     # speed tag like the other links
    S.text(WANX + 32, oy + 38, opn["wan_ip"], 14, C["wan"], 600, mono=True)
    for i in (0, 1):
        jack(port_x(i) - 24, oy + oh - 46, 48, 36, "#2a3443", TRUNK)
        if i == 1:                            # OPNsense is .1 in every VLAN on this trunk
            S.text(port_x(i) + 32, oy + oh - 22, ".1", 14, TRUNK, 600, mono=True)
        ticks(port_x(i), oy + oh - 51, tagged=ALL_VLANS, up=True)
    lx = (port_x(0) + port_x(1)) / 2
    ly = (oy + oh + by) / 2
    S.add(f'<ellipse cx="{lx}" cy="{ly}" rx="46" ry="12" fill="none" stroke="{TRUNK}" stroke-width="1.4" stroke-dasharray="3 3"/>')
    S.label(lx + 54, ly + 4, "LACP · dual 2.5G", TRUNK, 11, anchor="start", mono=True)

    # ================================================================ switch
    swc = INV["switch"]
    device_card(bx, by, bw, bh, ["mikrotik-l"], swc, C["99"], fill="#141b25", stroke=TRUNK_BORDER)

    PORTS = {}
    for i, p in enumerate(swc["ports"]):
        sfp = p["name"].startswith("sfpp")
        w = 60 if sfp else 48
        x = port_x(i) - w / 2
        y = by + 30
        unt = p.get("untagged")
        tagged = p.get("tagged", [])
        if p["to"] in ("free", "rescue"):
            fill, stroke = "#1b222c", (C[unt] if unt and not tagged else TRUNK)
        elif unt and not tagged:
            fill, stroke = C[unt] + "55", C[unt]
        else:
            fill, stroke = "#2a3443", TRUNK
        jack(x, y, w, 36, fill, stroke, sfp)
        short = "SFP+" + p["name"][-1] if sfp else p["name"].replace("ether", "")
        S.text(port_x(i), y - 7, short, 11, MUTED, 500, "middle", mono=True)
        ticks(port_x(i), y + 41, unt, tagged)
        S.text(port_x(i), by + bh - 9, p["to"], 10.5, FAINT if p["to"] in ("free", "rescue") else MUTED, 500, "middle")
        PORTS[p["name"]] = port_x(i)

    # ================================================================ device row
    DY = 1234
    dev = INV["devices"]
    MAD = (40, 400, 86)
    KVM = (460, 310, 86)
    AP = (790, 310, 160)
    ZB = (1120, 360, 86)



def device(key, box):
    x, w, h = box
    d = dev[key]
    col = C[d["vlan"]]
    device_card(x, DY, w, h, d["icons"], d, col, stroke=TRUNK_BORDER if d.get("trunk") else None)
    return x, w, h

if not COLLECTED:


    device("madcat", MAD)

    device("jetkvm", KVM)

    x, w, h = device("ap", AP)
    S.text(x + 18, DY + 96, "SSIDs", 11, FAINT, 600, ls=1.2)
    for i, s in enumerate(INV["ssids"]):
        name = s["redacted"] if (RED["ssid_names"] and not UNREDACTED) else s["name"]
        col = C[s["vlan"]]
        sy = DY + 106 + i * 17
        S.add(f'<circle cx="{x+24}" cy="{sy+5}" r="4" fill="{col}"/>')
        S.text(x + 36, sy + 9, name, 13, TEXT, 500)
        S.text(x + 150, sy + 9, vlan_tag(s["vlan"]), 12, col, 500, mono=True)

    device("slzb", ZB)

    # links switch → devices; width = negotiated speed (read from the switch 2026-11-07)
    MAD_10G = MAD[0] + tab_width(dev["madcat"]) + 34
    MAD_25G = MAD_10G + 54
    S.line([(PORTS["ether3"], SB), (PORTS["ether3"], SB + 46), (MAD_25G, SB + 46), (MAD_25G, DY)], C["10"], SPEED_W["2.5G"])
    # cables enter the card bodies right of the folder tabs
    KVM_IN = KVM[0] + tab_width(dev["jetkvm"]) + 34
    AP_IN = AP[0] + tab_width(dev["ap"]) + 40
    ZB_IN = ZB[0] + tab_width(dev["slzb"]) + 40
    S.line([(PORTS["ether5"], SB), (PORTS["ether5"], SB + 66), (KVM_IN, SB + 66), (KVM_IN, DY)], C["10"], SPEED_W["100M"])
    S.trunk([(PORTS["ether6"], SB), (PORTS["ether6"], SB + 86), (AP_IN, SB + 86), (AP_IN, DY)], sw=trunk_w("2.5G"))
    S.line([(PORTS["ether7"], SB), (PORTS["ether7"], SB + 76), (ZB_IN, SB + 76), (ZB_IN, DY)], C["40"], SPEED_W["100M"])
    p10 = [(PORTS["sfpp1"], SB + 5), (PORTS["sfpp1"], SB + 20), (MAD_10G, SB + 20), (MAD_10G, DY)]
    S.line(p10, BG, SPEED_W["10G"] + 8, cap="butt")                      # knock-out: 10G crosses over the others
    S.line([(PORTS["sfpp1"], SB)] + p10[1:], C["10"], SPEED_W["10G"])



def speed_tag(x, y, txt, color, anchor="start"):
    """Small speed label where a cable enters a device."""
    S.label(x, y, txt, color, 11, anchor=anchor, mono=True)

if not COLLECTED:


    ST = DY - 9
    speed_tag(MAD_10G + 8, ST, "10G", C["10"])
    speed_tag(MAD_25G + 6, ST, "2.5G", C["10"])
    speed_tag(KVM_IN + 5, ST, "100M", C["10"])
    speed_tag(AP_IN + 8, ST, "2.5G", TRUNK)
    speed_tag(ZB_IN + 5, ST, "100M", C["40"])

    # ================================================================ open to the internet (info card, right column, no link)
    ix_, iy_, iw_ = 1790, 262, 570
    pf = INV["port_forwards"]
    ih_ = 84 + len(pf) * 44
    S.rect(ix_, iy_, iw_, ih_, rx=14, fill=PANEL, stroke=BORDER, sw=1.4)
    S.text(ix_ + 20, iy_ + 34, "Open to the internet", 19, TEXT, 600)
    S.text(ix_ + 20, iy_ + 56, "port forwards on OPNsense · blocklist + CrowdSec drop bad IPs first", 12.5, MUTED, 400)
    for i, r in enumerate(pf):
        y = iy_ + 72 + i * 44
        S.rect(ix_ + 14, y, iw_ - 28, 38, rx=8, fill=CHIP, stroke=BORDER, sw=1)
        S.text(ix_ + 26, y + 24, r["port"], 13, TEXT, 600, mono=True)
        S.text(ix_ + 236, y + 17, r["to"], 13.5, TEXT, 600)
        S.text(ix_ + 236, y + 32, r["what"], 11.5, MUTED, 400)
        px = ix_ + iw_ - 24
        for pr in reversed(r["proto"].split("/")):
            px -= S.pill(px, y + 9, pr, PROTO[pr], 11, mono=True, anchor="end", pad=7, h=20) + 6

    # ================================================================ legend (left column, under the Networks card)
    LG_ROWS = ["trunk", "access", "wan", "kvm", "net", "speed", "public", "internal", "lan", "ticks", "share"]
    lgx, lgy, lgw = 40, 660, 500
    LR = 27
    lgh = 52 + len(LG_ROWS) * LR + 8
    S.rect(lgx, lgy, lgw, lgh, rx=14, fill=PANEL, stroke=BORDER, sw=1.4)
    S.text(lgx + 20, lgy + 36, "Legend", 19, TEXT, 600)
    SX, TX = lgx + 22, lgx + 162          # symbol column, text column
    for i, k in enumerate(LG_ROWS):
        y = lgy + 66 + i * LR
        t = None
        if k == "trunk":
            S.trunk([(SX, y), (SX + 50, y)], sw=trunk_w("2.5G"), r=0); t = "802.1Q trunk (tagged VLANs)"
        elif k == "access":
            for jj, c in enumerate(["10", "20", "40", "99"]):
                S.line([(SX + jj * 13, y), (SX + jj * 13 + 9, y)], C[c], 3.6, r=0, cap="butt")
            t = "access port, colored by VLAN"
        elif k == "wan":
            S.line([(SX, y), (SX + 50, y)], C["wan"], 3, r=0); t = "WAN (Fritzbox network)"
        elif k == "kvm":
            S.line([(SX, y), (SX + 50, y)], MUTED, 2, dash="5 5", r=0, cap="butt"); t = "KVM console (HDMI + USB)"
        elif k == "net":
            S.line([(SX, y), (SX + 50, y)], MUTED, 1.8, dash="2 5", r=0); t = "over the internet (not a cable)"
        elif k == "speed":
            S.text(SX, y + 4.5, "line width = speed", 12.5, MUTED, 400)
            x0 = TX
            for lbl in ("10G", "2.5G", "1G", "100M"):
                S.line([(x0, y), (x0 + 26, y)], C["10"], SPEED_W[lbl], r=0, cap="butt")
                S.text(x0 + 32, y + 4.5, lbl, 12, TEXT, 500, mono=True)
                x0 += 32 + tw(lbl, 12, True) + 20
        elif k == "public":
            S.text(SX, y + 4.5, "app." + SHOWN_DOMAIN, 12, LINK, 500, mono=True); t = "public via Traefik"
        elif k == "internal":
            S.text(SX, y + 4.5, "name.internal", 12, C["10"], 400, mono=True, op=0.78); t = "local DNS, no Traefik"
        elif k == "lan":
            S.pill(SX, y - 9, "LAN", MUTED, 10, mono=True, pad=5); t = "only from LAN / VPN"
        elif k == "ticks":
            for jj, c in enumerate(["10", "20", "40"]):
                S.add(f'<rect x="{SX + jj*7}" y="{y-5 if jj == 0 else y-2}" width="5" height="{8 if jj == 0 else 5}" rx="1" fill="{C[c]}"/>')
            t = "port VLANs (tall = untagged)"
        elif k == "share":
            S.rect(SX, y - 8, 22, 15, rx=3, fill=C["10"] + "16", stroke=C["10"] + "cc", sw=1.2, dash="4 3")
            t = "TrueNAS share, bind-mounted"
        if t:
            S.text(TX, y + 4.5, t, 13, MUTED, 400)

    # ================================================================ left column: VLAN table
    vx, vy, vw = 40, 150, 500
    vh = 70 + len(INV["vlans"]) * 60
    S.rect(vx, vy, vw, vh, rx=14, fill=PANEL, stroke=BORDER, sw=1.4)
    S.text(vx + 20, vy + 36, "Networks", 19, TEXT, 600)
    for i, v in enumerate(INV["vlans"]):
        y = vy + 56 + i * 60
        S.rect(vx + 14, y, vw - 28, 52, rx=9, fill=CHIP, stroke=v["color"] + "55", sw=1)
        S.add(f'<rect x="{vx+14}" y="{y}" width="6" height="52" rx="3" fill="{v["color"]}"/>')
        S.text(vx + 32, y + 22, v["tag"], 13, v["color"], 600, mono=True)
        S.text(vx + 128, y + 22, v["name"], 15.5, TEXT, 600)
        S.text(vx + vw - 28, y + 22, v["subnet"], 13.5, TEXT, 500, "end", mono=True)
        S.text(vx + 32, y + 42, v["note"], 12, MUTED, 400)

    # ================================================================ terra
    T = INV["terra"]
    tx0, ty0, tw0 = 40, 1468, W - 80
    GY = 92           # body starts below the header
    ZH = 712          # body height: hardware list | other-VLAN guests | DMZ zone
    th0 = GY + ZH + 22
    device_card(tx0, ty0, tw0, th0, ["proxmox"], T, C["10"], fill="#0f151e", stroke=TRUNK_BORDER, sw=2)

    # ---- column 1: hardware as a vertical list
    hwx, HWW = tx0 + 20, 250
    hy0 = ty0 + GY
    S.text(hwx + 2, hy0 + 12, "HARDWARE", 11.5, HWC, 700, ls=1.4)
    TH_, TG_ = 58, 6
    for i, hwi in enumerate(T["hw"]):
        x, y = hwx, hy0 + 22 + i * (TH_ + TG_)
        S.rect(x, y, HWW, TH_, rx=11, fill="#151d29", stroke="#2e3a4c", sw=1.2)
        hw_bar(x, y, TH_)
        S.icon(hwi["icon"], x + 12, y + 15, 28)
        S.text(x + 50, y + 17, hwi["label"], 10, "#c08a5c", 700, ls=1.3)
        vs = min(15.5, 15.5 * (HWW - 62) / measure(hwi["value"], 15.5, 700))   # shrink long part names to fit
        S.text(x + 50, y + 35, hwi["value"], round(vs, 2), TEXT, 700)
        S.text(x + 50, y + 50, hwi["sub"], 10.5, MUTED, 400)
    assert hy0 + 22 + len(T["hw"]) * (TH_ + TG_) <= hy0 + ZH + 6, "hardware list too tall"

    S.trunk([(PORTS["sfpp2"], SB), (PORTS["sfpp2"], ty0)], sw=trunk_w("10G"))
    speed_tag(PORTS["sfpp2"] + 10, ty0 - 9, "10G", TRUNK)

    kx = KVM[0] + KVM[1] / 2
    S.line([(kx, DY + KVM[2]), (kx, ty0)], MUTED, 2, dash="5 5", cap="butt")
    S.label(kx + 10, (DY + KVM[2] + ty0) / 2 + 5, "HDMI + USB console", MUTED, 12, anchor="start")

    # ---- other-VLAN guests (left column inside terra)
    og = T["other_guests"]
    gx, gy, gw = hwx + HWW + 20, ty0 + GY, 480



def guest_card(g, x, y, w, h):
    col = C[g["vlan"]]
    S.rect(x, y, w, h, rx=12, fill=PANEL, stroke=col + "99", sw=1.5)
    S.icon(g["icons"][0], x + 16, y + 14, 34)
    if g.get("badge"):
        S.add(f'<circle cx="{x+45}" cy="{y+44}" r="11" fill="{PANEL}"/>')
        S.icon(g["badge"], x + 35, y + 34, 20)
    S.text(x + 60, y + 32, g["name"], 17, TEXT, 600)
    S.pill(x + w - 14, y + 16, vlan_tag(g["vlan"]), col, 10.5, mono=True, h=19, pad=6, anchor="end")
    addr(x + 60, y + 51, g["ip"], g, col)
    S.text(x + 60, y + 69, g["note"], 12.5, MUTED, 400)

def disk(kind, x, y):
    if kind == "hdd":
        S.rect(x, y, 30, 40, rx=4, fill=DISK, stroke=DISK_EDGE, sw=1.2)
        S.add(f'<circle cx="{x+15}" cy="{y+16}" r="9" fill="none" stroke="{C["10"]}" stroke-width="1.6"/>'
              f'<circle cx="{x+15}" cy="{y+16}" r="2" fill="{C["10"]}"/>')
        S.rect(x + 8, y + 31, 14, 3, rx=1, fill=DISK_EDGE, stroke="none", sw=0)
        return 30
    if kind == "ssd":
        S.rect(x, y + 6, 44, 28, rx=3, fill=DISK, stroke=DISK_EDGE, sw=1.2)
        S.rect(x + 6, y + 12, 20, 16, rx=2, fill=C["10"] + "55", stroke="none", sw=0)
        S.rect(x + 30, y + 12, 8, 16, rx=1, fill=DISK_EDGE, stroke="none", sw=0)
        return 44
    S.rect(x, y + 10, 96, 20, rx=2, fill=DISK, stroke=DISK_EDGE, sw=1.2)        # nvme
    for k in range(3):
        S.rect(x + 8 + k * 22, y + 14, 16, 12, rx=1, fill=C["10"] + "55", stroke="none", sw=0)
    S.rect(x + 88, y + 15, 4, 10, rx=1, fill=BG, stroke="none", sw=0)
    return 96

def pool_box(p, x, y, w, h):
    S.rect(x, y, w, h, rx=10, fill=CHIP, stroke=BORDER, sw=1)
    S.text(x + 14, y + 24, p["name"], 15.5, TEXT, 700)
    S.text(x + 14 + tw(p["name"], 15.5) + 12, y + 24, p["layout"], 12.5, MUTED, 400)
    S.text(x + w - 14, y + 24, p["used"], 12, MUTED, 400, "end")
    bw_ = w - 28
    S.rect(x + 14, y + 34, bw_, 8, rx=4, fill="#253042", stroke="none", sw=0)
    S.rect(x + 14, y + 34, max(bw_ * p["pct"] / 100, 8), 8, rx=4, fill=C["10"], stroke="none", sw=0)
    gx0 = x + 14
    for grp in p["groups"]:
        dx = gx0
        for _ in range(grp["count"]):
            dx += disk(grp["kind"], dx, y + 54) + 7
        gw_ = dx - 7 - gx0
        if grp["kind"] == "nvme":          # label to the right of the stick
            S.text(dx + 8, y + 64, grp["label"], 12.5, TEXT, 500)
            S.text(dx + 8, y + 80, grp["sub"], 11.5, MUTED, 400)
            if grp.get("sub2"):
                S.text(dx + 8, y + 95, grp["sub2"], 11.5, MUTED, 400)
        else:
            S.line([(gx0, y + 102), (gx0, y + 106), (gx0 + gw_, y + 106), (gx0 + gw_, y + 102)], DISK_EDGE, 1.2, r=0, cap="butt")
            S.text(gx0, y + 122, grp["label"], 12.5, TEXT, 500)
            S.text(gx0, y + 137, grp["sub"], 11.5, MUTED, 400)
            if grp.get("sub2"):
                S.text(gx0, y + 152, grp["sub2"], 11.5, MUTED, 400)
            gw_ = max(gw_, tw(grp["label"], 12.5), tw(grp["sub"], 11.5), tw(grp.get("sub2", ""), 11.5))
        gx0 += gw_ + 30

if not COLLECTED:


    tn = og["truenas"]
    guest_card(tn, gx, gy, gw, 382)
    pool_box(tn["pools"][0], gx + 14, gy + 84, gw - 28, 158)
    pool_box(tn["pools"][1], gx + 14, gy + 250, gw - 28, 102)
    S.text(gx + 18, gy + 370, tn["footer"], 12, MUTED, 400)

    ha = og["haos"]
    hy = gy + 396
    guest_card(ha, gx, hy, gw, 120)
    ax = gx + 18
    for ic in ha["addons"]:
        S.icon(ic, ax, hy + 80, 26)
        ax += 34
    S.text(ax + 8, hy + 98, ha["addons_text"], 12, MUTED, 400)

    guest_card(og["unifi"], gx, hy + 134, gw, 84)
    guest_card(og["bliss"], gx, hy + 232, gw, 84)

    # ---- DMZ zone
    zx = gx + gw + 20
    zy = gy
    zw = tx0 + tw0 - 20 - zx
    S.rect(zx, zy, zw, ZH, rx=14, fill=C["20"] + "0d", stroke=C["20"] + "88", sw=1.5)
    S.pill(zx + zw - 14, zy + 16, vlan_tag("20"), C["20"], 10.5, mono=True, h=19, pad=6, anchor="end")   # same as the VM/CT card pills
    S.text(zx + 18, zy + 31, "one unprivileged LXC per service · web apps behind Traefik (CT 149)",
           12.5, MUTED, 400)

    groups = {g["name"]: g for g in T["dmz_groups"]}
    cgap = 14
    NCOL = 4
    cw = (zw - 32 - cgap * (NCOL - 1)) / NCOL
    CH, CG = 64, 7
    GT = "#c08a5c"



def col_x(i):
    return zx + 16 + i * (cw + cgap)

def docker_badge(x, y):
    """Small Docker whale on a corner = this CT runs its apps as Docker containers."""
    S.add(f'<circle cx="{x}" cy="{y}" r="12" fill="{PANEL}" stroke="#2f6fb0" stroke-width="1.2"/>')
    S.icon("docker", x - 8.5, y - 8.5, 17)

def chip_apps(g, x, y, w):
    """One CT running several apps: header like a normal chip, then one row per app (icon, name, hostname)."""
    h = 46 + len(g["apps"]) * 21 + 8
    S.rect(x, y, w, h, rx=9, fill=CHIP, stroke=BORDER, sw=1)
    S.text(x + 14, y + 22, g["name"], 14.5, TEXT, 600)
    S.text(x + 14, y + 38, g.get("note", ""), 11.5, MUTED, 400)
    S.text(x + w - 12, y + 21, f"{g.get('kind', 'CT')} {g['id']}", 12, FAINT, 500, "end", mono=True)
    S.text(x + w - 12, y + 37, g.get("ip", f".{g['id']}"), 11, FAINT, 500, "end", mono=True)
    for k, a in enumerate(g["apps"]):
        ry = y + 50 + k * 21
        S.icon(a["icon"], x + 14, ry, 17)
        S.text(x + 38, ry + 13, a["name"], 12.5, TEXT, 600)
        if a.get("host"):
            S.text(x + 140, ry + 13, fqdn(a["host"]), 11, LINK, 500, mono=True)
        else:
            S.text(x + 140, ry + 13, a.get("note", ""), 11.5, MUTED, 400)
    if g.get("docker"):
        docker_badge(x + 2, y + 2)
    return h

def chip(g, x, y, w):
    if g.get("apps"):
        return chip_apps(g, x, y, w)
    S.rect(x, y, w, CH, rx=9, fill=CHIP, stroke=BORDER, sw=1)
    icons = g["icons"]
    if len(icons) == 4:                      # 2×2 grid
        for k, ic in enumerate(icons):
            S.icon(ic, x + 12 + (k % 2) * 23, y + 13 + (k // 2) * 21, 19)
        nx = x + 12 + 46 + 10
    else:
        isz = 32 if len(icons) == 1 else 26
        ix = x + 10
        for ic in icons:
            S.icon(ic, ix, y + (CH - isz) / 2, isz)
            ix += isz + 4
        nx = ix + 6
    S.text(nx, y + 21, g["name"], 14.5, TEXT, 600)
    S.text(nx, y + 37, g.get("note", ""), 11.5, MUTED, 400)
    name, ncol = hostname(g)
    if name:
        S.text(nx, y + 54, name, 11.5, ncol or MUTED, 500, mono=True)
        if g.get("exposure") == "local":
            S.pill(nx + tw(name, 11.5, True) + 8, y + 44, "LAN", MUTED, 9.5, mono=True, pad=4, h=14)
    S.text(x + w - 12, y + 21, f"{g.get('kind', 'CT')} {g['id']}", 12, FAINT, 500, "end", mono=True)
    S.text(x + w - 12, y + 37, g.get("ip", f".{g['id']}"), 11, FAINT, 500, "end", mono=True)
    if g.get("docker"):
        docker_badge(x + 2, y + 2)
    return CH

def column(i, names):
    x, y = col_x(i), zy + 56
    for gname in names:
        S.text(x + 2, y + 12, gname.upper(), 11.5, GT, 700, ls=1.4)
        y += 22
        for g in groups[gname]["guests"]:
            y += chip(g, x, y, cw) + CG
        y += 14
    assert y <= zy + ZH + 6, f"DMZ column {i} too tall"

if not COLLECTED:


    column(0, ["Edge & security", "Monitoring"])
    column(1, ["Media & photos"])
    column(2, ["Productivity", "Gaming"])
    column(3, ["Dev", "Chat"])

    # ================================================================ media pipeline (explainer panel, right column above terra)
    mp = T["media_pipeline"]
    N = mp["nodes"]
    PX, PY, PW = 1790, iy_ + ih_ + 20, 570
    CARD_BG = PANEL
    G_ = 42
    NW = (PW - 28 - 2 * G_) / 3
    NH = 68
    STACK_H = 3 * 46 + 2 * 6
    RA = PY + 98                       # top of the *arr stack (room for title + its label)
    RS = RA + (STACK_H - NH) / 2       # Seerr / Prowlarr (centered on the stack)
    RB = RA + STACK_H + 52             # Jellyfin / qBittorrent
    RC = RB + NH + 40                  # the two TrueNAS shares
    SH_ = 64
    SW_ = (PW - 28 - G_) / 2
    PH = RC + SH_ + 16 - PY
    S.rect(PX, PY, PW, PH, rx=14, fill=PANEL, stroke=BORDER, sw=1.4)
    S.text(PX + 20, PY + 32, "Media pipeline", 17, TEXT, 600)
    S.text(PX + 20, PY + 52, "how a request ends up in Jellyfin", 12.5, MUTED, 400)
    assert PY + PH <= ty0 - TAB - 16, f"pipeline panel overlaps terra: {PY + PH} > {ty0 - TAB - 16}"



def node_x(c):
    return PX + 14 + c * (NW + G_)

def node(n, c, y):
    x = node_x(c)
    S.rect(x, y, NW, NH, rx=9, fill=CHIP, stroke=BORDER, sw=1)
    S.icon(n["icon"], x + 8, y + 9, 22)
    S.text(x + 35, y + 26, n["name"], 12.5, TEXT, 600)
    S.text(x + NW - 10, y + 26, f"CT {n['ct']}", 10.5, FAINT, 500, "end", mono=True)
    S.text(x + NW - 10, y + 46, n["ip"], 10.5, FAINT, 500, "end", mono=True)
    S.text(x + 10, y + 46, n["sub"], 11, MUTED, 400)
    S.text(x + 10, y + 62, fqdn(n["host"]), 10, LINK, 500, mono=True)

def arr_node(a, x, y):
    S.rect(x, y, NW, 46, rx=8, fill=CHIP, stroke=BORDER, sw=1)
    S.icon(a["icon"], x + 10, y + 7, 20)
    S.text(x + 36, y + 22, a["name"], 13.5, TEXT, 600)
    S.text(x + NW - 10, y + 22, a["ip"], 12, FAINT, 500, "end", mono=True)
    S.text(x + 10, y + 38, fqdn(a["host"]), 10, LINK, 500, mono=True)

def share(sh, x, y):
    """A TrueNAS SMB share, mounted on terra and bind-mounted into the containers."""
    S.rect(x, y, SW_, SH_, rx=9, fill=C["10"] + "16", stroke=C["10"] + "cc", sw=1.3, dash="5 4")
    S.icon("truenas", x + 10, y + 10, 22)
    S.text(x + 40, y + 26, sh["name"], 13.5, TEXT, 600)
    S.text(x + SW_ - 10, y + 26, "TrueNAS SMB", 10.5, C["10"], 600, "end", mono=True)
    S.text(x + 10, y + 44, sh["pool"], 11, MUTED, 400)
    S.text(x + 10, y + 58, "bind mount: SMB ↔ terra ↔ CT", 10, C["10"], 500, mono=True)

if not COLLECTED:


    node(N["seerr"], 0, RS)
    node(N["prowlarr"], 2, RS)
    S.rect(node_x(1) - 6, RA - 6, NW + 12, STACK_H + 12, rx=12, fill="none", stroke="#3a475a", sw=1.2, dash="3 3")
    lx0 = node_x(1) + 2                                   # group label: Docker whale + "CT 154"
    S.rect(lx0, RA - 17, 58, 22, rx=5, fill=CARD_BG, stroke=CARD_BG, sw=0)
    S.text(lx0 + 6, RA - 1, "CT 154", 11.5, "#c3cdd9", 600, mono=True)
    for k, a in enumerate(mp["arrs"]):
        arr_node(a, node_x(1), RA + k * 52)
    node(N["jellyfin"], 0, RB)
    node(N["qbit"], 2, RB)
    mx, tx_ = PX + 14, PX + 14 + SW_ + G_
    share(mp["shares"]["media"], mx, RC)
    share(mp["shares"]["torrents"], tx_, RC)

    midS = RS + NH / 2
    S.arrow([(node_x(0) + NW + 4, midS), (node_x(1) - 10, midS)])
    S.label(node_x(0) + NW + G_ / 2 - 3, midS - 8, "request", MUTED, 11, bg=CARD_BG)
    S.arrow([(node_x(2) - 4, midS), (node_x(1) + NW + 10, midS)])
    S.label(node_x(1) + NW + G_ / 2 + 3, midS - 8, "indexers", MUTED, 11, bg=CARD_BG)
    qx = node_x(2) + NW / 2
    yr = RA + 2 * 52 + 23                       # Radarr row
    S.arrow([(node_x(1) + NW + 8, yr), (qx, yr), (qx, RB - 5)])
    S.label((node_x(1) + NW + qx) / 2 + 4, yr - 8, "torrent", MUTED, 11, bg=CARD_BG)
    # the *arr apps pick finished files up from Torrents and copy them (renamed, sorted) into Media
    ax1, ax2 = node_x(1) + 24, node_x(1) + NW - 24
    S.arrow([(ax1, RA + STACK_H + 7), (ax1, RC - 5)])
    S.text(ax1 + 8, RB + 30, "copy +", 11, MUTED, 500)
    S.text(ax1 + 8, RB + 44, "rename", 11, MUTED, 500)
    S.arrow([(ax2, RC - 2), (ax2, RA + STACK_H + 10)])
    S.text(ax2 + 8, RB + 30, "pick up", 11, MUTED, 500)
    S.text(ax2 + 8, RB + 44, "when done", 11, MUTED, 500)
    jx = node_x(0) + NW / 2
    S.arrow([(jx, RB - 2), (jx, RS + NH + 5)], dash="4 4")
    S.text(jx + 10, (RS + NH + RB) / 2 + 4, "available", 11, MUTED, 500)
    S.arrow([(qx, RB + NH + 2), (qx, RC - 5)])
    S.text(qx + 10, (RB + NH + RC) / 2 + 4, "download", 11, MUTED, 500)
    S.arrow([(jx, RC - 2), (jx, RB + NH + 5)])
    S.text(jx + 10, (RB + NH + RC) / 2 + 4, "library", 11, MUTED, 500)

    assert ty0 + th0 <= H - 20, f"canvas too short: terra ends at {ty0 + th0}"


def render_collected():
    """Lay out collected YAML using this renderer's original drawing functions.

    The original author-specific drawing blocks above remain the legacy mode.
    This is its multi-device/multi-server YAML layout, not an alternate engine.
    """
    global H, CH, CG
    import copy
    import math
    CH, CG = 64, 7
    private = UNREDACTED
    nets = INV['vlans']
    devices = list(INV['devices'].values())
    servers = INV['servers']
    unknown = INV['unplaced_assets'] if INV.get('layout_options', {}).get('show_unplaced', True) else []
    index = {g['asset_id']: i + 1 for i, g in enumerate(devices + servers + unknown)}

    def fitted(value, width, size=14, weight=600):
        value = str(value)
        while value and measure(value, size, weight) > width:
            value = value[:-1]
        return value

    def shown(g):
        out = copy.deepcopy(g)
        out['name'] = g['name'] if private else g.get('type', 'Device') + ' ' + str(index.get(g['asset_id'], 1))
        out['model'] = fitted(g['model'] if private else 'Hardware details hidden', 390)
        out['ip'] = g['ip'] if private else 'Address hidden'
        out['internal'] = ''
        out['type'] = g['type'] if private else ('Proxmox host' if g in servers else 'Network device')
        return out

    def ncolor(key):
        return C.get(key, TRUNK_BORDER)

    def hardware(items, x, y, width=250):
        for i, hw in enumerate(items):
            yy = y + i * 64
            S.rect(x, yy, width, 58, rx=11, fill='#151d29', stroke='#2e3a4c', sw=1.2)
            hw_bar(x, yy, 58)
            S.icon(hw['icon'], x + 12, yy + 15, 28)
            S.text(x + 50, yy + 17, hw['label'], 10, HWC, 700, ls=1.3)
            value = hw['value'] if private else ('Hardware details hidden' if hw['label'] != 'MEMORY' else hw['value'])
            size = min(15.5, 15.5 * (width - 62) / max(measure(value, 15.5, 700), 1))
            S.text(x + 50, yy + 35, value, round(size, 2), TEXT, 700)
            S.text(x + 50, yy + 50, hw['sub'] if private else 'Reported hardware', 10.5, MUTED)

    # Calculate heights before drawing so every server and all YAML guests fit.
    plans = []
    for server in servers:
        columns = [[], [], [], []]
        heights = [0, 0, 0, 0]
        for gi, group in enumerate(server['dmz_groups']):
            guests = group['guests']
            for offset in range(0, len(guests), 6):
                chunk = guests[offset:offset + 6]
                col = min(range(4), key=lambda i: heights[i])
                height = 30 + sum(46 + len(g['apps']) * 21 + 8 if g.get('apps') else 64 for g in chunk) + 7 * len(chunk) + 12
                columns[col].append((gi, group, chunk))
                heights[col] += height
        body = max(max(heights, default=0) + 28, len(server.get('hw', [])) * 64 + 28, 75 + math.ceil(len(server['storage']) / 2) * 58, 260)
        plans.append((server, columns, body + 116))
    left_bottom = 150 + 68 + len(nets) * 58 + 272
    routers = [g for g in devices if g['type'] in ('Router', 'Router / switch')]
    others = [g for g in devices if g not in routers]
    device_top = 180 + len(routers) * 340
    device_bottom = device_top + math.ceil(len(others) / 3) * 160
    first_host = max(left_bottom, device_bottom) + 90
    appendix_h = 70 + math.ceil(len(unknown) / 6) * 42 if unknown else 0
    H = max(1100, first_host + sum(p[2] + 75 for p in plans) + appendix_h + 60)
    if H > 12000:
        raise ValueError('This diagram is too tall. Hide unplaced assets or split it into smaller sites.')

    S.add(f'<defs><pattern id="dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1.5" cy="1.5" r="1.3" fill="{GRID}"/></pattern></defs>')
    S.rect(0, 0, W, H, rx=0, fill=BG, stroke=BG, sw=0)
    S.rect(0, 0, W, H, rx=0, fill='url(#dots)', stroke='none', sw=0)
    wire_index = len(S.p)
    title = INV['meta']['title'] if private else INV['meta']['title_redacted']
    S.text(40, 86, title, 46, TEXT, 700, ls=-0.5)
    S.text(W - 40, 74, 'Simulated inventory' if INV.get('source', {}).get('simulated') else INV['meta']['watermark'] if private else '', 21, REDDIT, 700, 'end')
    S.text(W - 40, 100, INV['meta']['date'], 16, MUTED, 400, 'end')
    vx, vy, vw = 40, 150, 500
    vh = 68 + len(nets) * 58
    S.rect(vx, vy, vw, vh, rx=14, fill=PANEL, stroke=BORDER, sw=1.4)
    S.text(vx + 20, vy + 36, 'Networks', 19, TEXT, 600)
    for i, v in enumerate(nets):
        yy = vy + 56 + i * 58
        S.rect(vx + 14, yy, vw - 28, 52, rx=8, fill=CHIP, stroke=BORDER, sw=1)
        S.add(f'<rect x="{vx+14}" y="{yy}" width="6" height="52" rx="3" fill="{v["color"]}"/>')
        S.text(vx + 32, yy + 21, v['tag'] if private else 'Network ' + str(i+1), 12, v['color'], 600, mono=True)
        S.text(vx + 146, yy + 21, fitted(v['name'] if private else 'Name hidden', 300, 14), 14, TEXT, 600)
        S.text(vx + 32, yy + 42, v['subnet'] if private else 'Subnet hidden', 12, MUTED, mono=True)
    ly = vy + vh + 20
    S.rect(vx, ly, vw, 252, rx=14, fill=PANEL, stroke=BORDER, sw=1.4)
    S.text(vx + 20, ly + 34, 'Legend', 19, TEXT, 600)
    S.trunk([(vx+22, ly+65),(vx+74, ly+65)], sw=trunk_w('1G'), r=0)
    S.text(vx+96, ly+70, 'Confirmed tagged trunk', 12, MUTED)
    S.line([(vx+22, ly+96),(vx+74, ly+96)], LINK, 2.4, r=0)
    S.text(vx+96, ly+101, 'Confirmed physical cable', 12, MUTED)
    S.line([(vx+22, ly+127),(vx+74, ly+127)], MUTED, 1.8, dash='2 5', r=0)
    S.text(vx+96, ly+132, 'Reported neighbor; physical path unverified', 12, MUTED)
    S.text(vx+22, ly+166, 'Line width follows a reported link speed.', 12, MUTED)
    S.text(vx+22, ly+187, 'Unreported speeds use a thin line.', 12, MUTED)
    S.text(vx+22, ly+212, 'Ports and VLAN ticks use collected facts.', 12, MUTED)
    S.text(vx+22, ly+233, 'Guest placement comes from Proxmox.', 12, MUTED)

    positions = {}
    cy = 180
    for raw in routers:
        g = shown(raw);x,y,w,h=620,cy,1740,230
        g['model']=fitted(g['model'], 600)
        device_card(x,y,w,h,g.get('icons',['glyph-nic']),g,ncolor(raw.get('vlan')),stroke=TRUNK_BORDER)
        S.text(x+20,y+96,'HARDWARE',11.5,HWC,700,ls=1.4)
        for hi,hw in enumerate(raw.get('hw',[])[:3]):hardware([hw],x+20+hi*250,y+108,238)
        ports=raw.get('ports',[])[:24];px=x+820;pitch=min(70, (w-850)/max(len(ports),1))
        S.text(px,y+96,'PORTS',11.5,HWC,700,ls=1.4)
        for pi,p in enumerate(ports):
            center=px+pi*pitch+22;py=y+118;sf='sfp' in p['name'].lower()
            jack(center-22,py,44,36,'#2a3443',TRUNK_BORDER,sf)
            S.text(center,py-7,p['name'] if private else str(pi+1),9,MUTED,500,'middle',mono=True)
            ticks(center,py+41,p.get('untagged') or None,p.get('tagged',[]))
            S.text(center,py+62,p.get('speed') or ('up' if p.get('running') else 'unknown'),9.5,MUTED,500,'middle')
        positions[raw['asset_id']]=(x,y,w,h,g)
        cy+=340
    for i,raw in enumerate(others):
        x=620+(i%3)*590;y=device_top+(i//3)*160;w,h=560,94;g=shown(raw)
        g['name']=fitted(g['name'],330,20,700);g['model']=fitted(g['model'],450)
        device_card(x,y,w,h,g.get('icons',['glyph-nic']),g,ncolor(raw.get('vlan')),stroke=TRUNK_BORDER)
        positions[raw['asset_id']]=(x,y,w,h,g)
    wire_start=len(S.p)
    for i,link in enumerate(INV['connections']):
        if link['src'] not in positions or link['dst'] not in positions:continue
        a=positions[link['src']];b=positions[link['dst']]
        # Neighbor discovery is logical evidence. Never draw it as a cable.
        pts=[(a[0]+a[2],a[1]+a[3]-15),(W-16-i%5*5,a[1]+a[3]-15),(W-16-i%5*5,b[1]+b[3]-12),(b[0]+b[2],b[1]+b[3]-12)]
        if link['kind']=='physical' and link.get('source')=='manual':
            speed=link.get('speed');sw=SPEED_W.get(speed,1.4)
            if link.get('tagged'):S.trunk(pts,sw=sw+3.4)
            else:S.line(pts,ncolor(INV['devices'][link['src']].get('vlan')),sw)
        else:S.line(pts,MUTED,1.6,dash='2 5')
    wires=S.p[wire_start:];del S.p[wire_start:];S.p[wire_index:wire_index]=wires

    yy=first_host
    for si,(raw,columns,height) in enumerate(plans):
        g=shown(raw);x,w=40,W-80
        device_card(x,yy,w,height,['proxmox'],g,ncolor(raw.get('vlan')),fill='#0f151e',stroke=TRUNK_BORDER,sw=2)
        hx,hy=x+20,yy+92
        S.text(hx+2,hy+12,'HARDWARE',11.5,HWC,700,ls=1.4)
        hardware(raw.get('hw',[]),hx,hy+22,250)
        sx,sw=hx+270,350
        S.rect(sx,hy,sw,height-116,rx=12,fill=PANEL,stroke=BORDER,sw=1.4)
        S.text(sx+16,hy+28,'Storage resources',17,TEXT,600)
        storage=raw['storage']
        if not storage:S.text(sx+16,hy+55,'Storage inventory not reported',12,MUTED)
        for j,item in enumerate(storage):
            rx=sx+12+(j%2)*(sw/2-6);ry=hy+46+(j//2)*58;rw=sw/2-16
            S.rect(rx,ry,rw,49,rx=8,fill=CHIP,stroke=BORDER,sw=1)
            S.icon(item.get('icon','glyph-hdd'),rx+7,ry+9,25)
            S.text(rx+40,ry+20,fitted(item['name'] if private else 'Storage '+str(j+1),rw-49,12),12,TEXT,600)
            S.text(rx+9,ry+39,'Proxmox storage',9.5,MUTED)
        zx,zy,zw=sx+sw+20,hy,w-680
        S.rect(zx,zy,zw,height-116,rx=14,fill='#18202a',stroke=BORDER,sw=1.5)
        cw=(zw-32-3*14)/4
        for ci,chunks in enumerate(columns):
            gx,gy=zx+16+ci*(cw+14),zy+18
            for gi,group,guests in chunks:
                heading=group['name'] if private else 'Guest group '+str(gi+1)
                S.text(gx+2,gy+12,fitted(heading,cw-4,11.5),11.5,HWC,700,ls=0.6)
                gy+=26
                for entry in guests:
                    guest=copy.deepcopy(entry)
                    guest['name']=fitted(guest['name'] if private else guest['kind']+' '+str(guests.index(entry)+1),cw-130,14.5)
                    guest['note']=fitted(guest.get('note','') if private else guest['kind'],cw-60,11.5)
                    guest['hostname']=entry.get('ip','') if private else 'Address hidden'
                    guest.pop('host',None);guest['internal']=''
                    ip=entry.get('ip','')
                    guest['ip']='.'+ip.rsplit('.',1)[1] if private and ip.count('.')==3 else ''
                    if not private:guest['id']='—';guest['apps']=[]
                    gy+=chip(guest,gx,gy,cw)+CG
                gy+=12
        yy+=height+75
    if unknown:
        S.rect(40,yy,W-80,appendix_h,rx=14,fill=PANEL,stroke=BORDER,sw=1.4)
        S.text(60,yy+32,'Other discovered assets · placement not confirmed',19,TEXT,600)
        for i,a in enumerate(unknown):
            ax=60+(i%6)*386;ay=yy+62+(i//6)*42
            S.text(ax,ay,fitted(a['name'] if private else 'Asset '+str(i+1),365,12),12,TEXT,500)
            S.text(ax,ay+17,a['ip'] if private else 'Address hidden',10,MUTED,mono=True)
        yy+=appendix_h
    S.text(40,H-20,'Generated from inventory.yaml by build.py · unreported hardware, service and physical-link details remain editable in YAML.',12,MUTED)


if COLLECTED:
    render_collected()

OUT.mkdir(parents=True, exist_ok=True)
name = "homelab-unredacted" if UNREDACTED else "homelab"
svg_path = OUT / f"{name}.svg"
svg_path.write_text(S.render())
png_path = OUT / f"{name}.png"
if not args.svg_only:
    subprocess.run(["rsvg-convert", "-z", "1.6", "-o", str(png_path), str(svg_path)], check=True)
print(svg_path, png_path)
