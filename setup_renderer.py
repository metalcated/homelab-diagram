"""Fetch and verify the original renderer's local icons and fonts."""
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib
import html
import io
import json
from pathlib import Path
import shutil
from urllib.request import Request,urlopen
import xml.etree.ElementTree as ET
import zipfile

ROOT=Path(__file__).resolve().parent

def fetch(item):
    target=ROOT/item['target'];expected=item['sha256']
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest()==expected:return
        raise ValueError('Existing renderer asset differs and was kept unchanged: '+target.name)
    with urlopen(Request(item['url'],headers={'User-Agent':'homelab-diagram-renderer-setup/1.0'}),timeout=25) as response:data=response.read(5_000_001)
    if len(data)>5_000_000:raise ValueError('Renderer asset exceeded its size limit.')
    if item.get('archive_member'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            member=next(n for n in archive.namelist() if n.endswith(item['archive_member']))
            if archive.getinfo(member).file_size>2_000_000:raise ValueError('Font exceeded its size limit.')
            data=archive.read(member)
    if item.get('replace'):data=data.decode().replace(*item['replace']).encode()
    if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Renderer asset checksum changed: '+target.name+'. Review the upstream file before updating the manifest.')
    if target.suffix=='.svg':ET.fromstring(data)
    target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)

def main():
    if not shutil.which('rsvg-convert'):raise SystemExit('rsvg-convert is required. Install librsvg separately, then run setup again.')
    assets=json.loads((ROOT/'renderer-assets.json').read_text())['assets'];errors=[]
    with ThreadPoolExecutor(max_workers=5) as pool:
        tasks={pool.submit(fetch,item):item['target'] for item in assets}
        for task in as_completed(tasks):
            try:task.result()
            except Exception as error:errors.append(type(error).__name__+': '+str(error))
    if errors:raise SystemExit('\n'.join(errors))
    folder=ROOT/'private'/'renderer-assets';folder.mkdir(parents=True,exist_ok=True,mode=0o700)
    include=next((p for p in ['/opt/homebrew/etc/fonts/fonts.conf','/usr/local/etc/fonts/fonts.conf','/etc/fonts/fonts.conf'] if Path(p).exists()),'')
    config='<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd"><fontconfig>'
    if include:config+='<include ignore_missing="yes">'+html.escape(include)+'</include>'
    config+='<dir>'+html.escape(str(folder/'fonts'))+'</dir><cachedir>'+html.escape(str(folder/'cache'))+'</cachedir></fontconfig>'
    (folder/'fonts.conf').write_text(config)
    print('Renderer ready: verified local icons and Fira fonts. System fonts were not changed.')

if __name__=='__main__':main()
