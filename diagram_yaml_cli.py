"""Compatibility entry point: discovery database -> YAML -> build.py."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import asset_inventory
from diagram_yaml import generated,dump,ROOT


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--discovered-db',type=Path,required=True);parser.add_argument('--site',required=True)
    parser.add_argument('--out',type=Path,default=ROOT/'out');parser.add_argument('--redacted',action='store_true');parser.add_argument('--svg-only',action='store_true')
    args=parser.parse_args(argv);path=args.discovered_db.expanduser().resolve()
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
        db.row_factory=sqlite3.Row
        sites=[{**dict(r),'targets':json.loads(r['targets'])} for r in db.execute('SELECT * FROM sites')]
        document=generated({**asset_inventory.state(db),'sites':sites},args.site)
    args.out.mkdir(parents=True,exist_ok=True)
    stem=args.site+'-original-style-'+('redacted' if args.redacted else 'private')
    yaml_path=args.out/(stem+'.yaml');yaml_path.write_text(dump(document));yaml_path.chmod(0o600)
    with tempfile.TemporaryDirectory(prefix='labmap-original-build-') as folder:
        command=[sys.executable,str(ROOT/'build.py'),'--inventory',str(yaml_path.resolve()),'--out',folder]
        if not args.redacted:command.append('--unredacted')
        if args.svg_only:command.append('--svg-only')
        subprocess.run(command,check=True)
        source='homelab' if args.redacted else 'homelab-unredacted'
        for extension in ['svg']+([] if args.svg_only else ['png']):shutil.copy2(Path(folder)/(source+'.'+extension),args.out/(stem+'.'+extension))
    print('Generated YAML and ran build.py:',stem)
    return 0
