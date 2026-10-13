"""Import a downloaded official sparse-index entry into a workspace Cargo cache.

Used only in this restricted environment; ordinary machines can use cargo fetch.
"""
import json
import pathlib
import sys

name = sys.argv[1]
relative = ("1/" + name if len(name) == 1 else "2/" + name if len(name) == 2
            else "3/" + name[0] + "/" + name if len(name) == 3
            else name[:2] + "/" + name[2:4] + "/" + name)
root = pathlib.Path('.cache/cargo/registry/index/index.crates.io-1949cf8c6b5b557f')
target = root / '.cache' / relative
target.parent.mkdir(parents=True, exist_ok=True)
data = bytearray(b'\x03\x02\x00\x00\x00etag: "workspace-import"\x00')
for line in pathlib.Path('.cache/index-entry.jsonl').read_bytes().splitlines():
    entry = json.loads(line)
    data.extend(entry['vers'].encode() + b'\x00' + line + b'\x00')
target.write_bytes(data)
