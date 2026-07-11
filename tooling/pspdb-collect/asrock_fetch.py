import os, sys, zipfile, io, re
os.environ["PSPDB_SELENIUM_USE_REMOTE_DRIVER"]="true"
os.environ["PSPDB_SELENIUM_HOST"]="localhost"; os.environ["PSPDB_SELENIUM_PORT"]="4444"
from pspdb.database import connect_db, Device
from pony.orm import db_session, select
from pspdb.strategies import asrock_consumer_motherboard
import requests

connect_db("sqlite","/tmp/PSP-DB/pspdb.sqlite",None)
TARGET = sys.argv[1] if len(sys.argv)>1 else "B650 PG Lightning"
with db_session:
    dev = select(d for d in Device if d.vendor=="asrock" and d.name==TARGET).first()
    if not dev: print("NOT FOUND:", TARGET); sys.exit(2)
    did = dev.id
print(f"resolving BIOS page for '{TARGET}' (id={did}) via selenium...", flush=True)
asrock_consumer_motherboard.get(did)
with db_session:
    dev = Device[did]
    dls = [d for d in dev.downloads]
    dls.sort(key=lambda d: str(d.date), reverse=True)
    print(f"  {len(dls)} BIOS entries resolved")
    for d in dls[:4]: print(f"    v{d.vendor_version} {d.date}: {d.link}")
    if not dls: print("NO BIOS LINKS — asrock page shape may have changed"); sys.exit(3)
    newest = dls[0]; link = newest.link; ver = str(newest.vendor_version)
os.makedirs("/tmp/psp-extra/corpus", exist_ok=True)
print(f"downloading newest (v{ver}): {link}", flush=True)
r = requests.get(link, timeout=180, headers={"User-Agent":"Mozilla/5.0"}, allow_redirects=True)
r.raise_for_status(); data = r.content
print(f"  downloaded {len(data)} bytes; magic={data[:4]!r}")
# extract ROM: try zip first
rom_bytes=None; rom_name=None
if data[:2]==b'PK':
    z=zipfile.ZipFile(io.BytesIO(data))
    cand=sorted(z.infolist(), key=lambda i:i.file_size, reverse=True)
    for i in cand:
        if i.file_size>1_000_000:  # the ROM is the big file
            rom_bytes=z.read(i.filename); rom_name=os.path.basename(i.filename); break
else:
    rom_bytes=data; rom_name=f"asrock_{TARGET.replace(' ','_')}_{ver}.rom"
print(f"  ROM file: {rom_name} ({len(rom_bytes) if rom_bytes else 0} bytes)")
if not rom_bytes: print("no ROM extracted"); sys.exit(4)
safe=f"ASRock_{TARGET.replace(' ','_').replace('/','')}_{ver}.bin"
outp=f"/tmp/psp-extra/corpus/{safe}"
open(outp,"wb").write(rom_bytes)
# analyze with reference psptool
from psptool import PSPTool
try:
    pt=PSPTool.from_file(outp)
    ndirs=len(pt.blob.directories) if hasattr(pt.blob,"directories") else "?"
    print(f"  psptool PARSED OK: {ndirs} directories. saved -> {outp}")
    # zen generation(s)
    gens=set()
    for d in getattr(pt.blob,"directories",[]):
        g=getattr(d,"zen_generation",None) or getattr(d,"magic",None)
        if g: gens.add(str(g))
    print(f"  zen/dir markers: {sorted(gens)[:8]}")
except Exception as e:
    print(f"  psptool parse ERROR: {e}")
