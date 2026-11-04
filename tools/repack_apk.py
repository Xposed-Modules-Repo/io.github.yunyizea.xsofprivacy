"""Assemble unsigned APK without recompressing Android resource tables.

Run before signing; arguments: resource-apk, classes.dex, xposed_init, output.
No mutation of a previously signed APK is supported.
"""
import struct
import sys
import zipfile
from pathlib import Path


def assemble(resource_apk, dex, entry, output):
    with zipfile.ZipFile(resource_apk) as src:
        entries = [(n, src.read(n)) for n in src.namelist()]
    entries += [("classes.dex", Path(dex).read_bytes())]
    asset_root = Path(entry).parent
    entries += [("assets/" + p.relative_to(asset_root).as_posix(), p.read_bytes())
                for p in sorted(asset_root.rglob("*")) if p.is_file()]
    with zipfile.ZipFile(output, "w") as dst:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 4, 0, 0, 0))
            info.compress_type = (zipfile.ZIP_STORED if name.endswith(".arsc")
                                  else zipfile.ZIP_DEFLATED)
            if info.compress_type == zipfile.ZIP_STORED:
                offset = dst.fp.tell() + 30 + len(name.encode("utf-8"))
                padding = (-offset) % 4
                if padding:
                    info.extra = struct.pack("<HH", 0xFFFF, padding) + bytes(padding)
            dst.writestr(info, data)
    verify(output)


def verify(path):
    with zipfile.ZipFile(path) as apk, open(path, "rb") as raw:
        assert apk.testzip() is None, "ZIP integrity check failed"
        table = apk.getinfo("resources.arsc")
        assert table.compress_type == zipfile.ZIP_STORED, "Compressed resources.arsc"
        for item in apk.infolist():
            if item.compress_type != zipfile.ZIP_STORED:
                continue
            raw.seek(item.header_offset)
            header = raw.read(30)
            assert header[:4] == b"PK\x03\x04", "Invalid local header"
            name_len, extra_len = struct.unpack_from("<HH", header, 26)
            offset = item.header_offset + 30 + name_len + extra_len
            assert offset % 4 == 0, f"Unaligned entry: {item.filename} at {offset}"
            print(f"PASS {item.filename}: STORED, offset={offset}, alignment=4")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--verify":
        verify(sys.argv[2])
    elif len(sys.argv) == 5:
        assemble(*sys.argv[1:])
    else:
        raise SystemExit("Usage: repack_apk.py resource-apk classes.dex xposed_init output\n"
                         "   or: repack_apk.py --verify signed.apk")
