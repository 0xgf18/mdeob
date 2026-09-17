#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build mdeob_dist.py -- one file tool with smali/baksmali jars + keystore embedded."""
import base64
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "mdeob.py")
OUT = os.path.join(HERE, "mdeob_dist.py")

RES = {
    "baksmali.jar": os.path.join(HERE, "baksmali.jar"),
    "smali.jar": os.path.join(HERE, "smali.jar"),
    "apksigner.jar": os.path.join(HERE, "apksigner.jar"),
    "mdeob.keystore": os.path.join(HERE, "mdeob.keystore"),
}

def main():
    with open(SRC, encoding="utf-8") as f:
        src = f.read()

    table = ",\n".join(
        "    %r: %r" % (name,
                        base64.b64encode(open(path, "rb").read()).decode("ascii"))
        for name, path in sorted(RES.items())
        if os.path.exists(path)
    )
    filled = "BUNDLED = {\n%s\n}" % table

    if "BUNDLED = {}" not in src:
        sys.stderr.write("mdeob.py missing 'BUNDLED = {}' sentinel\n")
        sys.exit(1)
    dist = src.replace("BUNDLED = {}", filled, 1)

    with open(OUT, "w", encoding="utf-8") as f:
        f.write(dist)

    sizes = {os.path.basename(p): os.path.getsize(p) for p in RES.values()
             if os.path.exists(p)}
    total = os.path.getsize(OUT)
    print("bundled: %s" % ", ".join("%s (%d B)" % (k, v) for k, v in sorted(sizes.items())))
    print("wrote   : %s (%d B)" % (OUT, total))

if __name__ == "__main__":
    main()