#!/usr/bin/env python3
"""Parse a Linux wtmp file with UTC-accurate timestamps.

The bundled utmp.py helper decodes ut_tv.tv_sec with time.localtime(),
which applies whatever timezone the analysis machine is set to. This
version uses datetime.utcfromtimestamp() so timestamps line up with
auth.log (UTC on stock AWS Ubuntu AMIs) regardless of analyst timezone.
"""

import struct
import sys
import datetime

STATUS = {
    0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
    5: "INIT", 6: "LOGIN", 7: "USER", 8: "DEAD", 9: "ACCOUNTING",
}

RECORD_SIZE = 384


def parse(path):
    with open(path, "rb") as f:
        data = f.read()

    for offset in range(0, len(data), RECORD_SIZE):
        rec = data[offset:offset + RECORD_SIZE]
        if len(rec) < RECORD_SIZE:
            break
        typ = struct.unpack("<L", rec[0:4])[0]
        pid = struct.unpack("<L", rec[4:8])[0]
        line = rec[8:40].decode("utf-8", "replace").split("\0", 1)[0]
        user = rec[44:76].decode("utf-8", "replace").split("\0", 1)[0]
        host = rec[76:332].decode("utf-8", "replace").split("\0", 1)[0]
        session = struct.unpack("<L", rec[336:340])[0]
        sec = struct.unpack("<L", rec[340:344])[0]
        ts = datetime.datetime.utcfromtimestamp(sec).strftime("%Y-%m-%d %H:%M:%S UTC")
        yield {
            "type": STATUS.get(typ, typ), "pid": pid, "line": line,
            "user": user, "host": host, "session": session, "time": ts,
        }


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "wtmp"
    for r in parse(path):
        if r["type"] in ("USER", "DEAD", "LOGIN"):
            print(f"{r['type']:10} pid={r['pid']:<8} line={r['line']:<8} "
                  f"user={r['user']:<12} host={r['host']:<16} "
                  f"session={r['session']:<6} time={r['time']}")
