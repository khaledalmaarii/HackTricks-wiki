# Windows Credentials Protections

## Credentials Protections

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## WDigest

The [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396) protocol, introduced with Windows XP, is designed for authentication via the HTTP Protocol and is **enabled by default on Windows XP through Windows 8.0 and Windows Server 2003 to Windows Server 2012**. This default setting results in **plain-text password storage in LSASS** (Local Security Authority Subsystem Service). An attacker can use Mimikatz to **extract these credentials** by executing:

---

## qo' vItlhutlh

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396) protokol, Windows XP jatlhlaH, HTTP protokolDaq jabbI'IDchaj 'e' yIlo' je Windows XP through Windows 8.0 je Windows Server 2003 through Windows Server 2012. vItlhutlhDaq **plain-text password storage in LSASS** (Local Security Authority Subsystem Service) jatlhlaH. 'ach vItlhutlhDaq, 'oH attacker Mimikatz **credentials** **extract** vItlhutlhDaq:
```bash
sekurlsa::wdigest
```
**ghItlh** _**UseLogonCredential**_ **je** _**Negotiate**_ **registry key** **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest** **DaH** "1" **qIm** **vItlhutlh**. **vaj** **DaH** **'oH** **'ej** "0" **qIm** **vItlhutlh**, WDigest **qoH**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection

**Windows 8.1** jatlhlaHbe'chugh, Microsoft LSA **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh** **ghItlhvam vItlhutlh**
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

mimidrv.sys jIHDaq Mimikatz driver vItlhutlh.

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**, **Windows 10 (Enterprise and Education editions)** vItlhutlh, **Virtual Secure Mode (VSM)** je **Virtualization Based Security (VBS)** vItlhutlh, machine credentials vItlhutlh. CPU virtualization extensions vItlhutlh, key processes vItlhutlh protected memory space vItlhutlh, DaH jup 'e' vItlhutlh. vSM, kernel vItlhutlh memory vItlhutlh access, **pass-the-hash** vItlhutlh attacks vItlhutlh credentials vItlhutlh. **Local Security Authority (LSA)** vItlhutlh trustlet vItlhutlh secure environment vItlhutlh, **LSASS** process vItlhutlh main OS vItlhutlh communicator vItlhutlh VSM's LSA vItlhutlh.

**Credential Guard**, organization vItlhutlh manual activation vItlhutlh. **Mimikatz** vItlhutlh tools vItlhutlh credentials vItlhutlh extract vItlhutlh hindered vItlhutlh, security vItlhutlh critical vItlhutlh. However, vulnerabilities vItlhutlh custom **Security Support Providers (SSP)** vItlhutlh credentials vItlhutlh capture vItlhutlh clear text vItlhutlh login attempts vItlhutlh exploited vItlhutlh.

**Credential Guard**'s activation status vItlhutlh verify, registry key **_LsaCfgFlags_** vItlhutlh **_HKLM\System\CurrentControlSet\Control\LSA_** vItlhutlh inspect vItlhutlh. Value "**1**" vItlhutlh activation **UEFI lock** vItlhutlh, "**2**" vItlhutlh lock vItlhutlh, "**0**" vItlhutlh enabled vItlhutlh. Registry check vItlhutlh, strong indicator vItlhutlh, Credential Guard vItlhutlh enable vItlhutlh sole step vItlhutlh. Detailed guidance je PowerShell script vItlhutlh enabling feature vItlhutlh online vItlhutlh.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
For a comprehensive understanding and instructions on enabling **Credential Guard** in Windows 10 and its automatic activation in compatible systems of **Windows 11 Enterprise and Education (version 22H2)**, visit [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Further details on implementing custom SSPs for credential capture are provided in [this guide](../active-directory-methodology/custom-ssp.md).


## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** introduced several new security features, including the **_Restricted Admin mode for RDP_**. This mode was designed to enhance security by mitigating the risks associated with **[pass the hash](https://blog.ahasayen.com/pass-the-hash/)** attacks.

Traditionally, when connecting to a remote computer via RDP, your credentials are stored on the target machine. This poses a significant security risk, especially when using accounts with elevated privileges. However, with the introduction of **_Restricted Admin mode_**, this risk is substantially reduced.

When initiating an RDP connection using the command **mstsc.exe /RestrictedAdmin**, authentication to the remote computer is performed without storing your credentials on it. This approach ensures that, in the event of a malware infection or if a malicious user gains access to the remote server, your credentials are not compromised, as they are not stored on the server.

It's important to note that in **Restricted Admin mode**, attempts to access network resources from the RDP session will not use your personal credentials; instead, the **machine's identity** is used.

This feature marks a significant step forward in securing remote desktop connections and protecting sensitive information from being exposed in case of a security breach.

![](../../.gitbook/assets/ram.png)

For more detailed information on visit [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).


## Cached Credentials

Windows secures **domain credentials** through the **Local Security Authority (LSA)**, supporting logon processes with security protocols like **Kerberos** and **NTLM**. A key feature of Windows is its capability to cache the **last ten domain logins** to ensure users can still access their computers even if the **domain controller is offline**—a boon for laptop users often away from their company's network.

The number of cached logins is adjustable via a specific **registry key or group policy**. To view or change this setting, the following command is utilized:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Access to these cached credentials is tightly controlled, with only the **SYSTEM** account having the necessary permissions to view them. Administrators needing to access this information must do so with SYSTEM user privileges. The credentials are stored at: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** can be employed to extract these cached credentials using the command `lsadump::cache`.

For further details, the original [source](http://juggernaut.wikidot.com/cached-credentials) provides comprehensive information.


## Protected Users

Membership in the **Protected Users group** introduces several security enhancements for users, ensuring higher levels of protection against credential theft and misuse:

- **Credential Delegation (CredSSP)**: Even if the Group Policy setting for **Allow delegating default credentials** is enabled, plain text credentials of Protected Users will not be cached.
- **Windows Digest**: Starting from **Windows 8.1 and Windows Server 2012 R2**, the system will not cache plain text credentials of Protected Users, regardless of the Windows Digest status.
- **NTLM**: The system will not cache Protected Users' plain text credentials or NT one-way functions (NTOWF).
- **Kerberos**: For Protected Users, Kerberos authentication will not generate **DES** or **RC4 keys**, nor will it cache plain text credentials or long-term keys beyond the initial Ticket-Granting Ticket (TGT) acquisition.
- **Offline Sign-In**: Protected Users will not have a cached verifier created at sign-in or unlock, meaning offline sign-in is not supported for these accounts.

These protections are activated the moment a user, who is a member of the **Protected Users group**, signs into the device. This ensures that critical security measures are in place to safeguard against various methods of credential compromise.

For more detailed information, consult the official [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
