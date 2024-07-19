# Windows Credentials Protections

## Credentials Protections

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) 프로토콜은 Windows XP와 함께 도입되었으며, HTTP 프로토콜을 통한 인증을 위해 설계되었으며 **Windows XP에서 Windows 8.0 및 Windows Server 2003에서 Windows Server 2012까지 기본적으로 활성화되어 있습니다**. 이 기본 설정은 **LSASS(로컬 보안 권한 하위 시스템 서비스)에서 평문 비밀번호 저장**을 초래합니다. 공격자는 Mimikatz를 사용하여 **이 자격 증명을 추출할 수 있습니다**:
```bash
sekurlsa::wdigest
```
이 기능을 **켜거나 끄려면**, _**UseLogonCredential**_ 및 _**Negotiate**_ 레지스트리 키가 _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 내에서 "1"로 설정되어야 합니다. 이러한 키가 **없거나 "0"으로 설정되어 있으면**, WDigest는 **비활성화**됩니다:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA 보호

**Windows 8.1**부터 Microsoft는 LSA의 보안을 강화하여 **신뢰할 수 없는 프로세스에 의한 무단 메모리 읽기 또는 코드 주입을 차단**합니다. 이 강화는 `mimikatz.exe sekurlsa:logonpasswords`와 같은 명령의 일반적인 기능을 방해합니다. 이 _**강화된 보호**_를 **활성화**하려면 _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_의 _**RunAsPPL**_ 값을 1로 조정해야 합니다:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

이 보호를 우회하는 것은 Mimikatz 드라이버 mimidrv.sys를 사용하여 가능합니다:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**는 **Windows 10 (Enterprise 및 Education 에디션)** 전용 기능으로, **Virtual Secure Mode (VSM)** 및 **Virtualization Based Security (VBS)**를 사용하여 머신 자격 증명의 보안을 강화합니다. 이는 CPU 가상화 확장을 활용하여 주요 프로세스를 보호된 메모리 공간 내에서 격리시켜, 주요 운영 체제의 접근을 차단합니다. 이 격리는 커널조차 VSM의 메모리에 접근할 수 없도록 하여, **pass-the-hash**와 같은 공격으로부터 자격 증명을 효과적으로 보호합니다. **Local Security Authority (LSA)**는 이 안전한 환경 내에서 신뢰할 수 있는 요소로 작동하며, 주요 OS의 **LSASS** 프로세스는 VSM의 LSA와 단순히 통신하는 역할만 합니다.

기본적으로 **Credential Guard**는 활성화되어 있지 않으며, 조직 내에서 수동으로 활성화해야 합니다. 이는 **Mimikatz**와 같은 도구에 대한 보안을 강화하는 데 중요하며, 이러한 도구들이 자격 증명을 추출하는 능력이 제한됩니다. 그러나 사용자 정의 **Security Support Providers (SSP)**를 추가하여 로그인 시도 중에 자격 증명을 평문으로 캡처하는 취약점은 여전히 악용될 수 있습니다.

**Credential Guard**의 활성화 상태를 확인하려면, _**HKLM\System\CurrentControlSet\Control\LSA**_ 아래의 레지스트리 키 _**LsaCfgFlags**_를 검사할 수 있습니다. "**1**" 값은 **UEFI 잠금**이 있는 활성화를 나타내고, "**2**"는 잠금 없이, "**0**"은 활성화되지 않았음을 나타냅니다. 이 레지스트리 확인은 강력한 지표이지만, Credential Guard를 활성화하기 위한 유일한 단계는 아닙니다. 이 기능을 활성화하기 위한 자세한 안내와 PowerShell 스크립트는 온라인에서 확인할 수 있습니다.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
For a comprehensive understanding and instructions on enabling **Credential Guard** in Windows 10 and its automatic activation in compatible systems of **Windows 11 Enterprise and Education (version 22H2)**, visit [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Further details on implementing custom SSPs for credential capture are provided in [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 및 Windows Server 2012 R2**는 _**RDP를 위한 제한된 관리자 모드**_를 포함한 여러 새로운 보안 기능을 도입했습니다. 이 모드는 [**해시 전달**](https://blog.ahasayen.com/pass-the-hash/) 공격과 관련된 위험을 완화하여 보안을 강화하기 위해 설계되었습니다.

전통적으로 RDP를 통해 원격 컴퓨터에 연결할 때, 귀하의 자격 증명은 대상 컴퓨터에 저장됩니다. 이는 특히 권한이 상승된 계정을 사용할 때 상당한 보안 위험을 초래합니다. 그러나 _**제한된 관리자 모드**_의 도입으로 이 위험이 크게 줄어듭니다.

**mstsc.exe /RestrictedAdmin** 명령을 사용하여 RDP 연결을 시작할 때, 원격 컴퓨터에 귀하의 자격 증명을 저장하지 않고 인증이 수행됩니다. 이 접근 방식은 악성 소프트웨어 감염이 발생하거나 악의적인 사용자가 원격 서버에 접근할 경우 귀하의 자격 증명이 손상되지 않도록 보장합니다. 왜냐하면 자격 증명이 서버에 저장되지 않기 때문입니다.

**제한된 관리자 모드**에서는 RDP 세션에서 네트워크 리소스에 접근하려는 시도가 귀하의 개인 자격 증명을 사용하지 않고, 대신 **기계의 신원**이 사용된다는 점에 유의해야 합니다.

이 기능은 원격 데스크톱 연결을 보호하고 보안 위반 시 민감한 정보가 노출되는 것을 방지하는 데 있어 중요한 진전을 나타냅니다.

![](../../.gitbook/assets/RAM.png)

For more detailed information on visit [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows는 **로컬 보안 권한(LSA)**를 통해 **도메인 자격 증명**을 보호하며, **Kerberos** 및 **NTLM**과 같은 보안 프로토콜로 로그온 프로세스를 지원합니다. Windows의 주요 기능 중 하나는 **마지막 10개의 도메인 로그인**을 캐시하여 **도메인 컨트롤러가 오프라인**일 때도 사용자가 여전히 컴퓨터에 접근할 수 있도록 하는 것입니다. 이는 회사 네트워크에서 자주 떨어져 있는 노트북 사용자에게 유용합니다.

캐시된 로그인 수는 특정 **레지스트리 키 또는 그룹 정책**을 통해 조정할 수 있습니다. 이 설정을 보거나 변경하려면 다음 명령을 사용합니다:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Access to these cached credentials is tightly controlled, with only the **SYSTEM** account having the necessary permissions to view them. Administrators needing to access this information must do so with SYSTEM user privileges. The credentials are stored at: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** can be employed to extract these cached credentials using the command `lsadump::cache`.

For further details, the original [source](http://juggernaut.wikidot.com/cached-credentials) provides comprehensive information.

## Protected Users

Membership in the **Protected Users group** introduces several security enhancements for users, ensuring higher levels of protection against credential theft and misuse:

* **Credential Delegation (CredSSP)**: Even if the Group Policy setting for **Allow delegating default credentials** is enabled, plain text credentials of Protected Users will not be cached.
* **Windows Digest**: Starting from **Windows 8.1 and Windows Server 2012 R2**, the system will not cache plain text credentials of Protected Users, regardless of the Windows Digest status.
* **NTLM**: The system will not cache Protected Users' plain text credentials or NT one-way functions (NTOWF).
* **Kerberos**: For Protected Users, Kerberos authentication will not generate **DES** or **RC4 keys**, nor will it cache plain text credentials or long-term keys beyond the initial Ticket-Granting Ticket (TGT) acquisition.
* **Offline Sign-In**: Protected Users will not have a cached verifier created at sign-in or unlock, meaning offline sign-in is not supported for these accounts.

이러한 보호 기능은 **Protected Users group**의 구성원이 장치에 로그인하는 순간 활성화됩니다. 이는 다양한 자격 증명 손상 방법으로부터 보호하기 위한 중요한 보안 조치가 마련되어 있음을 보장합니다.

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

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
