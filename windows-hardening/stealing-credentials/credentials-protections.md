# Windows Credentials Protections

## 자격 증명 보호

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) 프로토콜은 Windows XP부터 도입되었으며, HTTP 프로토콜을 통한 인증을 위해 설계되었습니다. 이 프로토콜은 **Windows XP에서 Windows 8.0 및 Windows Server 2003에서 Windows Server 2012까지 기본적으로 활성화**되어 있습니다. 이 기본 설정으로 인해 LSASS(로컬 보안 권한 부분 시스템 서비스)에는 **평문 암호 저장**이 이루어집니다. 공격자는 Mimikatz를 사용하여 다음 명령을 실행하여 이러한 자격 증명을 **추출**할 수 있습니다:

```bash
sekurlsa::wdigest
```

**이 기능을 끄거나 켜려면**, _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ 내의 _**UseLogonCredential**_ 및 _**Negotiate**_ 레지스트리 키를 "1"로 설정해야 합니다. 이러한 키가 **없거나 "0"으로 설정**되어 있으면 WDigest가 **비활성화**됩니다.

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```

## LSA 보호

**Windows 8.1**부터 Microsoft는 LSA의 보안을 강화하여 **신뢰되지 않는 프로세스에 의한 무단 메모리 읽기 또는 코드 주입을 차단**합니다. 이 개선 사항은 `mimikatz.exe sekurlsa:logonpasswords`와 같은 명령어의 일반적인 기능을 방해합니다. 이 **강화된 보호를 활성화**하려면 \_**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**\_의 _**RunAsPPL**_ 값을 1로 조정해야 합니다:

```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```

### 우회

Mimikatz 드라이버 mimidrv.sys를 사용하여 이 보호를 우회할 수 있습니다:

![](../../.gitbook/assets/mimidrv.png)

## 자격 증명 보호

\*\*자격 증명 보호(Credential Guard)\*\*는 \*\*Windows 10(Enterprise 및 Education 버전)\*\*에만 있는 기능으로, \*\*가상 보안 모드(VSM)\*\*와 \*\*가상화 기반 보안(VBS)\*\*을 사용하여 기계 자격 증명의 보안을 강화합니다. 이 기능은 CPU 가상화 확장을 활용하여 주요 프로세스를 보호된 메모리 공간에 격리시켜 메인 운영 체제의 접근을 차단합니다. 이 격리는 커널조차 VSM의 메모리에 접근할 수 없도록 하여 \*\*해시 전달(pass-the-hash)\*\*과 같은 공격으로부터 자격 증명을 효과적으로 보호합니다. \*\*로컬 보안 권한자(LSA)\*\*는 신뢰성 있는 환경으로서 이 보안 환경 내에서 작동하며, 메인 운영 체제의 LSASS 프로세스는 VSM의 LSA와 통신하는 역할만 수행합니다.

기본적으로 **자격 증명 보호**는 비활성화되어 있으며 조직에서 수동으로 활성화해야 합니다. 이 기능은 **Mimikatz**와 같은 도구가 자격 증명을 추출하는 능력이 제한되도록 보안을 강화하는 데 중요합니다. 그러나 사용자 정의 \*\*보안 지원 공급자(SSP)\*\*를 추가하여 로그인 시도 중에 평문으로 자격 증명을 캡처하는 취약점은 여전히 악용될 수 있습니다.

**자격 증명 보호**의 활성화 상태를 확인하기 위해 레지스트리 키 _**HKLM\System\CurrentControlSet\Control\LSA**_ 아래의 _**LsaCfgFlags**_ 레지스트리 키를 검사할 수 있습니다. 값이 "**1**"이면 **UEFI 잠금**으로 활성화되었음을 나타내고, "**2**"는 잠금 없이 활성화되었음을 나타내며, "**0**"은 비활성화되었음을 나타냅니다. 이 레지스트리 확인은 강력한 지표이지만, 자격 증명 보호를 활성화하기 위한 유일한 단계는 아닙니다. 자세한 지침과 이 기능을 활성화하기 위한 PowerShell 스크립트는 온라인에서 제공됩니다.

```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```

Windows 10에서 **Credential Guard**를 활성화하고 \*\*Windows 11 Enterprise 및 Education (버전 22H2)\*\*의 호환 시스템에서 자동으로 활성화하는 방법에 대한 포괄적인 이해와 지침은 [Microsoft의 문서](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)를 참조하십시오.

자격 캡처를 위한 사용자 정의 SSP를 구현하는 자세한 내용은 [이 가이드](../active-directory-methodology/custom-ssp.md)에서 제공됩니다.

## RDP RestrictedAdmin 모드

**Windows 8.1 및 Windows Server 2012 R2**에서는 _**RDP의 Restricted Admin 모드**_를 포함한 여러 가지 새로운 보안 기능이 도입되었습니다. 이 모드는 [**해시 전달**](https://blog.ahasayen.com/pass-the-hash/) 공격과 관련된 위험을 완화하여 보안을 강화하기 위해 설계되었습니다.

기존에는 RDP를 통해 원격 컴퓨터에 연결할 때 자격 증명이 대상 컴퓨터에 저장되었습니다. 특히 권한이 상승된 계정을 사용할 때 이는 상당한 보안 위험을 초래합니다. 그러나 _**Restricted Admin 모드**_의 도입으로 이러한 위험은 크게 감소되었습니다.

**mstsc.exe /RestrictedAdmin** 명령을 사용하여 RDP 연결을 시작할 때, 원격 컴퓨터로의 인증은 자격 증명을 저장하지 않고 수행됩니다. 이 접근 방식은 악성 코드 감염이 발생하거나 악의적 사용자가 원격 서버에 액세스하는 경우 자격 증명이 서버에 저장되지 않으므로 자격 증명이 노출되지 않습니다.

**Restricted Admin 모드**에서는 RDP 세션에서 네트워크 리소스에 액세스하려는 시도가 개인 자격 증명 대신 **기기의 신원**을 사용합니다.

이 기능은 원격 데스크톱 연결을 보호하고 보안 침해 발생 시 민감한 정보가 노출되는 것을 방지하는 데 있어서 중요한 발전입니다.

![](../../.gitbook/assets/ram.png)

자세한 정보는 [이 자료](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)를 참조하십시오.

## 캐시된 자격 증명

Windows는 \*\*로컬 보안 권한 (LSA)\*\*를 통해 **도메인 자격 증명**을 보호하며, **Kerberos** 및 **NTLM**과 같은 보안 프로토콜을 사용하여 로그온 프로세스를 지원합니다. Windows의 주요 기능 중 하나는 **마지막 10개의 도메인 로그인**을 캐시하여 사용자가 **도메인 컨트롤러가 오프라인인 경우에도** 컴퓨터에 계속 액세스할 수 있도록 하는 것입니다. 이는 종종 회사 네트워크에서 벗어나는 노트북 사용자에게 큰 도움이 됩니다.

캐시된 로그인 수는 특정 **레지스트리 키 또는 그룹 정책**을 통해 조정할 수 있습니다. 이 설정을 보거나 변경하려면 다음 명령을 사용합니다:

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

이러한 캐시된 자격 증명에 대한 액세스는 엄격히 제어되며, **SYSTEM** 계정만이 이를 볼 수 있는 필요한 권한을 가지고 있습니다. 이 정보에 액세스해야 하는 관리자는 SYSTEM 사용자 권한으로 이를 수행해야 합니다. 자격 증명은 다음 위치에 저장됩니다: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz**를 사용하여 `lsadump::cache` 명령을 사용하여 이러한 캐시된 자격 증명을 추출할 수 있습니다.

자세한 내용은 원본 [소스](http://juggernaut.wikidot.com/cached-credentials)에서 포괄적인 정보를 제공합니다.

## 보호된 사용자

**보호된 사용자 그룹**에 속한 사용자는 자격 증명 도용 및 남용에 대한 더 높은 수준의 보호를 보장하기 위해 여러 보안 개선 사항을 도입합니다:

* **자격 증명 위임 (CredSSP)**: **기본 자격 증명 위임 허용** 그룹 정책 설정이 활성화되어 있더라도, 보호된 사용자의 평문 자격 증명은 캐시되지 않습니다.
* **Windows Digest**: **Windows 8.1 및 Windows Server 2012 R2**부터, 보호된 사용자의 평문 자격 증명은 Windows Digest 상태에 관계없이 캐시되지 않습니다.
* **NTLM**: 시스템은 보호된 사용자의 평문 자격 증명이나 NT 일방향 함수 (NTOWF)를 캐시하지 않습니다.
* **Kerberos**: 보호된 사용자의 경우, Kerberos 인증은 **DES** 또는 **RC4 키**를 생성하지 않으며, 평문 자격 증명이나 초기 Ticket-Granting Ticket (TGT) 획득 이후의 장기 키도 캐시하지 않습니다.
* **오프라인 로그인**: 보호된 사용자는 로그인 또는 잠금 해제 시 캐시된 검증자가 생성되지 않으므로, 이러한 계정에 대한 오프라인 로그인은 지원되지 않습니다.

이러한 보호 기능은 **보호된 사용자 그룹**의 구성원인 사용자가 장치에 로그인할 때 즉시 활성화됩니다. 이를 통해 다양한 자격 증명 침해 방법에 대한 중요한 보안 조치가 시행되는 것을 보장합니다.

더 자세한 정보는 공식 [문서](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)를 참조하십시오.

**문서에서 가져온 표**입니다. [**문서**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**에서 확인하세요**.

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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
