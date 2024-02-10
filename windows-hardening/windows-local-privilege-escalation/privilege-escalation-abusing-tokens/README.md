# 토큰 남용

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전을 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## 토큰

**Windows 액세스 토큰이 무엇인지 모르신다면**, 계속하기 전에 이 페이지를 읽어보세요:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**이미 가지고 있는 토큰을 남용하여 권한 상승을 할 수도 있습니다**

### SeImpersonatePrivilege

이 권한은 어떤 프로세스에서든 토큰을 가장할 수 있게 해줍니다. 특정 도구를 사용하여 Windows 서비스(DCOM)에서 특권 토큰을 얻을 수 있습니다. 이 취약점을 이용하여 NTLM 인증을 수행하고, 이후 SYSTEM 권한으로 프로세스를 실행할 수 있습니다. 이 취약점은 [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm을 비활성화해야 함), [SweetPotato](https://github.com/CCob/SweetPotato) 및 [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)와 같은 다양한 도구를 사용하여 악용할 수 있습니다.

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

**SeImpersonatePrivilege**와 매우 유사하며 특권 토큰을 얻는 **동일한 방법**을 사용합니다.\
그런 다음, 이 권한을 사용하여 새로운/중단된 프로세스에 **기본 토큰을 할당**할 수 있습니다. 특권 가장 토큰을 사용하여 기본 토큰(DuplicateTokenEx)을 파생시킬 수 있습니다.\
토큰을 사용하여 'CreateProcessAsUser'로 **새로운 프로세스**를 생성하거나 프로세스를 중단시키고 토큰을 **설정**할 수 있습니다(일반적으로 실행 중인 프로세스의 기본 토큰을 수정할 수 없습니다).

### SeTcbPrivilege

이 토큰을 활성화하면 **KERB\_S4U\_LOGON**을 사용하여 자격 증명을 알지 못하는 다른 사용자를 위한 **가장 토큰**을 얻을 수 있습니다. 임의의 그룹(관리자)을 토큰에 **추가**하고, 토큰의 **무결성 수준**을 "**중간**"으로 설정하고, 이 토큰을 **현재 스레드**에 할당할 수 있습니다(SetThreadToken).

### SeBackupPrivilege

이 권한으로 시스템은 이 권한으로 **모든 읽기 액세스** 제어를 어떤 파일에게나 부여합니다(읽기 작업에 제한됨). 이 권한은 레지스트리에서 로컬 관리자 계정의 **비밀번호 해시를 읽기 위해 사용**됩니다. 이후 "**psexec**" 또는 "**wmicexec**"와 같은 도구를 사용하여 해시를 사용할 수 있습니다(해시 전달 기법). 그러나 이 기법은 두 가지 조건에서 실패합니다. 로컬 관리자 계정이 비활성화되었거나 원격으로 연결하는 로컬 관리자의 관리 권한이 제거되는 정책이 적용된 경우입니다.\
다음과 같은 방법으로 이 권한을 **남용**할 수 있습니다:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)에서 **IppSec**을(를) 따르세요.
* 또는 다음의 **백업 연산자를 사용하여 권한 상승** 섹션에서 설명된 대로:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

이 권한은 파일의 액세스 제어 목록(ACL)과 관계없이 **시스템 파일에 대한 쓰기 액세스**를 허용합니다. 이 권한은 서비스 수정, DLL 하이재킹, 이미지 파일 실행 옵션을 통한 디버거 설정 등 다양한 기법을 통해 권한 상승의 여러 가지 가능성을 엽니다.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege는 특히 SeImpersonatePrivilege가 없는 경우에 유용한 강력한 권한입니다. 이 기능은 동일한 사용자를 나타내는 토큰을 가장할 수 있는 능력에 의존하지만 현재 프로세스의 무결성 수준을 초과하지 않는 토큰을 나타내는 토큰을 가장할 수 있는 경우에도 사용됩니다.

**주요 포인트:**
- **SeImpersonatePrivilege 없이 가장하기:** 특정 조건에서 SeCreateTokenPrivilege를 사용하여 특정 조건에서 토큰을 가장할 수 있으므로 권한 상승에 SeCreateTokenPrivilege를 활용할 수 있습니다.
- **
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)에서 이 특권을 남용하는 더 많은 방법을 찾을 수 있습니다.

### SeTakeOwnershipPrivilege

이는 **SeRestorePrivilege**와 유사합니다. 주요 기능은 명시적인 재량적 액세스 요구 사항을 우회하여 **객체의 소유권을 가정**할 수 있게 합니다. WRITE_OWNER 액세스 권한을 제공함으로써 이루어집니다. 프로세스는 먼저 쓰기 목적으로 의도한 레지스트리 키의 소유권을 보호한 다음, DACL을 수정하여 쓰기 작업을 가능하게 합니다.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

이 특권은 **다른 프로세스를 디버그**할 수 있게 해주며, 메모리에 읽고 쓸 수 있습니다. 이 특권을 사용하여 대부분의 백신 및 호스트 침입 방지 솔루션을 우회할 수 있는 다양한 메모리 인젝션 전략을 사용할 수 있습니다.

#### 메모리 덤프

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)의 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)를 사용하여 **프로세스의 메모리를 캡처**할 수 있습니다. 특히, 이는 사용자가 시스템에 성공적으로 로그인한 후 사용자 자격 증명을 저장하는 **로컬 보안 권한 하위 시스템 서비스 ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))** 프로세스에 적용될 수 있습니다.

그런 다음 이 덤프를 mimikatz에로드하여 암호를 얻을 수 있습니다:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` 쉘을 얻고 싶다면 다음을 사용할 수 있습니다:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## 권한 확인

To escalate privileges on a Windows system, it is important to first check the current privileges of the user. This can be done using various methods:

### 1. `whoami /priv`

The `whoami /priv` command can be used to display the privileges of the current user. This command will list all the privileges assigned to the user, including any enabled or disabled privileges.

### 2. `net user <username>`

The `net user <username>` command can be used to view the privileges assigned to a specific user. Replace `<username>` with the username of the user you want to check.

### 3. `whoami /groups`

The `whoami /groups` command can be used to display the group membership of the current user. This will show the groups that the user belongs to, which can provide information about the privileges they may have.

### 4. `secpol.msc`

The `secpol.msc` command can be used to open the Local Security Policy editor. From here, you can navigate to Security Settings > Local Policies > User Rights Assignment to view and modify the privileges assigned to different users and groups.

By checking the privileges of the current user, you can identify any potential privileges that can be abused for privilege escalation.
```
whoami /priv
```
**비활성화된 토큰**은 활성화할 수 있으며, 실제로 _활성화된_ 및 _비활성화된_ 토큰을 악용할 수 있습니다.

### 모든 토큰 활성화하기

토큰이 비활성화된 경우 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) 스크립트를 사용하여 모든 토큰을 활성화할 수 있습니다:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
또는 이 [게시물](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)에 포함된 **스크립트**를 사용하십시오.

## 테이블

전체 토큰 권한 치트 시트는 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)에서 확인할 수 있으며, 아래 요약은 관리자 세션을 얻거나 민감한 파일을 읽기 위해 권한을 악용하는 직접적인 방법만 나열합니다.

| 권한                       | 영향         | 도구                    | 실행 경로                                                                                                                                                                                                                                                                                                                                          | 비고                                                                                                                                                                                                                                                                                                                           |
| -------------------------- | ------------ | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**관리자**_ | 제3자 도구              | _"potato.exe, rottenpotato.exe 및 juicypotato.exe와 같은 도구를 사용하여 토큰을 가장하고 nt 시스템으로 권한 상승할 수 있습니다."_                                                                                                                                                                                                                          | 업데이트해 주신 [Aurélien Chalot](https://twitter.com/Defte_)에게 감사드립니다. 곧 레시피와 같은 형식으로 다시 작성해 보겠습니다.                                                                                                                                                                                        |
| **`SeBackup`**             | **위협**     | _**내장된 명령어**_     | `robocopy /b`로 민감한 파일 읽기                                                                                                                                                                                                                                                                                                                   | <p>- %WINDIR%\MEMORY.DMP를 읽을 수 있다면 더 흥미로울 수 있습니다.<br><br>- `SeBackupPrivilege` (및 robocopy)는 파일을 열 때 도움이 되지 않습니다.<br><br>- Robocopy는 /b 매개변수와 함께 작동하려면 SeBackup 및 SeRestore 모두 필요합니다.</p>                                                                                     |
| **`SeCreateToken`**        | _**관리자**_ | 제3자 도구              | `NtCreateToken`을 사용하여 로컬 관리자 권한을 포함한 임의의 토큰 생성                                                                                                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**관리자**_ | **PowerShell**          | `lsass.exe` 토큰 복제                                                                                                                                                                                                                                                                                                                             | [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)에서 스크립트 찾기                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**관리자**_ | 제3자 도구              | <p>1. `szkg64.sys`와 같은 버그가 있는 커널 드라이버 로드<br>2. 드라이버 취약점 악용<br><br>또는 `ftlMC` 내장 명령어를 사용하여 보안 관련 드라이버를 언로드하는 데 권한 사용 가능. 예: `fltMC sysmondrv`</p>                                                                                                                                           | <p>1. `szkg64` 취약점은 [CVE-2018-15732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732)로 나열됩니다.<br>2. `szkg64` [악용 코드](https://www.greyhathacker.net/?p=1025)는 [Parvez Anwar](https://twitter.com/parvezghh)가 작성했습니다.</p> |
| **`SeRestore`**            | _**관리자**_ | **PowerShell**          | <p>1. SeRestore 권한이 있는 PowerShell/ISE 실행<br>2. [Enable-SeRestorePrivilege](https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1)를 사용하여 권한 활성화<br>3. utilman.exe를 utilman.old로 이름 변경<br>4. cmd.exe를 utilman.exe로 이름 변경<br>5. 콘솔 잠금 후 Win+U 누르기</p> | 일부 AV 소프트웨어에서 공격을 감지할 수 있습니다.<p>대체 방법은 동일한 권한을 사용하여 "Program Files"에 저장된 서비스 이진 파일을 교체하는 것에 의존합니다.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**관리자**_ | _**내장된 명령어**_     | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe를 utilman.exe로 이름 변경<br>4. 콘솔 잠금 후 Win+U 누르기</p>                                                                                                                                       | 일부 AV 소프트웨어에서 공격을 감지할 수 있습니다.<p>대체 방법은 동일한 권한을 사용하여 "Program Files"에 저장된 서비스 이진 파일을 교체하는 것에 의존합니다.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**관리자**_ | 제3자 도구              | 로컬 관리자 권한을 포함한 토큰 조작. SeImpersonate가 필요할 수 있음.                                                                                                                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |

## 참고

* Windows 토큰을 정의하는 이 테이블을 확인하세요: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* 토큰을 사용한 권한 상승에 대한 [**이 논문**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt)을 확인하세요.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하고 계신가요? **회사를 HackTricks에서 홍보**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 확인하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks 저장소](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud 저장소](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
