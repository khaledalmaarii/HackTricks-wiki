# 토큰 남용

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하고 싶으신가요? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우**하세요.
* **해킹 요령을 공유하려면 [hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**로 PR을 제출하세요.

</details>

## 토큰

**Windows 액세스 토큰이 무엇인지 모르는 경우** 계속하기 전에 이 페이지를 읽어보세요:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**이미 가지고 있는 토큰을 남용하여 권한 상승을 할 수도 있습니다**

### SeImpersonatePrivilege

이 특권은 어떤 프로세스가 토큰을 생성하지는 못하지만 어떤 토큰이든 위임할 수 있게 해줍니다. 특권이 있는 토큰은 Windows 서비스(DCOM)로부터 얻을 수 있으며, 해당 서비스를 NTLM 인증을 수행하도록 유도하여 exploit을 통해 SYSTEM 권한으로 프로세스를 실행할 수 있게 됩니다. 이 취약점은 [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm 비활성화 필요), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)와 같은 다양한 도구를 사용하여 악용할 수 있습니다.

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

**SeImpersonatePrivilege**와 매우 유사하며 특권을 얻기 위해 **동일한 방법**을 사용합니다.\
이 특권은 **새로운/일시 중단된 프로세스에 기본 토큰을 할당**할 수 있습니다. 특권 있는 위임 토큰을 사용하여 기본 토큰(DuplicateTokenEx)을 파생시킬 수 있습니다.\
토큰을 사용하여 'CreateProcessAsUser'로 **새로운 프로세스**를 생성하거나 프로세스를 일시 중단시키고 토큰을 설정할 수 있습니다(일반적으로 실행 중인 프로세스의 기본 토큰을 수정할 수 없습니다).

### SeTcbPrivilege

이 토큰을 활성화하면 **KERB\_S4U\_LOGON**을 사용하여 자격 증명을 알지 못해도 다른 사용자를 위한 **위임 토큰**을 얻을 수 있습니다. 임의의 그룹(관리자)을 토큰에 **추가**하고, 토큰의 **무결성 수준**을 "**중간**"으로 설정하고, 이 토큰을 **현재 스레드**에 할당할 수 있습니다(SetThreadToken).

### SeBackupPrivilege

이 특권으로 시스템은 이 특권을 통해 모든 파일에 대한 **모든 읽기 액세스** 권한을 부여합니다(읽기 작업에 제한됨). 이 특권은 레지스트리에서 로컬 관리자 계정의 암호 해시를 읽기 위해 사용되며, 이후 "**psexec**" 또는 "**wmicexec**"과 같은 도구를 해당 해시와 함께 사용할 수 있습니다(해시 전달 기법). 그러나 이 기술은 두 가지 조건에서 실패합니다: 로컬 관리자 계정이 비활성화된 경우 또는 원격으로 연결하는 로컬 관리자에서 관리 권한을 제거하는 정책이 적용된 경우.\
다음과 같은 방법으로 **이 특권을 남용**할 수 있습니다:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)에서 **IppSec**을 따르기
* 또는 다음에서 **백업 연산자를 통한 권한 상승** 섹션에 설명된 대로:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

이 특권은 파일의 **모든 시스템 파일에 대한 쓰기 액세스** 권한을 부여하며, 파일의 액세스 제어 목록(ACL)에 관계없이 제공됩니다. 이는 **서비스 수정**, DLL Hijacking 수행, 이미지 파일 실행 옵션을 통한 **디버거 설정** 등 다양한 기술을 통해 권한 상승에 대한 다양한 가능성을 엽니다.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege은 사용자가 토큰을 위임할 수 있는 능력을 가지고 있을 때 특히 유용한 강력한 권한입니다. SeImpersonatePrivilege가 없는 경우에도 사용자가 현재 프로세스의 무결성 수준을 초과하지 않는 동일한 사용자를 나타내는 토큰을 위임할 수 있는 능력에 의존합니다.

**주요 포인트:**
- **SeImpersonatePrivilege 없이 위임:** 특정 조건 하에서 토큰을 위임하기 위해 SeCreateTokenPrivilege를 활용할 수 있습니다.
- **토큰 위임 조건:** 성공적인 위임을 위해서는 대상 토큰이 동일한 사용자에게 속하고, 위임을 시도하는 프로세스의 무결성 수준이 대상 토큰의 무결성 수준보다 작거나 같아야 합니다.
- **위임 토큰 생성 및 수정:** 사용자는 위임 토큰을 생성하고 특권 그룹의 SID(보안 식별자)를 추가하여 향상시킬 수 있습니다.


### SeLoadDriverPrivilege

이 특권은 `ImagePath` 및 `Type`에 특정 값이 있는 레지스트리 항목을 생성하여 **장치 드라이버를 로드하고 언로드**할 수 있게 합니다. `HKLM` (HKEY_LOCAL_MACHINE)에 대한 직접 쓰기 액세스가 제한되어 있기 때문에 `HKCU` (HKEY_CURRENT_USER)를 대신 사용해야 합니다. 그러나 드라이버 구성을 위해 커널에서 `HKCU`를 인식하려면 특정 경로를 따라야 합니다.

이 경로는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`이며, 여기서 `<RID>`는 현재 사용자의 상대 식별자를 나타냅니다. `HKCU` 내에서 이 전체 경로를 생성하고 두 가지 값을 설정해야 합니다:
- 실행할 이진 파일의 경로인 `ImagePath`
- `SERVICE_KERNEL_DRIVER`(`0x00000001`) 값인 `Type`.

**수행할 단계:**
1. `HKLM` 대신 제한된 쓰기 액세스로 `HKCU`에 액세스합니다.
2. `HKCU` 내에서 현재 사용자의 상대 식별자를 나타내는 `<RID>`를 사용하여 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` 경로를 생성합니다.
3. `ImagePath`를 실행 경로로 설정합니다.
4. `Type`을 `SERVICE_KERNEL_DRIVER`(`0x00000001`)로 할당합니다.
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
더 많은 방법은 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)에서 이 권한을 남용하는 방법을 찾을 수 있습니다.

### SeTakeOwnershipPrivilege

이것은 **SeRestorePrivilege**와 유사합니다. 주요 기능은 **객체의 소유권을 가정**하도록 프로세스를 허용하여 명시적인 DISCRETIONARY ACCESS 권한이 필요하지 않도록 우회합니다. 프로세스는 먼저 쓰기 목적으로 의도한 레지스트리 키의 소유권을 보호한 다음 DACL을 변경하여 쓰기 작업을 가능하게 합니다.
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

이 권한은 **다른 프로세스를 디버그**할 수 있게 허용하며, 메모리에서 읽고 쓸 수 있습니다. 이 권한을 사용하면 대부분의 백신 및 호스트 침입 방지 솔루션을 우회할 수 있는 다양한 메모리 인젝션 전략을 사용할 수 있습니다.

#### 메모리 덤프

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)에서 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)를 사용하여 **프로세스의 메모리를 캡처**할 수 있습니다. 구체적으로, 이는 사용자가 시스템에 성공적으로 로그인한 후 사용자 자격 증명을 저장하는 **로컬 보안 권한 부분 시스템 서비스 ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))** 프로세스에 적용될 수 있습니다.

그런 다음 이 덤프를 mimikatz에로드하여 암호를 얻을 수 있습니다:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` 쉘을 획득하려면 다음을 사용할 수 있습니다:

* ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
* ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## 권한 확인
```
whoami /priv
```
**비활성화된 상태로 나타나는 토큰**은 활성화할 수 있으며, 실제로 _활성화_ 및 _비활성화_ 토큰을 남용할 수 있습니다.

### 모든 토큰 활성화

토큰이 비활성화된 경우 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) 스크립트를 사용하여 모든 토큰을 활성화할 수 있습니다:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
또는 [이 게시물](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)에 포함된 **스크립트**.

## 표

전체 토큰 권한 치트시트는 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)에서 확인할 수 있으며, 아래 요약은 관리자 세션을 얻거나 민감한 파일을 읽기 위해 특권을 악용하는 직접적인 방법만 나열합니다.

| 특권                      | 영향        | 도구                    | 실행 경로                                                                                                                                                                                                                                                                                                                                     | 비고                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**관리자**_ | 제3자 도구              | _"사용자가 토큰을 가장하여 potato.exe, rottenpotato.exe 및 juicypotato.exe와 같은 도구를 사용하여 nt 시스템으로 권한 상승할 수 있게 합니다"_                                                                                                                                                                                                      | 업데이트해 주신 [Aurélien Chalot](https://twitter.com/Defte\_)에게 감사드립니다. 곧 좀 더 레시피 같은 내용으로 다시 표현해 보겠습니다.                                                                                                                                                                                        |
| **`SeBackup`**             | **위협**    | _**내장 명령어**_       | `robocopy /b`로 민감한 파일 읽기                                                                                                                                                                                                                                                                                                             | <p>- %WINDIR%\MEMORY.DMP를 읽을 수 있다면 더 흥미로울 수 있음<br><br>- <code>SeBackupPrivilege</code> (및 robocopy)는 파일을 열 때 도움이 되지 않음.<br><br>- Robocopy는 /b 매개변수와 함께 작동하려면 SeBackup 및 SeRestore가 모두 필요함.</p>                                                                      |
| **`SeCreateToken`**        | _**관리자**_ | 제3자 도구              | `NtCreateToken`을 사용하여 로컬 관리자 권한을 포함한 임의의 토큰 생성                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**관리자**_ | **PowerShell**          | `lsass.exe` 토큰 복제                                                                                                                                                                                                                                                                                                                   | [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)에서 스크립트 찾기                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**관리자**_ | 제3자 도구              | <p>1. <code>szkg64.sys</code>와 같은 버그가 있는 커널 드라이버 로드<br>2. 드라이버 취약점 악용<br><br>대안으로 <code>ftlMC</code> 내장 명령어를 사용하여 보안 관련 드라이버를 언로드할 수 있음. 즉, <code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code> 취약점은 <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a>로 나열됨<br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">악용 코드</a>는 <a href="https://twitter.com/parvezghh">Parvez Anwar</a>에 의해 작성됨</p> |
| **`SeRestore`**            | _**관리자**_ | **PowerShell**          | <p>1. SeRestore 특권이 있는 PowerShell/ISE 실행<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>로 특권 활성화<br>3. utilman.exe를 utilman.old로 이름 바꾸기<br>4. cmd.exe를 utilman.exe로 이름 바꾸기<br>5. 콘솔 잠금 후 Win+U 누르기</p> | <p>일부 AV 소프트웨어에서 공격을 감지할 수 있음.</p><p>대체 방법은 동일한 특권을 사용하여 "Program Files"에 저장된 서비스 이진 파일을 교체하는 것에 의존함</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**관리자**_ | _**내장 명령어**_       | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe를 utilman.exe로 이름 바꾸기<br>4. 콘솔 잠금 후 Win+U 누르기</p>                                                                                                                                       | <p>일부 AV 소프트웨어에서 공격을 감지할 수 있음.</p><p>대체 방법은 동일한 특권을 사용하여 "Program Files"에 저장된 서비스 이진 파일을 교체하는 것에 의존함.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**관리자**_ | 제3자 도구              | <p>로컬 관리자 권한을 포함하도록 토큰 조작. SeImpersonate가 필요할 수 있음.</p><p>검증 필요.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## 참고

* Windows 토큰을 정의하는 이 표를 확인하세요: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* 토큰을 통한 권한 상승에 관한 [**이 논문**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt)을 확인하세요.

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고**하고 싶으신가요? 아니면 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* **💬** [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우**하세요.
* **[hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**로 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
