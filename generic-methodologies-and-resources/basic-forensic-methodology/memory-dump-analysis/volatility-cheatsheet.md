# Volatility - CheatSheet

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

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성이 높은 사이버 보안 이벤트이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술 지식을 촉진하는 임무**를 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들이 모이는 뜨거운 만남의 장소입니다.

{% embed url="https://www.rootedcon.com/" %}

여러 Volatility 플러그인을 병렬로 실행할 수 있는 **빠르고 미친** 것을 원하신다면 다음을 사용할 수 있습니다: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## 설치

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="Method1" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="방법 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatility Commands

Access the official doc in [Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### “list” 플러그인과 “scan” 플러그인에 대한 주의 사항

Volatility는 플러그인에 대해 두 가지 주요 접근 방식을 가지고 있으며, 이는 때때로 이름에 반영됩니다. “list” 플러그인은 Windows Kernel 구조를 탐색하여 프로세스(메모리에서 `_EPROCESS` 구조의 연결 리스트를 찾고 탐색)와 OS 핸들(핸들 테이블을 찾고 나열하며, 발견된 포인터를 역참조 등)과 같은 정보를 검색하려고 합니다. 이들은 요청 시 Windows API가 프로세스를 나열하는 것처럼 행동합니다.

이로 인해 “list” 플러그인은 꽤 빠르지만, 악성 소프트웨어에 의해 조작될 수 있는 Windows API와 마찬가지로 취약합니다. 예를 들어, 악성 소프트웨어가 DKOM을 사용하여 프로세스를 `_EPROCESS` 연결 리스트에서 분리하면, 이는 작업 관리자에 나타나지 않으며 pslist에서도 나타나지 않습니다.

반면에 “scan” 플러그인은 특정 구조로 역참조될 때 의미가 있을 수 있는 것들을 메모리에서 조각내는 접근 방식을 취합니다. 예를 들어, `psscan`은 메모리를 읽고 이를 기반으로 `_EPROCESS` 객체를 만들려고 합니다(이는 관심 있는 구조의 존재를 나타내는 4바이트 문자열을 검색하는 풀 태그 스캐닝을 사용합니다). 장점은 종료된 프로세스를 찾아낼 수 있으며, 악성 소프트웨어가 `_EPROCESS` 연결 리스트를 조작하더라도 플러그인은 여전히 메모리에서 구조를 찾을 수 있습니다(프로세스가 실행되기 위해서는 여전히 존재해야 하므로). 단점은 “scan” 플러그인이 “list” 플러그인보다 약간 느리며, 때때로 잘못된 긍정 결과(너무 오래 전에 종료되어 다른 작업에 의해 구조의 일부가 덮어씌워진 프로세스)를 생성할 수 있다는 것입니다.

From: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## OS Profiles

### Volatility3

readme에 설명된 바와 같이 지원하려는 **OS의 심볼 테이블**을 _volatility3/volatility/symbols_에 넣어야 합니다.\
다양한 운영 체제에 대한 심볼 테이블 팩은 **다운로드**를 위해 다음에서 사용할 수 있습니다:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### 외부 프로필

지원되는 프로필 목록을 얻으려면 다음을 수행할 수 있습니다:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
만약 **다운로드한 새 프로필**(예: 리눅스 프로필)을 사용하고 싶다면, 다음과 같은 폴더 구조를 어딘가에 만들어야 합니다: _plugins/overlays/linux_ 그리고 이 폴더 안에 프로필이 포함된 zip 파일을 넣습니다. 그런 다음, 프로필의 번호를 얻으려면 다음을 사용하세요:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
You can **download Linux and Mac profiles** from [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

In the previous chunk you can see that the profile is called `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, and you can use it to execute something like:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### 프로필 발견
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo와 kdbgscan의 차이점**

[**여기에서**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): 단순히 프로필 제안을 제공하는 imageinfo와 달리, **kdbgscan**은 올바른 프로필과 올바른 KDBG 주소(여러 개가 있을 경우)를 긍정적으로 식별하도록 설계되었습니다. 이 플러그인은 Volatility 프로필과 연결된 KDBGHeader 서명을 스캔하고 잘못된 긍정 결과를 줄이기 위해 정상성 검사를 적용합니다. 출력의 상세도와 수행할 수 있는 정상성 검사 수는 Volatility가 DTB를 찾을 수 있는지에 따라 달라지므로, 이미 올바른 프로필을 알고 있거나 imageinfo에서 프로필 제안을 받은 경우, 반드시 그것을 사용해야 합니다.

항상 **kdbgscan이 찾은 프로세스 수**를 확인하세요. 때때로 imageinfo와 kdbgscan은 **하나 이상의** 적합한 **프로필**을 찾을 수 있지만, **유효한 프로필만 프로세스와 관련이 있습니다** (이는 프로세스를 추출하기 위해 올바른 KDBG 주소가 필요하기 때문입니다).
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

**커널 디버거 블록**은 Volatility에서 **KDBG**로 언급되며, Volatility와 다양한 디버거가 수행하는 포렌식 작업에 필수적입니다. `KdDebuggerDataBlock`으로 식별되며 `_KDDEBUGGER_DATA64` 유형을 가지며, `PsActiveProcessHead`와 같은 필수 참조를 포함합니다. 이 특정 참조는 프로세스 목록의 헤드를 가리키며, 모든 프로세스를 나열할 수 있게 하여 철저한 메모리 분석에 기본적입니다.

## OS 정보
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
The plugin `banners.Banners`는 **vol3에서 덤프에서 리눅스 배너를 찾기 위해 사용할 수 있습니다**.

## 해시/비밀번호

SAM 해시, [도메인 캐시된 자격 증명](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) 및 [lsa 비밀](../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets)을 추출합니다.

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}
{% endtabs %}

## Memory Dump

프로세스의 메모리 덤프는 프로세스의 현재 상태를 **모두 추출**합니다. **procdump** 모듈은 **코드**만 **추출**합니다.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성이 높은 사이버 보안 이벤트이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술 지식 증진**이라는 사명을 가지고, 이 컨그레스는 모든 분야의 기술 및 사이버 보안 전문가들이 모이는 뜨거운 만남의 장소입니다.

{% embed url="https://www.rootedcon.com/" %}

## 프로세스

### 프로세스 목록

**의심스러운** 프로세스(이름으로) 또는 **예상치 못한** 자식 **프로세스**(예: iexplorer.exe의 자식으로 cmd.exe)를 찾으려고 시도하십시오.\
pslist의 결과와 psscan의 결과를 **비교**하여 숨겨진 프로세스를 식별하는 것이 흥미로울 수 있습니다.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}

### 덤프 프로세스

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### 명령줄

의심스러운 것이 실행되었나요?

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

`cmd.exe`에서 실행된 명령은 **`conhost.exe`** (또는 Windows 7 이전 시스템의 경우 **`csrss.exe`**)에 의해 관리됩니다. 이는 공격자가 메모리 덤프가 얻어지기 전에 **`cmd.exe`**를 종료하더라도 **`conhost.exe`**의 메모리에서 세션의 명령 기록을 복구할 수 있음을 의미합니다. 이를 위해 콘솔의 모듈 내에서 비정상적인 활동이 감지되면 관련된 **`conhost.exe`** 프로세스의 메모리를 덤프해야 합니다. 그런 다음 이 덤프 내에서 **strings**를 검색하여 세션에서 사용된 명령줄을 추출할 수 있습니다.

### 환경

각 실행 중인 프로세스의 env 변수를 가져옵니다. 흥미로운 값이 있을 수 있습니다.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{% endtab %}
{% endtabs %}

### 토큰 권한

예상치 못한 서비스에서 권한 토큰을 확인하십시오.\
특권 토큰을 사용하는 프로세스를 나열하는 것이 흥미로울 수 있습니다.

{% tabs %}
{% tab title="vol3" %}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

프로세스가 소유한 각 SSID를 확인하십시오.\
특권 SID를 사용하는 프로세스(및 일부 서비스 SID를 사용하는 프로세스)를 나열하는 것이 흥미로울 수 있습니다.

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### 핸들

**프로세스가 핸들**을 가지고 있는 다른 파일, 키, 스레드, 프로세스 등에 대한 정보를 아는 것이 유용합니다. 

{% tabs %}
{% tab title="vol3" %}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### DLLs

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### 프로세스별 문자열

Volatility는 문자열이 어떤 프로세스에 속하는지 확인할 수 있게 해줍니다.

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

또한 yarascan 모듈을 사용하여 프로세스 내에서 문자열을 검색할 수 있습니다:

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows**는 **UserAssist 키**라는 레지스트리 기능을 사용하여 실행한 프로그램을 추적합니다. 이 키는 각 프로그램이 실행된 횟수와 마지막 실행 시간을 기록합니다.

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성이 높은 사이버 보안 이벤트이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술 지식을 촉진하는 사명**을 가지고, 이 컨그레스는 모든 분야의 기술 및 사이버 보안 전문가들이 모이는 뜨거운 만남의 장소입니다.

{% embed url="https://www.rootedcon.com/" %}

## 서비스

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{% endtab %}
{% endtabs %}

## 네트워크

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{% endtab %}
{% endtabs %}

## 레지스트리 하이브

### 사용 가능한 하이브 인쇄

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### 값을 가져오기

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### 덤프
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## 파일 시스템

### 마운트

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}

### 스캔/덤프

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}

### 마스터 파일 테이블

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

**NTFS 파일 시스템**은 _마스터 파일 테이블_ (MFT)이라는 중요한 구성 요소를 사용합니다. 이 테이블은 볼륨의 모든 파일에 대해 최소한 하나의 항목을 포함하며, MFT 자체도 포함됩니다. 각 파일에 대한 중요한 세부정보, 예를 들어 **크기, 타임스탬프, 권한 및 실제 데이터**는 MFT 항목 내 또는 MFT 외부의 영역에 캡슐화되어 있으며, 이러한 항목에 의해 참조됩니다. 더 많은 세부정보는 [공식 문서](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)에서 확인할 수 있습니다.

### SSL 키/인증서

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="vol2" %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

## 악성코드

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% endtabs %}

### Yara로 스캔하기

이 스크립트를 사용하여 github에서 모든 yara 악성코드 규칙을 다운로드하고 병합하세요: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ 디렉토리를 만들고 실행하세요. 이렇게 하면 악성코드에 대한 모든 yara 규칙이 포함된 _**malware\_rules.yar**_라는 파일이 생성됩니다.

{% tabs %}
{% tab title="vol3" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% tab title="vol2" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## MISC

### 외부 플러그인

외부 플러그인을 사용하려면 플러그인과 관련된 폴더가 사용되는 첫 번째 매개변수인지 확인하십시오.

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

[https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)에서 다운로드하세요.
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### 심볼릭 링크

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

**메모리에서 bash 기록을 읽는 것이 가능합니다.** _.bash\_history_ 파일을 덤프할 수도 있지만, 비활성화되어 있다면 이 volatility 모듈을 사용할 수 있어 기쁠 것입니다.

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### 타임라인

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### 드라이버

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### 클립보드 가져오기
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IE 기록 가져오기
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### 메모장 텍스트 가져오기
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### 스크린샷
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### 마스터 부트 레코드 (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
The **Master Boot Record (MBR)**는 다양한 [파일 시스템](https://en.wikipedia.org/wiki/File\_system)으로 구조화된 저장 매체의 논리적 파티션을 관리하는 데 중요한 역할을 합니다. MBR은 파티션 레이아웃 정보뿐만 아니라 부트 로더 역할을 하는 실행 가능한 코드를 포함하고 있습니다. 이 부트 로더는 OS의 2단계 로딩 프로세스를 직접 시작하거나 (자세한 내용은 [2단계 부트 로더](https://en.wikipedia.org/wiki/Second-stage\_boot\_loader) 참조) 각 파티션의 [볼륨 부트 레코드](https://en.wikipedia.org/wiki/Volume\_boot\_record) (VBR)와 조화를 이루어 작동합니다. 자세한 내용은 [MBR 위키 페이지](https://en.wikipedia.org/wiki/Master\_boot\_record)를 참조하십시오.

## References

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성이 높은 사이버 보안 이벤트이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술 지식을 촉진하는 사명**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들이 모이는 뜨거운 만남의 장소입니다.

{% embed url="https://www.rootedcon.com/" %}

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
