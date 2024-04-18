# macOS Apps - 검사, 디버깅 및 Fuzzing

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>을 통해 **제로**부터 **히어로**로 **AWS 해킹** 배우기!</summary>

HackTricks를 지원하는 다른 방법:

- **회사를 HackTricks에서 광고**하거나 **PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com) 받기
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하고, 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션을 만나보세요.
- 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, **회사**나 **고객**이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 **무료**로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난하는 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 확인하고 **무료**로 엔진을 시도해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

---

## 정적 분석

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
{% endcode %}

### jtool2

이 도구는 **codesign**, **otool**, **objdump**의 **대체**로 사용될 수 있으며 몇 가지 추가 기능을 제공합니다. [**여기에서 다운로드하세요**](http://www.newosxbook.com/tools/jtool.html) 또는 `brew`를 사용하여 설치하세요.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
### Codesign / ldid

{% hint style="danger" %}
**`Codesign`**은 **macOS**에서 찾을 수 있으며 **`ldid`**는 **iOS**에서 찾을 수 있습니다.
{% endhint %}
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html)은 **.pkg** 파일(설치 프로그램)을 검사하고 설치하기 전에 내부를 확인하는 데 유용한 도구입니다.\
이러한 설치 프로그램에는 일반적으로 악성 소프트웨어 제작자가 악용하는 `preinstall` 및 `postinstall` bash 스크립트가 포함되어 있습니다.

### hdiutil

이 도구를 사용하면 Apple 디스크 이미지(**.dmg**) 파일을 **마운트**하여 실행하기 전에 내용을 검사할 수 있습니다:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
`/Volumes`에 마운트됩니다.

### Objective-C

#### Metadata

{% hint style="danger" %}
Objective-C로 작성된 프로그램은 [Mach-O 바이너리](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)로 컴파일될 때 **클래스 선언을 유지**합니다. 이러한 클래스 선언에는 다음이 포함됩니다:
{% endhint %}

* 클래스
* 클래스 메소드
* 클래스 인스턴스 변수

[class-dump](https://github.com/nygard/class-dump)을 사용하여 이 정보를 얻을 수 있습니다:
```bash
class-dump Kindle.app
```
#### 함수 호출

바이너리에서 Objective-C를 사용하는 함수가 호출될 때, 컴파일된 코드는 해당 함수를 호출하는 대신 **`objc_msgSend`**를 호출합니다. 이는 최종 함수를 호출할 것입니다:

![](<../../../.gitbook/assets/image (302).png>)

이 함수가 기대하는 매개변수는 다음과 같습니다:

- 첫 번째 매개변수인 (**self**)은 "메시지를 수신할 클래스의 **인스턴스를 가리키는 포인터**"입니다. 간단히 말하면, 메소드가 호출되는 객체입니다. 메소드가 클래스 메소드인 경우, 이것은 클래스 객체의 인스턴스(전체)일 것이며, 인스턴스 메소드의 경우 self는 객체로서 클래스의 인스턴스를 가리킵니다.
- 두 번째 매개변수인 (**op**)은 "메시지를 처리하는 메소드의 셀렉터"입니다. 간단히 말하면, 이것은 **메소드의 이름**입니다.
- 나머지 매개변수는 메소드에서 **필요로 하는 값들**입니다 (op).

ARM64에서 **`lldb`**를 사용하여 이 정보를 쉽게 얻는 방법은 이 페이지에서 확인할 수 있습니다:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **인자**          | **레지스터**                                                    | **(objc\_msgSend에 대해)**                             |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1번째 인자**    | **rdi**                                                         | **self: 메소드가 호출되는 객체**                       |
| **2번째 인자**    | **rsi**                                                         | **op: 메소드의 이름**                                 |
| **3번째 인자**    | **rdx**                                                         | **메소드에 대한 1번째 인자**                          |
| **4번째 인자**    | **rcx**                                                         | **메소드에 대한 2번째 인자**                          |
| **5번째 인자**    | **r8**                                                          | **메소드에 대한 3번째 인자**                          |
| **6번째 인자**    | **r9**                                                          | **메소드에 대한 4번째 인자**                          |
| **7번째+ 인자**   | <p><strong>rsp+</strong><br><strong>(스택 상에)</strong></p> | **메소드에 대한 5번째+ 인자**                         |

### Swift

Swift 바이너리의 경우, Objective-C 호환성이 있기 때문에 때로는 [class-dump](https://github.com/nygard/class-dump/)를 사용하여 선언을 추출할 수 있지만 항상 그렇지는 않습니다.

**`jtool -l`** 또는 **`otool -l`** 명령어를 사용하면 **`__swift5`** 접두어로 시작하는 여러 섹션을 찾을 수 있습니다:
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
다음 블로그 포스트에서 이 섹션에 저장된 정보에 대한 자세한 내용을 찾을 수 있습니다.

또한, **Swift 이진 파일에는 심볼이 포함**될 수 있습니다 (예: 라이브러리는 함수를 호출하기 위해 심볼을 저장해야 함). **일반적으로 심볼에는 함수 이름과 속성에 대한 정보**가 지저분한 방식으로 포함되어 있으므로 매우 유용하며 "**디멩글러"**가 원래 이름을 가져올 수 있습니다:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### 패킹된 이진 파일

* 고 엔트로피를 확인합니다.
* 문자열을 확인합니다 (거의 이해할 수 없는 문자열이 있는 경우, 패킹됨).
* MacOS용 UPX 패커는 "\_\_XHDR"이라는 섹션을 생성합니다.

## 동적 분석

{% hint style="warning" %}
바이너리를 디버깅하려면 **SIP를 비활성화**해야 합니다 (`csrutil disable` 또는 `csrutil enable --without debug`) 또는 바이너리를 임시 폴더로 복사하고 `codesign --remove-signature <binary-path>`로 서명을 제거하거나 바이너리의 디버깅을 허용해야 합니다 (이 스크립트를 사용할 수 있습니다).
{% endhint %}

{% hint style="warning" %}
macOS의 **시스템 바이너리** (예: `cloudconfigurationd`)를 **인스트루먼트**하려면 **SIP를 비활성화**해야 합니다 (서명을 제거하는 것만으로는 작동하지 않습니다).
{% endhint %}

### 통합 로그

MacOS는 **어플리케이션 실행 중 무엇을 하는지** 이해하는 데 유용한 많은 로그를 생성합니다.

또한, 일부 로그에는 `<private>` 태그가 포함되어 **사용자** 또는 **컴퓨터** **식별 가능한** 정보를 **숨기기** 위한 것입니다. 그러나 **이 정보를 공개하기 위해 인증서를 설치**할 수 있습니다. [**여기**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)의 설명을 따르세요.

### Hopper

#### 왼쪽 패널

Hopper의 왼쪽 패널에서는 이진 파일의 심볼 (**라벨**), 프로시저 및 함수 목록 (**Proc**) 및 문자열 (**Str**)을 볼 수 있습니다. 이들은 Mac-O 파일의 여러 부분에서 정의된 문자열 중 일부이지만 모든 문자열은 아닙니다 (예: _cstring 또는 `objc_methname`).

#### 가운데 패널

가운데 패널에서는 **어셈블리 코드**를 볼 수 있습니다. **원시** 어셈블리, **그래프**, **디컴파일** 및 **바이너리**로 볼 수 있습니다. 각 아이콘을 클릭하여 확인할 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (340).png" alt=""><figcaption></figcaption></figure>

코드 객체를 마우스 오른쪽 버튼으로 클릭하면 해당 객체에 대한 **참조/참조**를 볼 수 있거나 이름을 변경할 수 있습니다 (디컴파일된 의사 코드에서는 작동하지 않음):

<figure><img src="../../../.gitbook/assets/image (1114).png" alt=""><figcaption></figcaption></figure>

또한, **가운데 아래에서 파이썬 명령어를 작성**할 수 있습니다.

#### 오른쪽 패널

오른쪽 패널에서는 **탐색 기록** (현재 상황에 도달한 방법을 알 수 있음), **호출 그래프** (이 함수를 호출하는 모든 함수 및 이 함수가 호출하는 모든 함수를 볼 수 있는 그래프) 및 **로컬 변수** 정보와 같은 흥미로운 정보를 볼 수 있습니다.

### dtrace

Dtrace는 사용자가 **매우 낮은 수준**에서 응용 프로그램에 액세스할 수 있도록 하며 프로그램을 **추적**하고 실행 흐름을 변경할 수 있는 방법을 제공합니다. Dtrace는 **커널 전체에 배치된 프로브**를 사용하며 시스템 호출의 시작과 끝과 같은 위치에 있습니다.

DTrace는 각 시스템 호출에 대해 프로브를 생성하기 위해 **`dtrace_probe_create`** 함수를 사용합니다. 이러한 프로브는 각 시스템 호출의 **진입점과 종료점**에서 발생할 수 있습니다. DTrace와의 상호 작용은 루트 사용자만 사용할 수 있는 /dev/dtrace를 통해 이루어집니다.

{% hint style="success" %}
SIP 보호를 완전히 비활성화하지 않고 Dtrace를 활성화하려면 복구 모드에서 다음을 실행할 수 있습니다: `csrutil enable --without dtrace`

또한 **컴파일한 바이너리**를 **`dtrace`** 또는 **`dtruss`**할 수 있습니다.
{% endhint %}

dtrace의 사용 가능한 프로브는 다음과 같이 얻을 수 있습니다:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
프로브 이름은 제공자, 모듈, 함수 및 이름(`fbt:mach_kernel:ptrace:entry`)으로 구성됩니다. 이름의 일부를 지정하지 않으면 Dtrace는 해당 부분을 와일드카드로 적용합니다.

프로브를 활성화하고 발생할 때 수행할 작업을 지정하려면 D 언어를 사용해야 합니다.

더 자세한 설명 및 예제는 [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)에서 찾을 수 있습니다.

#### 예시

`man -k dtrace`를 실행하여 **사용 가능한 DTrace 스크립트 목록**을 확인합니다. 예: `sudo dtruss -n binary`

* 한 줄에서
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* 스크립트
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

**SIP가 활성화된 상태에서도** 사용할 수 있습니다.
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor)은 프로세스가 수행하는 프로세스 관련 작업을 확인하는 매우 유용한 도구입니다 (예: 프로세스가 생성하는 새로운 프로세스를 모니터링).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/)는 프로세스 간 관계를 출력하는 도구입니다.\
**`sudo eslogger fork exec rename create > cap.json`**과 같은 명령을 사용하여 맥을 모니터링해야 합니다 (이 명령을 실행하는 터미널은 FDA가 필요합니다). 그런 다음 이 도구에서 json을 로드하여 모든 관계를 볼 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor)는 파일 이벤트 (생성, 수정, 삭제와 같은)를 모니터링하여 이러한 이벤트에 대한 자세한 정보를 제공합니다.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo)는 Microsoft Sysinternal의 _Procmon_에서 Windows 사용자가 알 수 있는 외관을 가진 GUI 도구입니다. 이 도구를 사용하면 다양한 이벤트 유형의 녹화를 시작하고 중지할 수 있으며 파일, 프로세스, 네트워크 등과 같은 범주별로 이러한 이벤트를 필터링할 수 있으며 녹화된 이벤트를 json 형식으로 저장할 수 있습니다.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html)은 Xcode의 개발자 도구의 일부로 사용되며 애플리케이션 성능을 모니터링하고 메모리 누수를 식별하며 파일 시스템 활동을 추적하는 데 사용됩니다.

![](<../../../.gitbook/assets/image (1135).png>)

### fs\_usage

프로세스가 수행하는 작업을 따를 수 있게 합니다:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html)는 이진 파일이 사용하는 **라이브러리**, 사용 중인 **파일** 및 **네트워크** 연결을 확인하는 데 유용합니다.\
또한 바이너리 프로세스를 **virustotal**에 대해 확인하고 해당 바이너리에 대한 정보를 표시합니다.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

[**이 블로그 게시물**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)에서는 SIP가 비활성화되어 있더라도 **`PT_DENY_ATTACH`**를 사용하여 디버깅을 방지하는 **실행 중인 데몬을 디버깅**하는 예제를 찾을 수 있습니다.

### lldb

**lldb**는 **macOS** 이진 파일 **디버깅**에 대한 사실상의 도구입니다.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
홈 폴더에 다음 라인을 포함하는 **`.lldbinit`**이라는 파일을 만들어 lldb를 사용할 때 intel 플레이버를 설정할 수 있습니다:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
lldb 내에서 `process save-core`를 사용하여 프로세스 덤프
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) 명령어</strong></td><td><strong>설명</strong></td></tr><tr><td><strong>run (r)</strong></td><td>중단점이 만나거나 프로세스가 종료될 때까지 계속 실행을 시작합니다.</td></tr><tr><td><strong>continue (c)</strong></td><td>디버깅 중인 프로세스의 실행을 계속합니다.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>다음 명령을 실행합니다. 이 명령은 함수 호출을 건너뜁니다.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>다음 명령을 실행합니다. nexti 명령과 달리, 이 명령은 함수 호출 내부로 진입합니다.</td></tr><tr><td><strong>finish (f)</strong></td><td>현재 함수("프레임")의 남은 명령을 실행하고 중지합니다.</td></tr><tr><td><strong>control + c</strong></td><td>실행을 일시 중지합니다. 프로세스가 실행 중이거나 계속되고 있다면, 프로세스가 현재 실행 중인 위치에서 중지됩니다.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main # main 함수 호출</p><p>b <binname>`main # 바이너리의 main 함수</p><p>b set -n main --shlib <lib_name> # 지정된 바이너리의 main 함수</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l # 중단점 목록</p><p>br e/dis <num> # 중단점 활성화/비활성화</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint # 중단점 명령어 도움말</p><p>help memory write # 메모리 쓰기 도움말</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <a href="https://lldb.llvm.org/use/variable.html#type-format">format</a></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>메모리를 널 종료된 문자열로 표시합니다.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>어셈블리 명령으로 메모리를 표시합니다.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>바이트로 메모리를 표시합니다.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>매개변수로 참조된 객체를 출력합니다.</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>대부분의 Apple Objective-C API 또는 메서드는 객체를 반환하므로 "print object" (po) 명령을 통해 표시해야 합니다. 의미 있는 출력이 나오지 않으면 <code>x/b</code>를 사용하세요.</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 # 해당 주소에 AAAA 쓰기<br>memory write -f s $rip+0x11f+7 "AAAA" # 주소에 AAAA 쓰기</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis # 현재 함수의 어셈블리 코드 표시</p><p>dis -n <funcname> # 함수의 어셈블리 코드 표시</p><p>dis -n <funcname> -b <basename> # 함수의 어셈블리 코드 표시</p><p>dis -c 6 # 6줄 어셈블리 코드 표시</p><p>dis -c 0x100003764 -e 0x100003768 # 한 주소부터 다른 주소까지</p><p>dis -p -c 4 # 현재 주소부터 어셈블리 코드 표시 시작</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # x1 레지스터의 3개 구성 요소 배열 확인</td></tr></tbody></table>

{% hint style="info" %}
**`objc_sendMsg`** 함수를 호출할 때, **rsi** 레지스터는 널 종료된 ("C") 문자열로 **메서드 이름**을 보유합니다. lldb를 통해 이름을 출력하려면:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### 동적 분석 방지

#### VM 탐지

* **`sysctl hw.model`** 명령은 호스트가 MacOS인 경우 "Mac"을 반환하고 VM인 경우 다른 값을 반환합니다.
* 일부 악성 코드는 **`hw.logicalcpu`** 및 **`hw.physicalcpu`** 값을 조작하여 VM인지 여부를 감지하려고 합니다.
* 일부 악성 코드는 MAC 주소(00:50:56)를 기반으로 기계가 VMware인지 여부를 감지할 수 있습니다.
* 간단한 코드로 **프로세스가 디버깅되고 있는지** 확인할 수 있습니다:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
* **`ptrace`** 시스템 호출을 **`PT_DENY_ATTACH`** 플래그와 함께 호출할 수도 있습니다. 이렇게 하면 디버거가 첨부되고 추적되는 것을 방지합니다.
* **`sysctl`** 또는 **`ptrace`** 함수가 **가져오기(imported)**되었는지 확인할 수 있습니다(악성 코드가 동적으로 가져올 수도 있음)
* 이 글에서 언급된 대로, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_메시지 Process # exited with **status = 45 (0x0000002d)**는 일반적으로 디버그 대상이 **PT\_DENY\_ATTACH**를 사용하고 있음을 나타내는 신호입니다._”
## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **는 충돌하는 프로세스를 분석하고 충돌 보고서를 디스크에 저장**합니다. 충돌 보고서에는 충돌 원인을 진단하는 데 **도움이 되는 정보**가 포함되어 있습니다.\
응용 프로그램 및 다른 프로세스 **사용자별 launchd 컨텍스트에서 실행**되는 경우 ReportCrash는 LaunchAgent로 실행되어 사용자의 `~/Library/Logs/DiagnosticReports/`에 충돌 보고서를 저장합니다.\
데몬, 시스템 launchd 컨텍스트에서 실행되는 다른 프로세스 및 다른 권한이 있는 프로세스의 경우 ReportCrash는 LaunchDaemon으로 실행되어 시스템의 `/Library/Logs/DiagnosticReports`에 충돌 보고서를 저장합니다.

Apple로 **보내지는 충돌 보고서**에 대해 걱정된다면 비활성화할 수 있습니다. 그렇지 않으면 충돌 보고서는 **서버가 어떻게 충돌했는지 파악하는 데 유용**할 수 있습니다.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### 수면

MacOS에서 퍼징을 할 때 Mac이 잠들지 않도록하는 것이 중요합니다:

* systemsetup -setsleep Never
* pmset, 시스템 환경 설정
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 연결 끊김

SSH 연결을 통해 퍼징을 하는 경우 세션이 종료되지 않도록해야 합니다. 따라서 sshd\_config 파일을 다음과 같이 변경하십시오:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### 내부 핸들러

**다음 페이지를 확인하여** 지정된 scheme 또는 protocol을 처리하는 앱을 찾는 방법을 알아보세요:

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### 네트워크 프로세스 열거

네트워크 데이터를 관리하는 프로세스를 찾는 것은 흥미로운 작업입니다:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
또는 `netstat` 또는 `lsof`를 사용하십시오.

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

CLI 도구에 대해 작동합니다.

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

macOS GUI 도구와 "**그냥 작동"**합니다. 일부 macOS 앱은 고유한 파일 이름, 올바른 확장자, 샌드박스에서 파일을 읽어야 하는 등 특정 요구 사항이 있습니다 (`~/Library/Containers/com.apple.Safari/Data`)...

일부 예시:

{% code overflow="wrap" %}
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
{% endcode %}

### 더 많은 MacOS Fuzzing 정보

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## 참고 자료

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보 도난 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격에 대항하는 것입니다.

그들의 웹사이트를 방문하여 엔진을 무료로 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>와 함께 **제로**부터 **히어로**까지 **AWS 해킹 배우기**</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>
