# macOS 앱 - 검사, 디버깅 및 Fuzzing

{% hint style="success" %}
AWS 해킹 배우고 실습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 실습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 코드**에 의해 **침해**당했는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난당한 악성 코드로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료**로 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

***

## 정적 분석

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
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
```bash
nm -m ./tccd # List of symbols
```
### jtool2 및 Disarm

[**여기에서 disarm을 다운로드할 수 있습니다**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
[**jtool2를 여기서 다운로드하세요**](http://www.newosxbook.com/tools/jtool.html) 또는 `brew`로 설치하세요.
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
{% hint style="danger" %}
**jtool은 disarm을 사용하는 것이 권장됩니다.**
{% endhint %}

### Codesign / ldid

{% hint style="success" %}
**`Codesign`**은 **macOS**에, **`ldid`**는 **iOS**에 있습니다.
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
이러한 설치 프로그램에는 일반적으로 악성 코드 제작자가 악용하는 `preinstall` 및 `postinstall` bash 스크립트가 포함되어 있습니다.

### hdiutil

이 도구를 사용하면 Apple 디스크 이미지(**.dmg**) 파일을 **마운트**하여 실행하기 전에 내용을 확인할 수 있습니다:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
### 패킹된 이진 파일

* 고엔트로피를 확인합니다.
* 문자열을 확인합니다 (거의 이해할 수 없는 문자열이 있는지 확인하여 패킹된지 확인).
* MacOS용 UPX 패커는 "\_\_XHDR"이라는 섹션을 생성합니다.

## 정적 Objective-C 분석

### 메타데이터

{% hint style="danger" %}
Objective-C로 작성된 프로그램은 [Mach-O 이진 파일](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)로 컴파일될 때 클래스 선언을 유지합니다. 이러한 클래스 선언에는 다음이 포함됩니다:
{% endhint %}

* 정의된 인터페이스
* 인터페이스 메소드
* 인터페이스 인스턴스 변수
* 정의된 프로토콜

이러한 이름들은 바이너리의 역공학을 어렵게 만들기 위해 난독화될 수 있습니다.

### 함수 호출

Objective-C를 사용하는 바이너리에서 함수가 호출될 때, 컴파일된 코드는 해당 함수를 호출하는 대신 **`objc_msgSend`**를 호출합니다. 이는 최종 함수를 호출할 것입니다:

![](<../../../.gitbook/assets/image (305).png>)

이 함수가 기대하는 매개변수는 다음과 같습니다:

* 첫 번째 매개변수 (**self**)는 "메시지를 수신할 클래스의 인스턴스를 가리키는 포인터"입니다. 간단히 말해, 메소드가 호출되는 객체입니다. 메소드가 클래스 메소드인 경우, 이것은 클래스 객체의 인스턴스(전체)일 것이며, 인스턴스 메소드의 경우 self는 클래스의 인스턴스로 가리킬 것입니다.
* 두 번째 매개변수인 (**op**)은 "메시지를 처리하는 메소드의 셀렉터"입니다. 간단히 말해, 이것은 메소드의 **이름**입니다.
* 나머지 매개변수는 메소드에서 필요한 **값**입니다 (op).

ARM64에서 **`lldb`를 사용하여 이 정보를 쉽게 얻는 방법**은 다음 페이지에서 확인할 수 있습니다:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **인자**          | **레지스터**                                                    | **(objc\_msgSend용) **                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1번째 인자**    | **rdi**                                                         | **self: 메소드가 호출되는 객체**                       |
| **2번째 인자**    | **rsi**                                                         | **op: 메소드의 이름**                                 |
| **3번째 인자**    | **rdx**                                                         | **메소드에 대한 1번째 인자**                          |
| **4번째 인자**    | **rcx**                                                         | **메소드에 대한 2번째 인자**                          |
| **5번째 인자**    | **r8**                                                          | **메소드에 대한 3번째 인자**                          |
| **6번째 인자**    | **r9**                                                          | **메소드에 대한 4번째 인자**                          |
| **7번째+ 인자**   | <p><strong>rsp+</strong><br><strong>(스택 상에)</strong></p> | **메소드에 대한 5번째+ 인자**                         |

### ObjectiveC 메타데이터 덤프

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump)는 Objective-C 이진 파일을 클래스 덤프하는 도구입니다. 깃허브에서는 dylibs를 지정하지만 실행 파일에서도 작동합니다.
```bash
./dynadump dump /path/to/bin
```
현재 이것이 **가장 잘 작동하는 것**입니다.

#### 일반 도구
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/)은 ObjetiveC 형식의 코드에서 클래스, 카테고리 및 프로토콜에 대한 선언을 생성하는 원본 도구입니다.

이 도구는 오래되었고 유지되지 않았으므로 제대로 작동하지 않을 수 있습니다.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump)은 현대적이고 크로스 플랫폼 Objective-C 클래스 덤프입니다. 기존 도구와 비교하여 iCDump는 Apple 생태계와 독립적으로 실행되며 Python 바인딩을 노출합니다.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## 정적 Swift 분석

Swift 이진 파일의 경우 Objective-C 호환성이 있기 때문에 때로는 [class-dump](https://github.com/nygard/class-dump/)를 사용하여 선언을 추출할 수 있지만 항상 그렇지는 않습니다.

**`jtool -l`** 또는 **`otool -l`** 명령줄을 사용하면 **`__swift5`** 접두사로 시작하는 여러 섹션을 찾을 수 있습니다:
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
당부 섹션에 저장된 정보에 대한 자세한 내용은 [이 블로그 게시물](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)에서 찾을 수 있습니다.

또한, **Swift 이진 파일에는 심볼이 포함**될 수 있습니다(예: 라이브러리는 함수를 호출하기 위해 심볼을 저장해야 함). **심볼에는 일반적으로 함수 이름과 속성에 대한 정보**가 포함되어 있으며 형식이 복잡하기 때문에 매우 유용하며 "**디멩글러"**가 원래 이름을 가져올 수 있습니다:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## 동적 분석

{% hint style="warning" %}
바이너리를 디버깅하려면 **SIP를 비활성화**해야 합니다 (`csrutil disable` 또는 `csrutil enable --without debug`) 또는 바이너리를 임시 폴더로 복사하고 `codesign --remove-signature <binary-path>`로 서명을 **제거**하거나 바이너리의 디버깅을 허용해야 합니다(이 스크립트를 사용할 수 있습니다 [여기](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)).
{% endhint %}

{% hint style="warning" %}
macOS에서 **시스템 바이너리를 instrument**하려면(`cloudconfigurationd`와 같은) **SIP를 비활성화**해야 합니다(서명을 제거하는 것만으로는 작동하지 않습니다).
{% endhint %}

### APIs

macOS는 프로세스에 대한 정보를 제공하는 몇 가지 흥미로운 API를 노출합니다:

* `proc_info`: 각 프로세스에 대한 많은 정보를 제공하는 주요 API입니다. 다른 프로세스 정보를 얻으려면 루트여야 하지만 특별한 권한이나 mach 포트가 필요하지는 않습니다.
* `libsysmon.dylib`: XPC 노출 함수를 통해 프로세스 정보를 얻을 수 있게 해줍니다. 그러나 `com.apple.sysmond.client` 엔터티가 필요합니다.

### Stackshot & microstackshots

**Stackshotting**은 프로세스의 상태를 캡처하는 기술로, 모든 실행 중인 스레드의 콜 스택을 포함합니다. 이는 디버깅, 성능 분석 및 특정 시점에서 시스템의 동작을 이해하는 데 특히 유용합니다. iOS 및 macOS에서는 **`sample`** 및 **`spindump`**와 같은 도구 및 방법을 사용하여 stackshotting을 수행할 수 있습니다.

### Sysdiagnose

이 도구(`/usr/bini/ysdiagnose`)는 기본적으로 `ps`, `zprint` 등 수십 가지 다른 명령을 실행하여 컴퓨터에서 많은 정보를 수집합니다.

**루트**로 실행해야 하며 `/usr/libexec/sysdiagnosed` 데몬에는 `com.apple.system-task-ports` 및 `get-task-allow`와 같은 매우 흥미로운 엔터티가 있습니다.

그 plist는 `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`에 있으며 3개의 MachServices를 선언합니다:

* `com.apple.sysdiagnose.CacheDelete`: /var/rmp의 이전 아카이브를 삭제합니다.
* `com.apple.sysdiagnose.kernel.ipc`: 특별 포트 23(커널)
* `com.apple.sysdiagnose.service.xpc`: `Libsysdiagnose` Obj-C 클래스를 통한 사용자 모드 인터페이스. 딕셔너리에 세 가지 인수를 전달할 수 있습니다(`compress`, `display`, `run`).

### Unified Logs

MacOS는 응용 프로그램을 실행할 때 매우 유용한 로그를 생성합니다.

또한, 일부 로그에는 `<private>` 태그가 포함되어 **사용자** 또는 **컴퓨터** **식별 가능한** 정보를 **숨기기** 위해 사용됩니다. 그러나 **인증서를 설치하여 이 정보를 공개**할 수 있습니다. [**여기**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)의 설명을 따르세요.

### Hopper

#### 왼쪽 패널

Hopper의 왼쪽 패널에서는 바이너리의 심볼(**라벨**), 프로시저 및 함수 목록(**Proc**) 및 문자열(**Str**)을 볼 수 있습니다. 이들은 Mac-O 파일의 여러 부분(예: _cstring 또는 `objc_methname`)에 정의된 문자열 중 일부입니다.

#### 가운데 패널

가운데 패널에서는 **어셈블리 코드**를 볼 수 있습니다. 그리고 **원시** 어셈블리, **그래프**, **디컴파일** 및 **바이너리**로 볼 수 있습니다. 각각의 아이콘을 클릭하여:

<figure><img src="../../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

코드 객체를 마우스 오른쪽 버튼으로 클릭하면 해당 객체에 대한 **참조/참조**를 볼 수 있거나 이름을 변경할 수 있습니다(디컴파일된 의사 코드에서는 작동하지 않음):

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

또한, **가운데 아래에서 python 명령을 작성**할 수 있습니다.

#### 오른쪽 패널

오른쪽 패널에서는 **탐색 기록**(현재 상황에 도달한 방법을 알 수 있음), **호출 그래프**(이 함수를 호출하는 모든 함수 및 이 함수가 호출하는 모든 함수를 볼 수 있는 그래프) 및 **로컬 변수** 정보와 같은 흥미로운 정보를 볼 수 있습니다.

### dtrace

Dtrace는 사용자가 **매우 낮은 수준**에서 응용 프로그램에 액세스할 수 있게 하며 프로그램을 **추적**하고 실행 흐름을 심지어 변경할 수 있는 방법을 제공합니다. Dtrace는 **커널 전체에 배치된** 프로브를 사용하며 시스템 호출의 시작과 끝과 같은 위치에 있습니다.

DTrace는 각 시스템 호출에 대해 프로브를 생성하기 위해 **`dtrace_probe_create`** 함수를 사용합니다. 이러한 프로브는 각 시스템 호출의 **진입점과 종료점**에서 발사될 수 있습니다. DTrace와의 상호 작용은 루트 사용자에게만 사용 가능한 /dev/dtrace를 통해 이루어집니다.

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
다음은 네 가지 부분으로 구성된 프로브 이름입니다: 제공자, 모듈, 함수 및 이름(`fbt:mach_kernel:ptrace:entry`). 이름의 일부를 지정하지 않으면 Dtrace는 해당 부분을 와일드카드로 적용합니다.

프로브를 활성화하고 그들이 발생할 때 수행할 작업을 지정하려면 D 언어를 사용해야 합니다.

더 자세한 설명과 예제는 [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)에서 찾을 수 있습니다.

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
### kdebug

커널 추적 시설입니다. 문서화된 코드는 **`/usr/share/misc/trace.codes`**에서 찾을 수 있습니다.

`latency`, `sc_usage`, `fs_usage`, `trace`와 같은 도구들이 내부적으로 사용합니다.

`kdebug`와 상호 작용하기 위해 `sysctl`을 사용하며 `kern.kdebug` 네임스페이스를 통해 MIB를 사용할 수 있으며, 해당 함수는 `bsd/kern/kdebug.c`에 구현되어 있습니다.

일반적으로 사용자 지정 클라이언트와 상호 작용하기 위한 단계는 다음과 같습니다:

* 기존 설정을 `KERN_KDSETREMOVE`로 제거합니다.
* `KERN_KDSETBUF` 및 `KERN_KDSETUP`으로 추적을 설정합니다.
* 버퍼 항목 수를 얻기 위해 `KERN_KDGETBUF`를 사용합니다.
* 추적에서 자체 클라이언트를 가져오려면 `KERN_KDPINDEX`를 사용합니다.
* `KERN_KDENABLE`로 추적을 활성화합니다.
* `KERN_KDREADTR`를 호출하여 버퍼를 읽습니다.
* 각 스레드를 해당 프로세스와 일치시키려면 `KERN_KDTHRMAP`을 호출합니다.

이 정보를 얻기 위해 Apple 도구 **`trace`** 또는 사용자 지정 도구 [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**를** 사용할 수 있습니다.

**Kdebug는 한 번에 1명의 고객만 사용할 수 있습니다.** 따라서 동시에 실행되는 k-debug 기능 도구는 하나뿐입니다.

### ktrace

`ktrace_*` API는 `libktrace.dylib`에서 가져오며 `Kdebug`의 API를 래핑합니다. 그런 다음 클라이언트는 `ktrace_session_create` 및 `ktrace_events_[single/class]`를 호출하여 특정 코드에 대한 콜백을 설정한 다음 `ktrace_start`로 시작할 수 있습니다.

**SIP가 활성화된 상태에서도** 이를 사용할 수 있습니다.

`ktrace` 유틸리티를 클라이언트로 사용할 수 있습니다:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Or `tailspin`.

### kperf

이는 커널 레벨 프로파일링을 수행하는 데 사용되며 `Kdebug` 호출을 사용하여 구축됩니다.

기본적으로 전역 변수 `kernel_debug_active`가 확인되고 설정되면 `Kdebug` 코드와 호출하는 커널 프레임의 주소와 함께 `kperf_kdebug_handler`를 호출합니다. `Kdebug` 코드가 선택한 코드와 일치하는 경우 "actions"가 비트맵으로 구성된 것을 가져옵니다 (옵션은 `osfmk/kperf/action.h`를 확인하십시오).

Kperf에는 sysctl MIB 테이블도 있습니다: (루트로) `sysctl kperf`. 이 코드는 `osfmk/kperf/kperfbsd.c`에서 찾을 수 있습니다.

또한 Kperfs 기능의 하위 집합은 기계 성능 카운터에 대한 정보를 제공하는 `kpc`에 있습니다.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor)는 프로세스가 수행하는 프로세스 관련 작업을 확인하는 매우 유용한 도구입니다 (예: 프로세스가 생성하는 새 프로세스를 모니터링).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/)는 프로세스 간 관계를 출력하는 도구입니다.\
**`sudo eslogger fork exec rename create > cap.json`**과 같은 명령을 사용하여 맥을 모니터링해야 합니다 (이를 시작하는 터미널에 FDA가 필요함). 그런 다음이 도구에서 json을 로드하여 모든 관계를 볼 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor)는 파일 이벤트 (생성, 수정, 삭제 등)를 모니터링하여 해당 이벤트에 대한 자세한 정보를 제공합니다.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo)는 Microsoft Sysinternal의 _Procmon_에서 Windows 사용자가 알 수 있는 룩 앤 필을 가진 GUI 도구입니다. 이 도구를 사용하면 다양한 이벤트 유형의 녹화를 시작하고 중지할 수 있으며 파일, 프로세스, 네트워크 등과 같은 범주별로 이러한 이벤트를 필터링할 수 있으며 녹화된 이벤트를 json 형식으로 저장할 수 있습니다.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html)은 Xcode의 개발자 도구의 일부로, 애플리케이션 성능을 모니터링하고 메모리 누수를 식별하며 파일 시스템 활동을 추적하는 데 사용됩니다.

![](<../../../.gitbook/assets/image (1138).png>)

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

[**이 블로그 게시물**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)에서는 SIP가 비활성화되어 있더라도 **`PT_DENY_ATTACH`**를 사용하여 디버깅을 방지하는 **실행 중인 데몬을 디버깅하는** 예제를 찾을 수 있습니다.

### lldb

**lldb**는 **macOS** 이진 파일 **디버깅**의 **사실상 표준 도구**입니다.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
다음 줄을 포함하는 홈 폴더에 **`.lldbinit`**이라는 파일을 만들어 lldb를 사용할 때 intel 플레이버를 설정할 수 있습니다:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
lldb 내에서 `process save-core`를 사용하여 프로세스 덤프를 수행합니다.
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) 명령어</strong></td><td><strong>설명</strong></td></tr><tr><td><strong>run (r)</strong></td><td>중단점이 만나거나 프로세스가 종료될 때까지 계속 실행을 시작합니다.</td></tr><tr><td><strong>continue (c)</strong></td><td>디버깅 중인 프로세스의 실행을 계속합니다.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>다음 명령을 실행합니다. 이 명령은 함수 호출을 건너뜁니다.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>다음 명령을 실행합니다. nexti 명령과 달리, 이 명령은 함수 호출 내부로 진입합니다.</td></tr><tr><td><strong>finish (f)</strong></td><td>현재 함수("프레임")의 남은 명령을 실행하고 중지합니다.</td></tr><tr><td><strong>control + c</strong></td><td>실행을 일시 중지합니다. 프로세스가 실행 중이거나 계속되고 있으면 현재 실행 중인 위치에서 프로세스를 중지시킵니다.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main # main 함수 호출</p><p>b &#x3C;binname>`main # 바이너리의 main 함수</p><p>b set -n main --shlib &#x3C;lib_name> # 지정된 바이너리의 main 함수</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l # 중단점 목록</p><p>br e/dis &#x3C;num> # 중단점 활성화/비활성화</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint # 중단점 명령어 도움말</p><p>help memory write # 메모리 쓰기 도움말</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address</strong></td><td>메모리를 널 종료된 문자열로 표시합니다.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address</strong></td><td>어셈블리 명령으로 메모리를 표시합니다.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address</strong></td><td>바이트로 메모리를 표시합니다.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>매개변수로 참조된 객체를 출력합니다.</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Apple의 대부분의 Objective-C API 또는 메서드는 객체를 반환하므로 "print object" (po) 명령을 통해 표시해야 합니다. 의미 있는 출력이 생성되지 않는 경우 <code>x/b</code>를 사용하세요.</p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 # 해당 주소에 AAAA를 씁니다<br>memory write -f s $rip+0x11f+7 "AAAA" # 해당 주소에 AAAA를 씁니다</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis # 현재 함수의 어셈블리 코드 표시</p><p>dis -n &#x3C;funcname> # 함수의 어셈블리 코드 표시</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> # 함수의 어셈블리 코드 표시<br>dis -c 6 # 6줄 어셈블리 코드 표시<br>dis -c 0x100003764 -e 0x100003768 # 한 주소부터 다른 주소까지 어셈블리 코드 표시<br>dis -p -c 4 # 현재 주소부터 어셈블리 코드 표시 시작</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # x1 레지스터의 3개 구성 요소 배열 확인</td></tr></tbody></table>

{% hint style="info" %}
**`objc_sendMsg`** 함수를 호출할 때 **rsi** 레지스터는 널 종료된 ("C") 문자열로 메서드의 이름을 보유합니다. lldb를 통해 이름을 출력하려면 다음을 수행합니다:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### 동적 분석 방지

#### 가상 머신 탐지

* **`sysctl hw.model`** 명령은 호스트가 MacOS인 경우 "Mac"을 반환하고 VM인 경우 다른 값을 반환합니다.
* 일부 악성 코드는 **`hw.logicalcpu`** 및 **`hw.physicalcpu`** 값을 조작하여 VM인지 여부를 감지하려고 합니다.
* 일부 악성 코드는 MAC 주소(00:50:56)를 기반으로 기계가 VMware인지 여부를 감지할 수 있습니다.
* 간단한 코드로 **프로세스가 디버깅되고 있는지** 확인할 수 있습니다:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
* **`ptrace`** 시스템 호출을 **`PT_DENY_ATTACH`** 플래그와 함께 호출할 수도 있습니다. 이는 디버거가 첨부되고 추적되는 것을 방지합니다.
* **`sysctl`** 또는 **`ptrace`** 함수가 **가져오기(imported)**되었는지 확인할 수 있습니다(그러나 악성 코드는 동적으로 가져올 수 있음).
* 이 글에서 언급된 대로, “[Anti-Debug 기술 무력화: macOS ptrace 변형](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_메시지 Process # exited with **status = 45 (0x0000002d)**는 일반적으로 디버그 대상이 **PT\_DENY\_ATTACH**를 사용하고 있음을 나타내는 신호입니다_”
## 코어 덤프

코어 덤프는 다음과 같은 경우에 생성됩니다:

- `kern.coredump` sysctl이 1로 설정된 경우 (기본값)
- 프로세스가 suid/sgid가 아니거나 `kern.sugid_coredump`가 1인 경우 (기본값은 0)
- `AS_CORE` 제한이 작동을 허용하는 경우. `ulimit -c 0`를 호출하여 코어 덤프 생성을 억제하고, `ulimit -c unlimited`로 다시 활성화할 수 있습니다.

이러한 경우에는 코어 덤프가 `kern.corefile` sysctl에 따라 생성되며, 일반적으로 `/cores/core/.%P`에 저장됩니다.

## 퍼징

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash는 **충돌하는 프로세스를 분석하고 충돌 보고서를 디스크에 저장**합니다. 충돌 보고서에는 충돌 원인을 **진단하는 데 도움이 되는 정보**가 포함되어 있습니다.\
사용자별 launchd 컨텍스트에서 실행되는 응용 프로그램 및 기타 프로세스의 경우, ReportCrash는 LaunchAgent로 실행되어 사용자의 `~/Library/Logs/DiagnosticReports/`에 충돌 보고서를 저장합니다.\
데몬, 시스템 launchd 컨텍스트에서 실행되는 기타 프로세스 및 다른 권한이 있는 프로세스의 경우, ReportCrash는 LaunchDaemon으로 실행되어 시스템의 `/Library/Logs/DiagnosticReports`에 충돌 보고서를 저장합니다.

Apple로 **보내지는 충돌 보고서**에 대해 걱정된다면 비활성화할 수 있습니다. 그렇지 않으면 충돌 보고서는 **서버가 어떻게 충돌했는지 파악하는 데 유용**할 수 있습니다.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### 슬립

MacOS에서 퍼징을 할 때 Mac이 슬립 모드로 들어가지 않도록하는 것이 중요합니다:

* systemsetup -setsleep Never
* pmset, 시스템 환경 설정
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH 연결 끊김

SSH 연결을 통해 퍼징을 하는 경우 세션이 종료되지 않도록하는 것이 중요합니다. 따라서 sshd\_config 파일을 다음과 같이 변경하십시오:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### 내부 핸들러

**다음 페이지를 확인**하여 특정 scheme 또는 protocol을 처리하는 앱을 찾는 방법을 알아보세요:

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

### 더 많은 Fuzzing MacOS 정보

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

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, 회사나 그 고객이 **stealer malwares**에 의해 **침해**당했는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난하는 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격에 대항하는 것입니다.

그들의 웹사이트를 방문하여 엔진을 무료로 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop) 확인하기!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass) 참여 또는 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 팔로우하기**.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 트릭 공유하기.

</details>
{% endhint %}
