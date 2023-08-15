# macOS Apps - Inspection, débogage et fuzzing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Analyse statique

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

`objdump` est un outil de débogage et d'inspection de fichiers binaires sur macOS. Il permet d'analyser les fichiers exécutables, les bibliothèques partagées et les fichiers d'objets pour obtenir des informations détaillées sur leur structure interne.

L'utilisation de `objdump` peut être utile dans le cadre de l'analyse de logiciels malveillants ou de l'audit de sécurité, car il permet de visualiser le contenu des fichiers binaires, y compris les sections, les symboles, les instructions assembleur et les adresses mémoire.

Voici quelques exemples d'utilisation courante de `objdump` :

- Afficher les informations d'en-tête d'un fichier binaire :
```
$ objdump -h fichier_binaire
```

- Afficher les symboles d'un fichier binaire :
```
$ objdump -t fichier_binaire
```

- Désassembler un fichier binaire pour afficher le code assembleur :
```
$ objdump -d fichier_binaire
```

- Extraire les chaînes de caractères d'un fichier binaire :
```
$ objdump -s fichier_binaire
```

`objdump` est un outil puissant pour l'analyse de fichiers binaires sur macOS. Il peut être utilisé pour comprendre le fonctionnement interne des applications, détecter les vulnérabilités potentielles et effectuer des tâches de débogage avancées.
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
```
### jtool2

L'outil peut être utilisé comme un **remplacement** pour **codesign**, **otool** et **objdump**, et offre quelques fonctionnalités supplémentaires.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

```
### Codesign

La commande `codesign` est utilisée pour signer numériquement les applications macOS, ce qui garantit leur authenticité et leur intégrité. La signature numérique est une mesure de sécurité importante pour empêcher les applications malveillantes d'être exécutées sur un système.

La commande `codesign` peut être utilisée pour inspecter les signatures numériques des applications macOS, ainsi que pour vérifier si une application a été altérée ou modifiée depuis sa signature. Elle peut également être utilisée pour ajouter, supprimer ou remplacer des signatures numériques sur les applications.

Lors de l'inspection d'une signature numérique avec `codesign`, vous pouvez obtenir des informations telles que le certificat utilisé pour signer l'application, la date de signature, les identifiants de l'émetteur et du sujet, ainsi que d'autres détails liés à la signature.

La commande `codesign` peut également être utilisée pour vérifier si une application a été modifiée depuis sa signature en utilisant l'option `--verify`. Cela permet de détecter toute altération ou modification de l'application après sa signature.

En utilisant `codesign`, vous pouvez également ajouter, supprimer ou remplacer des signatures numériques sur les applications. Cela peut être utile dans le cas où vous souhaitez modifier ou mettre à jour la signature d'une application existante.

En résumé, la commande `codesign` est un outil essentiel pour inspecter, vérifier et gérer les signatures numériques des applications macOS, garantissant ainsi leur authenticité et leur intégrité.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) est un outil utile pour inspecter les fichiers **.pkg** (installateurs) et voir ce qu'ils contiennent avant de les installer.\
Ces installateurs ont des scripts bash `preinstall` et `postinstall` que les auteurs de logiciels malveillants utilisent généralement pour **persister** **le** **logiciel malveillant**.

### hdiutil

Cet outil permet de **monter** les images disque Apple (**.dmg**) pour les inspecter avant d'exécuter quoi que ce soit:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Il sera monté dans `/Volumes`

### Objective-C

#### Métadonnées

{% hint style="danger" %}
Notez que les programmes écrits en Objective-C **conservent** leurs déclarations de classe **lorsqu'ils** **sont** **compilés** en [binaires Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Ces déclarations de classe **incluent** le nom et le type de :
{% endhint %}

* La classe
* Les méthodes de classe
* Les variables d'instance de classe

Vous pouvez obtenir ces informations en utilisant [**class-dump**](https://github.com/nygard/class-dump) :
```bash
class-dump Kindle.app
```
Notez que ces noms peuvent être obscurcis pour rendre la rétro-ingénierie du binaire plus difficile.

#### Appel de fonction

Lorsqu'une fonction est appelée dans un binaire qui utilise Objective-C, le code compilé, au lieu d'appeler cette fonction, appellera **`objc_msgSend`**. Ce dernier appellera la fonction finale :

![](<../../../.gitbook/assets/image (560).png>)

Les paramètres que cette fonction attend sont les suivants :

* Le premier paramètre (**self**) est "un pointeur qui pointe vers l'**instance de la classe qui doit recevoir le message**". En d'autres termes, il s'agit de l'objet sur lequel la méthode est invoquée. Si la méthode est une méthode de classe, il s'agira d'une instance de l'objet de classe (dans son ensemble), tandis que pour une méthode d'instance, self pointera vers une instance instanciée de la classe en tant qu'objet.
* Le deuxième paramètre (**op**) est "le sélecteur de la méthode qui gère le message". Encore une fois, plus simplement, il s'agit simplement du **nom de la méthode**.
* Les paramètres restants sont toutes les **valeurs requises par la méthode** (op).

| **Argument**      | **Registre**                                                    | **(pour) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1er argument**  | **rdi**                                                         | **self : objet sur lequel la méthode est invoquée**     |
| **2e argument**  | **rsi**                                                         | **op : nom de la méthode**                             |
| **3e argument**  | **rdx**                                                         | **1er argument de la méthode**                         |
| **4e argument**  | **rcx**                                                         | **2e argument de la méthode**                          |
| **5e argument**  | **r8**                                                          | **3e argument de la méthode**                          |
| **6e argument**  | **r9**                                                          | **4e argument de la méthode**                          |
| **7e+ argument** | <p><strong>rsp+</strong><br><strong>(sur la pile)</strong></p> | **5e+ argument de la méthode**                         |

### Swift

Avec les binaires Swift, étant donné qu'il y a une compatibilité avec Objective-C, il est parfois possible d'extraire des déclarations à l'aide de [class-dump](https://github.com/nygard/class-dump/), mais pas toujours.

Avec les commandes **`jtool -l`** ou **`otool -l`**, il est possible de trouver plusieurs sections qui commencent par le préfixe **`__swift5`** :
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
Vous pouvez trouver plus d'informations sur les [**informations stockées dans ces sections dans cet article de blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

### Binaires compressés

* Vérifiez l'entropie élevée
* Vérifiez les chaînes (s'il n'y a presque aucune chaîne compréhensible, c'est compressé)
* Le packer UPX pour MacOS génère une section appelée "\_\_XHDR"

## Analyse dynamique

{% hint style="warning" %}
Notez que pour déboguer les binaires, **SIP doit être désactivé** (`csrutil disable` ou `csrutil enable --without debug`) ou copier les binaires dans un dossier temporaire et **supprimer la signature** avec `codesign --remove-signature <chemin-du-binaire>` ou autoriser le débogage du binaire (vous pouvez utiliser [ce script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)).
{% endhint %}

{% hint style="warning" %}
Notez que pour **instrumenter les binaires système** (comme `cloudconfigurationd`) sur macOS, **SIP doit être désactivé** (supprimer simplement la signature ne fonctionnera pas).
{% endhint %}

### Journaux unifiés

MacOS génère de nombreux journaux qui peuvent être très utiles lors de l'exécution d'une application pour comprendre **ce qu'elle fait**.

De plus, il existe des journaux qui contiendront la balise `<private>` pour **masquer** certaines informations **identifiables par l'utilisateur** ou **l'ordinateur**. Cependant, il est possible d'**installer un certificat pour divulguer ces informations**. Suivez les explications [**ici**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Panneau de gauche

Dans le panneau de gauche de Hopper, il est possible de voir les symboles (**Labels**) du binaire, la liste des procédures et fonctions (**Proc**) et les chaînes (**Str**). Ce ne sont pas toutes les chaînes, mais celles définies dans plusieurs parties du fichier Mac-O (comme _cstring ou_ `objc_methname`).

#### Panneau central

Dans le panneau central, vous pouvez voir le **code désassemblé**. Et vous pouvez le voir sous forme de désassemblage **brut**, sous forme de **graphique**, sous forme de **décompilation** et sous forme de **binaire** en cliquant sur l'icône respective:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

En cliquant avec le bouton droit sur un objet de code, vous pouvez voir les **références vers/depuis cet objet** ou même changer son nom (cela ne fonctionne pas dans le pseudocode décompilé):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

De plus, dans la **partie inférieure du panneau central, vous pouvez écrire des commandes python**.

#### Panneau de droite

Dans le panneau de droite, vous pouvez voir des informations intéressantes telles que l'**historique de navigation** (pour savoir comment vous êtes arrivé à la situation actuelle), le **graphique d'appel** où vous pouvez voir toutes les **fonctions qui appellent cette fonction** et toutes les fonctions que **cette fonction appelle**, et des informations sur les **variables locales**.

### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Vous pouvez utiliser celui-ci même avec **SIP activé**.
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### dtrace

Il permet aux utilisateurs d'accéder aux applications à un niveau extrêmement **bas** et offre un moyen de **tracer** les **programmes** et même de modifier leur flux d'exécution. Dtrace utilise des **sondes** qui sont **placées dans tout le noyau** et se trouvent à des emplacements tels que le début et la fin des appels système.

DTrace utilise la fonction **`dtrace_probe_create`** pour créer une sonde pour chaque appel système. Ces sondes peuvent être déclenchées au **point d'entrée et de sortie de chaque appel système**. L'interaction avec DTrace se fait via /dev/dtrace, qui n'est disponible que pour l'utilisateur root.

Les sondes disponibles de dtrace peuvent être obtenues avec :
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Le nom de la sonde se compose de quatre parties : le fournisseur, le module, la fonction et le nom (`fbt:mach_kernel:ptrace:entry`). Si vous ne spécifiez pas une partie du nom, Dtrace l'appliquera comme un joker.

Pour configurer DTrace afin d'activer les sondes et spécifier les actions à effectuer lorsqu'elles se déclenchent, nous devrons utiliser le langage D.

Une explication plus détaillée et plus d'exemples peuvent être trouvés sur [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Exemples

Exécutez `man -k dtrace` pour lister les **scripts DTrace disponibles**. Exemple : `sudo dtruss -n binary`

* À la ligne
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
# MacOS Apps: Inspecting, Debugging, and Fuzzing

## Introduction

In this section, we will explore various techniques for inspecting, debugging, and fuzzing MacOS applications. These techniques are essential for identifying vulnerabilities and potential security issues in applications running on MacOS.

## Inspecting MacOS Apps

Inspecting MacOS apps involves analyzing the binary code and resources of an application to understand its inner workings. This can be done using tools like `otool`, `class-dump`, and `Hopper Disassembler`. These tools allow us to examine the app's executable file, libraries, and frameworks, and gain insights into its functionality and potential vulnerabilities.

## Debugging MacOS Apps

Debugging MacOS apps involves analyzing the runtime behavior of an application to identify and fix bugs or security issues. The `lldb` debugger is a powerful tool for debugging MacOS apps. It allows us to set breakpoints, inspect variables, and step through the code to understand how the application behaves under different conditions.

## Fuzzing MacOS Apps

Fuzzing is a technique used to discover vulnerabilities in software by providing unexpected or malformed inputs. Fuzzing MacOS apps involves generating and feeding random or mutated inputs to an application to trigger crashes or unexpected behavior. Tools like `AFL` (American Fuzzy Lop) and `honggfuzz` are commonly used for fuzzing MacOS apps.

## Conclusion

Inspecting, debugging, and fuzzing MacOS apps are crucial steps in the process of identifying and mitigating security vulnerabilities. By understanding the inner workings of an application and analyzing its runtime behavior, we can uncover potential weaknesses and improve the overall security of MacOS apps.

---

* script
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) est un outil très utile pour vérifier les actions liées aux processus qu'un processus effectue (par exemple, surveiller les nouveaux processus qu'un processus crée).

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permet de surveiller les événements liés aux fichiers (tels que la création, les modifications et les suppressions) en fournissant des informations détaillées sur ces événements.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) font partie des outils de développement de Xcode - utilisés pour surveiller les performances des applications, identifier les fuites de mémoire et suivre l'activité du système de fichiers.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Permet de suivre les actions effectuées par les processus :
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) est utile pour voir les **bibliothèques** utilisées par un binaire, les **fichiers** qu'il utilise et les **connexions réseau**.\
Il vérifie également les processus binaires avec **virustotal** et affiche des informations sur le binaire.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

Dans [**cet article de blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), vous pouvez trouver un exemple sur la façon de **déboguer un démon en cours d'exécution** qui utilise **`PT_DENY_ATTACH`** pour empêcher le débogage même si SIP est désactivé.

### lldb

**lldb** est l'outil de **débogage** binaire de facto pour **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
{% hint style="warning" %}
À l'intérieur de lldb, effectuez un dump d'un processus avec `process save-core`
{% endhint %}

| **Commande (lldb)**           | **Description**                                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **run (r)**                   | Démarre l'exécution, qui se poursuivra jusqu'à ce qu'un point d'arrêt soit atteint ou que le processus se termine.                                                                                                                                                                                                                                                                                                         |
| **continue (c)**              | Poursuit l'exécution du processus en cours de débogage.                                                                                                                                                                                                                                                                                                                                                                   |
| **nexti (n / ni)**            | Exécute l'instruction suivante. Cette commande sautera les appels de fonction.                                                                                                                                                                                                                                                                                                                                             |
| **stepi (s / si)**            | Exécute l'instruction suivante. Contrairement à la commande nexti, cette commande entrera dans les appels de fonction.                                                                                                                                                                                                                                                                                                    |
| **finish (f)**                | Exécute le reste des instructions dans la fonction ("frame") en cours, retourne et s'arrête.                                                                                                                                                                                                                                                                                                                              |
| **control + c**               | Met en pause l'exécution. Si le processus a été exécuté (r) ou poursuivi (c), cela provoquera l'arrêt du processus ... où qu'il se trouve actuellement en cours d'exécution.                                                                                                                                                                                                                                               |
| **breakpoint (b)**            | <p>b main</p><p>b -[NSDictionary objectForKey:]</p><p>b 0x0000000100004bd9</p><p>br l #Liste des points d'arrêt</p><p>br e/dis &#x3C;num> #Activer/Désactiver le point d'arrêt</p><p>breakpoint delete &#x3C;num><br>b set -n main --shlib &#x3C;lib_name></p>                                                                                                                                                                               |
| **help**                      | <p>help breakpoint #Obtenir de l'aide sur la commande breakpoint</p><p>help memory write #Obtenir de l'aide pour écrire dans la mémoire</p>                                                                                                                                                                                                                                                                               |
| **reg**                       | <p>reg read</p><p>reg read $rax</p><p>reg write $rip 0x100035cc0</p>                                                                                                                                                                                                                                                                                                                                                      |
| **x/s \<reg/adresse mémoire>** | Affiche la mémoire sous forme de chaîne terminée par un caractère nul.                                                                                                                                                                                                                                                                                                                                                    |
| **x/i \<reg/adresse mémoire>** | Affiche la mémoire sous forme d'instruction d'assemblage.                                                                                                                                                                                                                                                                                                                                                                 |
| **x/b \<reg/adresse mémoire>** | Affiche la mémoire sous forme d'octet.                                                                                                                                                                                                                                                                                                                                                                                     |
| **print object (po)**         | <p>Cela affichera l'objet référencé par le paramètre</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Notez que la plupart des API ou méthodes Objective-C d'Apple renvoient des objets et doivent donc être affichées via la commande "print object" (po). Si po ne produit pas de sortie significative, utilisez <code>x/b</code></p> |
| **memory**                    | <p>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Écrire AAAA à cette adresse<br>memory write -f s $rip+0x11f+7 "AAAA" #Écrire AAAA à l'adresse</p>                                                                                                                                                                                                                            |
| **disassembly**               | <p>dis #Désassemble la fonction en cours<br>dis -c 6 #Désassemble 6 lignes<br>dis -c 0x100003764 -e 0x100003768 # De l'une à l'autre<br>dis -p -c 4 # Commence à l'adresse actuelle de désassemblage</p>                                                                                                                                                                                                                     |
| **parray**                    | parray 3 (char \*\*)$x1 # Vérifiez le tableau de 3 composants dans le registre x1                                                                                                                                                                                                                                                                                                                                         |

{% hint style="info" %}
Lors de l'appel de la fonction **`objc_sendMsg`**, le registre **rsi** contient le **nom de la méthode** sous forme de chaîne terminée par un caractère nul ("C"). Pour afficher le nom via lldb, faites :

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Analyse Dynamique

#### Détection de la machine virtuelle

* La commande **`sysctl hw.model`** renvoie "Mac" lorsque l'hôte est un MacOS, mais quelque chose de différent lorsqu'il s'agit d'une machine virtuelle.
* En jouant avec les valeurs de **`hw.logicalcpu`** et **`hw.physicalcpu`**, certains logiciels malveillants tentent de détecter s'il s'agit d'une machine virtuelle.
* Certains logiciels malveillants peuvent également **détecter** si la machine est basée sur VMware en fonction de l'adresse MAC (00:50:56).
* Il est également possible de savoir si un processus est en cours de débogage avec un code simple tel que :
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //processus en cours de débogage }`
* Il peut également invoquer l'appel système **`ptrace`** avec le drapeau **`PT_DENY_ATTACH`**. Cela **empêche** un débogueur de se connecter et de tracer.
* Vous pouvez vérifier si la fonction **`sysctl`** ou **`ptrace`** est **importée** (mais le logiciel malveillant pourrait l'importer dynamiquement)
* Comme indiqué dans cet article, "[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)":\
"_Le message Process # exited with **status = 45 (0x0000002d)** est généralement un signe révélateur que la cible de débogage utilise **PT\_DENY\_ATTACH**_"

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analyse les processus en cours de plantage et enregistre un rapport de plantage sur le disque**. Un rapport de plantage contient des informations qui peuvent **aider un développeur à diagnostiquer** la cause d'un plantage.\
Pour les applications et autres processus **exécutés dans le contexte de lancement par utilisateur**, ReportCrash s'exécute en tant que LaunchAgent et enregistre les rapports de plantage dans le dossier `~/Library/Logs/DiagnosticReports/` de l'utilisateur.\
Pour les démons, les autres processus **exécutés dans le contexte de lancement système** et les autres processus privilégiés, ReportCrash s'exécute en tant que LaunchDaemon et enregistre les rapports de plantage dans le dossier `/Library/Logs/DiagnosticReports` du système.

Si vous êtes préoccupé par l'envoi des rapports de plantage à Apple, vous pouvez les désactiver. Sinon, les rapports de plantage peuvent être utiles pour **déterminer comment un serveur a planté**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sommeil

Lors de la fuzzing sur un MacOS, il est important de ne pas permettre au Mac de se mettre en veille :

* systemsetup -setsleep Never
* pmset, Préférences Système
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Déconnexion SSH

Si vous effectuez une fuzzing via une connexion SSH, il est important de s'assurer que la session ne se termine pas. Modifiez donc le fichier sshd\_config avec :

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Gestionnaires internes

**Consultez la page suivante** pour découvrir comment vous pouvez trouver quelle application est responsable de **la gestion du schéma ou du protocole spécifié :**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Énumération des processus réseau

C'est intéressant de trouver les processus qui gèrent les données réseau :
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Ou utilisez `netstat` ou `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Fonctionne pour les outils en ligne de commande

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Il fonctionne "**juste"** avec les outils GUI de macOS. Notez que certaines applications macOS ont des exigences spécifiques telles que des noms de fichiers uniques, la bonne extension, la nécessité de lire les fichiers à partir du sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

Quelques exemples :

{% code overflow="wrap" %}
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
{% endcode %}

### Plus d'informations sur le fuzzing MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Références

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
