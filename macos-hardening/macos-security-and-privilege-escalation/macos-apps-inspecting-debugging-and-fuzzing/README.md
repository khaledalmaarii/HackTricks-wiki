# Applications macOS - Inspection, débogage et Fuzzing

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Analyse Statique

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
### jtool2

L'outil peut être utilisé comme **remplacement** pour **codesign**, **otool**, et **objdump**, et offre quelques fonctionnalités supplémentaires. [**Téléchargez-le ici**](http://www.newosxbook.com/tools/jtool.html) ou installez-le avec `brew`.
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

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
### Codesign / ldid

{% hint style="danger" %}
**`Codesign`** se trouve dans **macOS** tandis que **`ldid`** se trouve dans **iOS**
{% endhint %}
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

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) est un outil utile pour inspecter les fichiers **.pkg** (installateurs) et voir ce qu'ils contiennent avant de les installer.\
Ces installateurs ont des scripts bash `preinstall` et `postinstall` que les auteurs de logiciels malveillants utilisent souvent pour **persister** **le** **malware**.

### hdiutil

Cet outil permet de **monter** des images disque Apple (**.dmg**) pour les inspecter avant d'exécuter quoi que ce soit :
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Il sera monté dans `/Volumes`

### Objective-C

#### Métadonnées

{% hint style="danger" %}
Notez que les programmes écrits en Objective-C **conservent** leurs déclarations de classe **lorsqu'ils sont** **compilés** en [binaires Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Ces déclarations de classe **incluent** le nom et le type de :
{% endhint %}

* La classe
* Les méthodes de la classe
* Les variables d'instance de la classe

Vous pouvez obtenir ces informations en utilisant [**class-dump**](https://github.com/nygard/class-dump) :
```bash
class-dump Kindle.app
```
#### Appel de fonction

Lorsqu'une fonction est appelée dans un binaire qui utilise Objective-C, le code compilé, au lieu d'appeler cette fonction, appellera **`objc_msgSend`**. Ce dernier appellera la fonction finale :

![](<../../../.gitbook/assets/image (560).png>)

Les paramètres attendus par cette fonction sont :

* Le premier paramètre (**self**) est "un pointeur qui pointe vers **l'instance de la classe qui doit recevoir le message**". En d'autres termes, c'est l'objet sur lequel la méthode est invoquée. Si la méthode est une méthode de classe, ce sera une instance de l'objet de classe (dans son ensemble), tandis que pour une méthode d'instance, self pointera vers une instance instanciée de la classe en tant qu'objet.
* Le deuxième paramètre, (**op**), est "le sélecteur de la méthode qui gère le message". Encore une fois, pour simplifier, c'est juste le **nom de la méthode**.
* Les paramètres restants sont toutes les **valeurs requises par la méthode** (op).

| **Argument**      | **Registre**                                                    | **(pour) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1er argument**  | **rdi**                                                         | **self : objet sur lequel la méthode est invoquée**    |
| **2e argument**   | **rsi**                                                         | **op : nom de la méthode**                             |
| **3e argument**   | **rdx**                                                         | **1er argument pour la méthode**                       |
| **4e argument**   | **rcx**                                                         | **2e argument pour la méthode**                        |
| **5e argument**   | **r8**                                                          | **3e argument pour la méthode**                        |
| **6e argument**   | **r9**                                                          | **4e argument pour la méthode**                        |
| **7e argument et plus** | <p><strong>rsp+</strong><br><strong>(sur la pile)</strong></p> | **5e argument et plus pour la méthode**               |

### Swift

Avec les binaires Swift, puisqu'il y a compatibilité avec Objective-C, parfois vous pouvez extraire des déclarations en utilisant [class-dump](https://github.com/nygard/class-dump/) mais pas toujours.

Avec les lignes de commande **`jtool -l`** ou **`otool -l`**, il est possible de trouver plusieurs sections qui commencent par le préfixe **`__swift5`** :
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
Vous pouvez trouver plus d'informations sur [**les données stockées dans ces sections dans cet article de blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

De plus, **les binaires Swift peuvent contenir des symboles** (par exemple, les bibliothèques doivent stocker des symboles afin que leurs fonctions puissent être appelées). Les **symboles contiennent généralement des informations sur le nom de la fonction** et les attributs de manière peu élégante, donc ils sont très utiles et il existe des "**démangleurs**" qui peuvent retrouver le nom original :
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Binaires compressés

* Vérifier la haute entropie
* Vérifier les chaînes de caractères (si presque aucune chaîne compréhensible, compressé)
* Le compresseur UPX pour MacOS génère une section appelée "\_\_XHDR"

## Analyse dynamique

{% hint style="warning" %}
Notez que pour déboguer des binaires, **SIP doit être désactivé** (`csrutil disable` ou `csrutil enable --without debug`) ou copier les binaires dans un dossier temporaire et **retirer la signature** avec `codesign --remove-signature <chemin-du-binaire>` ou autoriser le débogage du binaire (vous pouvez utiliser [ce script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Notez que pour **instrumenter des binaires système**, (comme `cloudconfigurationd`) sur macOS, **SIP doit être désactivé** (juste retirer la signature ne fonctionnera pas).
{% endhint %}

### Journaux unifiés

MacOS génère beaucoup de journaux qui peuvent être très utiles lors de l'exécution d'une application pour comprendre **ce qu'elle fait**.

De plus, certains journaux contiendront la balise `<private>` pour **cacher** certaines informations **identifiables** de **l'utilisateur** ou de **l'ordinateur**. Cependant, il est possible **d'installer un certificat pour divulguer ces informations**. Suivez les explications de [**ici**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Panneau de gauche

Dans le panneau de gauche de Hopper, il est possible de voir les symboles (**Labels**) du binaire, la liste des procédures et fonctions (**Proc**) et les chaînes de caractères (**Str**). Ce ne sont pas toutes les chaînes mais celles définies dans plusieurs parties du fichier Mac-O (comme _cstring ou_ `objc_methname`).

#### Panneau du milieu

Dans le panneau du milieu, vous pouvez voir le **code désassemblé**. Et vous pouvez le voir en désassemblage **brut**, en **graphique**, en **décompilé** et en **binaire** en cliquant sur l'icône respective :

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

En cliquant avec le bouton droit sur un objet de code, vous pouvez voir les **références vers/de cet objet** ou même changer son nom (cela ne fonctionne pas dans le pseudocode décompilé) :

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

De plus, dans le **bas du milieu, vous pouvez écrire des commandes python**.

#### Panneau de droite

Dans le panneau de droite, vous pouvez voir des informations intéressantes telles que l'**historique de navigation** (pour savoir comment vous êtes arrivé à la situation actuelle), le **graphe d'appel** où vous pouvez voir toutes les **fonctions qui appellent cette fonction** et toutes les fonctions que **cette fonction appelle**, et les informations sur les **variables locales**.

### dtrace

Il permet aux utilisateurs d'accéder aux applications à un niveau **très bas** et offre un moyen de **tracer** les **programmes** et même de changer leur flux d'exécution. Dtrace utilise des **sondes** qui sont **placées dans tout le noyau** et se trouvent à des emplacements tels que le début et la fin des appels système.

DTrace utilise la fonction **`dtrace_probe_create`** pour créer une sonde pour chaque appel système. Ces sondes peuvent être déclenchées au **point d'entrée et de sortie de chaque appel système**. L'interaction avec DTrace se fait via /dev/dtrace qui est uniquement disponible pour l'utilisateur root.

{% hint style="success" %}
Pour activer Dtrace sans désactiver complètement la protection SIP, vous pourriez exécuter en mode de récupération : `csrutil enable --without dtrace`

Vous pouvez aussi **`dtrace`** ou **`dtruss`** des binaires que **vous avez compilés**.
{% endhint %}

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
Le nom de la sonde se compose de quatre parties : le fournisseur, le module, la fonction et le nom (`fbt:mach_kernel:ptrace:entry`). Si vous ne spécifiez pas certaines parties du nom, Dtrace appliquera cette partie comme un joker.

Pour configurer DTrace afin d'activer les sondes et de spécifier quelles actions effectuer lorsqu'elles se déclenchent, nous devrons utiliser le langage D.

Une explication plus détaillée et plus d'exemples peuvent être trouvés sur [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Exemples

Exécutez `man -k dtrace` pour lister les **scripts DTrace disponibles**. Exemple : `sudo dtruss -n binary`

* En ligne
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
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
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Vous pouvez utiliser celui-ci même avec **SIP activé**
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) est un outil très utile pour vérifier les actions liées aux processus qu'un processus effectue (par exemple, surveiller quels nouveaux processus un processus crée).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) est un outil qui imprime les relations entre les processus.\
Vous devez surveiller votre mac avec une commande comme **`sudo eslogger fork exec rename create > cap.json`** (le terminal qui lance cette commande nécessite FDA). Ensuite, vous pouvez charger le json dans cet outil pour voir toutes les relations :

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permet de surveiller les événements de fichiers (tels que la création, les modifications et les suppressions) en fournissant des informations détaillées sur ces événements.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) est un outil GUI qui offre une apparence et une convivialité que les utilisateurs de Windows peuvent connaître de _Procmon_ de Microsoft Sysinternal. Il vous permet de démarrer et d'arrêter l'enregistrement des événements de tous types, de les filtrer par catégories (fichier, processus, réseau, etc.) et d'enregistrer les événements enregistrés sous forme de fichier json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) fait partie des outils de développement de Xcode – utilisés pour surveiller la performance des applications, identifier les fuites de mémoire et suivre l'activité du système de fichiers.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Permet de suivre les actions effectuées par les processus :
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**TaskExplorer**](https://objective-see.com/products/taskexplorer.html) est utile pour voir les **bibliothèques** utilisées par un binaire, les **fichiers** qu'il utilise et les connexions **réseau**.\
Il vérifie également les processus binaires contre **virustotal** et affiche des informations sur le binaire.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

Dans [**ce billet de blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), vous trouverez un exemple de la manière de **déboguer un daemon en cours d'exécution** qui a utilisé **`PT_DENY_ATTACH`** pour empêcher le débogage même si SIP était désactivé.

### lldb

**lldb** est l'outil **de facto** pour le **débogage** de binaires **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Vous pouvez définir la saveur Intel lors de l'utilisation de lldb en créant un fichier appelé **`.lldbinit`** dans votre dossier personnel avec la ligne suivante :
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Dans lldb, sauvegardez un processus avec `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Commande</strong></td><td><strong>Description</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Démarre l'exécution, qui continuera sans interruption jusqu'à ce qu'un point d'arrêt soit atteint ou que le processus se termine.</td></tr><tr><td><strong>continue (c)</strong></td><td>Continue l'exécution du processus débogué.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Exécute l'instruction suivante. Cette commande passera outre les appels de fonction.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Exécute l'instruction suivante. Contrairement à la commande nexti, cette commande entrera dans les appels de fonction.</td></tr><tr><td><strong>finish (f)</strong></td><td>Exécute le reste des instructions dans la fonction actuelle ("frame") et s'arrête après le retour.</td></tr><tr><td><strong>control + c</strong></td><td>Interrompt l'exécution. Si le processus a été lancé (r) ou continué (c), cela fera s'arrêter le processus... où qu'il soit en train d'exécuter.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Toute fonction appelée main</p><p>b &#x3C;binname>`main #Fonction principale du binaire</p><p>b set -n main --shlib &#x3C;lib_name> #Fonction principale du binaire indiqué</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Liste des points d'arrêt</p><p>br e/dis &#x3C;num> #Activer/Désactiver le point d'arrêt</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Obtenir de l'aide sur la commande breakpoint</p><p>help memory write #Obtenir de l'aide pour écrire dans la mémoire</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;adresse reg/mémoire></strong></td><td>Affiche la mémoire comme une chaîne de caractères terminée par un null.</td></tr><tr><td><strong>x/i &#x3C;adresse reg/mémoire></strong></td><td>Affiche la mémoire comme une instruction d'assemblage.</td></tr><tr><td><strong>x/b &#x3C;adresse reg/mémoire></strong></td><td>Affiche la mémoire comme un octet.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Cela affichera l'objet référencé par le paramètre</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Notez que la plupart des API ou méthodes Objective-C d'Apple retournent des objets, et doivent donc être affichés via la commande "print object" (po). Si po ne produit pas de sortie significative, utilisez <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Écrire AAAA à cette adresse<br>memory write -f s $rip+0x11f+7 "AAAA" #Écrire AAAA à l'adresse</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Désassemble la fonction actuelle</p><p>dis -n &#x3C;nom_fonc> #Désassemble la fonction</p><p>dis -n &#x3C;nom_fonc> -b &#x3C;basename> #Désassemble la fonction<br>dis -c 6 #Désassemble 6 lignes<br>dis -c 0x100003764 -e 0x100003768 # D'une adresse à l'autre<br>dis -p -c 4 #Commence à l'adresse actuelle pour désassembler</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Vérifie un tableau de 3 composants dans le registre x1</td></tr></tbody></table>

{% hint style="info" %}
Lors de l'appel de la fonction **`objc_sendMsg`**, le registre **rsi** contient le **nom de la méthode** sous forme de chaîne de caractères terminée par un null ("C"). Pour afficher le nom via lldb, faites :

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Analyse Dynamique

#### Détection de VM

* La commande **`sysctl hw.model`** retourne "Mac" lorsque l'**hôte est un MacOS** mais quelque chose de différent lorsqu'il s'agit d'une VM.
* En jouant avec les valeurs de **`hw.logicalcpu`** et **`hw.physicalcpu`**, certains malwares tentent de détecter s'il s'agit d'une VM.
* Certains malwares peuvent également **détecter** si la machine est basée sur **VMware** en fonction de l'adresse MAC (00:50:56).
* Il est également possible de trouver **si un processus est débogué** avec un code simple tel que :
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //processus en cours de débogage }`
* Il peut également invoquer l'appel système **`ptrace`** avec le drapeau **`PT_DENY_ATTACH`**. Cela **empêche** un débogueur de s'attacher et de tracer.
* Vous pouvez vérifier si la fonction **`sysctl`** ou **`ptrace`** est **importée** (mais le malware pourrait l'importer dynamiquement)
* Comme noté dans cet article, "[Défaire les Techniques Anti-Débogage : variantes de ptrace sur macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
"_Le message Processus # terminé avec **status = 45 (0x0000002d)** est généralement un signe révélateur que la cible de débogage utilise **PT_DENY_ATTACH**_"

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analyse les processus qui plantent et sauvegarde un rapport de plantage sur le disque**. Un rapport de plantage contient des informations qui peuvent **aider un développeur à diagnostiquer** la cause d'un plantage.\
Pour les applications et autres processus **fonctionnant dans le contexte de lancement par utilisateur**, ReportCrash fonctionne comme un LaunchAgent et sauvegarde les rapports de plantage dans `~/Library/Logs/DiagnosticReports/` de l'utilisateur\
Pour les daemons, autres processus **fonctionnant dans le contexte de lancement système** et autres processus privilégiés, ReportCrash fonctionne comme un LaunchDaemon et sauvegarde les rapports de plantage dans `/Library/Logs/DiagnosticReports` du système

Si vous vous inquiétez que les rapports de plantage **soient envoyés à Apple**, vous pouvez les désactiver. Sinon, les rapports de plantage peuvent être utiles pour **comprendre comment un serveur a planté**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sommeil

Lors du fuzzing sur un MacOS, il est important de ne pas permettre au Mac de se mettre en veille :

* systemsetup -setsleep Never
* pmset, Préférences Système
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Déconnexion SSH

Si vous faites du fuzzing via une connexion SSH, il est important de s'assurer que la session ne va pas se terminer. Modifiez donc le fichier sshd_config avec :

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Gestionnaires internes

**Consultez la page suivante** pour découvrir comment vous pouvez trouver quelle application est responsable de **la gestion du schéma ou protocole spécifié :**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Énumération des processus réseau

Ceci est intéressant pour trouver des processus qui gèrent des données réseau :
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
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Fonctionne pour les outils CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Il fonctionne **"tout simplement"** avec les outils GUI de macOS. Notez que certaines applications macOS ont des exigences spécifiques comme des noms de fichiers uniques, la bonne extension, besoin de lire les fichiers depuis le sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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
```markdown
{% endcode %}

### Plus d'informations sur le Fuzzing MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Références

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
