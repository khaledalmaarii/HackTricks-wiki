# Applications macOS - Inspection, débogage et fuzzing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Analyse statique

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

### Description
`objdump` is a command-line tool that allows you to inspect binary files and object files. It can display information about the headers, sections, symbols, and relocations of a binary file. It can also disassemble the machine code of a binary file into assembly code.

### Description
`objdump` est un outil en ligne de commande qui vous permet d'inspecter les fichiers binaires et les fichiers objets. Il peut afficher des informations sur les en-têtes, les sections, les symboles et les relocalisations d'un fichier binaire. Il peut également désassembler le code machine d'un fichier binaire en code assembleur.
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
```
### jtool2

L'outil peut être utilisé en **remplacement** de **codesign**, **otool** et **objdump**, et offre quelques fonctionnalités supplémentaires.
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

Codesign est un outil de ligne de commande fourni avec Xcode qui permet de signer numériquement les fichiers exécutables et les bibliothèques partagées. La signature numérique garantit que le fichier n'a pas été modifié depuis sa signature et qu'il provient d'un développeur de confiance. Les développeurs peuvent utiliser codesign pour signer leurs applications avant de les distribuer, et les utilisateurs peuvent utiliser codesign pour vérifier l'authenticité des applications qu'ils téléchargent.
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) est un outil utile pour inspecter les fichiers **.pkg** (installateurs) et voir ce qu'il y a à l'intérieur avant de l'installer.\
Ces installateurs ont des scripts bash `preinstall` et `postinstall` que les auteurs de logiciels malveillants utilisent généralement pour **persister** **le** **logiciel malveillant**.

### hdiutil

Cet outil permet de **monter** les images disque Apple (**.dmg**) pour les inspecter avant d'exécuter quoi que ce soit :
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Il sera monté dans `/Volumes`

### Objective-C

Lorsqu'une fonction est appelée dans un binaire qui utilise Objective-C, le code compilé, au lieu d'appeler cette fonction, appellera **`objc_msgSend`**. Qui appellera la fonction finale :

![](<../../../.gitbook/assets/image (560).png>)

Les paramètres que cette fonction attend sont :

* Le premier paramètre (**self**) est "un pointeur qui pointe vers l'**instance de la classe qui doit recevoir le message**". Ou plus simplement, c'est l'objet sur lequel la méthode est invoquée. Si la méthode est une méthode de classe, il s'agira d'une instance de l'objet de classe (dans son ensemble), tandis que pour une méthode d'instance, self pointera vers une instance instanciée de la classe en tant qu'objet.
* Le deuxième paramètre, (**op**), est "le sélecteur de la méthode qui gère le message". Encore une fois, plus simplement, il s'agit simplement du **nom de la méthode**.
* Les paramètres restants sont toutes les **valeurs requises par la méthode** (op).

| **Argument**      | **Registre**                                                    | **(pour) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1er argument**  | **rdi**                                                         | **self : objet sur lequel la méthode est invoquée** |
| **2ème argument**  | **rsi**                                                         | **op : nom de la méthode**                             |
| **3ème argument**  | **rdx**                                                         | **1er argument de la méthode**                         |
| **4ème argument**  | **rcx**                                                         | **2ème argument de la méthode**                         |
| **5ème argument**  | **r8**                                                          | **3ème argument de la méthode**                         |
| **6ème argument**  | **r9**                                                          | **4ème argument de la méthode**                         |
| **7ème+ argument** | <p><strong>rsp+</strong><br><strong>(sur la pile)</strong></p> | **5ème+ argument de la méthode**                        |

### Binaires compressés

* Vérifier l'entropie élevée
* Vérifier les chaînes (s'il n'y a presque aucune chaîne compréhensible, compressée)
* Le packer UPX pour MacOS génère une section appelée "\_\_XHDR"

## Analyse dynamique

{% hint style="warning" %}
Notez que pour déboguer des binaires, **SIP doit être désactivé** (`csrutil disable` ou `csrutil enable --without debug`) ou pour copier les binaires dans un dossier temporaire et **supprimer la signature** avec `codesign --remove-signature <chemin-du-binaire>` ou autoriser le débogage du binaire (vous pouvez utiliser [ce script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Notez que pour **instrumenter les binaires système** (tels que `cloudconfigurationd`) sur macOS, **SIP doit être désactivé** (la simple suppression de la signature ne fonctionnera pas).
{% endhint %}

### Hopper

#### Panneau de gauche

Dans le panneau de gauche de Hopper, il est possible de voir les symboles (**Labels**) du binaire, la liste des procédures et fonctions (**Proc**) et les chaînes (**Str**). Ce ne sont pas toutes les chaînes, mais celles définies dans plusieurs parties du fichier Mac-O (comme _cstring ou_ `objc_methname`).

#### Panneau central

Dans le panneau central, vous pouvez voir le **code désassemblé**. Et vous pouvez le voir sous forme de désassemblage **brut**, sous forme de **graphique**, sous forme de **décompilé** et sous forme **binaire** en cliquant sur l'icône respective :

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

En cliquant avec le bouton droit de la souris sur un objet de code, vous pouvez voir les **références à/depuis cet objet** ou même changer son nom (cela ne fonctionne pas dans le pseudocode décompilé) :

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

De plus, dans le **milieu en bas, vous pouvez écrire des commandes python**.

#### Panneau de droite

Dans le panneau de droite, vous pouvez voir des informations intéressantes telles que l'**historique de navigation** (pour savoir comment vous êtes arrivé à la situation actuelle), le **graphique d'appel** où vous pouvez voir toutes les **fonctions qui appellent cette fonction** et toutes les fonctions que **cette fonction appelle**, et les informations sur les **variables locales**.
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

Il permet aux utilisateurs d'accéder aux applications à un niveau extrêmement **bas** et fournit un moyen aux utilisateurs de **tracer** les **programmes** et même de changer leur flux d'exécution. Dtrace utilise des **sondes** qui sont **placées dans tout le noyau** et se trouvent à des emplacements tels que le début et la fin des appels système.

DTrace utilise la fonction **`dtrace_probe_create`** pour créer une sonde pour chaque appel système. Ces sondes peuvent être déclenchées au **point d'entrée et de sortie de chaque appel système**. L'interaction avec DTrace se fait via /dev/dtrace qui n'est disponible que pour l'utilisateur root.

Les sondes disponibles de dtrace peuvent être obtenues avec:
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

Pour configurer DTrace afin d'activer les sondes et de spécifier les actions à effectuer lorsqu'elles se déclenchent, nous devrons utiliser le langage D.

Une explication plus détaillée et plus d'exemples peuvent être trouvés dans [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

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
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) est un outil très utile pour vérifier les actions liées aux processus qu'un processus effectue (par exemple, surveiller les nouveaux processus qu'un processus crée).

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permet de surveiller les événements de fichiers (tels que la création, la modification et la suppression) en fournissant des informations détaillées sur ces événements.

### fs\_usage

Permet de suivre les actions effectuées par les processus :
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) est utile pour voir les **bibliothèques** utilisées par un binaire, les **fichiers** qu'il utilise et les **connexions réseau**.\
Il vérifie également les processus binaires par rapport à **virustotal** et affiche des informations sur le binaire.

### lldb

**lldb** est l'outil de **débogage** binaire de **macOS** de facto.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
| **Commande (lldb)**           | **Description**                                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **run (r)**                   | Démarre l'exécution, qui se poursuivra sans interruption jusqu'à ce qu'un point d'arrêt soit atteint ou que le processus se termine.                                                                                                                                                                                                                                                                                                                     |
| **continue (c)**              | Continue l'exécution du processus en cours de débogage.                                                                                                                                                                                                                                                                                                                                                                               |
| **nexti (n / ni)**            | Exécute l'instruction suivante. Cette commande sautera les appels de fonction.                                                                                                                                                                                                                                                                                                                                                 |
| **stepi (s / si)**            | Exécute l'instruction suivante. Contrairement à la commande nexti, cette commande entrera dans les appels de fonction.                                                                                                                                                                                                                                                                                                                       |
| **finish (f)**                | Exécute le reste des instructions dans la fonction ("frame") actuelle, retourne et s'arrête.                                                                                                                                                                                                                                                                                                                                   |
| **control + c**               | Interrompt l'exécution. Si le processus a été exécuté (r) ou continué (c), cela provoquera l'arrêt du processus ... où qu'il soit en train d'être exécuté.                                                                                                                                                                                                                                                                             |
| **breakpoint (b)**            | <p>b main</p><p>b -[NSDictionary objectForKey:]</p><p>b 0x0000000100004bd9</p><p>br l #Liste des points d'arrêt</p><p>br e/dis &#x3C;num> #Activer/Désactiver le point d'arrêt</p><p>breakpoint delete &#x3C;num><br>b set -n main --shlib &#x3C;lib_name></p>                                                                                                                                                                               |
| **help**                      | <p>help breakpoint #Obtenir de l'aide sur la commande breakpoint</p><p>help memory write #Obtenir de l'aide pour écrire dans la mémoire</p>                                                                                                                                                                                                                                                                                                         |
| **reg**                       | <p>reg read</p><p>reg read $rax</p><p>reg write $rip 0x100035cc0</p>                                                                                                                                                                                                                                                                                                                                                      |
| **x/s \<reg/memory address>** | Affiche la mémoire sous forme de chaîne terminée par un caractère nul.                                                                                                                                                                                                                                                                                                                                                                           |
| **x/i \<reg/memory address>** | Affiche la mémoire sous forme d'instruction d'assemblage.                                                                                                                                                                                                                                                                                                                                                                               |
| **x/b \<reg/memory address>** | Affiche la mémoire sous forme de byte.                                                                                                                                                                                                                                                                                                                                                                                               |
| **print object (po)**         | <p>Cela affichera l'objet référencé par le paramètre</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Notez que la plupart des API ou méthodes Objective-C d'Apple renvoient des objets et doivent donc être affichées via la commande "print object" (po). Si po ne produit pas de sortie significative, utilisez <code>x/b</code></p> |
| **memory**                    | <p>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Écrire AAAA dans cette adresse<br>memory write -f s $rip+0x11f+7 "AAAA" #Écrire AAAA dans l'adresse</p>                                                                                                                                                                                                                            |
| **disassembly**               | <p>dis #Désassemble la fonction actuelle<br>dis -c 6 #Désassemble 6 lignes<br>dis -c 0x100003764 -e 0x100003768 # De l'une à l'autre<br>dis -p -c 4 # Commence à l'adresse actuelle à désassembler</p>                                                                                                                                                                                                                                 |
| **parray**                    | parray 3 (char \*\*)$x1 # Vérifiez le tableau de 3 composants dans le registre x1                                                                                                                                                                                                                                                                                                                                                           |

{% hint style="info" %}
Lors de l'appel de la fonction **`objc_sendMsg`**, le registre **rsi** contient le **nom de la méthode** sous forme de chaîne de caractères terminée par un caractère nul ("C"). Pour afficher le nom via lldb, faites :

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Analyse Dynamique

#### Détection de la VM

* La commande **`sysctl hw.model`** renvoie "Mac" lorsque l'hôte est un MacOS, mais quelque chose de différent lorsqu'il s'agit d'une VM.
* En jouant avec les valeurs de **`hw.logicalcpu`** et **`hw.physicalcpu`**, certains malwares essaient de détecter s'il s'agit d'une VM.
* Certains malwares peuvent également **détecter** si la machine est basée sur VMware en fonction de l'adresse MAC (00:50:56).
* Il est également possible de savoir si un processus est en cours de débogage avec un code simple tel que :
  * `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //processus en cours de débogage }`
* Il peut également invoquer l'appel système **`ptrace`** avec le drapeau **`PT_DENY_ATTACH`**. Cela **empêche** un débogueur de s'attacher et de tracer.
  * Vous pouvez vérifier si la fonction **`sysctl`** ou **`ptrace`** est **importée** (mais le malware pourrait l'importer dynamiquement)
  * Comme indiqué dans cet article, "[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)":\
    "_Le message Process # exited with **status = 45 (0x0000002d)** est généralement un signe révélateur que la cible de débogage utilise **PT\_DENY\_ATTACH**_"

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analyse les processus en cours de plantage et enregistre un rapport de plantage sur le disque**. Un rapport de plantage contient des informations qui peuvent aider un développeur à diagnostiquer la cause d'un plantage.\
Pour les applications et autres processus **exécutés dans le contexte de lancement par utilisateur**, ReportCrash s'exécute en tant que LaunchAgent et enregistre les rapports de plantage dans `~/Library/Logs/DiagnosticReports/` de l'utilisateur.\
Pour les démons, les autres processus **exécutés dans le contexte de lancement système** et les autres processus privilégiés, ReportCrash s'exécute en tant que LaunchDaemon et enregistre les rapports de plantage dans `/Library/Logs/DiagnosticReports` du système.

Si vous êtes préoccupé par le fait que les rapports de plantage soient envoyés à Apple, vous pouvez les désactiver. Sinon, les rapports de plantage peuvent être utiles pour **déterminer comment un serveur a planté**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sommeil

Lors du fuzzing sur un MacOS, il est important de ne pas permettre au Mac de dormir :

* systemsetup -setsleep Never
* pmset, Préférences Système
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Déconnexion SSH

Si vous faites du fuzzing via une connexion SSH, il est important de s'assurer que la session ne va pas se terminer. Pour cela, modifiez le fichier sshd\_config avec :

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Gestionnaires internes

**Consultez la page suivante** pour savoir comment trouver quelle application est responsable de **la gestion du schéma ou du protocole spécifié :**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Énumération des processus réseau

Il est intéressant de trouver les processus qui gèrent les données réseau :
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
### Utilisez `netstat` ou `lsof`

### Plus d'informations sur le fuzzing MacOS

* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Références

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
