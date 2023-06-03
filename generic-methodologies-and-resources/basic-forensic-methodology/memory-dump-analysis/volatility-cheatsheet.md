# Volatility - Fiche de triche

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus important en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

Si vous voulez quelque chose de **rapide et fou** qui lancera plusieurs plugins Volatility en parallèle, vous pouvez utiliser : [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Installation

### Volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="Méthode1" %} 

#### Analyse de la mémoire

- `volatility2 -f <dump> imageinfo` : Affiche les informations de l'image mémoire.
- `volatility2 -f <dump> kdbgscan` : Recherche le KDBG (Kernel Debugger Block) dans l'image mémoire.
- `volatility2 -f <dump> pslist` : Affiche la liste des processus en cours d'exécution.
- `volatility2 -f <dump> psscan` : Recherche les processus dans l'image mémoire.
- `volatility2 -f <dump> pstree` : Affiche l'arborescence des processus.
- `volatility2 -f <dump> psxview` : Affiche les processus cachés.
- `volatility2 -f <dump> dlllist -p <pid>` : Affiche les DLL chargées par un processus.
- `volatility2 -f <dump> handles -p <pid>` : Affiche les handles ouverts par un processus.
- `volatility2 -f <dump> filescan` : Recherche les fichiers ouverts dans l'image mémoire.
- `volatility2 -f <dump> netscan` : Recherche les connexions réseau dans l'image mémoire.
- `volatility2 -f <dump> connscan` : Recherche les connexions réseau dans l'image mémoire.
- `volatility2 -f <dump> cmdline` : Affiche les commandes exécutées par les processus.
- `volatility2 -f <dump> consoles` : Affiche les consoles ouvertes par les processus.
- `volatility2 -f <dump> hivelist` : Affiche la liste des hives de registre chargés dans l'image mémoire.
- `volatility2 -f <dump> printkey -K <registry_key>` : Affiche les valeurs d'une clé de registre.
- `volatility2 -f <dump> malfind` : Recherche les malwares dans l'image mémoire.
- `volatility2 -f <dump> apihooks` : Affiche les hooks d'API dans l'image mémoire.
- `volatility2 -f <dump> idt` : Affiche la Interrupt Descriptor Table.
- `volatility2 -f <dump> gdt` : Affiche la Global Descriptor Table.
- `volatility2 -f <dump> ldrmodules` : Affiche les modules chargés dans l'image mémoire.
- `volatility2 -f <dump> modscan` : Recherche les modules dans l'image mémoire.
- `volatility2 -f <dump> svcscan` : Recherche les services dans l'image mémoire.
- `volatility2 -f <dump> driverirp` : Affiche les IRP (I/O Request Packets) des drivers.
- `volatility2 -f <dump> callbacks` : Affiche les callbacks enregistrés dans l'image mémoire.
- `volatility2 -f <dump> timers` : Affiche les timers enregistrés dans l'image mémoire.
- `volatility2 -f <dump> mutantscan` : Recherche les mutants dans l'image mémoire.
- `volatility2 -f <dump> atomscan` : Recherche les atomes dans l'image mémoire.
- `volatility2 -f <dump> deskscan` : Recherche les desktops dans l'image mémoire.
- `volatility2 -f <dump> privs` : Affiche les privilèges des processus.
- `volatility2 -f <dump> getsids` : Affiche les SIDs (Security Identifiers) des processus.
- `volatility2 -f <dump> envars` : Affiche les variables d'environnement des processus.
- `volatility2 -f <dump> iehistory` : Affiche l'historique de navigation Internet Explorer.
- `volatility2 -f <dump> chromehistory` : Affiche l'historique de navigation Google Chrome.
- `volatility2 -f <dump> firefoxhistory` : Affiche l'historique de navigation Mozilla Firefox.
- `volatility2 -f <dump> shellbags` : Affiche les ShellBags (dossiers ouverts récemment).
- `volatility2 -f <dump> shimcache` : Affiche le cache de compatibilité des applications.
- `volatility2 -f <dump> userassist` : Affiche les entrées UserAssist (programmes exécutés récemment).
- `volatility2 -f <dump> printd` : Affiche les travaux d'impression.
- `volatility2 -f <dump> svcmod` : Affiche les modules des services.
- `volatility2 -f <dump> sessions` : Affiche les sessions utilisateur.
- `volatility2 -f <dump> clipboard` : Affiche le contenu du presse-papiers.
- `volatility2 -f <dump> hashdump -y <system_hive> -s <sam_hive>` : Dump les hashes des comptes utilisateurs.
- `volatility2 -f <dump> mimikatz` : Exécute Mimikatz dans l'image mémoire.
- `volatility2 -f <dump> yarascan -Y <rules_file>` : Recherche des patterns Yara dans l'image mémoire.
- `volatility2 -f <dump> yarascan -y <yararule>` : Recherche un pattern Yara dans l'image mémoire.
- `volatility2 -f <dump> dumpfiles -Q <offset>` : Dump un fichier à partir d'un offset.
- `volatility2 -f <dump> dumpfiles -D <directory>` : Dump tous les fichiers de l'image mémoire.
- `volatility2 -f <dump> dumpfiles -U <directory>` : Dump tous les fichiers uniques de l'image mémoire.
- `volatility2 -f <dump> dumpfiles -Q <offset> -n <filename>` : Dump un fichier à partir d'un offset avec un nom spécifique.
- `volatility2 -f <dump> dumpfiles -Q <offset> -s <size>` : Dump un fichier à partir d'un offset avec une taille spécifique.

{% endtab %}
{% endtabs %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="Méthode 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Commandes Volatility

Accédez à la documentation officielle dans [Référence des commandes Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Note sur les plugins "list" vs "scan"

Volatility a deux approches principales pour les plugins, qui sont parfois reflétées dans leurs noms. Les plugins "list" essaieront de naviguer à travers les structures du noyau Windows pour récupérer des informations telles que les processus (localiser et parcourir la liste chaînée des structures `_EPROCESS` en mémoire), les poignées OS (localiser et lister la table de poignées, déréférencer les pointeurs trouvés, etc.). Ils se comportent plus ou moins comme le ferait l'API Windows si on lui demandait, par exemple, de lister les processus.

Cela rend les plugins "list" assez rapides, mais tout aussi vulnérables que l'API Windows à la manipulation par les logiciels malveillants. Par exemple, si un logiciel malveillant utilise DKOM pour délier un processus de la liste chaînée `_EPROCESS`, il n'apparaîtra pas dans le Gestionnaire des tâches et ne le fera pas non plus dans la liste des processus.

Les plugins "scan", en revanche, adopteront une approche similaire à la sculpture de la mémoire pour des choses qui pourraient avoir du sens lorsqu'elles sont déréférencées en tant que structures spécifiques. `psscan`, par exemple, lira la mémoire et essaiera de créer des objets `_EPROCESS` à partir de celle-ci (il utilise la recherche de pool-tag, qui recherche des chaînes de 4 octets indiquant la présence d'une structure d'intérêt). L'avantage est qu'il peut déterrer des processus qui ont quitté, et même si les logiciels malveillants altèrent la liste chaînée `_EPROCESS`, le plugin trouvera toujours la structure qui traîne en mémoire (puisqu'elle doit encore exister pour que le processus s'exécute). La chute est que les plugins "scan" sont un peu plus lents que les plugins "list" et peuvent parfois donner des faux positifs (un processus qui a quitté il y a trop longtemps et dont certaines parties de sa structure ont été écrasées par d'autres opérations).

À partir de: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Profils OS

### Volatility3

Comme expliqué dans le fichier readme, vous devez mettre la **table des symboles de l'OS** que vous souhaitez prendre en charge dans _volatility3/volatility/symbols_.\
Les packs de tables de symboles pour les différents systèmes d'exploitation sont disponibles en **téléchargement** sur:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Profil externe

Vous pouvez obtenir la liste des profils pris en charge en faisant:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Si vous souhaitez utiliser un **nouveau profil que vous avez téléchargé** (par exemple, un profil Linux), vous devez créer quelque part la structure de dossier suivante : _plugins/overlays/linux_ et mettre à l'intérieur de ce dossier le fichier zip contenant le profil. Ensuite, obtenez le nombre de profils en utilisant :
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Vous pouvez **télécharger des profils Linux et Mac** depuis [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

Dans le chunk précédent, vous pouvez voir que le profil s'appelle `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, et vous pouvez l'utiliser pour exécuter quelque chose comme:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Découvrir le profil
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Différences entre imageinfo et kdbgscan**

Contrairement à imageinfo qui fournit simplement des suggestions de profil, **kdbgscan** est conçu pour identifier positivement le profil correct et l'adresse KDBG correcte (s'il y en a plusieurs). Ce plugin recherche les signatures KDBGHeader liées aux profils de Volatility et applique des vérifications de cohérence pour réduire les faux positifs. La verbosité de la sortie et le nombre de vérifications de cohérence qui peuvent être effectuées dépendent de la capacité de Volatility à trouver un DTB, donc si vous connaissez déjà le profil correct (ou si vous avez une suggestion de profil à partir de imageinfo), assurez-vous de l'utiliser (à partir de [ici](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)).

Vérifiez toujours le **nombre de processus que kdbgscan a trouvé**. Parfois, imageinfo et kdbgscan peuvent trouver **plus d'un** profil approprié, mais seul le **bon aura des processus associés** (Cela est dû au fait que pour extraire les processus, l'adresse KDBG correcte est nécessaire).
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

Le **bloc de débogage du noyau** (nommé KdDebuggerDataBlock de type \_KDDEBUGGER\_DATA64, ou **KDBG** par Volatility) est important pour de nombreuses choses que Volatility et les débogueurs font. Par exemple, il a une référence à PsActiveProcessHead qui est la tête de liste de tous les processus requis pour la liste des processus.

## Informations sur le système d'exploitation
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Le plugin `banners.Banners` peut être utilisé dans **vol3 pour essayer de trouver des bannières linux** dans le dump.

## Hashes/Mots de passe

Extraire les hachages SAM, les [informations d'identification mises en cache du domaine](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) et les [secrets LSA](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets).
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Installation

```bash
pip install volatility
```

## Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

## Plugins

### Process Analysis

#### pslist

List running processes.

```bash
volatility -f <memory_dump> pslist
```

#### psscan

Scan for processes.

```bash
volatility -f <memory_dump> psscan
```

#### pstree

Display process tree.

```bash
volatility -f <memory_dump> pstree
```

#### dlllist

List loaded DLLs.

```bash
volatility -f <memory_dump> dlllist
```

#### handles

List open handles.

```bash
volatility -f <memory_dump> handles
```

#### cmdscan

Scan for command history.

```bash
volatility -f <memory_dump> cmdscan
```

### Malware Analysis

#### malfind

Find hidden and injected code.

```bash
volatility -f <memory_dump> malfind
```

#### malprocfind

Find hidden processes.

```bash
volatility -f <memory_dump> malprocfind
```

#### malfind

Find hidden files.

```bash
volatility -f <memory_dump> malfind
```

### Memory Analysis

#### memdump

Dump process memory.

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
```

#### memmap

Display memory map.

```bash
volatility -f <memory_dump> memmap
```

#### memstrings

Extract printable strings.

```bash
volatility -f <memory_dump> memstrings
```

#### memimage

Extract PE files.

```bash
volatility -f <memory_dump> memimage
```

#### memdiff

Compare memory dumps.

```bash
volatility -f <memory_dump1> memdiff -f <memory_dump2>
```

### Network Analysis

#### connscan

List open connections.

```bash
volatility -f <memory_dump> connscan
```

#### sockets

List open sockets.

```bash
volatility -f <memory_dump> sockets
```

#### netscan

Scan for network activity.

```bash
volatility -f <memory_dump> netscan
```

### User Analysis

#### hivelist

List registry hives.

```bash
volatility -f <memory_dump> hivelist
```

#### hashdump

Dump password hashes.

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -u <user_hive>
```

#### userassist

List userassist entries.

```bash
volatility -f <memory_dump> userassist
```

#### getsids

List user SIDs.

```bash
volatility -f <memory_dump> getsids
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

### Windows Registry Analysis

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### printval

Print registry value.

```bash
volatility -f <memory_dump> printval -K <key_path> -V <value_name>
```

#### hivedump

Dump registry hive.

```bash
volatility -f <memory_dump> hivedump -o <offset> -s <size> -w <output_file>
```

### Virtualization Analysis

#### vboxinfo

Display VirtualBox information.

```bash
volatility -f <memory_dump> vboxinfo
```

#### vboxsf

List VirtualBox shared folders.

```bash
volatility -f <memory_dump> vboxsf
```

#### vmwareinfo

Display VMware information.

```bash
volatility -f <memory_dump> vmwareinfo
```

#### vmscan

Scan for virtual machines.

```bash
volatility -f <memory_dump> vmscan
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}
{% endtabs %}

## Dump de mémoire

Le dump de mémoire d'un processus va extraire tout ce qui concerne l'état actuel du processus. Le module **procdump** ne va extraire que le **code**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en Espagne et l'un des plus importants en Europe. Avec pour mission de promouvoir les connaissances techniques, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

## Processus

### Liste des processus

Essayez de trouver des processus **suspects** (par nom) ou des **processus** enfants **inattendus** (par exemple, un cmd.exe en tant qu'enfant de iexplorer.exe).\
Il pourrait être intéressant de **comparer** le résultat de pslist avec celui de psscan pour identifier les processus cachés. 

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

### Plugin `dumpregistry`

```bash
volatility -f <nom_du_fichier> dumpregistry -o <registry_hive> -D <dossier_de_sortie>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `dumpcerts`

```bash
volatility -f <nom_du_fichier> dumpcerts -O <dossier_de_sortie>
```

### Plugin `dumpcache`

```bash
volatility -f <nom_du_fichier> dumpcache -D <dossier_de_sortie>
```

### Plugin `dumpregistry`

```bash
volatility -f <nom_du_fichier> dumpregistry -o <registry_hive> -D <dossier_de_sortie>
```

### Plugin `dumpregistryvalues`

```bash
volatility -f <nom_du_fichier> dumpregistryvalues -o <registry_hive> -D <dossier_de_sortie>
```

### Plugin `dumpall`

```bash
volatility -f <nom_du_fichier> dumpall -D <dossier_de_sortie>
```

### Plugin `moddump`

```bash
volatility -f <nom_du_fichier> moddump -D <dossier_de_sortie>
```

### Plugin `modscan`

```bash
volatility -f <nom_du_fichier> modscan
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `svcscan`

```bash
volatility -f <nom_du_fichier> svcscan
```

### Plugin `printkey`

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Plugin `getsids`

```bash
volatility -f <nom_du_fichier> getsids
```

### Plugin `userassist`

```bash
volatility -f <nom_du_fichier> userassist
```

### Plugin `dumpcerts`

```bash
volatility -f <nom_du_fichier> dumpcerts -O <dossier_de_sortie>
```

### Plugin `dumpcache`

```bash
volatility -f <nom_du_fichier> dumpcache -D <dossier_de_sortie>
```

### Plugin `connscan`

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

### Plugin `sockets`

```bash
volatility -f <nom_du_fichier> sockets
```

### Plugin `sockscan`

```bash
volatility -f <nom_du_fichier> sockscan
```

### Plugin `filescan`

```bash
volatility -f <nom_du_fichier> filescan
```

### Plugin `pslist`

```bash
volatility -f <nom_du_fichier> pslist
```

### Plugin `psscan`

```bash
volatility -f <nom_du_fichier> psscan
```

### Plugin `pstree`

```bash
volatility -f <nom_du_fichier> pstree
```

### Plugin `dlllist`

```bash
volatility -f <nom_du_fichier> dlllist
```

### Plugin `netscan`

```bash
volatility -f <nom_du_fichier> netscan
```

### Plugin `procdump`

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

### Plugin `memdump`

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet) (en anglais)
- [Volatility Plugin List](https://github.com/superponible/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/tehw0lf/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/JamesHabben/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/JamesHabben/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/JamesHabben/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/JamesHabben/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/JamesHabben/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/JamesHabben/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/JamesHabben/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/JamesHabben/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/JamesHabben/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Analyse de dump proc

{% tabs %}
{% tab title="vol3" %}
#### Commandes de base

- `volatility -f <dump> --profile=<profile> pslist` : liste des processus
- `volatility -f <dump> --profile=<profile> psscan` : liste des processus (scan)
- `volatility -f <dump> --profile=<profile> pstree` : arborescence des processus
- `volatility -f <dump> --profile=<profile> psxview` : liste des processus cachés
- `volatility -f <dump> --profile=<profile> dlllist -p <pid>` : liste des DLL chargées par un processus
- `volatility -f <dump> --profile=<profile> handles -p <pid>` : liste des handles ouverts par un processus
- `volatility -f <dump> --profile=<profile> cmdline -p <pid>` : commande lancée par un processus
- `volatility -f <dump> --profile=<profile> consoles` : liste des consoles ouvertes
- `volatility -f <dump> --profile=<profile> consoles -p <pid>` : console ouverte par un processus
- `volatility -f <dump> --profile=<profile> consoles -u <user>` : consoles ouvertes par un utilisateur
- `volatility -f <dump> --profile=<profile> consoles -t <session>` : consoles ouvertes dans une session
- `volatility -f <dump> --profile=<profile> getsids` : liste des SIDs
- `volatility -f <dump> --profile=<profile> getsids -p <pid>` : SID d'un processus
- `volatility -f <dump> --profile=<profile> getsids -u <user>` : SIDs d'un utilisateur
- `volatility -f <dump> --profile=<profile> getsids -t <session>` : SIDs d'une session

#### Analyse de processus

- `volatility -f <dump> --profile=<profile> procdump -p <pid> -D <output_directory>` : dump d'un processus
- `volatility -f <dump> --profile=<profile> memdump -p <pid> -D <output_directory>` : dump de la mémoire d'un processus
- `volatility -f <dump> --profile=<profile> memdump -p <pid> --dump-dir=<output_directory>` : dump de la mémoire d'un processus (alternative)
- `volatility -f <dump> --profile=<profile> memmap` : liste des régions mémoire
- `volatility -f <dump> --profile=<profile> memmap -p <pid>` : liste des régions mémoire d'un processus
- `volatility -f <dump> --profile=<profile> memdump -r <start_address>-<end_address> -D <output_directory>` : dump d'une région mémoire
- `volatility -f <dump> --profile=<profile> memdump -R <region_number> -D <output_directory>` : dump d'une région mémoire (alternative)
- `volatility -f <dump> --profile=<profile> memdump --dump-dir=<output_directory> --pid=<pid>` : dump de la mémoire d'un processus (alternative)
- `volatility -f <dump> --profile=<profile> memdump --dump-dir=<output_directory> --address=<address>` : dump d'une région mémoire (alternative)

#### Analyse de DLL

- `volatility -f <dump> --profile=<profile> dlldump -p <pid> -b <base_address> -D <output_directory>` : dump d'une DLL chargée par un processus
- `volatility -f <dump> --profile=<profile> dlldump -b <base_address> -D <output_directory>` : dump d'une DLL chargée dans le dump
- `volatility -f <dump> --profile=<profile> dlldump -p <pid> -b <base_address> --dump-dir=<output_directory>` : dump d'une DLL chargée par un processus (alternative)
- `volatility -f <dump> --profile=<profile> dlldump -b <base_address> --dump-dir=<output_directory>` : dump d'une DLL chargée dans le dump (alternative)

#### Analyse de handles

- `volatility -f <dump> --profile=<profile> handles` : liste des handles ouverts
- `volatility -f <dump> --profile=<profile> handles -p <pid>` : liste des handles ouverts par un processus
- `volatility -f <dump> --profile=<profile> handles -t <type>` : liste des handles d'un type
- `volatility -f <dump> --profile=<profile> handles -u <user>` : liste des handles ouverts par un utilisateur
- `volatility -f <dump> --profile=<profile> handles -p <pid> -o <object>` : liste des handles ouverts par un processus pour un objet donné
- `volatility -f <dump> --profile=<profile> handles -p <pid> -o <object> -O` : dump de l'objet associé à un handle

#### Analyse de threads

- `volatility -f <dump> --profile=<profile> threads` : liste des threads
- `volatility -f <dump> --profile=<profile> threads -p <pid>` : liste des threads d'un processus
- `volatility -f <dump> --profile=<profile> threads -t <tid>` : informations sur un thread
- `volatility -f <dump> --profile=<profile> threads -p <pid> --dump-dir=<output_directory>` : dump de la pile d'un processus
- `volatility -f <dump> --profile=<profile> threads -t <tid> --dump-dir=<output_directory>` : dump de la pile d'un thread

#### Analyse de la mémoire

- `volatility -f <dump> --profile=<profile> memdump -D <output_directory>` : dump de la mémoire
- `volatility -f <dump> --profile=<profile> memdump --dump-dir=<output_directory>` : dump de la mémoire (alternative)
- `volatility -f <dump> --profile=<profile> memdump -r <start_address>-<end_address> -D <output_directory>` : dump d'une région mémoire
- `volatility -f <dump> --profile=<profile> memdump -R <region_number> -D <output_directory>` : dump d'une région mémoire (alternative)
- `volatility -f <dump> --profile=<profile> memdump --dump-dir=<output_directory> --address=<address>` : dump d'une région mémoire (alternative)

#### Analyse de la pile

- `volatility -f <dump> --profile=<profile> stackstrings -p <pid>` : recherche de chaînes de caractères dans la pile d'un processus
- `volatility -f <dump> --profile=<profile> stack -p <pid>` : affichage de la pile d'un processus
- `volatility -f <dump> --profile=<profile> stack -p <pid> -o <offset>` : affichage de la pile d'un processus à partir d'un offset donné
- `volatility -f <dump> --profile=<profile> stack -p <pid> -o <offset> --dump-dir=<output_directory>` : dump de la pile d'un processus à partir d'un offset donné

#### Analyse de la heap

- `volatility -f <dump> --profile=<profile> heaps` : liste des heaps
- `volatility -f <dump> --profile=<profile> heaps -p <pid>` : liste des heaps d'un processus
- `volatility -f <dump> --profile=<profile> heap -p <pid> -D <output_directory>` : dump de la heap d'un processus
- `volatility -f <dump> --profile=<profile> heap -p <pid> -o <offset> -D <output_directory>` : dump de la heap d'un processus à partir d'un offset donné
- `volatility -f <dump> --profile=<profile> heap -p <pid> -o <offset> --dump-dir=<output_directory>` : dump de la heap d'un processus à partir d'un offset donné (alternative)

#### Analyse de la mémoire partagée

- `volatility -f <dump> --profile=<profile> shims -p <pid>` : liste des shims d'un processus
- `volatility -f <dump> --profile=<profile> shims -p <pid> -s <dll>` : informations sur un shim d'un processus pour une DLL donnée
- `volatility -f <dump> --profile=<profile> shims -p <pid> -s <dll> -D <output_directory>` : dump de la mémoire partagée d'un shim d'un processus pour une DLL donnée
- `volatility -f <dump> --profile=<profile> shims -p <pid> -s <dll> -o <offset> -D <output_directory>` : dump de la mémoire partagée d'un shim d'un processus pour une DLL donnée à partir d'un offset donné
- `volatility -f <dump> --profile=<profile> shims -p <pid> -s <dll> -o <offset> --dump-dir=<output_directory>` : dump de la mémoire partagée d'un shim d'un processus pour une DLL donnée à partir d'un offset donné (alternative)

#### Analyse de la mémoire virtuelle

- `volatility -f <dump> --profile=<profile> vadinfo` : informations sur les VADs
- `volatility -f <dump> --profile=<profile> vadtree` : arborescence des VADs
- `volatility -f <dump> --profile=<profile> vadwalk -p <pid>` : arborescence des VADs d'un processus
- `volatility -f <dump> --profile=<profile> vadtree -p <pid>` : arborescence des VADs d'un processus
- `volatility -f <dump> --profile=<profile> vadtree -p <pid> -o <offset>` : arborescence des VADs d'un processus à partir d'un offset donné
- `volatility -f <dump> --profile=<profile> vadtree -p <pid> -o <offset> --dump-dir=<output_directory>` : dump de la mémoire virtuelle d'un processus à partir d'un offset donné
- `volatility -f <dump> --profile=<profile> vadtree -p <pid> -o <offset> --dump-dir=<output_directory> --dump-children` : dump de la mémoire virtuelle d'un processus à partir d'un offset donné et de ses enfants

#### Analyse de la mémoire physique

- `volatility -f <dump> --profile=<profile> physmap` : liste des pages physiques
- `volatility -f <dump> --profile=<profile> physmap -p <pid>` : liste des pages physiques d'un processus
- `volatility -f <dump> --profile=<profile> physmap -p <pid> -o <offset>` : liste des pages physiques d'un processus à partir d'un offset donné
- `volatility -f <dump> --profile=<profile> physmap -p <pid> -o <offset> --dump-dir=<output_directory>` : dump des pages physiques d'un processus à partir d'un offset donné
- `volatility -f <dump> --profile=<profile> physmap -p <pid> -o <offset> --dump-dir=<output_directory> --dump-children` : dump des pages physiques d'un processus à partir d'un offset donné et de ses enfants
{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Liste des plugins de Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#plugins)
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
### Ligne de commande

Quelque chose de suspect a-t-il été exécuté ? 

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

### Plugin `dumpregistry`

```bash
volatility -f <nom_du_fichier> dumpregistry -o <registry_hive> -D <dossier_de_sortie>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `dumpcerts`

```bash
volatility -f <nom_du_fichier> dumpcerts -O <dossier_de_sortie>
```

### Plugin `dumpcache`

```bash
volatility -f <nom_du_fichier> dumpcache -D <dossier_de_sortie>
```

### Plugin `dumpregistry`

```bash
volatility -f <nom_du_fichier> dumpregistry -o <registry_hive> -D <dossier_de_sortie>
```

### Plugin `dumpregistryvalues`

```bash
volatility -f <nom_du_fichier> dumpregistryvalues -o <registry_hive> -D <dossier_de_sortie>
```

### Plugin `dumpall`

```bash
volatility -f <nom_du_fichier> dumpall -D <dossier_de_sortie>
```

### Plugin `moddump`

```bash
volatility -f <nom_du_fichier> moddump -D <dossier_de_sortie>
```

### Plugin `modscan`

```bash
volatility -f <nom_du_fichier> modscan
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `svcscan`

```bash
volatility -f <nom_du_fichier> svcscan
```

### Plugin `printkey`

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Plugin `getsids`

```bash
volatility -f <nom_du_fichier> getsids
```

### Plugin `userassist`

```bash
volatility -f <nom_du_fichier> userassist
```

### Plugin `dumpcerts`

```bash
volatility -f <nom_du_fichier> dumpcerts -O <dossier_de_sortie>
```

### Plugin `dumpcache`

```bash
volatility -f <nom_du_fichier> dumpcache -D <dossier_de_sortie>
```

### Plugin `connscan`

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

### Plugin `sockets`

```bash
volatility -f <nom_du_fichier> sockets
```

### Plugin `sockscan`

```bash
volatility -f <nom_du_fichier> sockscan
```

### Plugin `filescan`

```bash
volatility -f <nom_du_fichier> filescan
```

### Plugin `pslist`

```bash
volatility -f <nom_du_fichier> pslist
```

### Plugin `psscan`

```bash
volatility -f <nom_du_fichier> psscan
```

### Plugin `pstree`

```bash
volatility -f <nom_du_fichier> pstree
```

### Plugin `dlllist`

```bash
volatility -f <nom_du_fichier> dlllist
```

### Plugin `netscan`

```bash
volatility -f <nom_du_fichier> netscan
```

### Plugin `procdump`

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

### Plugin `memdump`

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet) (en anglais)
- [Volatility Plugin List](https://github.com/superponible/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/tehw0lf/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% tab title="vol3" lang="fr" %}

Les commandes entrées dans cmd.exe sont traitées par **conhost.exe** (csrss.exe avant Windows 7). Donc même si un attaquant a réussi à **tuer cmd.exe** **avant** que nous obtenions un **dump de mémoire**, il y a encore de bonnes chances de **récupérer l'historique** de la session de ligne de commande à partir de la **mémoire de conhost.exe**. Si vous trouvez **quelque chose d'étrange** (en utilisant les modules de la console), essayez de **dump** la **mémoire** du **processus associé à conhost.exe** et **recherchez** des **chaînes de caractères** à l'intérieur pour extraire les lignes de commande.

### Environnement

Obtenez les variables d'environnement de chaque processus en cours d'exécution. Il peut y avoir des valeurs intéressantes.

{% endtab %}
{% endtabs %}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Installation

```bash
pip install volatility
```

## Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

## Plugins

### Process Analysis

#### pslist

List running processes.

```bash
volatility -f <memory_dump> pslist
```

#### psscan

Scan for processes.

```bash
volatility -f <memory_dump> psscan
```

#### pstree

Display process tree.

```bash
volatility -f <memory_dump> pstree
```

#### dlllist

List loaded DLLs.

```bash
volatility -f <memory_dump> dlllist
```

#### handles

List open handles.

```bash
volatility -f <memory_dump> handles
```

#### cmdscan

Scan for command history.

```bash
volatility -f <memory_dump> cmdscan
```

### Malware Analysis

#### malfind

Find hidden and injected code.

```bash
volatility -f <memory_dump> malfind
```

#### malprocfind

Find hidden processes.

```bash
volatility -f <memory_dump> malprocfind
```

#### malfind

Find hidden files.

```bash
volatility -f <memory_dump> malfind
```

### Memory Analysis

#### memdump

Dump process memory.

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
```

#### memmap

Display memory map.

```bash
volatility -f <memory_dump> memmap
```

#### memstrings

Extract printable strings.

```bash
volatility -f <memory_dump> memstrings
```

#### memimage

Extract PE files.

```bash
volatility -f <memory_dump> memimage
```

#### memdump

Dump kernel memory.

```bash
volatility -f <memory_dump> memdump -p 0 -D <output_directory>
```

### Network Analysis

#### connscan

List open connections.

```bash
volatility -f <memory_dump> connscan
```

#### sockets

List open sockets.

```bash
volatility -f <memory_dump> sockets
```

#### netscan

Scan for network connections.

```bash
volatility -f <memory_dump> netscan
```

### User Analysis

#### hivelist

List registry hives.

```bash
volatility -f <memory_dump> hivelist
```

#### hashdump

Dump password hashes.

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -u <user_hive>
```

#### userassist

List userassist entries.

```bash
volatility -f <memory_dump> userassist
```

#### getsids

List user SIDs.

```bash
volatility -f <memory_dump> getsids
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### envars

List environment variables.

```bash
volatility -f <memory_dump> envars
```

### Windows Registry Analysis

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### hivelist

List registry hives.

```bash
volatility -f <memory_dump> hivelist
```

#### hivedump

Dump registry hive.

```bash
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
```

### Virtual Machine Analysis

#### vboxinfo

Display VirtualBox information.

```bash
volatility -f <memory_dump> vboxinfo
```

#### vboxsf

List VirtualBox shared folders.

```bash
volatility -f <memory_dump> vboxsf
```

#### vmwareinfo

Display VMware information.

```bash
volatility -f <memory_dump> vmwareinfo
```

#### vmpsaux

List VMware process information.

```bash
volatility -f <memory_dump> vmpsaux
```

### Other Plugins

#### apihooks

List API hooks.

```bash
volatility -f <memory_dump> apihooks
```

#### callbacks

List kernel callbacks.

```bash
volatility -f <memory_dump> callbacks
```

#### driverirp

List driver IRPs.

```bash
volatility -f <memory_dump> driverirp
```

#### filescan

Scan for files.

```bash
volatility -f <memory_dump> filescan
```

#### mutantscan

Scan for mutant objects.

```bash
volatility -f <memory_dump> mutantscan
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### privs

List process privileges.

```bash
volatility -f <memory_dump> privs
```

#### shimcache

List ShimCache entries.

```bash
volatility -f <memory_dump> shimcache
```

#### ssdt

List SSDT entries.

```bash
volatility -f <memory_dump> ssdt
```

#### thrdscan

Scan for threads.

```bash
volatility -f <memory_dump> thrdscan
```

#### timers

List kernel timers.

```bash
volatility -f <memory_dump> timers
```

#### vadinfo

Display VAD information.

```bash
volatility -f <memory_dump> vadinfo
```

#### vadtree

Display VAD tree.

```bash
volatility -f <memory_dump> vadtree
```

#### verinfo

Display version information.

```bash
volatility -f <memory_dump> verinfo
```

#### windows

List open windows.

```bash
volatility -f <memory_dump> windows
```

#### wintree

Display window tree.

```bash
volatility -f <memory_dump> wintree
```

#### yarascan

Scan for YARA signatures.

```bash
volatility -f <memory_dump> yarascan -Y <yara_rules_file>
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated 
```
### Privilèges de jetons

Vérifiez les jetons de privilèges dans les services inattendus.\
Il pourrait être intéressant de lister les processus utilisant un jeton privilégié.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des registres

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key> -o <offset>
```

```bash
volatility -f <nom_du_fichier> hashdump -y <system_hive> -s <security_hive> -o <sam_hive> --system <system_file> --security <security_file> --sam <sam_file>
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\ComputerName\ComputerName"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Services\Tcpip\Parameters"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\Terminal Server\WinStations\Console"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\LSA"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\SafeBoot\Minimal\{4D36E96A-E325-11CE-BFC1-08002BE10318}"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\SafeBoot\Network\{4D36E96A-E325-11CE-BFC1-08002BE10318}"
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

### Plugin `dumpregistry`

```bash
volatility -f <nom_du_fichier> dumpregistry -o <offset> -D <dossier_de_sortie>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `moddump`

```bash
volatility -f <nom_du_fichier> moddump -D <dossier_de_sortie> -m <nom_du_module>
```

### Plugin `procdump`

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

### Plugin `memdump`

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `connscan`

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

### Plugin `sockets`

```bash
volatility -f <nom_du_fichier> sockets
```

### Plugin `sockscan`

```bash
volatility -f <nom_du_fichier> sockscan
```

### Plugin `printkey`

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key> -o <offset>
```

### Plugin `hashdump`

```bash
volatility -f <nom_du_fichier> hashdump -y <system_hive> -s <security_hive> -o <sam_hive> --system <system_file> --security <security_file> --sam <sam_file>
```

### Plugin `hivelist`

```bash
volatility -f <nom_du_fichier> hivelist
```

### Plugin `pslist`

```bash
volatility -f <nom_du_fichier> pslist
```

### Plugin `psscan`

```bash
volatility -f <nom_du_fichier> psscan
```

### Plugin `pstree`

```bash
volatility -f <nom_du_fichier> pstree
```

### Plugin `dlllist`

```bash
volatility -f <nom_du_fichier> dlllist
```

### Plugin `filescan`

```bash
volatility -f <nom_du_fichier> filescan
```

### Plugin `netscan`

```bash
volatility -f <nom_du_fichier> netscan
```

### Plugin `kdbgscan`

```bash
volatility -f <nom_du_fichier> kdbgscan
```

### Plugin `kpcrscan`

```bash
volatility -f <nom_du_fichier> kpcrscan
```

### Plugin `dumpcerts`

```bash
volatility -f <nom_du_fichier> dumpcerts -D <dossier_de_sortie>
```

### Plugin `dumpcache`

```bash
volatility -f <nom_du_fichier> dumpcache -D <dossier_de_sortie>
```

### Plugin `dumpregistry`

```bash
volatility -f <nom_du_fichier> dumpregistry -o <offset> -D <dossier_de_sortie>
```

### Plugin `dumpregistryhive`

```bash
volatility -f <nom_du_fichier> dumpregistryhive -o <offset> -D <dossier_de_sortie>
```

### Plugin `dumpvad`

```bash
volatility -f <nom_du_fichier> dumpvad -D <dossier_de_sortie>
```

### Plugin `dumpvadtree`

```bash
volatility -f <nom_du_fichier> dumpvadtree -D <dossier_de_sortie>
```

### Plugin `getsids`

```bash
volatility -f <nom_du_fichier> getsids
```

### Plugin `hivedump`

```bash
volatility -f <nom_du_fichier> hivedump -o <offset> -D <dossier_de_sortie>
```

### Plugin `idt`

```bash
volatility -f <nom_du_fichier> idt
```

### Plugin `iehistory`

```bash
volatility -f <nom_du_fichier> iehistory
```

### Plugin `imagecopy`

```bash
volatility -f <nom_du_fichier> imagecopy -O <fichier_de_sortie> -S <adresse_de_départ> -E <adresse_de_fin>
```

### Plugin `imageinfo`

```bash
volatility -f <nom_du_fichier> imageinfo
```

### Plugin `impscan`

```bash
volatility -f <nom_du_fichier> impscan
```

### Plugin `kpcrscan`

```bash
volatility -f <nom_du_fichier> kpcrscan
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules
```

### Plugin `lsadump`

```bash
volatility -f <nom_du_fichier> lsadump -s <security_hive> -o <sam_hive> --security <security_file> --sam <sam_file>
```

### Plugin `memdump`

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

### Plugin `moddump`

```bash
volatility -f <nom_du_fichier> moddump -D <dossier_de_sortie> -m <nom_du_module>
```

### Plugin `modules`

```bash
volatility -f <nom_du_fichier> modules
```

### Plugin `mutantscan`

```bash
volatility -f <nom_du_fichier> mutantscan
```

### Plugin `printkey`

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key> -o <offset>
```

### Plugin `procdump`

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

### Plugin `pslist`

```bash
volatility -f <nom_du_fichier> pslist
```

### Plugin `psscan`

```bash
volatility -f <nom_du_fichier> psscan
```

### Plugin `pstree`

```bash
volatility -f <nom_du_fichier> pstree
```

### Plugin `sessions`

```bash
volatility -f <nom_du_fichier> sessions
```

### Plugin `sockets`

```bash
volatility -f <nom_du_fichier> sockets
```

### Plugin `sockscan`

```bash
volatility -f <nom_du_fichier> sockscan
```

### Plugin `ssdt`

```bash
volatility -f <nom_du_fichier> ssdt
```

### Plugin `symlinkscan`

```bash
volatility -f <nom_du_fichier> symlinkscan
```

### Plugin `thrdscan`

```bash
volatility -f <nom_du_fichier> thrdscan
```

### Plugin `timeliner`

```bash
volatility -f <nom_du_fichier> timeliner -o <dossier_de_sortie>
```

### Plugin `vadinfo`

```bash
volatility -f <nom_du_fichier> vadinfo -p <pid>
```

### Plugin `vadtree`

```bash
volatility -f <nom_du_fichier> vadtree -p <pid>
```

### Plugin `verinfo`

```bash
volatility -f <nom_du_fichier> verinfo
```

### Plugin `windows`

```bash
volatility -f <nom_du_fichier> windows
```

### Plugin `wndscan`

```bash
volatility -f <nom_du_fichier> wndscan
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet)
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
### SIDs

Vérifiez chaque SSID possédé par un processus.\
Il pourrait être intéressant de lister les processus utilisant un SID de privilèges (et les processus utilisant un SID de service).
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Installation

```bash
sudo apt-get install volatility
```

## Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

## Plugins

### Image Identification

```bash
volatility imageinfo -f <memory_dump>
```

### Process Listing

```bash
volatility pslist -f <memory_dump>
```

### Process Tree

```bash
volatility pstree -f <memory_dump>
```

### Process Memory Dump

```bash
volatility memdump -f <memory_dump> -p <pid> --dump-dir <output_directory>
```

### DLL Listing

```bash
volatility dlllist -f <memory_dump> -p <pid>
```

### Handles

```bash
volatility handles -f <memory_dump> -p <pid>
```

### Network Connections

```bash
volatility netscan -f <memory_dump>
```

### Open Files

```bash
volatility filescan -f <memory_dump>
```

### Registry Analysis

```bash
volatility hivelist -f <memory_dump>
volatility printkey -f <memory_dump> -o <offset>
volatility dumpkey -f <memory_dump> -o <offset> --dump-dir <output_directory>
```

### Malware Analysis

```bash
volatility malfind -f <memory_dump> --dump-dir <output_directory>
volatility malprocfind -f <memory_dump> --dump-dir <output_directory>
volatility malfind -f <memory_dump> --dump-dir <output_directory>
```

### User Account Analysis

```bash
volatility hivescan -f <memory_dump>
volatility userassist -f <memory_dump>
volatility getsids -f <memory_dump>
volatility hashdump -f <memory_dump> -s <system_offset> -u <user_offset>
```

### Miscellaneous

```bash
volatility cmdline -f <memory_dump> -p <pid>
volatility consoles -f <memory_dump>
volatility idt -f <memory_dump>
volatility modules -f <memory_dump>
volatility printkey -f <memory_dump> -o <offset>
volatility shellbags -f <memory_dump>
volatility sockets -f <memory_dump>
volatility ssdt -f <memory_dump>
volatility timers -f <memory_dump>
volatility truecryptmaster -f <memory_dump>
volatility vadinfo -f <memory_dump>
volatility vadtree -f <memory_dump>
volatility windows -f <memory_dump>
```
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### Handles

Il est utile de savoir à quels autres fichiers, clés, threads, processus... un **processus a une poignée** (a ouvert).
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des registres

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key> -o <offset>
```

```bash
volatility -f <nom_du_fichier> hashdump -y <system_hive> -s <security_hive> -o <sam_hive> --system <system_file> --security <security_file> --sam <sam_file>
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\ComputerName\ComputerName"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Services\Tcpip\Parameters"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\Terminal Server\WinStations\Console"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\LSA"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\SafeBoot\Minimal\{4D36E96A-E325-11CE-BFC1-08002BE10318}"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\SafeBoot\Network\{4D36E96A-E325-11CE-BFC1-08002BE10318}"
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Processus

#### pslist

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> pslist
```

#### psscan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> psscan
```

#### pstree

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> pstree
```

#### psxview

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> psxview
```

#### cmdscan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> cmdscan
```

#### consoles

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> consoles
```

#### consolescreeens

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> consolescreens
```

#### dlllist

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> dlllist
```

#### getsids

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> getsids
```

#### handles

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> handles
```

#### mutantscan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> mutantscan
```

#### privs

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> privs
```

#### privs2

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> privs2
```

#### thrdscan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> thrdscan
```

#### vadinfo

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> vadinfo
```

#### vadtree

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> vadtree
```

#### verinfo

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> verinfo
```

#### windows

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> windows
```

#### wintree

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> wintree
```

#### svcscan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> svcscan
```

#### svcscan2

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> svcscan2
```

#### svcstalker

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> svcstalker
```

#### envars

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> envars
```

#### modscan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> modscan
```

#### moddump

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> moddump -D <dossier_de_sortie> -p <pid>
```

#### moddump

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> moddump -D <dossier_de_sortie> -m <module_offset>
```

#### moddump

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> moddump -D <dossier_de_sortie> -f <module_file>
```

#### malfind

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> malfind
```

#### malfind

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> malfind --dump-dir <dossier_de_sortie>
```

#### apihooks

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> apihooks -p <pid>
```

#### ldrmodules

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> ldrmodules -p <pid>
```

#### handles

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> handles -p <pid>
```

### Réseau

#### connscan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> connscan
```

#### connscan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> connscan -s
```

#### sockets

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> sockets
```

#### sockscan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> sockscan
```

### Fichiers

#### filescan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> filescan
```

#### dumpfiles

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> dumpfiles -Q <nom_du_fichier>
```

#### dumpfiles

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Registres

#### hivelist

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> hivelist
```

#### printkey

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -K <registry_key>
```

#### printkey

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -K <registry_key> -o <offset>
```

#### hashdump

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> hashdump -y <system_hive> -s <security_hive> -o <sam_hive> --system <system_file> --security <security_file> --sam <sam_file>
```

### Utilisateurs

#### hivelist

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> hivelist
```

#### printkey

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -K "ControlSet001\Control\ComputerName\ComputerName"
```

#### printkey

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -K "ControlSet001\Services\Tcpip\Parameters"
```

#### printkey

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -K "ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp"
```

#### printkey

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -K "ControlSet001\Control\Terminal Server\WinStations\Console"
```

#### printkey

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -K "ControlSet001\Control\LSA"
```

#### printkey

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -K "ControlSet001\Control\SafeBoot\Minimal\{4D36E96A-E325-11CE-BFC1-08002BE10318}"
```

#### printkey

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -K "ControlSet001\Control\SafeBoot\Network\{4D36E96A-E325-11CE-BFC1-08002BE10318}"
```

### Vulnérabilités

#### malfind

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> malfind
```

#### malfind

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> malfind --dump-dir <dossier_de_sortie>
```

#### yarascan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> yarascan -Y <fichier_de_règles_yara>
```

#### yarascan

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Profils

### Windows

#### Windows XP SP2

```bash
volatility -f <nom_du_fichier> --profile=WinXPSP2x86 <commande>
```

#### Windows XP SP3

```bash
volatility -f <nom_du_fichier> --profile=WinXPSP3x86 <commande>
```

#### Windows Server 2003 SP0

```bash
volatility -f <nom_du_fichier> --profile=Win2003SP0x86 <commande>
```

#### Windows Server 2003 SP1

```bash
volatility -f <nom_du_fichier> --profile=Win2003SP1x86 <commande>
```

#### Windows Server 2003 SP2

```bash
volatility -f <nom_du_fichier> --profile=Win2003SP2x86 <commande>
```

#### Windows Vista SP0/SP1

```bash
volatility -f <nom_du_fichier> --profile=WinVistaSP0x86 <commande>
```

#### Windows Vista SP2

```bash
volatility -f <nom_du_fichier> --profile=WinVistaSP2x86 <commande>
```

#### Windows Server 2008 SP1

```bash
volatility -f <nom_du_fichier> --profile=Win2008SP1x86 <commande>
```

#### Windows Server 2008 SP2

```bash
volatility -f <nom_du_fichier> --profile=Win2008SP2x86 <commande>
```

#### Windows 7 SP0/SP1

```bash
volatility -f <nom_du_fichier> --profile=Win7SP0x86 <commande>
```

#### Windows 8/8.1

```bash
volatility -f <nom_du_fichier> --profile=Win8SP0x86 <commande>
```

#### Windows 10

```bash
volatility -f <nom_du_fichier> --profile=Win10x64 <commande>
```

### Linux

#### Ubuntu 12.04 LTS

```bash
volatility -f <nom_du_fichier> --profile=LinuxUbuntu1204x64 <commande>
```

#### Ubuntu 14.04 LTS

```bash
volatility -f <nom_du_fichier> --profile=LinuxUbuntu1404x64 <commande>
```

#### Ubuntu 16.04 LTS

```bash
volatility -f <nom_du_fichier> --profile=LinuxUbuntu1604x64 <commande>
```

#### CentOS 6

```bash
volatility -f <nom_du_fichier> --profile=LinuxCentos6x64 <commande>
```

#### CentOS 7

```bash
volatility -f <nom_du_fichier> --profile=LinuxCentos7x64 <commande>
```

#### Debian 7

```bash
volatility -
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### DLLs

{% tabs %}
{% tab title="vol3" %}
Les DLL (Dynamic Link Libraries) sont des fichiers qui contiennent du code et des données qui peuvent être utilisés par plusieurs programmes en même temps. Les DLL sont souvent utilisées pour économiser de l'espace disque et de la mémoire, car elles permettent de partager du code entre plusieurs programmes. Les DLL peuvent également être utilisées pour ajouter des fonctionnalités à un programme existant sans avoir à le modifier directement. 

Volatility dispose de plusieurs commandes pour analyser les DLL dans un dump de mémoire. La commande `dlllist` affiche une liste de toutes les DLL chargées dans le processus spécifié, ainsi que leur adresse de base et leur chemin d'accès sur le disque. La commande `dlldump` permet de récupérer une DLL spécifique à partir de la mémoire et de l'enregistrer sur le disque. 

Il est important de noter que les DLL peuvent être utilisées pour exécuter du code malveillant sur un système. Les attaquants peuvent remplacer une DLL légitime par une version malveillante pour obtenir un accès persistant au système ou pour voler des informations sensibles. Il est donc important de vérifier l'intégrité des DLL sur un système compromis. 
{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet) (en anglais)
- [Volatility Plugin List](https://github.com/superponible/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/te-k/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/aim4r/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/forensicmatt.github.io/tree/master/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/forensicmatt.github.io/tree/master/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/forensicmatt.github.io/tree/master/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/forensicmatt.github.io/tree/master/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/forensicmatt.github.io/tree/master/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/forensicmatt.github.io/tree/master/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/forensicmatt.github.io/tree/master/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/forensicmatt.github.io/tree/master/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/forensicmatt.github.io/tree/master/volatility) (en anglais)
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### Chaînes par processus

Volatility nous permet de vérifier à quel processus appartient une chaîne.

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet)
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

Il permet également de rechercher des chaînes de caractères à l'intérieur d'un processus en utilisant le module yarascan : 

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des registres

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key> -o <offset>
```

```bash
volatility -f <nom_du_fichier> hashdump -y <system_hive> -s <security_hive> -o <sam_hive> --system <system_file> --security <security_file> --sam <sam_file>
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\ComputerName\ComputerName"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Services\Tcpip\Parameters"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\Terminal Server\WinStations\Console"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\LSA"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\SafeBoot\Minimal\{4D36E96A-E325-11CE-BFC1-08002BE10318}"
```

```bash
volatility -f <nom_du_fichier> printkey -K "ControlSet001\Control\SafeBoot\Network\{4D36E96A-E325-11CE-BFC1-08002BE10318}"
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `connscan`

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

### Plugin `sockets`

```bash
volatility -f <nom_du_fichier> sockets
```

### Plugin `sockscan`

```bash
volatility -f <nom_du_fichier> sockscan
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `printkey`

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key> -o <offset>
```

### Plugin `hashdump`

```bash
volatility -f <nom_du_fichier> hashdump -y <system_hive> -s <security_hive> -o <sam_hive> --system <system_file> --security <security_file> --sam <sam_file>
```

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet) (en anglais)
- [Volatility Plugin List](https://github.com/superponible/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/te-k/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/JamesHabben/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/aim4r/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/alphaSeclab/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/alphaSeclab/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/alphaSeclab/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/alphaSeclab/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/alphaSeclab/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/alphaSeclab/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/alphaSeclab/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/alphaSeclab/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/alphaSeclab/Volatility-Plugins) (en anglais)
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

Les systèmes **Windows** conservent un ensemble de **clés** dans la base de données du registre (**clés UserAssist**) pour suivre les programmes qui sont exécutés. Le nombre d'exécutions et la date et l'heure de la dernière exécution sont disponibles dans ces **clés**.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Installation

```bash
pip install volatility
```

## Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

## Plugins

### Process Analysis

#### pslist

List running processes.

```bash
volatility -f <memory_dump> pslist
```

#### psscan

Scan for processes.

```bash
volatility -f <memory_dump> psscan
```

#### pstree

Display process tree.

```bash
volatility -f <memory_dump> pstree
```

#### dlllist

List loaded DLLs.

```bash
volatility -f <memory_dump> dlllist
```

#### handles

List open handles.

```bash
volatility -f <memory_dump> handles
```

#### cmdscan

Scan for command history.

```bash
volatility -f <memory_dump> cmdscan
```

### Malware Analysis

#### malfind

Find hidden and injected code.

```bash
volatility -f <memory_dump> malfind
```

#### malprocfind

Find hidden processes.

```bash
volatility -f <memory_dump> malprocfind
```

#### malfind

Find hidden files.

```bash
volatility -f <memory_dump> malfind
```

### Memory Analysis

#### memdump

Dump process memory.

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
```

#### memmap

Display memory map.

```bash
volatility -f <memory_dump> memmap
```

#### memstrings

Extract printable strings.

```bash
volatility -f <memory_dump> memstrings
```

#### memimage

Extract PE files.

```bash
volatility -f <memory_dump> memimage
```

#### memdiff

Compare memory dumps.

```bash
volatility -f <memory_dump1> memdiff -f <memory_dump2>
```

### Network Analysis

#### connscan

List open network connections.

```bash
volatility -f <memory_dump> connscan
```

#### sockets

List open sockets.

```bash
volatility -f <memory_dump> sockets
```

#### netscan

Scan for network activity.

```bash
volatility -f <memory_dump> netscan
```

### User Analysis

#### hivelist

List registry hives.

```bash
volatility -f <memory_dump> hivelist
```

#### hashdump

Dump password hashes.

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -u <user_hive>
```

#### userassist

List userassist entries.

```bash
volatility -f <memory_dump> userassist
```

#### getsids

List user SIDs.

```bash
volatility -f <memory_dump> getsids
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

### Windows Registry Analysis

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### printval

Print registry value.

```bash
volatility -f <memory_dump> printval -K <key_path> -V <value_name>
```

#### hivedump

Dump registry hive.

```bash
volatility -f <memory_dump> hivedump -o <offset> -s <size> -w <output_file>
```

### Virtualization Analysis

#### vboxinfo

Display VirtualBox information.

```bash
volatility -f <memory_dump> vboxinfo
```

#### vboxsf

List VirtualBox shared folders.

```bash
volatility -f <memory_dump> vboxsf
```

#### vmwareinfo

Display VMware information.

```bash
volatility -f <memory_dump> vmwareinfo
```

#### vmscan

Scan for virtual machines.

```bash
volatility -f <memory_dump> vmscan
```

### Other Plugins

#### apihooks

List API hooks.

```bash
volatility -f <memory_dump> apihooks
```

#### callbacks

List kernel callbacks.

```bash
volatility -f <memory_dump> callbacks
```

#### idt

Display Interrupt Descriptor Table.

```bash
volatility -f <memory_dump> idt
```

#### gdt

Display Global Descriptor Table.

```bash
volatility -f <memory_dump> gdt
```

#### ldrmodules

List loaded modules.

```bash
volatility -f <memory_dump> ldrmodules
```

#### modscan

Scan for modules.

```bash
volatility -f <memory_dump> modscan
```

#### ssdt

Display System Service Descriptor Table.

```bash
volatility -f <memory_dump> ssdt
```

#### driverirp

List driver IRPs.

```bash
volatility -f <memory_dump> driverirp
```

#### filescan

Scan for files.

```bash
volatility -f <memory_dump> filescan
```

#### mutantscan

Scan for mutant objects.

```bash
volatility -f <memory_dump> mutantscan
```

#### printdeltas

Print registry deltas.

```bash
volatility -f <memory_dump> printdeltas -s <system_hive> -u <user_hive>
```

#### printfile

Print file contents.

```bash
volatility -f <memory_dump> printfile -f <file_path>
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### printreg

Print registry hive.

```bash
volatility -f <memory_dump> printreg -o <offset> -s <size>
```

#### procdump

Dump process executable.

```bash
volatility -f <memory_dump> procdump -p <pid> -D <output_directory>
```

#### procmemdump

Dump process memory.

```bash
volatility -f <memory_dump> procmemdump -p <pid> -D <output_directory>
```

#### shimcache

List ShimCache entries.

```bash
volatility -f <memory_dump> shimcache
```

#### svcscan

List services.

```bash
volatility -f <memory_dump> svcscan
```

#### thrdscan

List threads.

```bash
volatility -f <memory_dump> thrdscan
```

#### timers

List timers.

```bash
volatility -f <memory_dump> timers
```

#### vadinfo

Display Virtual Address Descriptor information.

```bash
volatility -f <memory_dump> vadinfo
```

#### vadtree

Display Virtual Address Descriptor tree.

```bash
volatility -f <memory_dump> vadtree
```

#### windows

List windows.

```bash
volatility -f <memory_dump> windows
```

#### wndscan

Scan for windows.

```bash
volatility -f <memory_dump> wndscan
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en Espagne et l'un des plus importants en Europe. Avec pour mission de promouvoir les connaissances techniques, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

## Services
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Installation

```bash
pip install volatility
```

## Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

## Plugins

### Process Analysis

#### pslist

List running processes.

```bash
volatility -f <memory_dump> pslist
```

#### psscan

Scan for processes.

```bash
volatility -f <memory_dump> psscan
```

#### pstree

Display process tree.

```bash
volatility -f <memory_dump> pstree
```

#### dlllist

List loaded DLLs.

```bash
volatility -f <memory_dump> dlllist
```

#### handles

List open handles.

```bash
volatility -f <memory_dump> handles
```

#### cmdscan

Scan for command history.

```bash
volatility -f <memory_dump> cmdscan
```

### Malware Analysis

#### malfind

Find hidden and injected code.

```bash
volatility -f <memory_dump> malfind
```

#### malprocfind

Find hidden processes.

```bash
volatility -f <memory_dump> malprocfind
```

#### malfind

Find hidden files.

```bash
volatility -f <memory_dump> malfind
```

### Memory Analysis

#### memdump

Dump process memory.

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
```

#### memmap

Display memory map.

```bash
volatility -f <memory_dump> memmap
```

#### memstrings

Extract printable strings.

```bash
volatility -f <memory_dump> memstrings
```

#### memimage

Extract PE files.

```bash
volatility -f <memory_dump> memimage
```

#### memdump

Dump kernel memory.

```bash
volatility -f <memory_dump> memdump -p 0 -D <output_directory>
```

### Network Analysis

#### connscan

List open connections.

```bash
volatility -f <memory_dump> connscan
```

#### sockets

List open sockets.

```bash
volatility -f <memory_dump> sockets
```

#### netscan

Scan for network connections.

```bash
volatility -f <memory_dump> netscan
```

### User Analysis

#### hivelist

List registry hives.

```bash
volatility -f <memory_dump> hivelist
```

#### hashdump

Dump password hashes.

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -u <user_hive>
```

#### userassist

List userassist entries.

```bash
volatility -f <memory_dump> userassist
```

#### getsids

List user SIDs.

```bash
volatility -f <memory_dump> getsids
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### envars

List environment variables.

```bash
volatility -f <memory_dump> envars -p <pid>
```

#### consoles

List open consoles.

```bash
volatility -f <memory_dump> consoles
```

### Windows Registry Analysis

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### hivelist

List registry hives.

```bash
volatility -f <memory_dump> hivelist
```

#### hivedump

Dump registry hive.

```bash
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
```

### Virtual Machine Analysis

#### vboxinfo

Display VirtualBox information.

```bash
volatility -f <memory_dump> vboxinfo
```

#### vboxsf

List VirtualBox shared folders.

```bash
volatility -f <memory_dump> vboxsf
```

#### vmwareinfo

Display VMware information.

```bash
volatility -f <memory_dump> vmwareinfo
```

#### vmpsaux

List VMware process information.

```bash
volatility -f <memory_dump> vmpsaux
```

### Other Plugins

#### apihooks

List API hooks.

```bash
volatility -f <memory_dump> apihooks
```

#### callbacks

List kernel callbacks.

```bash
volatility -f <memory_dump> callbacks
```

#### driverirp

List driver IRPs.

```bash
volatility -f <memory_dump> driverirp
```

#### filescan

Scan for files.

```bash
volatility -f <memory_dump> filescan
```

#### mutantscan

Scan for mutant objects.

```bash
volatility -f <memory_dump> mutantscan
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### privs

List process privileges.

```bash
volatility -f <memory_dump> privs -p <pid>
```

#### shimcache

List ShimCache entries.

```bash
volatility -f <memory_dump> shimcache
```

#### ssdt

List SSDT entries.

```bash
volatility -f <memory_dump> ssdt
```

#### thrdscan

Scan for threads.

```bash
volatility -f <memory_dump> thrdscan
```

#### timers

List kernel timers.

```bash
volatility -f <memory_dump> timers
```

#### vadinfo

Display VAD information.

```bash
volatility -f <memory_dump> vadinfo
```

#### vadtree

Display VAD tree.

```bash
volatility -f <memory_dump> vadtree
```

#### verinfo

Display version information.

```bash
volatility -f <memory_dump> verinfo
```

#### windows

List open windows.

```bash
volatility -f <memory_dump> windows
```

#### wintree

Display window tree.

```bash
volatility -f <memory_dump> wintree
```

#### yarascan

Scan for YARA signatures.

```bash
volatility -f <memory_dump> yarascan -Y <yara_rules_file>
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{% endtab %}
{% endtabs %}

## Réseau

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Installation

```bash
pip install volatility
```

## Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

## Plugins

### Process Analysis

#### pslist

List running processes.

```bash
volatility -f <memory_dump> pslist
```

#### psscan

Scan for processes.

```bash
volatility -f <memory_dump> psscan
```

#### pstree

Display process tree.

```bash
volatility -f <memory_dump> pstree
```

#### dlllist

List loaded DLLs.

```bash
volatility -f <memory_dump> dlllist
```

#### handles

List open handles.

```bash
volatility -f <memory_dump> handles
```

#### cmdscan

Scan for command history.

```bash
volatility -f <memory_dump> cmdscan
```

### Malware Analysis

#### malfind

Find hidden and injected code.

```bash
volatility -f <memory_dump> malfind
```

#### malprocfind

Find hidden processes.

```bash
volatility -f <memory_dump> malprocfind
```

#### malfind

Find hidden files.

```bash
volatility -f <memory_dump> malfind
```

### Memory Analysis

#### memdump

Dump process memory.

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
```

#### memmap

Display memory map.

```bash
volatility -f <memory_dump> memmap
```

#### memstrings

Extract printable strings.

```bash
volatility -f <memory_dump> memstrings
```

#### memimage

Extract PE files.

```bash
volatility -f <memory_dump> memimage
```

#### memdiff

Compare memory dumps.

```bash
volatility -f <memory_dump1> memdiff -f <memory_dump2>
```

### Network Analysis

#### connscan

List open network connections.

```bash
volatility -f <memory_dump> connscan
```

#### sockets

List open sockets.

```bash
volatility -f <memory_dump> sockets
```

#### netscan

Scan for network activity.

```bash
volatility -f <memory_dump> netscan
```

### User Analysis

#### hivelist

List registry hives.

```bash
volatility -f <memory_dump> hivelist
```

#### hashdump

Dump password hashes.

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -u <user_hive>
```

#### userassist

List userassist entries.

```bash
volatility -f <memory_dump> userassist
```

#### getsids

List user SIDs.

```bash
volatility -f <memory_dump> getsids
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

### Windows Registry Analysis

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### printval

Print registry value.

```bash
volatility -f <memory_dump> printval -K <key_path> -V <value_name>
```

#### hivedump

Dump registry hive.

```bash
volatility -f <memory_dump> hivedump -o <offset> -s <size> -w <output_file>
```

### Virtualization Analysis

#### vboxinfo

Display VirtualBox information.

```bash
volatility -f <memory_dump> vboxinfo
```

#### vboxsf

List VirtualBox shared folders.

```bash
volatility -f <memory_dump> vboxsf
```

#### vmwareinfo

Display VMware information.

```bash
volatility -f <memory_dump> vmwareinfo
```

#### vmscan

Scan for virtual machines.

```bash
volatility -f <memory_dump> vmscan
```

### Other Plugins

#### apihooks

List API hooks.

```bash
volatility -f <memory_dump> apihooks
```

#### callbacks

List kernel callbacks.

```bash
volatility -f <memory_dump> callbacks
```

#### idt

Display Interrupt Descriptor Table.

```bash
volatility -f <memory_dump> idt
```

#### gdt

Display Global Descriptor Table.

```bash
volatility -f <memory_dump> gdt
```

#### ldrmodules

List loaded modules.

```bash
volatility -f <memory_dump> ldrmodules
```

#### modscan

Scan for modules.

```bash
volatility -f <memory_dump> modscan
```

#### ssdt

Display System Service Descriptor Table.

```bash
volatility -f <memory_dump> ssdt
```

#### driverirp

List driver IRPs.

```bash
volatility -f <memory_dump> driverirp
```

#### filescan

Scan for files.

```bash
volatility -f <memory_dump> filescan
```

#### mutantscan

Scan for mutant objects.

```bash
volatility -f <memory_dump> mutantscan
```

#### printd

Print kernel debugger information.

```bash
volatility -f <memory_dump> printd
```

#### procexedump

Dump process executable.

```bash
volatility -f <memory_dump> procexedump -p <pid> -D <output_directory>
```

#### shimcache

List ShimCache entries.

```bash
volatility -f <memory_dump> shimcache
```

#### svcscan

Scan for services.

```bash
volatility -f <memory_dump> svcscan
```

#### thrdscan

Scan for threads.

```bash
volatility -f <memory_dump> thrdscan
```

#### timers

List kernel timers.

```bash
volatility -f <memory_dump> timers
```

#### vadinfo

Display Virtual Address Descriptor information.

```bash
volatility -f <memory_dump> vadinfo
```

#### vadtree

Display Virtual Address Descriptor tree.

```bash
volatility -f <memory_dump> vadtree
```

#### verinfo

Display version information.

```bash
volatility -f <memory_dump> verinfo
```

#### windows

List open windows.

```bash
volatility -f <memory_dump> windows
```

#### yarascan

Scan for YARA signatures.

```bash
volatility -f <memory_dump> yarascan -Y <yara_rules_file>
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections 
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{% endtab %}
{% endtabs %}

## Ruche de registre

### Afficher les ruches disponibles

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Liste des plugins de Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#plugins)
- [Liste des règles Yara pour Volatility](https://github.com/Neo23x0/signature-base/tree/master/yara/volatility)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
### Obtenir une valeur

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> getsids -U <nom_d'utilisateur>
```

```bash
volatility -f <nom_du_fichier> getsids -u <uid>
```

```bash
volatility -f <nom_du_fichier> getsids -p <pid>
```

```bash
volatility -f <nom_du_fichier> envars -p <pid>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan | grep -i <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <adresse_physique> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <adresse_physique> -D <dossier_de_sortie> --name
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <adresse_physique> -D <dossier_de_sortie> --dump-dir <dossier_de_sortie>
```

### Analyse des registres

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> printkey -K <chemin_du_registre>
```

```bash
volatility -f <nom_du_fichier> printkey -o <offset_du_registre>
```

```bash
volatility -f <nom_du_fichier> hashdump -y <nom_du_système> -s <chemin_du_système> -h <chemin_du_sam> -S <chemin_du_security>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie> | grep -i <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie> | grep -i <nom_du_processus>
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie> | grep -i <nom_du_module>
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie> | grep -i <nom_de_la_dll>
```

## Plugins

### Plugin `pslist`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> pslist
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> pslist -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> pslist -t <tid>
```

### Plugin `psscan`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> psscan
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> psscan -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> psscan -t <tid>
```

### Plugin `pstree`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> pstree
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> pstree -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> pstree -t <tid>
```

### Plugin `dlllist`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> dlllist
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> dlllist -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> dlllist -t <tid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> handles
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> handles -t <tid>
```

### Plugin `filescan`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> filescan
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> filescan -F <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> filescan -S <chemin_du_dossier>
```

### Plugin `netscan`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> netscan
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> netscan -p <pid>
```

### Plugin `connscan`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> connscan
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> connscan -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> connscan -s
```

### Plugin `sockscan`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> sockscan
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> sockscan -p <pid>
```

### Plugin `envars`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> envars -p <pid>
```

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> malfind
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> malfind -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> malfind -D <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> ldrmodules -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> cmdscan -p <pid>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> dumpfiles -Q <adresse_physique> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> dumpfiles -Q <adresse_physique> -D <dossier_de_sortie> --name
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> dumpfiles -Q <adresse_physique> -D <dossier_de_sortie> --dump-dir <dossier_de_sortie>
```

### Plugin `hivelist`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> hivelist
```

### Plugin `printkey`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -K <chemin_du_registre>
```

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> printkey -o <offset_du_registre>
```

### Plugin `hashdump`

```bash
volatility -f <nom_du_fichier> --profile=<nom_du_profile> hashdump -y <nom_du_système> -s <chemin_du_système> -h <chemin_du_sam> -S <chemin_du_security>
```
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### Dump

### Décharge
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Système de fichiers

### Montage

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet)
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% tab title="volatility" %}
# Volatility Cheat Sheet

## Scan/Dump

### Scan for running processes

```
volatility -f <memory_dump> --profile=<profile> pslist
```

### Dump a process

```
volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>
```

### Dump a process by name

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') -D <output_directory>
```

### Dump a process by name and user

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ && /<user>/ {print $2}') -D <output_directory>
```

### Dump a process by name and PID

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ && /<pid>/ {print $2}') -D <output_directory>
```

### Dump a process by name and PPID

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ && /<ppid>/ {print $2}') -D <output_directory>
```

### Dump a process by name and command line

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ && /<command_line>/ {print $2}') -D <output_directory>
```

### Dump a process by name and DLL

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls=<dll_name>
```

### Dump a process by name and DLL hash

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls=<dll_hash>
```

### Dump a process by name and DLL regex

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex>
```

### Dump a process by name and DLL regex (case insensitive)

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i
```

### Dump a process by name and DLL regex (case insensitive) and DLL hash

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_hash>
```

### Dump a process by name and DLL regex (case insensitive) and DLL name

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_name>
```

### Dump a process by name and DLL regex (case insensitive) and DLL name and hash

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_name> --dump-dlls=<dll_hash>
```

### Dump a process by name and DLL regex (case insensitive) and DLL name and hash and output format

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_name> --dump-dlls=<dll_hash> --output=<output_format>
```

### Dump a process by name and DLL regex (case insensitive) and DLL name and hash and output format and physical offset

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_name> --dump-dlls=<dll_hash> --output=<output_format> --physical-offset=<physical_offset>
```

### Dump a process by name and DLL regex (case insensitive) and DLL name and hash and output format and physical offset and virtual offset

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_name> --dump-dlls=<dll_hash> --output=<output_format> --physical-offset=<physical_offset> --virtual-offset=<virtual_offset>
```

### Dump a process by name and DLL regex (case insensitive) and DLL name and hash and output format and physical offset and virtual offset and no data

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_name> --dump-dlls=<dll_hash> --output=<output_format> --physical-offset=<physical_offset> --virtual-offset=<virtual_offset> --no-data
```

### Dump a process by name and DLL regex (case insensitive) and DLL name and hash and output format and physical offset and virtual offset and no data and no headers

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_name> --dump-dlls=<dll_hash> --output=<output_format> --physical-offset=<physical_offset> --virtual-offset=<virtual_offset> --no-data --no-headers
```

### Dump a process by name and DLL regex (case insensitive) and DLL name and hash and output format and physical offset and virtual offset and no data and no headers and no pad

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_name> --dump-dlls=<dll_hash> --output=<output_format> --physical-offset=<physical_offset> --virtual-offset=<virtual_offset> --no-data --no-headers --no-pad
```

### Dump a process by name and DLL regex (case insensitive) and DLL name and hash and output format and physical offset and virtual offset and no data and no headers and no pad and no spaces

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_name> --dump-dlls=<dll_hash> --output=<output_format> --physical-offset=<physical_offset> --virtual-offset=<virtual_offset> --no-data --no-headers --no-pad --no-spaces
```

### Dump a process by name and DLL regex (case insensitive) and DLL name and hash and output format and physical offset and virtual offset and no data and no headers and no pad and no spaces and no hex

```
volatility -f <memory_dump> --profile=<profile> memdump -p $(volatility -f <memory_dump> --profile=<profile> pslist | awk '/<process_name>/ {print $2}') --dump-dir=<output_directory> --dump-dlls-regex=<dll_regex> --dump-dlls-regex-i --dump-dlls=<dll_name> --dump-dlls=<dll_hash> --output=<output_format> --physical-offset=<physical_offset> --virtual-offset=<virtual_offset> --no-data --no-headers --no-pad --no-spaces --no-hex
```


{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Installation

```bash
pip install volatility
```

## Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

## Plugins

### Process Analysis

#### pslist

List running processes.

```bash
volatility -f <memory_dump> pslist
```

#### psscan

Scan for processes.

```bash
volatility -f <memory_dump> psscan
```

#### pstree

Display process tree.

```bash
volatility -f <memory_dump> pstree
```

#### dlllist

List loaded DLLs.

```bash
volatility -f <memory_dump> dlllist
```

#### handles

List open handles.

```bash
volatility -f <memory_dump> handles
```

#### cmdscan

Scan for command history.

```bash
volatility -f <memory_dump> cmdscan
```

### Malware Analysis

#### malfind

Find hidden and injected code.

```bash
volatility -f <memory_dump> malfind
```

#### malprocfind

Find hidden processes.

```bash
volatility -f <memory_dump> malprocfind
```

#### malfind

Find hidden files.

```bash
volatility -f <memory_dump> malfind
```

### Memory Analysis

#### memdump

Dump process memory.

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
```

#### memmap

Display memory map.

```bash
volatility -f <memory_dump> memmap
```

#### memstrings

Extract printable strings.

```bash
volatility -f <memory_dump> memstrings
```

#### memimage

Extract PE files.

```bash
volatility -f <memory_dump> memimage
```

#### memdump

Dump kernel memory.

```bash
volatility -f <memory_dump> memdump -p 0 -D <output_directory>
```

### Network Analysis

#### connscan

List open connections.

```bash
volatility -f <memory_dump> connscan
```

#### sockets

List open sockets.

```bash
volatility -f <memory_dump> sockets
```

#### netscan

Scan for network connections.

```bash
volatility -f <memory_dump> netscan
```

### User Analysis

#### hivelist

List registry hives.

```bash
volatility -f <memory_dump> hivelist
```

#### hashdump

Dump password hashes.

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -u <user_hive>
```

#### userassist

List userassist entries.

```bash
volatility -f <memory_dump> userassist
```

#### getsids

List user SIDs.

```bash
volatility -f <memory_dump> getsids
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### envars

List environment variables.

```bash
volatility -f <memory_dump> envars
```

### Windows Registry Analysis

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### hivelist

List registry hives.

```bash
volatility -f <memory_dump> hivelist
```

#### hivedump

Dump registry hive.

```bash
volatility -f <memory_dump> hivedump -o <offset> -s <size> -f <output_file>
```

### Virtual Machine Analysis

#### vboxinfo

Display VirtualBox information.

```bash
volatility -f <memory_dump> vboxinfo
```

#### vboxsf

List VirtualBox shared folders.

```bash
volatility -f <memory_dump> vboxsf
```

#### vmwareinfo

Display VMware information.

```bash
volatility -f <memory_dump> vmwareinfo
```

#### vmpsaux

List VMware process information.

```bash
volatility -f <memory_dump> vmpsaux
```

### Other Plugins

#### apihooks

List API hooks.

```bash
volatility -f <memory_dump> apihooks
```

#### callbacks

List kernel callbacks.

```bash
volatility -f <memory_dump> callbacks
```

#### driverirp

List driver IRPs.

```bash
volatility -f <memory_dump> driverirp
```

#### filescan

Scan for files.

```bash
volatility -f <memory_dump> filescan
```

#### mutantscan

Scan for mutant objects.

```bash
volatility -f <memory_dump> mutantscan
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### privs

List process privileges.

```bash
volatility -f <memory_dump> privs
```

#### shimcache

List ShimCache entries.

```bash
volatility -f <memory_dump> shimcache
```

#### ssdt

List SSDT entries.

```bash
volatility -f <memory_dump> ssdt
```

#### thrdscan

Scan for threads.

```bash
volatility -f <memory_dump> thrdscan
```

#### timers

List kernel timers.

```bash
volatility -f <memory_dump> timers
```

#### vadinfo

Display VAD information.

```bash
volatility -f <memory_dump> vadinfo
```

#### vadtree

Display VAD tree.

```bash
volatility -f <memory_dump> vadtree
```

#### verinfo

Display version information.

```bash
volatility -f <memory_dump> verinfo
```

#### windows

List open windows.

```bash
volatility -f <memory_dump> windows
```

#### wintree

Display window tree.

```bash
volatility -f <memory_dump> wintree
```

#### yarascan

Scan for YARA signatures.

```bash
volatility -f <memory_dump> yarascan -Y <yara_rules_file>
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% tab title="fr" %}
### Tableau maître de fichiers

{% tabs %}
{% tab title="vol3" %}
Le Tableau maître de fichiers (MFT) est une structure de données utilisée par le système de fichiers NTFS pour stocker les informations sur les fichiers et les répertoires sur un disque. L'analyse du MFT peut fournir des informations précieuses sur les fichiers supprimés, les fichiers cachés et les fichiers système. Volatility dispose de plusieurs plugins pour extraire et analyser le MFT, notamment `mftparser`, `mftparser2` et `mftparser3`.
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Installation

```bash
pip install volatility
```

## Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

## Plugins

### Process Analysis

#### pslist

List running processes.

```bash
volatility -f <memory_dump> pslist
```

#### psscan

Scan for processes.

```bash
volatility -f <memory_dump> psscan
```

#### pstree

Display process tree.

```bash
volatility -f <memory_dump> pstree
```

#### dlllist

List loaded DLLs.

```bash
volatility -f <memory_dump> dlllist
```

#### handles

List open handles.

```bash
volatility -f <memory_dump> handles
```

#### cmdscan

Scan for command history.

```bash
volatility -f <memory_dump> cmdscan
```

### Malware Analysis

#### malfind

Find hidden and injected code.

```bash
volatility -f <memory_dump> malfind
```

#### malprocfind

Find hidden processes.

```bash
volatility -f <memory_dump> malprocfind
```

#### malfind

Find hidden files.

```bash
volatility -f <memory_dump> malfind
```

### Memory Analysis

#### memdump

Dump process memory.

```bash
volatility -f <memory_dump> memdump -p <pid> -D <output_directory>
```

#### memmap

Display memory map.

```bash
volatility -f <memory_dump> memmap
```

#### memstrings

Extract printable strings.

```bash
volatility -f <memory_dump> memstrings
```

#### memimage

Extract PE files.

```bash
volatility -f <memory_dump> memimage
```

#### memdiff

Compare memory dumps.

```bash
volatility -f <memory_dump1> memdiff -f <memory_dump2>
```

### Network Analysis

#### connscan

List open connections.

```bash
volatility -f <memory_dump> connscan
```

#### sockets

List open sockets.

```bash
volatility -f <memory_dump> sockets
```

#### netscan

Scan for network activity.

```bash
volatility -f <memory_dump> netscan
```

### User Analysis

#### hivelist

List registry hives.

```bash
volatility -f <memory_dump> hivelist
```

#### hashdump

Dump password hashes.

```bash
volatility -f <memory_dump> hashdump -s <system_hive> -u <user_hive>
```

#### userassist

List userassist entries.

```bash
volatility -f <memory_dump> userassist
```

#### getsids

List user SIDs.

```bash
volatility -f <memory_dump> getsids
```

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

### Windows Registry Analysis

#### printkey

Print registry key.

```bash
volatility -f <memory_dump> printkey -K <key_path>
```

#### printval

Print registry value.

```bash
volatility -f <memory_dump> printval -K <key_path> -V <value_name>
```

#### hivedump

Dump registry hive.

```bash
volatility -f <memory_dump> hivedump -o <offset> -s <size> -w <output_file>
```

### Virtualization Analysis

#### vboxinfo

Display VirtualBox information.

```bash
volatility -f <memory_dump> vboxinfo
```

#### vboxsf

List VirtualBox shared folders.

```bash
volatility -f <memory_dump> vboxsf
```

#### vmwareinfo

Display VMware information.

```bash
volatility -f <memory_dump> vmwareinfo
```

#### vmscan

Scan for virtual machines.

```bash
volatility -f <memory_dump> vmscan
```

## References

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

Le système de fichiers NTFS contient un fichier appelé _tableau de fichiers principal_, ou MFT. Il y a au moins une entrée dans le MFT pour chaque fichier sur un volume de système de fichiers NTFS, y compris le MFT lui-même. **Toutes les informations sur un fichier, y compris sa taille, ses horodatages, ses autorisations et son contenu de données**, sont stockées soit dans des entrées MFT, soit dans un espace en dehors du MFT qui est décrit par des entrées MFT. À partir de [ici](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Clés/Certificats SSL
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des registres

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key> -o <offset>
```

```bash
volatility -f <nom_du_fichier> hashdump -y <system_hive> -s <software_hive>
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key> -o <offset>
```

```bash
volatility -f <nom_du_fichier> hashdump -y <system_hive> -s <software_hive>
```

## Plugins

### Plugin `pslist`

```bash
volatility -f <nom_du_fichier> --profile=<profile> pslist
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> pslist -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> pslist --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> pslist --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `psscan`

```bash
volatility -f <nom_du_fichier> --profile=<profile> psscan
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> psscan -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> psscan --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> psscan --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `pstree`

```bash
volatility -f <nom_du_fichier> --profile=<profile> pstree
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> pstree -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> pstree --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> pstree --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `dlllist`

```bash
volatility -f <nom_du_fichier> --profile=<profile> dlllist
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> dlllist -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> dlllist --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> dlllist --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> --profile=<profile> handles
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> handles --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> handles --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `filescan`

```bash
volatility -f <nom_du_fichier> --profile=<profile> filescan
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> filescan -F <nom_du_fichier_recherché>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> filescan --filename=<nom_du_fichier_recherché>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> filescan --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `netscan`

```bash
volatility -f <nom_du_fichier> --profile=<profile> netscan
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> netscan -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> netscan --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> netscan --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `connscan`

```bash
volatility -f <nom_du_fichier> --profile=<profile> connscan
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> connscan -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> connscan --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> connscan --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `sockscan`

```bash
volatility -f <nom_du_fichier> --profile=<profile> sockscan
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> sockscan -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> sockscan --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> sockscan --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> --profile=<profile> malfind
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> malfind -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> malfind --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> malfind --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> --profile=<profile> apihooks
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> apihooks --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> apihooks --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> --profile=<profile> ldrmodules
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> ldrmodules --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> ldrmodules --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> --profile=<profile> cmdscan
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> cmdscan -p <pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> cmdscan --pid=<pid>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> cmdscan --output-file=<nom_du_fichier_de_sortie>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> --profile=<profile> dumpfiles
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> dumpfiles -Q <nom_du_fichier_recherché>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> dumpfiles --name=<nom_du_fichier_recherché>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> dumpfiles --output-dir=<dossier_de_sortie>
```

### Plugin `hashdump`

```bash
volatility -f <nom_du_fichier> --profile=<profile> hashdump -y <system_hive> -s <software_hive>
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> hashdump -y <system_hive> -s <software_hive> --output-file=<nom_du_fichier_de_sortie>
```

## Profils

### Liste des profils

```bash
volatility --info | grep "Suggested Profile(s)"
```

### Utilisation des profils

```bash
volatility -f <nom_du_fichier> --profile=<profile> <commande>
```

## Autres commandes utiles

### Recherche de chaînes de caractères

```bash
volatility -f <nom_du_fichier> --profile=<profile> strings -s <adresse_de_départ> -e <adresse_de_fin> --print
```

### Recherche de chaînes de caractères dans les fichiers

```bash
volatility -f <nom_du_fichier> --profile=<profile> filescan | grep <nom_du_fichier_recherché>
```

### Recherche de processus

```bash
volatility -f <nom_du_fichier> --profile=<profile> pslist | grep <nom_du_processus>
```

### Recherche de connexions réseau

```bash
volatility -f <nom_du_fichier> --profile=<profile> connscan | grep <adresse_IP>
```

### Recherche de fichiers

```bash
volatility -f <nom_du_fichier> --profile=<profile> filescan | grep <nom_du_fichier>
```

### Recherche de clés de registre

```bash
volatility -f <nom_du_fichier> --profile=<profile> hivelist
```

```bash
volatility -f <nom_du_fichier> --profile=<profile> printkey -K <registry_key>
```

### Recherche de mots de passe

```bash
volatility -f <nom_du_fichier> --profile=<profile> hashdump -y <system_hive> -s <software_hive>
```

## Ressources

- [Documentation officielle de Volatility](https://github.com/volatilityfoundation/volatility/wiki)
- [Liste des profils supportés par Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#-f-file--profile-profile)
- [Liste des plugins de Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#plugins)
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## Logiciel malveillant

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Volatility Cheatsheet

## Installation

```bash
sudo apt-get install volatility
```

## Basic Usage

```bash
volatility -f <memory_dump> <plugin> [options]
```

## Plugins

### Image Identification

```bash
volatility imageinfo -f <memory_dump>
```

### Process Listing

```bash
volatility pslist -f <memory_dump>
```

### Process Tree

```bash
volatility pstree -f <memory_dump>
```

### Process Memory Dump

```bash
volatility memdump -f <memory_dump> -p <pid> --dump-dir <output_directory>
```

### DLL Listing

```bash
volatility dlllist -f <memory_dump> -p <pid>
```

### Handles

```bash
volatility handles -f <memory_dump> -p <pid>
```

### Network Connections

```bash
volatility netscan -f <memory_dump>
```

### Open Files

```bash
volatility filescan -f <memory_dump>
```

### Registry Analysis

```bash
volatility hivelist -f <memory_dump>
volatility printkey -f <memory_dump> -o <offset>
volatility dumpkey -f <memory_dump> -o <offset> --dump-dir <output_directory>
```

### Malware Analysis

```bash
volatility malfind -f <memory_dump> --dump-dir <output_directory>
volatility malprocfind -f <memory_dump> --dump-dir <output_directory>
volatility malfind -f <memory_dump> --dump-dir <output_directory>
```

### User Account Analysis

```bash
volatility hivescan -f <memory_dump>
volatility userassist -f <memory_dump>
volatility getsids -f <memory_dump>
volatility hashdump -f <memory_dump> -s <system_offset> -u <user_offset>
```

### Miscellaneous

```bash
volatility cmdline -f <memory_dump> -p <pid>
volatility consoles -f <memory_dump>
volatility idt -f <memory_dump>
volatility modules -f <memory_dump>
volatility printkey -f <memory_dump> -o <offset>
volatility shellbags -f <memory_dump>
volatility sockets -f <memory_dump>
volatility ssdt -f <memory_dump>
volatility timers -f <memory_dump>
volatility truecryptmaster -f <memory_dump>
volatility vadinfo -f <memory_dump>
volatility vadtree -f <memory_dump>
volatility windows -f <memory_dump>
```
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% tab title="volatility-cheatsheet.md" %}

### Analyse de dump mémoire avec Volatility

#### Commandes de base

- `volatility -f <dump> imageinfo`: Affiche les informations de l'image mémoire.
- `volatility -f <dump> pslist`: Affiche la liste des processus.
- `volatility -f <dump> pstree`: Affiche l'arborescence des processus.
- `volatility -f <dump> psscan`: Affiche les processus actifs.
- `volatility -f <dump> netscan`: Affiche les connexions réseau.
- `volatility -f <dump> connscan`: Affiche les connexions réseau.
- `volatility -f <dump> filescan`: Affiche les fichiers ouverts.
- `volatility -f <dump> dlllist`: Affiche les DLL chargées.
- `volatility -f <dump> handles`: Affiche les handles ouverts.
- `volatility -f <dump> getsids`: Affiche les SID des processus.
- `volatility -f <dump> printkey`: Affiche les clés de registre.
- `volatility -f <dump> hivelist`: Affiche les fichiers de registre.
- `volatility -f <dump> hashdump -y <system hive> -s <security hive> -a`: Affiche les hashes des mots de passe.

#### Plugins

- `volatility -f <dump> --profile=<profile> <plugin>`: Exécute un plugin spécifique.

#### Analyse de malware

- `volatility -f <dump> malfind`: Recherche les processus infectés par un malware.
- `volatility -f <dump> malsysproc`: Recherche les processus système infectés par un malware.
- `volatility -f <dump> malprocfind`: Recherche les processus infectés par un malware en utilisant des signatures Yara.
- `volatility -f <dump> yarascan -Y <yara rules file>`: Recherche les processus infectés par un malware en utilisant des signatures Yara.

#### Analyse de la mémoire virtuelle

- `volatility -f <dump> memdump -p <pid> <output file>`: Dump la mémoire virtuelle d'un processus.
- `volatility -f <dump> memdump -D <output directory> --dump-dir=<output directory>`: Dump la mémoire virtuelle de tous les processus.
- `volatility -f <dump> memdump --dump-dir=<output directory> --name=<process name>`: Dump la mémoire virtuelle d'un processus en utilisant son nom.

#### Analyse de la mémoire physique

- `volatility -f <dump> hiberfil`: Analyse un fichier hibernation.
- `volatility -f <dump> hibinfo`: Affiche les informations d'un fichier hibernation.
- `volatility -f <dump> kdbgscan`: Recherche le KDBG.
- `volatility -f <dump> kpcrscan`: Recherche le KPCR.
- `volatility -f <dump> physmap`: Affiche la carte mémoire physique.
- `volatility -f <dump> memmap`: Affiche la carte mémoire virtuelle.

### Analyse de dump mémoire avec Rekall

#### Commandes de base

- `rekall -f <dump> pslist`: Affiche la liste des processus.
- `rekall -f <dump> pstree`: Affiche l'arborescence des processus.
- `rekall -f <dump> psscan`: Affiche les processus actifs.
- `rekall -f <dump> netscan`: Affiche les connexions réseau.
- `rekall -f <dump> connscan`: Affiche les connexions réseau.
- `rekall -f <dump> filescan`: Affiche les fichiers ouverts.
- `rekall -f <dump> dlllist`: Affiche les DLL chargées.
- `rekall -f <dump> handles`: Affiche les handles ouverts.
- `rekall -f <dump> getsids`: Affiche les SID des processus.
- `rekall -f <dump> printkey`: Affiche les clés de registre.
- `rekall -f <dump> hivelist`: Affiche les fichiers de registre.
- `rekall -f <dump> hashdump -y <system hive> -s <security hive> -a`: Affiche les hashes des mots de passe.

#### Plugins

- `rekall -f <dump> <plugin>`: Exécute un plugin spécifique.

#### Analyse de malware

- `rekall -f <dump> malfind`: Recherche les processus infectés par un malware.
- `rekall -f <dump> malsysproc`: Recherche les processus système infectés par un malware.
- `rekall -f <dump> malprocfind`: Recherche les processus infectés par un malware en utilisant des signatures Yara.
- `rekall -f <dump> yarascan -Y <yara rules file>`: Recherche les processus infectés par un malware en utilisant des signatures Yara.

#### Analyse de la mémoire virtuelle

- `rekall -f <dump> memdump -p <pid> <output file>`: Dump la mémoire virtuelle d'un processus.
- `rekall -f <dump> memdump -D <output directory> --dump-dir=<output directory>`: Dump la mémoire virtuelle de tous les processus.
- `rekall -f <dump> memdump --dump-dir=<output directory> --name=<process name>`: Dump la mémoire virtuelle d'un processus en utilisant son nom.

#### Analyse de la mémoire physique

- `rekall -f <dump> hiberfil`: Analyse un fichier hibernation.
- `rekall -f <dump> hibinfo`: Affiche les informations d'un fichier hibernation.
- `rekall -f <dump> kdbgscan`: Recherche le KDBG.
- `rekall -f <dump> kpcrscan`: Recherche le KPCR.
- `rekall -f <dump> physmap`: Affiche la carte mémoire physique.
- `rekall -f <dump> memmap`: Affiche la carte mémoire virtuelle.

### Analyse de dump mémoire avec LiME

#### Commandes de base

- `lime-forensics -r <dump> -p <profile> -i <path to profile>`: Charge le profil.
- `lime-forensics -r <dump> -p <profile> -c <command>`: Exécute une commande spécifique.

#### Analyse de la mémoire virtuelle

- `lime-forensics -r <dump> -p <profile> -c "memdump <pid> <output file>"`: Dump la mémoire virtuelle d'un processus.
- `lime-forensics -r <dump> -p <profile> -c "memdump -A <output directory>"`: Dump la mémoire virtuelle de tous les processus.

#### Analyse de la mémoire physique

- `lime-forensics -r <dump> -p <profile> -c "raw2lime <output file>"`: Convertit un dump mémoire brut en format LiME.
- `lime-forensics -r <dump> -p <profile> -c "limeinfo"`: Affiche les informations de la mémoire LiME.
- `lime-forensics -r <dump> -p <profile> -c "volatility --plugins=<path to plugins> -f <path to LiME> <plugin>"`: Exécute un plugin Volatility sur la mémoire LiME.

### Scanning avec yara

Utilisez ce script pour télécharger et fusionner toutes les règles de malware yara depuis github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Créez le répertoire _**rules**_ et exécutez-le. Cela créera un fichier appelé _**malware\_rules.yar**_ qui contient toutes les règles yara pour les malwares.

{% endtab %}
{% endtabs %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Liste des plugins de Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#plugins)
- [Liste des règles Yara pour Volatility](https://github.com/Neo23x0/signature-base/tree/master/yara/volatility)
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% tab title="vol3" %}
## DIVERS

### Plugins externes

Si vous souhaitez utiliser des plugins externes, assurez-vous que les dossiers liés aux plugins sont le premier paramètre utilisé.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Liste des plugins de Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#plugins)
```bash
 volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

Téléchargez-le depuis [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
 volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

### Mutexes

Les mutexes sont des objets de synchronisation qui permettent à un seul thread d'accéder à une ressource partagée à la fois. Les mutexes sont souvent utilisés pour protéger les sections critiques du code et pour éviter les conflits de données.

#### Afficher la liste des mutexes

```
volatility -f <dump> --profile=<profile> mutex
```

#### Afficher les threads en attente d'un mutex

```
volatility -f <dump> --profile=<profile> mutex -t <mutex_address>
```

#### Afficher les mutexes détenus par un processus

```
volatility -f <dump> --profile=<profile> mutex -p <pid>
```

#### Afficher les processus détenant un mutex

```
volatility -f <dump> --profile=<profile> mutex -m <mutex_address>
```

#### Afficher les mutexes détenus par un thread

```
volatility -f <dump> --profile=<profile> mutex -t <tid>
```

#### Afficher les threads détenant un mutex

```
volatility -f <dump> --profile=<profile> mutex -m <mutex_address> --output=dot --output-file=<output_file>
```

#### Afficher les mutexes détenus par un processus en mode graphique

```
volatility -f <dump> --profile=<profile> mutex -p <pid> --output=dot --output-file=<output_file>
```

#### Afficher les mutexes détenus par un thread en mode graphique

```
volatility -f <dump> --profile=<profile> mutex -t <tid> --output=dot --output-file=<output_file>
```

#### Afficher les mutexes détenus par un processus en mode texte

```
volatility -f <dump> --profile=<profile> mutex -p <pid> --output=text --output-file=<output_file>
```

#### Afficher les mutexes détenus par un thread en mode texte

```
volatility -f <dump> --profile=<profile> mutex -t <tid> --output=text --output-file=<output_file>
```

#### Afficher les mutexes détenus par un processus en mode JSON

```
volatility -f <dump> --profile=<profile> mutex -p <pid> --output=json --output-file=<output_file>
```

#### Afficher les mutexes détenus par un thread en mode JSON

```
volatility -f <dump> --profile=<profile> mutex -t <tid> --output=json --output-file=<output_file>
```
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet)
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### Liens symboliques
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

### Plugin `dumpregistry`

```bash
volatility -f <nom_du_fichier> dumpregistry -o <registry_hive> -D <dossier_de_sortie>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `dumpcerts`

```bash
volatility -f <nom_du_fichier> dumpcerts -O <dossier_de_sortie>
```

### Plugin `moddump`

```bash
volatility -f <nom_du_fichier> moddump -D <dossier_de_sortie>
```

### Plugin `modscan`

```bash
volatility -f <nom_du_fichier> modscan
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `svcscan`

```bash
volatility -f <nom_du_fichier> svcscan
```

### Plugin `printkey`

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Plugin `getsids`

```bash
volatility -f <nom_du_fichier> getsids
```

### Plugin `userassist`

```bash
volatility -f <nom_du_fichier> userassist
```

### Plugin `dumpregistry`

```bash
volatility -f <nom_du_fichier> dumpregistry -o <registry_hive> -D <dossier_de_sortie>
```

### Plugin `dumpcerts`

```bash
volatility -f <nom_du_fichier> dumpcerts -O <dossier_de_sortie>
```

### Plugin `connscan`

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

### Plugin `sockets`

```bash
volatility -f <nom_du_fichier> sockets
```

### Plugin `sockscan`

```bash
volatility -f <nom_du_fichier> sockscan
```

### Plugin `connscan`

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

### Plugin `sockets`

```bash
volatility -f <nom_du_fichier> sockets
```

### Plugin `sockscan`

```bash
volatility -f <nom_du_fichier> sockscan
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet) (en anglais)
- [Volatility Plugin List](https://github.com/superponible/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/tehw0lf/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/504ensicsLabs/LiME/tree/master/src/volatility) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

Il est possible de **lire depuis la mémoire l'historique de bash**. Vous pouvez également extraire le fichier _.bash\_history_, mais s'il est désactivé, vous serez heureux de pouvoir utiliser ce module de Volatility.
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet)
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### Chronologie
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

```bash
volatility -f <nom_du_fichier> userassist
```

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

## Plugins

### Plugin `malfind`

```bash
volatility -f <nom_du_fichier> malfind
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie>
```

### Plugin `yarascan`

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara>
```

```bash
volatility -f <nom_du_fichier> yarascan -Y <fichier_de_règles_yara> --dump-dir <dossier_de_sortie>
```

### Plugin `dumpregistry`

```bash
volatility -f <nom_du_fichier> dumpregistry -o <registry_hive> -D <dossier_de_sortie>
```

### Plugin `dumpfiles`

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <nom_du_fichier> --dump-dir <dossier_de_sortie>
```

### Plugin `moddump`

```bash
volatility -f <nom_du_fichier> moddump -D <dossier_de_sortie> -m <nom_du_module>
```

### Plugin `procdump`

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

### Plugin `memdump`

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

### Plugin `apihooks`

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### Plugin `ldrmodules`

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### Plugin `handles`

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

### Plugin `cmdscan`

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Plugin `hashdump`

```bash
volatility -f <nom_du_fichier> hashdump -s <system_hive> -y <system_key> -s <sam_hive> -y <sam_key>
```

### Plugin `printkey`

```bash
volatility -f <nom_du_fichier> printkey -K <registry_key>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://github.com/413x90/volatility-cheatsheet) (en anglais)
- [Volatility Plugin List](https://github.com/superponible/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/tehw0lf/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/aim4r/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/aim4r/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/aim4r/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/forensicmatt/VolUtility) (en anglais)
- [Volatility Plugin List](https://github.com/woanware/volatility-plugins) (en anglais)
- [Volatility Plugin List](https://github.com/kevthehermit/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/aim4r/Volatility-Plugins) (en anglais)
- [Volatility Plugin List](https://github.com/tribalchicken/volatility-plugins) (en anglais)
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% tab title="vol3" %}

### Pilotes

{% endtab %}
{% endtabs %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="volatility-cheatsheet.md" %}
# Feuille de triche Volatility

## Commandes de base

### Analyse de l'image mémoire

```bash
volatility -f <nom_du_fichier> imageinfo
```

```bash
volatility -f <nom_du_fichier> kdbgscan
```

```bash
volatility -f <nom_du_fichier> kpcrscan
```

```bash
volatility -f <nom_du_fichier> pslist
```

```bash
volatility -f <nom_du_fichier> psscan
```

```bash
volatility -f <nom_du_fichier> pstree
```

```bash
volatility -f <nom_du_fichier> dlllist
```

```bash
volatility -f <nom_du_fichier> handles
```

```bash
volatility -f <nom_du_fichier> filescan
```

```bash
volatility -f <nom_du_fichier> netscan
```

### Analyse des processus

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> malfind -p <pid> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

```bash
volatility -f <nom_du_fichier> handles -p <pid>
```

```bash
volatility -f <nom_du_fichier> cmdscan -p <pid>
```

### Analyse des connexions réseau

```bash
volatility -f <nom_du_fichier> connscan
```

```bash
volatility -f <nom_du_fichier> connscan -s
```

```bash
volatility -f <nom_du_fichier> sockets
```

```bash
volatility -f <nom_du_fichier> sockscan
```

### Analyse des utilisateurs

```bash
volatility -f <nom_du_fichier> getsids
```

```bash
volatility -f <nom_du_fichier> getsids -U <nom_d'utilisateur>
```

```bash
volatility -f <nom_du_fichier> getsids -u <uid>
```

```bash
volatility -f <nom_du_fichier> getsids -p <pid>
```

```bash
volatility -f <nom_du_fichier> envars -p <pid>
```

### Analyse des fichiers

```bash
volatility -f <nom_du_fichier> filescan | grep -i <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <adresse_physique> -D <dossier_de_sortie>
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <adresse_physique> -D <dossier_de_sortie> --name
```

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <adresse_physique> -D <dossier_de_sortie> --dump-dir <dossier_de_sortie>
```

### Analyse des registres

```bash
volatility -f <nom_du_fichier> hivelist
```

```bash
volatility -f <nom_du_fichier> printkey -K <chemin_du_registre>
```

```bash
volatility -f <nom_du_fichier> printkey -o <offset_du_registre>
```

```bash
volatility -f <nom_du_fichier> hashdump -y <nom_du_système> -s <chemin_du_système> -h <chemin_du_sam> -S <chemin_du_security>
```

### Analyse des vulnérabilités

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie> | grep -i <nom_du_fichier>
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie> | grep -i <nom_du_processus>
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie> | grep -i <nom_du_module>
```

```bash
volatility -f <nom_du_fichier> malfind --dump-dir <dossier_de_sortie> | grep -i <nom_de_la_dll>
```

## Plugins

### apihooks

```bash
volatility -f <nom_du_fichier> apihooks -p <pid>
```

### atomscan

```bash
volatility -f <nom_du_fichier> atomscan
```

### autoruns

```bash
volatility -f <nom_du_fichier> autoruns
```

### bigpools

```bash
volatility -f <nom_du_fichier> bigpools
```

### bioskbd

```bash
volatility -f <nom_du_fichier> bioskbd
```

### callbacks

```bash
volatility -f <nom_du_fichier> callbacks
```

### clipboard

```bash
volatility -f <nom_du_fichier> clipboard
```

### cmdscan

```bash
volatility -f <nom_du_fichier> cmdscan
```

### connections

```bash
volatility -f <nom_du_fichier> connections
```

### connscan

```bash
volatility -f <nom_du_fichier> connscan
```

### crashinfo

```bash
volatility -f <nom_du_fichier> crashinfo
```

### deskscan

```bash
volatility -f <nom_du_fichier> deskscan
```

### devicetree

```bash
volatility -f <nom_du_fichier> devicetree
```

### dlldump

```bash
volatility -f <nom_du_fichier> dlldump -p <pid> -D <dossier_de_sortie>
```

### dlllist

```bash
volatility -f <nom_du_fichier> dlllist
```

### driverirp

```bash
volatility -f <nom_du_fichier> driverirp
```

### driverscan

```bash
volatility -f <nom_du_fichier> driverscan
```

### dumpcerts

```bash
volatility -f <nom_du_fichier> dumpcerts
```

### dumpfiles

```bash
volatility -f <nom_du_fichier> dumpfiles -Q <adresse_physique> -D <dossier_de_sortie>
```

### envars

```bash
volatility -f <nom_du_fichier> envars -p <pid>
```

### evtlogs

```bash
volatility -f <nom_du_fichier> evtlogs
```

### filescan

```bash
volatility -f <nom_du_fichier> filescan
```

### gahti

```bash
volatility -f <nom_du_fichier> gahti
```

### getsids

```bash
volatility -f <nom_du_fichier> getsids
```

### handles

```bash
volatility -f <nom_du_fichier> handles
```

### hashdump

```bash
volatility -f <nom_du_fichier> hashdump -y <nom_du_système> -s <chemin_du_système> -h <chemin_du_sam> -S <chemin_du_security>
```

### hibinfo

```bash
volatility -f <nom_du_fichier> hibinfo
```

### hivelist

```bash
volatility -f <nom_du_fichier> hivelist
```

### hivescan

```bash
volatility -f <nom_du_fichier> hivescan
```

### hpakextract

```bash
volatility -f <nom_du_fichier> hpakextract -O <dossier_de_sortie> -p <pid>
```

### iehistory

```bash
volatility -f <nom_du_fichier> iehistory
```

### imagecopy

```bash
volatility -f <nom_du_fichier> imagecopy -O <dossier_de_sortie> -p <pid>
```

### imageinfo

```bash
volatility -f <nom_du_fichier> imageinfo
```

### impscan

```bash
volatility -f <nom_du_fichier> impscan
```

### kdbgscan

```bash
volatility -f <nom_du_fichier> kdbgscan
```

### kpcrscan

```bash
volatility -f <nom_du_fichier> kpcrscan
```

### kthreadscan

```bash
volatility -f <nom_du_fichier> kthreadscan
```

### ldrmodules

```bash
volatility -f <nom_du_fichier> ldrmodules -p <pid>
```

### lsadump

```bash
volatility -f <nom_du_fichier> lsadump -s <chemin_du_système> -d <chemin_du_sam> -p <chemin_du_security>
```

### malfind

```bash
volatility -f <nom_du_fichier> malfind -D <dossier_de_sortie>
```

### memdump

```bash
volatility -f <nom_du_fichier> memdump -p <pid> -D <dossier_de_sortie>
```

### messagehooks

```bash
volatility -f <nom_du_fichier> messagehooks
```

### moddump

```bash
volatility -f <nom_du_fichier> moddump -p <pid> -D <dossier_de_sortie>
```

### modscan

```bash
volatility -f <nom_du_fichier> modscan
```

### mutantscan

```bash
volatility -f <nom_du_fichier> mutantscan
```

### netscan

```bash
volatility -f <nom_du_fichier> netscan
```

### notepad

```bash
volatility -f <nom_du_fichier> notepad
```

### poolscanner

```bash
volatility -f <nom_du_fichier> poolscanner
```

### printkey

```bash
volatility -f <nom_du_fichier> printkey -K <chemin_du_registre>
```

### privs

```bash
volatility -f <nom_du_fichier> privs
```

### procdump

```bash
volatility -f <nom_du_fichier> procdump -p <pid> -D <dossier_de_sortie>
```

### pslist

```bash
volatility -f <nom_du_fichier> pslist
```

### psscan

```bash
volatility -f <nom_du_fichier> psscan
```

### pstree

```bash
volatility -f <nom_du_fichier> pstree
```

### regdiff

```bash
volatility -f <nom_du_fichier> regdiff -K <chemin_du_registre> -O <dossier_de_sortie>
```

### screenshot

```bash
volatility -f <nom_du_fichier> screenshot -p <pid> -D <dossier_de_sortie>
```

### shellbags

```bash
volatility -f <nom_du_fichier> shellbags
```

### shimcache

```bash
volatility -f <nom_du_fichier> shimcache
```

### sockets

```bash
volatility -f <nom_du_fichier> sockets
```

### sockscan

```bash
volatility -f <nom_du_fichier> sockscan
```

### ssdt

```bash
volatility -f <nom_du_fichier> ssdt
```

### strings

```bash
volatility -f <nom_du_fichier> strings -s <adresse_de_début> -e <adresse_de_fin> -n <nombre_de_caractères>
```

### svcscan

```bash
volatility -f <nom_du_fichier> svcscan
```

### thrdscan

```bash
volatility -f <nom_du_fichier> thrdscan
```

### timers

```bash
volatility -f <nom_du_fichier> timers
```

### userassist

```bash
volatility -f <nom_du_fichier> userassist
```

### vadinfo

```bash
volatility -f <nom_du_fichier> vadinfo -p <pid>
```

### vadtree

```bash
volatility -f <nom_du_fichier> vadtree -p <pid>
```

### verinfo

```bash
volatility -f <nom_du_fichier> verinfo
```

### windows

```bash
volatility -f <nom_du_fichier> windows
```

### wndscan

```bash
volatility -f <nom_du_fichier> wndscan
```

### yarascan

```bash
volatility -f <nom_du_fichier> yarascan -Y <chemin_du_fichier_de_règles_yara>
```

## Ressources

- [Documentation officielle de Volatility](https://www.volatilityfoundation.org/)
- [Volatility Labs](https://volatility-labs.blogspot.com/)
- [Volatility Foundation GitHub](https://github.com/volatilityfoundation)
- [Volatility Cheat Sheet](https://www.sans.org/blog/volatility-cheat-sheet-2-0/)
- [Volatility Cheat Sheet 2.0](https://www.sans.org/blog/volatility-cheat-sheet-2-0/)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### Obtenir le presse-papiers
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Obtenir l'historique d'Internet Explorer
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Obtenir le texte du bloc-notes
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Capture d'écran
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Master Boot Record (MBR)

### Enregistrement de démarrage principal (MBR)
```
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
Le MBR contient des informations sur la façon dont les partitions logiques, contenant des systèmes de fichiers, sont organisées sur ce support. Le MBR contient également un code exécutable pour fonctionner en tant que chargeur pour le système d'exploitation installé - généralement en passant le contrôle au deuxième étage du chargeur, ou en conjonction avec le volume boot record (VBR) de chaque partition. Ce code MBR est généralement appelé chargeur de démarrage. À partir d'ici.

RootedCON est l'événement de cybersécurité le plus pertinent en Espagne et l'un des plus importants en Europe. Avec pour mission de promouvoir les connaissances techniques, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.
