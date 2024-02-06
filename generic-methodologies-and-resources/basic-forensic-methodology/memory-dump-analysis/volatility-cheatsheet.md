# Volatility - Feuille de triche

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

Si vous voulez quelque chose de **rapide et fou** qui lancera plusieurs plugins Volatility en parallèle, vous pouvez utiliser : [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Installation

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
#### volatility2

{% tabs %}
{% tab title="Méthode1" %}
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

Volatility a deux approches principales pour les plugins, qui se reflètent parfois dans leurs noms. Les plugins "list" essaieront de naviguer à travers les structures du noyau Windows pour récupérer des informations telles que les processus (localiser et parcourir la liste chaînée des structures `_EPROCESS` en mémoire), les poignées du système d'exploitation (localiser et répertorier la table des poignées, déréférencer les pointeurs trouvés, etc). Ils se comportent plus ou moins comme le ferait l'API Windows si on lui demandait, par exemple, de lister les processus.

Cela rend les plugins "list" assez rapides, mais tout aussi vulnérables que l'API Windows à la manipulation par des logiciels malveillants. Par exemple, si un logiciel malveillant utilise DKOM pour détacher un processus de la liste chaînée `_EPROCESS`, il n'apparaîtra pas dans le Gestionnaire des tâches ni dans la liste des processus.

Les plugins "scan", en revanche, adopteront une approche similaire à celle de la recherche de structures spécifiques dans la mémoire. Par exemple, `psscan` lira la mémoire et essaiera de créer des objets `_EPROCESS` à partir de celle-ci (il utilise la recherche de balises de pool, qui consiste à rechercher des chaînes de 4 octets indiquant la présence d'une structure d'intérêt). L'avantage est qu'il peut retrouver des processus qui ont été arrêtés, et même si un logiciel malveillant altère la liste chaînée `_EPROCESS`, le plugin trouvera toujours la structure laissée en mémoire (car elle doit toujours exister pour que le processus s'exécute). L'inconvénient est que les plugins "scan" sont un peu plus lents que les plugins "list" et peuvent parfois donner des faux positifs (un processus qui s'est arrêté il y a trop longtemps et dont certaines parties de la structure ont été écrasées par d'autres opérations).

Source: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Profils OS

### Volatility3

Comme expliqué dans le fichier readme, vous devez placer la **table des symboles du système d'exploitation** que vous souhaitez prendre en charge dans _volatility3/volatility/symbols_.\
Les packs de tables de symboles pour les différents systèmes d'exploitation sont disponibles en **téléchargement** sur :

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Profil Externe

Vous pouvez obtenir la liste des profils pris en charge en exécutant :
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Si vous souhaitez utiliser un **nouveau profil que vous avez téléchargé** (par exemple un profil linux), vous devez créer quelque part la structure de dossier suivante : _plugins/overlays/linux_ et placer à l'intérieur de ce dossier le fichier zip contenant le profil. Ensuite, obtenez le nombre de profils en utilisant :
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Vous pouvez **télécharger les profils Linux et Mac** depuis [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

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

Contrairement à imageinfo qui fournit simplement des suggestions de profil, **kdbgscan** est conçu pour identifier de manière positive le bon profil et la bonne adresse KDBG (s'il y en a plusieurs). Ce plugin recherche les signatures KDBGHeader liées aux profils de Volatility et applique des vérifications de cohérence pour réduire les faux positifs. La verbosité de la sortie et le nombre de vérifications de cohérence pouvant être effectuées dépendent de la capacité de Volatility à trouver un DTB, donc si vous connaissez déjà le bon profil (ou si vous avez une suggestion de profil à partir de imageinfo), assurez-vous de l'utiliser (à partir de [ici](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)).

Jetez toujours un œil au **nombre de processus trouvés par kdbgscan**. Parfois, imageinfo et kdbgscan peuvent trouver **plus d'un** **profil** approprié, mais seul le **bon aura des processus associés** (Cela est dû au fait que pour extraire les processus, l'adresse KDBG correcte est nécessaire)
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

Le **bloc de débogage du noyau** (nommé KdDebuggerDataBlock du type \_KDDEBUGGER\_DATA64, ou **KDBG** par Volatility) est important pour de nombreuses tâches que Volatility et les débogueurs effectuent. Par exemple, il contient une référence à PsActiveProcessHead qui est la tête de liste de tous les processus nécessaires pour la liste des processus.

## Informations sur le système d'exploitation
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Le plugin `banners.Banners` peut être utilisé dans **vol3 pour essayer de trouver des bannières linux** dans le dump.

## Hashes/Mots de passe

Extraire les hachages SAM, les [informations d'identification mises en cache du domaine](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) et les [secrets lsa](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets).

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## Analyse de la mémoire

Le dump de mémoire d'un processus va **extraire tout** de l'état actuel du processus. Le module **procdump** va seulement **extraire** le **code**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) est l'événement le plus pertinent en matière de cybersécurité en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

## Processes

### List processes

Essayez de trouver des processus **suspects** (par leur nom) ou des **processus** enfants **inattendus** (par exemple, un cmd.exe en tant que processus enfant de iexplorer.exe).\
Il pourrait être intéressant de **comparer** le résultat de pslist avec celui de psscan pour identifier les processus cachés.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.mem imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.mem pslist** : Liste des processus en cours d'exécution
- **volatility -f dump.mem psscan** : Analyse des processus non alloués
- **volatility -f dump.mem pstree** : Affiche les processus sous forme d'arborescence
- **volatility -f dump.mem dlllist -p PID** : Liste des DLL chargées par un processus
- **volatility -f dump.mem filescan** : Analyse des fichiers non alloués
- **volatility -f dump.mem cmdline -p PID** : Ligne de commande d'un processus
- **volatility -f dump.mem netscan** : Liste des connexions réseau
- **volatility -f dump.mem connections** : Analyse des connexions réseau
- **volatility -f dump.mem malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.mem apihooks** : Recherche des hooks API dans les processus
- **volatility -f dump.mem ldrmodules** : Liste des modules chargés par les processus
- **volatility -f dump.mem modscan** : Analyse des modules noyau non alloués
- **volatility -f dump.mem shimcache** : Analyse du cache de compatibilité des applications
- **volatility -f dump.mem userassist** : Analyse des éléments récemment utilisés par l'utilisateur
- **volatility -f dump.mem hivelist** : Liste des hôtes de registre
- **volatility -f dump.mem printkey -o OFFSET** : Affiche les sous-clés d'une clé de registre
- **volatility -f dump.mem hashdump** : Extraction des hachages de mots de passe
- **volatility -f dump.mem truecryptpassphrase** : Recherche de phrases de passe TrueCrypt
- **volatility -f dump.mem clipboard** : Analyse du presse-papiers
- **volatility -f dump.mem screenshot** : Capture d'écran de l'image mémoire
- **volatility -f dump.mem memdump -p PID -D /path/to/dump/** : Extraction de la mémoire d'un processus
- **volatility -f dump.mem memdump -p PID -D /path/to/dump/ -r RANGE** : Extraction de la mémoire d'un processus dans une plage spécifique
- **volatility -f dump.mem memmap** : Cartographie de la mémoire physique
- **volatility -f dump.mem memmap --profile=PROFILE** : Cartographie de la mémoire physique avec un profil spécifique

### Plugins supplémentaires

- **volatility -f dump.mem kdbgscan** : Recherche du KDBG (Kernel Debugger Block)
- **volatility -f dump.mem ssdt** : Affiche la table des descripteurs de services système
- **volatility -f dump.mem driverirp** : Analyse des IRP (I/O Request Packets) des pilotes
- **volatility -f dump.mem callbacks** : Recherche des callbacks de notification de pilote
- **volatility -f dump.mem devicetree** : Affiche l'arborescence des périphériques
- **volatility -f dump.mem handles** : Liste des handles du noyau
- **volatility -f dump.mem mutantscan** : Analyse des objets mutant
- **volatility -f dump.mem qpc** : Affiche les valeurs de l'horloge haute résolution
- **volatility -f dump.mem timers** : Liste des timers du noyau
- **volatility -f dump.mem idt** : Affiche la table des descripteurs d'interruption
- **volatility -f dump.mem gdt** : Affiche la table des descripteurs de tâche globale
- **volatility -f dump.mem threads** : Liste des threads du noyau
- **volatility -f dump.mem thrdscan** : Analyse des threads non alloués
- **volatility -f dump.mem vadinfo** : Informations sur les zones d'allocation virtuelle
- **volatility -f dump.mem vadtree** : Affiche les zones d'allocation virtuelle sous forme d'arborescence
- **volatility -f dump.mem deskscan** : Analyse des objets de bureau
- **volatility -f dump.mem hivescan** : Analyse des hôtes de registre non alloués
- **volatility -f dump.mem userhandles** : Liste des handles utilisateur
- **volatility -f dump.mem wndscan** : Analyse des objets de fenêtre
- **volatility -f dump.mem atomscan** : Analyse des atomes
- **volatility -f dump.mem gditimers** : Liste des timers GDI
- **volatility -f dump.mem usermodules** : Liste des modules utilisateur
- **volatility -f dump.mem userstack** : Affiche la pile utilisateur
- **volatility -f dump.mem ssdeep** : Calcul de l'empreinte SSDeep des sections PE
- **volatility -f dump.mem yarascan** : Analyse des processus à l'aide de règles Yara
- **volatility -f dump.mem yarascan -Y "rule_file.yar"** : Analyse des processus à l'aide d'un fichier de règles Yara
- **volatility -f dump.mem malfind -Y "rule_file.yar"** : Recherche de code malveillant dans les processus à l'aide de règles Yara
- **volatility -f dump.mem malfind --output-file=output.txt** : Enregistre la sortie de la recherche de code malveillant dans un fichier

{% endtab %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Analyse du dump

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.mem imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.mem pslist** : Liste des processus en cours d'exécution
- **volatility -f dump.mem pstree** : Affiche les processus sous forme d'arborescence
- **volatility -f dump.mem psscan** : Analyse les processus inactifs
- **volatility -f dump.mem dlllist -p PID** : Liste les DLL chargées par un processus
- **volatility -f dump.mem filescan** : Analyse les fichiers ouverts
- **volatility -f dump.mem cmdline -p PID** : Affiche la ligne de commande d'un processus
- **volatility -f dump.mem netscan** : Analyse les connexions réseau
- **volatility -f dump.mem connections** : Affiche les connexions réseau
- **volatility -f dump.mem malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.mem apihooks** : Recherche de hooks API dans les processus
- **volatility -f dump.mem ldrmodules** : Liste les modules chargés par les processus
- **volatility -f dump.mem modscan** : Analyse les modules noyau
- **volatility -f dump.mem shimcache** : Analyse la base de données ShimCache
- **volatility -f dump.mem userassist** : Analyse les entrées UserAssist
- **volatility -f dump.mem hivelist** : Liste les hives de registre
- **volatility -f dump.mem printkey -o OFFSET** : Affiche les valeurs d'une clé de registre
- **volatility -f dump.mem hashdump** : Extrait les hachages de mots de passe
- **volatility -f dump.mem truecryptpassphrase** : Extrait les passphrases TrueCrypt
- **volatility -f dump.mem clipboard** : Examine le contenu du presse-papiers
- **volatility -f dump.mem screenshot** : Prend une capture d'écran de l'écran mémoire
- **volatility -f dump.mem memdump -p PID -D /path/to/dump/** : Effectue un dump de la mémoire d'un processus
- **volatility -f dump.mem memdump -p PID -D /path/to/dump/ -r RANGE** : Effectue un dump de la mémoire d'un processus dans une plage spécifique
- **volatility -f dump.mem memmap** : Affiche la carte mémoire

### Plugins supplémentaires

- **volatility -f dump.mem timeliner** : Crée une timeline des activités du système
- **volatility -f dump.mem dumpregistry -o /path/to/dump/registry/** : Extrait la base de registre
- **volatility -f dump.mem dumpfiles -Q /path/to/output/directory/** : Extrait les fichiers du système
- **volatility -f dump.mem dumpfiles -Q /path/to/output/directory/ -r file** : Extrait un fichier spécifique
- **volatility -f dump.mem dumpfiles -Q /path/to/output/directory/ -S /path/to/search/directory/** : Extrait les fichiers correspondant à une liste de hachages
- **volatility -f dump.mem dumpfiles -Q /path/to/output/directory/ -Y /path/to/yara/rules/** : Extrait les fichiers correspondant à des règles YARA
- **volatility -f dump.mem yarascan -Y /path/to/yara/rules/** : Analyse la mémoire à l'aide de règles YARA
- **volatility -f dump.mem mftparser -o /path/to/output/directory/** : Extrait les entrées MFT
- **volatility -f dump.mem mftparser -o /path/to/output/directory/ -r file** : Extrait un fichier MFT spécifique
- **volatility -f dump.mem mftparser -o /path/to/output/directory/ -s /path/to/search/directory/** : Extrait les entrées MFT correspondant à une liste de hachages
- **volatility -f dump.mem mftparser -o /path/to/output/directory/ -Y /path/to/yara/rules/** : Extrait les entrées MFT correspondant à des règles YARA

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### Ligne de commande

Quelque chose de suspect a-t-il été exécuté?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.raw imageinfo** : Affiche des informations générales sur l'image mémoire.
- **volatility -f dump.raw pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.raw psscan** : Recherche les processus supprimés.
- **volatility -f dump.raw dlllist -p PID** : Liste les DLL chargées par un processus spécifique.
- **volatility -f dump.raw cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique.
- **volatility -f dump.raw filescan** : Recherche les fichiers ouverts par les processus.
- **volatility -f dump.raw netscan** : Affiche les connexions réseau.
- **volatility -f dump.raw connections** : Affiche les connexions réseau avec les adresses IP et les ports.
- **volatility -f dump.raw malfind** : Recherche les injections de code malveillant.
- **volatility -f dump.raw timeliner** : Crée une timeline des activités du système.
- **volatility -f dump.raw hivelist** : Liste les hives de registre.
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les valeurs d'une clé de registre.
- **volatility -f dump.raw userassist** : Affiche les éléments récemment ouverts par l'utilisateur.
- **volatility -f dump.raw shimcache** : Affiche les entrées de la cache de compatibilité des applications.

### Plugins supplémentaires

- **psxview** : Détecte les rootkits en comparant les listes de processus.
- **malfind** : Recherche les injections de code malveillant.
- **apihooks** : Détecte les hooks d'API.
- **ldrmodules** : Affiche les modules chargés par les processus.
- **svcscan** : Enumère les services.
- **driverirp** : Affiche les IRP des pilotes.
- **ssdt** : Affiche la table de services du noyau.
- **callbacks** : Affiche les callbacks du noyau.
- **gdt** : Affiche la table de descripteurs globaux.
- **idt** : Affiche la table des descripteurs d'interruption.
- **mutantscan** : Enumère les objets mutant.
- **getsids** : Affiche les SID des processus.
- **atomscan** : Enumère les atomes du système.
- **atomscan** : Enumère les atomes du système.
- **atomscan** : Enumère les atomes du système.

{% endtab %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

Les commandes saisies dans cmd.exe sont traitées par **conhost.exe** (csrss.exe avant Windows 7). Donc même si un attaquant parvient à **arrêter de force cmd.exe** **avant** que nous obtenions un **dump de mémoire**, il y a encore de bonnes chances de **récupérer l'historique** de la session de ligne de commande à partir de la **mémoire de conhost.exe**. Si vous trouvez quelque chose de **bizarre** (en utilisant les modules de la console), essayez de **dump** la **mémoire** du processus associé à **conhost.exe** et **recherchez** des **chaînes de caractères** à l'intérieur pour extraire les lignes de commande.

### Environnement

Obtenez les variables d'environnement de chaque processus en cours d'exécution. Il pourrait y avoir des valeurs intéressantes.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% onglet title="vol2" %}
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

{% onglet title="vol2" %}
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

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### Poignées

Utile pour savoir à quels autres fichiers, clés, threads, processus... un **processus a une poignée** (a ouvert)
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### DLLs

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.raw imageinfo** : Affiche les informations générales sur l'image mémoire.
- **volatility -f dump.raw pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.raw psscan** : Analyse tous les processus.
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.raw dlllist -p PID** : Liste les DLL chargées par un processus spécifique.
- **volatility -f dump.raw filescan** : Analyse les fichiers ouverts par les processus.
- **volatility -f dump.raw cmdline -p PID** : Affiche la ligne de commande d'un processus.
- **volatility -f dump.raw netscan** : Analyse les connexions réseau.
- **volatility -f dump.raw connections** : Affiche les connexions réseau.
- **volatility -f dump.raw malfind** : Recherche de code malveillant dans les processus.
- **volatility -f dump.raw cmdline** : Affiche les lignes de commande des processus.
- **volatility -f dump.raw consoles** : Affiche les consoles des processus.
- **volatility -f dump.raw hivelist** : Liste les hives du registre.
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les valeurs d'une clé de registre.
- **volatility -f dump.raw userassist** : Affiche les entrées UserAssist.
- **volatility -f dump.raw shimcache** : Affiche les entrées ShimCache.
- **volatility -f dump.raw ldrmodules** : Affiche les modules chargés par les processus.
- **volatility -f dump.raw modscan** : Analyse les modules du noyau.
- **volatility -f dump.raw getsids** : Affiche les SID des processus.
- **volatility -f dump.raw apihooks** : Recherche les hooks API dans les processus.
- **volatility -f dump.raw mutantscan** : Analyse les objets mutant.
- **volatility -f dump.raw driverirp** : Affiche les IRP des pilotes.
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques.
- **volatility -f dump.raw svcscan** : Analyse les services.
- **volatility -f dump.raw svcscan --verbose** : Analyse les services en mode verbeux.
- **volatility -f dump.raw envars** : Affiche les variables d'environnement des processus.
- **volatility -f dump.raw atomscan** : Analyse les atomes des processus.
- **volatility -f dump.raw callbacks** : Affiche les callbacks des processus.
- **volatility -f dump.raw idt** : Affiche la table des descripteurs d'interruption.
- **volatility -f dump.raw gdt** : Affiche la table des descripteurs globaux.
- **volatility -f dump.raw threads** : Affiche les threads des processus.
- **volatility -f dump.raw handles** : Affiche les handles des processus.
- **volatility -f dump.raw mutantscan** : Analyse les objets mutant.
- **volatility -f dump.raw driverirp** : Affiche les IRP des pilotes.
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques.
- **volatility -f dump.raw svcscan** : Analyse les services.
- **volatility -f dump.raw svcscan --verbose** : Analyse les services en mode verbeux.
- **volatility -f dump.raw envars** : Affiche les variables d'environnement des processus.
- **volatility -f dump.raw atomscan** : Analyse les atomes des processus.
- **volatility -f dump.raw callbacks** : Affiche les callbacks des processus.
- **volatility -f dump.raw idt** : Affiche la table des descripteurs d'interruption.
- **volatility -f dump.raw gdt** : Affiche la table des descripteurs globaux.
- **volatility -f dump.raw threads** : Affiche les threads des processus.
- **volatility -f dump.raw handles** : Affiche les handles des processus.

### Plugins supplémentaires

- **volatility -f dump.raw shimcachemem** : Analyse le cache de compatibilité des applications.
- **volatility -f dump.raw mftparser** : Analyse la table de fichiers maîtres (MFT).
- **volatility -f dump.raw dumpfiles -Q OFFSET -D dump_dir/** : Extrait les fichiers en mémoire.
- **volatility -f dump.raw dumpregistry -o OFFSET -D dump_dir/** : Extrait une ruche de registre en mémoire.
- **volatility -f dump.raw yarascan -Y "rule_file"** : Recherche de motifs avec Yara.
- **volatility -f dump.raw memdump -p PID -D dump_dir/** : Effectue un vidage mémoire d'un processus spécifique.
- **volatility -f dump.raw memmap --profile=PROFILE** : Affiche la carte mémoire.
- **volatility -f dump.raw memmap --profile=PROFILE -p PID** : Affiche la carte mémoire d'un processus spécifique.
- **volatility -f dump.raw memstrings -p PID** : Recherche de chaînes dans l'espace mémoire d'un processus.
- **volatility -f dump.raw memdump --profile=PROFILE -p PID -D dump_dir/** : Effectue un vidage mémoire d'un processus spécifique avec un profil spécifique.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### Chaînes par processus

Volatility nous permet de vérifier à quel processus appartient une chaîne.
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% onglet title="vol2" %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
Il permet également de rechercher des chaînes de caractères à l'intérieur d'un processus en utilisant le module yarascan :
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

Les systèmes **Windows** conservent un ensemble de **clés** dans la base de registre (**clés UserAssist**) pour suivre les programmes qui sont exécutés. Le nombre d'exécutions et la date et l'heure de la dernière exécution sont disponibles dans ces **clés**.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% onglet title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) est l'événement le plus pertinent en matière de cybersécurité en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

## Services

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% onglet title="vol2" %}
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

{% onglet title="vol2" %}
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
## Registre de ruche

### Afficher les ruches disponibles

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### Obtenir une valeur

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- `volatility -f <dumpfile> imageinfo` : Informations sur l'image mémoire
- `volatility -f <dumpfile> pslist` : Liste des processus en cours d'exécution
- `volatility -f <dumpfile> pstree` : Arborescence des processus
- `volatility -f <dumpfile> psscan` : Analyse des processus
- `volatility -f <dumpfile> dlllist -p <pid>` : Liste des DLL chargées par un processus
- `volatility -f <dumpfile> cmdline -p <pid>` : Ligne de commande d'un processus
- `volatility -f <dumpfile> filescan` : Analyse des fichiers ouverts
- `volatility -f <dumpfile> netscan` : Analyse des connexions réseau
- `volatility -f <dumpfile> connections` : Liste des connexions réseau
- `volatility -f <dumpfile> timeliner` : Ligne temporelle des activités
- `volatility -f <dumpfile> malfind` : Recherche de code malveillant
- `volatility -f <dumpfile> apihooks` : Recherche de hooks API
- `volatility -f <dumpfile> ldrmodules` : Modules chargés par le loader
- `volatility -f <dumpfile> modscan` : Analyse des modules du kernel
- `volatility -f <dumpfile> ssdt` : Table des services du système
- `volatility -f <dumpfile> callbacks` : Liste des callbacks
- `volatility -f <dumpfile> driverirp` : Analyse des IRP des drivers
- `volatility -f <dumpfile> devicetree` : Arborescence des périphériques
- `volatility -f <dumpfile> hivelist` : Liste des hives de registre
- `volatility -f <dumpfile> printkey -o <offset>` : Affichage du contenu d'une clé de registre
- `volatility -f <dumpfile> userassist` : Analyse des entrées UserAssist
- `volatility -f <dumpfile> shimcache` : Analyse du cache de compatibilité des applications
- `volatility -f <dumpfile> getsids` : Liste des SID des utilisateurs
- `volatility -f <dumpfile> getservicesids` : Liste des SID des services
- `volatility -f <dumpfile> getsids` : Liste des SID des utilisateurs
- `volatility -f <dumpfile> getservicesids` : Liste des SID des services
- `volatility -f <dumpfile> envars` : Variables d'environnement
- `volatility -f <dumpfile> consoles` : Liste des consoles
- `volatility -f <dumpfile> deskscan` : Analyse des objets de bureau
- `volatility -f <dumpfile> hivescan` : Analyse des hives de registre
- `volatility -f <dumpfile> userhandles` : Liste des handles utilisateur
- `volatility -f <dumpfile> mutantscan` : Analyse des mutants
- `volatility -f <dumpfile> svcscan` : Analyse des services
- `volatility -f <dumpfile> yarascan --yara-file=<rules> --yara-rules=<rules>` : Analyse Yara
- `volatility -f <dumpfile> dumpfiles -Q <address>` : Extraction de fichiers en mémoire
- `volatility -f <dumpfile> dumpfiles -D <output_directory>` : Extraction de tous les fichiers en mémoire
- `volatility -f <dumpfile> dumpfiles -Q <address> -D <output_directory>` : Extraction de fichiers spécifiques en mémoire
- `volatility -f <dumpfile> memdump -p <pid> -D <output_directory>` : Extraction de l'espace mémoire d'un processus
- `volatility -f <dumpfile> memdump --profile=<profile> -p <pid> -D <output_directory>` : Extraction de l'espace mémoire d'un processus avec un profil spécifique
- `volatility -f <dumpfile> memmap` : Cartographie de l'espace mémoire
- `volatility -f <dumpfile> memmap --profile=<profile>` : Cartographie de l'espace mémoire avec un profil spécifique
- `volatility -f <dumpfile> memmap --dump-dir=<output_directory>` : Cartographie de l'espace mémoire avec sauvegarde des données
- `volatility -f <dumpfile> memdump --dump-dir=<output_directory>` : Extraction de l'ensemble de l'espace mémoire
- `volatility -f <dumpfile> memdump --dump-dir=<output_directory> --name=<filename>` : Extraction de l'ensemble de l'espace mémoire avec un nom de fichier spécifique
- `volatility -f <dumpfile> memdump --dump-dir=<output_directory> --name=<filename> --pid=<pid>` : Extraction de l'espace mémoire d'un processus avec un nom de fichier spécifique
- `volatility -f <dumpfile> memdump --dump-dir=<output_directory> --name=<filename> --profile=<profile> --pid=<pid>` : Extraction de l'espace mémoire d'un processus avec un profil spécifique et un nom de fichier spécifique

### Plugins supplémentaires

- **Volatility** propose de nombreux autres plugins pour l'analyse de la mémoire. Vous pouvez les trouver dans la documentation officielle de Volatility.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### Vidage
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Système de fichiers

### Monter

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %} 

### Feuille de triche Volatility

#### Commandes de base

- **volatility -f dump.mem imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.mem --profile=PROFILE pslist** : Liste des processus
- **volatility -f dump.mem --profile=PROFILE psscan** : Analyse des processus
- **volatility -f dump.mem --profile=PROFILE pstree** : Arborescence des processus
- **volatility -f dump.mem --profile=PROFILE dlllist -p PID** : Liste des DLL chargées par un processus
- **volatility -f dump.mem --profile=PROFILE cmdline -p PID** : Ligne de commande d'un processus
- **volatility -f dump.mem --profile=PROFILE filescan** : Analyse des fichiers ouverts
- **volatility -f dump.mem --profile=PROFILE netscan** : Analyse des connexions réseau
- **volatility -f dump.mem --profile=PROFILE connections** : Connexions réseau
- **volatility -f dump.mem --profile=PROFILE consoles** : Informations sur les consoles
- **volatility -f dump.mem --profile=PROFILE getsids** : Liste des SID
- **volatility -f dump.mem --profile=PROFILE hivelist** : Liste des hives
- **volatility -f dump.mem --profile=PROFILE hashdump** : Dump des mots de passe en mémoire
- **volatility -f dump.mem --profile=PROFILE userassist** : Informations sur les programmes utilisés
- **volatility -f dump.mem --profile=PROFILE malfind** : Recherche de processus suspects
- **volatility -f dump.mem --profile=PROFILE shimcache** : Analyse du cache de compatibilité des applications
- **volatility -f dump.mem --profile=PROFILE ldrmodules** : Modules chargés par les processus
- **volatility -f dump.mem --profile=PROFILE modscan** : Analyse des modules noyau
- **volatility -f dump.mem --profile=PROFILE ssdt** : Table des services du noyau
- **volatility -f dump.mem --profile=PROFILE callbacks** : Liste des callbacks du noyau
- **volatility -f dump.mem --profile=PROFILE driverirp** : Analyse des IRP des pilotes
- **volatility -f dump.mem --profile=PROFILE devicetree** : Arborescence des périphériques
- **volatility -f dump.mem --profile=PROFILE filescan** : Analyse des fichiers ouverts
- **volatility -f dump.mem --profile=PROFILE mutantscan** : Analyse des objets de synchronisation
- **volatility -f dump.mem --profile=PROFILE threads** : Liste des threads
- **volatility -f dump.mem --profile=PROFILE handles** : Liste des handles
- **volatility -f dump.mem --profile=PROFILE vadinfo -p PID** : Informations sur les espaces d'adressage virtuel d'un processus
- **volatility -f dump.mem --profile=PROFILE vadtree -p PID** : Arborescence des espaces d'adressage virtuel d'un processus
- **volatility -f dump.mem --profile=PROFILE vadwalk -p PID** : Parcours des espaces d'adressage virtuel d'un processus
- **volatility -f dump.mem --profile=PROFILE dlldump -p PID -D /path/to/dump/dir/** : Extraction des DLL d'un processus
- **volatility -f dump.mem --profile=PROFILE procdump -p PID -D /path/to/dump/dir/** : Extraction de l'espace mémoire d'un processus
- **volatility -f dump.mem --profile=PROFILE memdump -p PID -D /path/to/dump/dir/** : Extraction de la mémoire d'un processus
- **volatility -f dump.mem --profile=PROFILE memmap** : Cartographie de la mémoire
- **volatility -f dump.mem --profile=PROFILE memstrings** : Recherche de chaînes dans la mémoire
- **volatility -f dump.mem --profile=PROFILE memdump --dump-dir=/path/to/dump/dir/** : Extraction de toute la mémoire
- **volatility -f dump.mem --profile=PROFILE dumpfiles -Q 0xADDRESS -D /path/to/dump/dir/** : Extraction de fichiers en mémoire
- **volatility -f dump.mem --profile=PROFILE dumpregistry -D /path/to/dump/dir/** : Extraction de la base de registre en mémoire
- **volatility -f dump.mem --profile=PROFILE dumpcerts -D /path/to/dump/dir/** : Extraction des certificats en mémoire
- **volatility -f dump.mem --profile=PROFILE dumpcache -D /path/to/dump/dir/** : Extraction du cache en mémoire
- **volatility -f dump.mem --profile=PROFILE dumpfiles -Q 0xADDRESS -D /path/to/dump/dir/** : Extraction de fichiers en mémoire
- **volatility -f dump.mem --profile=PROFILE dumpregistry -D /path/to/dump/dir/** : Extraction de la base de registre en mémoire
- **volatility -f dump.mem --profile=PROFILE dumpcerts -D /path/to/dump/dir/** : Extraction des certificats en mémoire
- **volatility -f dump.mem --profile=PROFILE dumpcache -D /path/to/dump/dir/** : Extraction du cache en mémoire

#### Plugins supplémentaires

- **volatility -f dump.mem --profile=PROFILE mimikatz** : Utilisation du plugin Mimikatz
- **volatility -f dump.mem --profile=PROFILE truecryptpassphrase** : Récupération des mots de passe TrueCrypt
- **volatility -f dump.mem --profile=PROFILE hashdump** : Dump des mots de passe en mémoire
- **volatility -f dump.mem --profile=PROFILE hivelist** : Liste des hives
- **volatility -f dump.mem --profile=PROFILE printkey -o "REGISTRY_PATH"** : Affichage du contenu d'une clé de registre
- **voljson -f dump.mem --profile=PROFILE pslist** : Exporter la liste des processus au format JSON
- **volatility -f dump.mem --profile=PROFILE pstotal** : Calculer le nombre total de processus
- **volatility -f dump.mem --profile=PROFILE pstotal --pid=PID** : Calculer le nombre de processus pour un PID spécifique
- **volatility -f dump.mem --profile=PROFILE psscan --output-file=/path/to/output.txt** : Sauvegarder la sortie dans un fichier
- **volatility -f dump.mem --profile=PROFILE psscan --output=dot --output-file=/path/to/output.dot** : Générer un graphe des processus
- **volatility -f dump.mem --profile=PROFILE psscan --output=html --output-file=/path/to/output.html** : Générer un rapport HTML des processus
- **volatility -f dump.mem --profile=PROFILE psscan --output=json --output-file=/path/to/output.json** : Exporter les résultats au format JSON
- **volatility -f dump.mem --profile=PROFILE psscan --pid=PID** : Analyser un processus spécifique
- **volatility -f dump.mem --profile=PROFILE psscan --pname=PROCESS_NAME** : Analyser un processus par nom
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output/dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output/dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output/dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output/dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output/dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output/dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan-dir=/path/to/output.dir/** : Sauvegarder les résultats dans un répertoire
- **volatility -f dump.mem --profile=PROFILE psscan --psscan
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}

### Analyse de la mémoire

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### Tableau de maître de fichiers

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

Le système de fichiers NTFS contient un fichier appelé la _table des fichiers principaux_, ou MFT. Il y a au moins une entrée dans le MFT pour chaque fichier sur un volume de système de fichiers NTFS, y compris le MFT lui-même. **Toutes les informations sur un fichier, y compris sa taille, ses horodatages, ses autorisations et son contenu de données**, sont stockées soit dans les entrées du MFT, soit dans l'espace en dehors du MFT qui est décrit par les entrées du MFT. À partir de [ici](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Clés/Certificats SSL
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="vol2" %} 

### Feuille de triche Volatility

#### Commandes de base

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil commandes_volatility**

#### Analyse de la mémoire

- **volatility.exe -f chemin_vers_le_fichier_memoire imageinfo**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil pslist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil pstree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil psscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil dlllist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil getsids**

#### Extraction de processus

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil procdump -p PID -D dossier_destination**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil memdump -p PID -D dossier_destination**

#### Analyse des connexions réseau

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil connscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil netscan**

#### Analyse du Registre

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil hivelist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil printkey -o "REGISTRY_PATH"**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil hashdump**

#### Analyse des fichiers

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil filescan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil dumpfiles -Q "REGEX" -D dossier_destination**

#### Analyse des tâches planifiées

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil cmdline**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil consoles**

#### Analyse des pilotes

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil modules**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil modscan**

#### Analyse des services

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil services**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan --start=SERVICE_START_OFFSET**

#### Analyse des connexions réseau

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil connscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil netscan**

#### Analyse des tâches planifiées

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil cmdline**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil consoles**

#### Analyse des pilotes

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil modules**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil modscan**

#### Analyse des services

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil services**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan --start=SERVICE_START_OFFSET**

{% endtab %}
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

{% onglet title="vol2" %}
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
{% endtabs %}

### Analyse de la mémoire avec Volatility

Utilisez ce script pour télécharger et fusionner toutes les règles de logiciels malveillants yara depuis github : [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Créez le répertoire _**rules**_ et exécutez-le. Cela créera un fichier appelé _**malware\_rules.yar**_ qui contient toutes les règles yara pour les logiciels malveillants.
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

{% onglet title="vol2" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## DIVERS

### Plugins externes

Si vous souhaitez utiliser des plugins externes, assurez-vous que les dossiers liés aux plugins sont le premier paramètre utilisé.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% onglet title="vol2" %}
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

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% onglet title="vol2" %}
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

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

Il est possible de **lire l'historique de bash en mémoire.** Vous pourriez également extraire le fichier _.bash\_history_, mais s'il est désactivé, vous serez heureux de pouvoir utiliser ce module de volatilité
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %} 

### Feuille de triche Volatility

#### Commandes de base

- **volatility -f dump.mem imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.mem pslist** : Liste des processus en cours d'exécution
- **volatility -f dump.mem pstree** : Arborescence des processus
- **volatility -f dump.mem psscan** : Analyse des processus
- **volatility -f dump.mem dlllist -p PID** : Liste des DLL chargées par un processus
- **volatility -f dump.mem filescan** : Analyse des fichiers ouverts
- **volatility -f dump.mem cmdscan** : Analyse des commandes exécutées
- **volatility -f dump.mem connections** : Liste des connexions réseau
- **volatility -f dump.mem netscan** : Analyse des connexions réseau
- **volatility -f dump.mem malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.mem yarascan** : Analyse avec Yara
- **volatility -f dump.mem dumpfiles -Q 0xADDRESS -D /path/to/dump/** : Extraction de fichiers à partir de l'adresse mémoire spécifiée
- **volatility -f dump.mem cmdline -p PID** : Affichage de la ligne de commande d'un processus
- **volatility -f dump.mem consoles** : Liste des consoles interactives
- **volatility -f dump.mem hivelist** : Liste des hives de registre
- **volatility -f dump.mem printkey -o OFFSET** : Affichage du contenu d'une clé de registre
- **volatility -f dump.mem userassist** : Analyse des éléments UserAssist
- **volatility -f dump.mem shimcache** : Analyse du cache de compatibilité des applications
- **volatility -f dump.mem ldrmodules** : Liste des modules chargés
- **volatility -f dump.mem modscan** : Analyse des modules
- **volatility -f dump.mem getsids** : Affichage des SID des processus
- **volatility -f dump.mem getservicesids** : Affichage des SID des services
- **volatility -f dump.mem svcscan** : Analyse des services
- **volatility -f dump.mem driverirp** : Analyse des pilotes et des IRP
- **volatility -f dump.mem callbacks** : Analyse des callbacks
- **volatility -f dump.mem mutantscan** : Analyse des mutants
- **volatility -f dump.mem envars** : Affichage des variables d'environnement
- **volatility -f dump.mem atomscan** : Analyse des atom tables
- **volatility -f dump.mem deskscan** : Analyse des objets de bureau
- **volatility -f dump.mem hivescan** : Analyse des hives de registre
- **volatility -f dump.mem userhandles** : Analyse des handles utilisateur
- **volatility -f dump.mem vadinfo -p PID** : Informations sur les zones d'allocation virtuelle d'un processus
- **volatility -f dump.mem vadtree -p PID** : Arborescence des zones d'allocation virtuelle d'un processus
- **volatility -f dump.mem vadwalk -p PID -A StartAddress** : Parcours des zones d'allocation virtuelle à partir d'une adresse spécifique
- **volatility -f dump.mem dlldump -p PID -D /path/to/dump/** : Extraction d'une DLL à partir de l'espace mémoire d'un processus
- **volatility -f dump.mem memmap** : Cartographie de la mémoire physique
- **volatility -f dump.mem memdump -p PID -D /path/to/dump/** : Extraction de l'espace mémoire d'un processus
- **volatility -f dump.mem memstrings -p PID** : Recherche de chaînes dans l'espace mémoire d'un processus
- **volatility -f dump.mem malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.mem malfind -p PID** : Recherche de code malveillant dans un processus spécifique
- **volatility -f dump.mem malfind -D /path/to/dump/** : Recherche de code malveillant dans tous les processus
- **volatility -f dump.mem malfind -p PID -D /path/to/dump/** : Recherche de code malveillant dans un processus spécifique et extraction des fichiers
- **volatility -f dump.mem malfind -D /path/to/dump/ --profile=PROFILE** : Recherche de code malveillant en spécifiant un profil
- **volatility -f dump.mem malfind --output=html -D /path/to/dump/** : Générer un rapport HTML de l'analyse de code malveillant
- **volatility -f dump.mem malfind --output=json -D /path/to/dump/** : Générer un rapport JSON de l'analyse de code malveillant
- **volatility -f dump.mem malfind --output=body -D /path/to/dump/** : Générer un rapport texte de l'analyse de code malveillant
- **volatility -f dump.mem malfind --output=body --output-file=/path/to/output.txt -D /path/to/dump/** : Enregistrer le rapport texte de l'analyse de code malveillant dans un fichier spécifié
- **volatility -f dump.mem malfind --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/** : Enregistrer le rapport texte de l'analyse de code malveillant en spécifiant un profil
- **volatility -f dump.mem malfind --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=malware** : Enregistrer le rapport texte de l'analyse de code malveillant en spécifiant un profil et un nom de fichier
- **volatility -f dump.mem malfind --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=malware --dump-dir=/path/to/dump_dir/** : Enregistrer le rapport texte de l'analyse de code malveillant en spécifiant un profil, un nom de fichier et un répertoire d'extraction
- **volatility -f dump.mem malfind --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=malware --dump-dir=/path/to/dump_dir/ --dump** : Extraire les fichiers malveillants identifiés
- **volatility -f dump.mem malfind --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=malware --dump-dir=/path/to/dump_dir/ --dump --dump-dir=/path/to/dump_dir2/** : Extraire les fichiers malveillants identifiés dans un répertoire spécifié
- **volatility -f dump.mem malfind --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=malware --dump-dir=/path/to/dump_dir/ --dump --dump-dir=/path/to/dump_dir2/ --dump** : Extraire les fichiers malveillants identifiés dans un répertoire spécifié et les enregistrer dans un répertoire d'extraction
- **volatility -f dump.mem malfind --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=malware --dump-dir=/path/to/dump_dir/ --dump --dump-dir=/path/to/dump_dir2/ --dump --dump-dir=/path/to/dump_dir3/** : Extraire les fichiers malveillants identifiés dans plusieurs répertoires spécifiés
- **volatility -f dump.mem malfind --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=malware --dump-dir=/path/to/dump_dir/ --dump --dump-dir=/path/to/dump_dir2/ --dump --dump-dir=/path/to/dump_dir3/ --dump** : Extraire les fichiers malveillants identifiés dans plusieurs répertoires spécifiés et les enregistrer dans un répertoire d'extraction

#### Plugins supplémentaires

- **volatility -f dump.mem shimcachemem** : Analyse du cache de compatibilité des applications en mémoire
- **volatility -f dump.mem shimcachemem -D /path/to/dump/** : Extraction du cache de compatibilité des applications en mémoire
- **volatility -f dump.mem shimcachemem --output=html -D /path/to/dump/** : Générer un rapport HTML de l'analyse du cache de compatibilité des applications en mémoire
- **volatility -f dump.mem shimcachemem --output=json -D /path/to/dump/** : Générer un rapport JSON de l'analyse du cache de compatibilité des applications en mémoire
- **volatility -f dump.mem shimcachemem --output=body -D /path/to/dump/** : Générer un rapport texte de l'analyse du cache de compatibilité des applications en mémoire
- **volatility -f dump.mem shimcachemem --output=body --output-file=/path/to/output.txt -D /path/to/dump/** : Enregistrer le rapport texte de l'analyse du cache de compatibilité des applications en mémoire dans un fichier spécifié
- **volatility -f dump.mem shimcachemem --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/** : Enregistrer le rapport texte de l'analyse du cache de compatibilité des applications en mémoire en spécifiant un profil
- **volatility -f dump.mem shimcachemem --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=shimcache** : Enregistrer le rapport texte de l'analyse du cache de compatibilité des applications en mémoire en spécifiant un profil et un nom de fichier
- **volatility -f dump.mem shimcachemem --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=shimcache --dump-dir=/path/to/dump_dir/** : Enregistrer le rapport texte de l'analyse du cache de compatibilité des applications en mémoire en spécifiant un profil, un nom de fichier et un répertoire d'extraction
- **volatility -f dump.mem shimcachemem --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=shimcache --dump-dir=/path/to/dump_dir/ --dump** : Extraire les fichiers du cache de compatibilité des applications identifiés en mémoire
- **volatility -f dump.mem shimcachemem --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=shimcache --dump-dir=/path/to/dump_dir/ --dump --dump-dir=/path/to/dump_dir2/** : Extraire les fichiers du cache de compatibilité des applications identifiés en mémoire dans un répertoire spécifié
- **volatility -f dump.mem shimcachemem --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=shimcache --dump-dir=/path/to/dump_dir/ --dump --dump-dir=/path/to/dump_dir2/ --dump** : Extraire les fichiers du cache de compatibilité des applications identifiés en mémoire dans un répertoire spécifié et les enregistrer dans un répertoire d'extraction
- **volatility -f dump.mem shimcachemem --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=shimcache --dump-dir=/path/to/dump_dir/ --dump --dump-dir=/path/to/dump_dir2/ --dump --dump-dir=/path/to/dump_dir3/** : Extraire les fichiers du cache de compatibilité des applications identifiés en mémoire dans plusieurs répertoires spécifiés
- **volatility -f dump.mem shimcachemem --output=body --output-file=/path/to/output.txt --profile=PROFILE -D /path/to/dump/ --name=shimcache --dump-dir=/path/to/dump_dir/ --dump --dump-dir=/path/to/dump_dir2/ --dump --dump-dir=/path/to/dump_dir3/ --dump** : Extraire les fichiers du cache de compatibilité des applications identifiés en mémoire dans plusieurs répertoires spécifiés et les enregistrer dans un répertoire d'extraction

{% endtab %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### Chronologie

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% onglet title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### Pilotes

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% onglet title="vol2" %}
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
### Obtenir l'historique d'IE
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
```
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
Le MBR contient les informations sur la façon dont les partitions logiques, contenant [les systèmes de fichiers](https://fr.wikipedia.org/wiki/Syst%C3%A8me_de_fichiers), sont organisées sur ce support. Le MBR contient également un code exécutable pour fonctionner en tant que chargeur pour le système d'exploitation installé, généralement en passant le contrôle au [deuxième étage](https://fr.wikipedia.org/wiki/Chargeur_d%C3%A9tape_deux) du chargeur, ou en conjonction avec le [registre d'amorçage de volume](https://fr.wikipedia.org/wiki/Registre_d%27amor%C3%A7age_de_volume) (VBR) de chaque partition. Ce code MBR est généralement appelé un [chargeur d'amorçage](https://fr.wikipedia.org/wiki/Chargeur_d%27amor%C3%A7age). De [ici](https://fr.wikipedia.org/wiki/Enregistrement_de_d%C3%A9marrage_principal).

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement le plus pertinent en matière de cybersécurité en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
