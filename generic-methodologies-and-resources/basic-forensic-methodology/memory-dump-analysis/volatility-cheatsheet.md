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

Les plugins "scan", en revanche, adopteront une approche similaire à celle de la recherche dans la mémoire d'éléments qui pourraient avoir un sens lorsqu'ils sont déréférencés en tant que structures spécifiques. Par exemple, `psscan` lira la mémoire et essaiera de créer des objets `_EPROCESS` à partir de celle-ci (il utilise la recherche de balises de pool, qui consiste à rechercher des chaînes de 4 octets indiquant la présence d'une structure d'intérêt). L'avantage est qu'il peut retrouver des processus qui ont été arrêtés, et même si un logiciel malveillant altère la liste chaînée `_EPROCESS`, le plugin trouvera toujours la structure qui traîne en mémoire (car elle doit toujours exister pour que le processus s'exécute). L'inconvénient est que les plugins "scan" sont un peu plus lents que les plugins "list", et peuvent parfois donner des faux positifs (un processus qui s'est arrêté il y a trop longtemps et dont certaines parties de la structure ont été écrasées par d'autres opérations).

Source : [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

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
Si vous souhaitez utiliser un **nouveau profil que vous avez téléchargé** (par exemple un profil Linux), vous devez créer quelque part la structure de dossier suivante : _plugins/overlays/linux_ et placer à l'intérieur de ce dossier le fichier zip contenant le profil. Ensuite, obtenez le nombre de profils en utilisant :
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

[**À partir d'ici**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Contrairement à imageinfo qui fournit simplement des suggestions de profil, **kdbgscan** est conçu pour identifier positivement le bon profil et la bonne adresse KDBG (s'il y en a plusieurs). Ce plugin recherche les signatures KDBGHeader liées aux profils de Volatility et applique des vérifications de cohérence pour réduire les faux positifs. La verbosité de la sortie et le nombre de vérifications de cohérence pouvant être effectuées dépendent de la capacité de Volatility à trouver un DTB, donc si vous connaissez déjà le bon profil (ou si vous avez une suggestion de profil à partir de imageinfo), assurez-vous de l'utiliser à partir de .

Jetez toujours un œil au **nombre de processus trouvés par kdbgscan**. Parfois, imageinfo et kdbgscan peuvent trouver **plus d'un** profil **approprié**, mais seul le **bon aura des processus associés** (Cela est dû au fait que pour extraire des processus, l'adresse KDBG correcte est nécessaire)
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

Le **bloc de débogage du noyau**, appelé **KDBG** par Volatility, est crucial pour les tâches forensiques effectuées par Volatility et divers débogueurs. Identifié sous le nom de `KdDebuggerDataBlock` et du type `_KDDEBUGGER_DATA64`, il contient des références essentielles telles que `PsActiveProcessHead`. Cette référence spécifique pointe vers la tête de la liste des processus, permettant ainsi l'énumération de tous les processus, ce qui est fondamental pour une analyse approfondie de la mémoire.

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

Le vidage de la mémoire d'un processus extraira tout de l'état actuel du processus. Le module **procdump** extraira uniquement le **code**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) est l'événement le plus pertinent en matière de cybersécurité en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

## Processes

### List processes

Essayez de trouver des processus **suspects** (par leur nom) ou des **processus** enfants **inattendus** (par exemple un cmd.exe en tant que processus enfant de iexplorer.exe).\
Il pourrait être intéressant de **comparer** le résultat de pslist avec celui de psscan pour identifier les processus cachés.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% onglet title="vol2" %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}

### Analyse du dump de la mémoire

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.mem imageinfo** : Affiche des informations générales sur l'image mémoire
- **volatility -f dump.mem pslist** : Liste les processus en cours d'exécution
- **volatility -f dump.mem pstree** : Affiche les processus sous forme d'arborescence
- **volatility -f dump.mem psscan** : Recherche les processus supprimés
- **volatility -f dump.mem dlllist -p PID** : Liste les DLL chargées par un processus spécifique
- **volatility -f dump.mem filescan** : Recherche les fichiers ouverts par les processus
- **volatility -f dump.mem cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique
- **volatility -f dump.mem netscan** : Recherche les connexions réseau
- **volatility -f dump.mem connections** : Affiche les connexions réseau
- **volatility -f dump.mem timeliner** : Crée une timeline des activités du système
- **volatility -f dump.mem malfind** : Recherche les indicateurs de programmes malveillants
- **volatility -f dump.mem apihooks** : Recherche les hooks API
- **volatility -f dump.mem ldrmodules** : Liste les modules chargés dynamiquement
- **volatility -f dump.mem modscan** : Recherche les modules noyau
- **volatility -f dump.mem ssdt** : Affiche la table de service du système
- **volatility -f dump.mem callbacks** : Affiche les callbacks du noyau
- **volatility -f dump.mem driverirp** : Affiche les IRP des pilotes
- **volatility -f dump.mem devicetree** : Affiche l'arborescence des périphériques
- **volatility -f dump.mem hivelist** : Liste les hives de registre
- **volatility -f dump.mem printkey -o OFFSET** : Affiche les valeurs d'une clé de registre
- **volatility -f dump.mem userassist** : Affiche les entrées UserAssist
- **volatility -f dump.mem shimcache** : Affiche les entrées ShimCache
- **volatility -f dump.mem getsids** : Affiche les SID des processus
- **volatility -f dump.mem getservicesids** : Affiche les SID des services
- **volatility -f dump.mem getsids -p PID** : Affiche les SID d'un processus spécifique
- **volatility -f dump.mem hivescan** : Recherche les hives de registre non montés
- **volatility -f dump.mem hashdump** : Dump les mots de passe en clair
- **volatility -f dump.mem truecryptpassphrase** : Récupère les passphrases TrueCrypt
- **volatility -f dump.mem mimikatz** : Exécute Mimikatz sur l'image mémoire
- **volatility -f dump.mem yarascan -Y "/path/to/rules"** : Recherche des indicateurs avec Yara
- **volatility -f dump.mem envars** : Affiche les variables d'environnement
- **volatility -f dump.mem consoles** : Affiche les consoles interactives
- **volatility -f dump.mem consoles -p PID** : Affiche les consoles d'un processus spécifique
- **volatility -f dump.mem deskscan** : Recherche les objets de bureau
- **volatility -f dump.mem vadinfo -p PID** : Affiche les informations VAD d'un processus spécifique
- **volatility -f dump.mem vadtree -p PID** : Affiche l'arborescence VAD d'un processus spécifique
- **volatility -f dump.mem mutantscan** : Recherche les objets mutant
- **volatility -f dump.mem mutantscan -s** : Recherche les objets mutant partagés
- **volatility -f dump.mem ldrmodules -p PID** : Liste les modules chargés par un processus spécifique
- **volatility -f dump.mem malfind -p PID** : Recherche les indicateurs de programmes malveillants pour un processus spécifique
- **volatility -f dump.mem mftparser -o OFFSET** : Analyse le Master File Table (MFT)
- **volatility -f dump.mem shimcachemem -s** : Recherche les entrées ShimCache dans l'espace mémoire
- **volatility -f dump.mem shimcachemem -l** : Recherche les entrées ShimCache dans l'espace mémoire non alloué
- **volatility -f dump.mem shimcachemem -a** : Recherche les entrées ShimCache dans tous les espaces mémoire
- **volatility -f dump.mem shimcachemem -c** : Recherche les entrées ShimCache dans les espaces mémoire alloués
- **volatility -f dump.mem shimcachemem -u** : Recherche les entrées ShimCache dans les espaces mémoire non alloués
- **volatility -f dump.mem shimcachemem -r** : Recherche les entrées ShimCache dans les espaces mémoire réservés
- **volatility -f dump.mem shimcachemem -w** : Recherche les entrées ShimCache dans les espaces mémoire écrits
- **volatility -f dump.mem shimcachemem -x** : Recherche les entrées ShimCache dans les espaces mémoire non écrits
- **volatility -f dump.mem shimcachemem -m** : Recherche les entrées ShimCache dans les espaces mémoire modifiés
- **volatility -f dump.mem shimcachemem -n** : Recherche les entrées ShimCache dans les espaces mémoire non modifiés
- **volatility -f dump.mem shimcachemem -i** : Recherche les entrées ShimCache dans les espaces mémoire initialisés
- **volatility -f dump.mem shimcachemem -z** : Recherche les entrées ShimCache dans les espaces mémoire non initialisés
- **volatility -f dump.mem shimcachemem -f FILE** : Recherche les entrées ShimCache dans un fichier spécifique
- **volatility -f dump.mem shimcachemem -b** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués
- **volatility -f dump.mem shimcachemem -d** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits
- **volatility -f dump.mem shimcachemem -t** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés
- **volatility -f dump.mem shimcachemem -y** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés
- **volatility -f dump.mem shimcachemem -g** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique
- **volatility -f dump.mem shimcachemem -h** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires
- **volatility -f dump.mem shimcachemem -j** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires et des statistiques
- **volatility -f dump.mem shimcachemem -k** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires, des statistiques et des détails
- **volatility -f dump.mem shimcachemem -q** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires, des statistiques, des détails et des recommandations
- **volatility -f dump.mem shimcachemem -v** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires, des statistiques, des détails, des recommandations et des avertissements
- **volatility -f dump.mem shimcachemem -n** : Recherche les entrées ShimCache dans les espaces mémoire non modifiés
- **volatility -f dump.mem shimcachemem -i** : Recherche les entrées ShimCache dans les espaces mémoire initialisés
- **volatility -f dump.mem shimcachemem -z** : Recherche les entrées ShimCache dans les espaces mémoire non initialisés
- **volatility -f dump.mem shimcachemem -f FILE** : Recherche les entrées ShimCache dans un fichier spécifique
- **volatility -f dump.mem shimcachemem -b** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués
- **volatility -f dump.mem shimcachemem -d** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits
- **volatility -f dump.mem shimcachemem -t** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés
- **volatility -f dump.mem shimcachemem -y** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés
- **volatility -f dump.mem shimcachemem -g** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique
- **volatility -f dump.mem shimcachemem -h** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires
- **volatility -f dump.mem shimcachemem -j** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires et des statistiques
- **volatility -f dump.mem shimcachemem -k** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires, des statistiques et des détails
- **volatility -f dump.mem shimcachemem -q** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires, des statistiques, des détails et des recommandations
- **volatility -f dump.mem shimcachemem -v** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires, des statistiques, des détails, des recommandations et des avertissements
- **volatility -f dump.mem shimcachemem -n** : Recherche les entrées ShimCache dans les espaces mémoire non modifiés
- **volatility -f dump.mem shimcachemem -i** : Recherche les entrées ShimCache dans les espaces mémoire initialisés
- **volatility -f dump.mem shimcachemem -z** : Recherche les entrées ShimCache dans les espaces mémoire non initialisés
- **volatility -f dump.mem shimcachemem -f FILE** : Recherche les entrées ShimCache dans un fichier spécifique
- **volatility -f dump.mem shimcachemem -b** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués
- **volatility -f dump.mem shimcachemem -d** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits
- **volatility -f dump.mem shimcachemem -t** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés
- **volatility -f dump.mem shimcachemem -y** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés
- **volatility -f dump.mem shimcachemem -g** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique
- **volatility -f dump.mem shimcachemem -h** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires
- **volatility -f dump.mem shimcachemem -j** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires et des statistiques
- **volatility -f dump.mem shimcachemem -k** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires, des statistiques et des détails
- **volatility -f dump.mem shimcachemem -q** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires, des statistiques, des détails et des recommandations
- **volatility -f dump.mem shimcachemem -v** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés, initialisés et non initialisés, dans un fichier spécifique, avec des informations supplémentaires, des statistiques, des détails, des recommandations et des avertissements
- **volatility -f dump.mem shimcachemem -n** : Recherche les entrées ShimCache dans les espaces mémoire non modifiés
- **volatility -f dump.mem shimcachemem -i** : Recherche les entrées ShimCache dans les espaces mémoire initialisés
- **volatility -f dump.mem shimcachemem -z** : Recherche les entrées ShimCache dans les espaces mémoire non initialisés
- **volatility -f dump.mem shimcachemem -f FILE** : Recherche les entrées ShimCache dans un fichier spécifique
- **volatility -f dump.mem shimcachemem -b** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués
- **volatility -f dump.mem shimcachemem -d** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits
- **volatility -f dump.mem shimcachemem -t** : Recherche les entrées ShimCache dans les espaces mémoire alloués et non alloués, écrits et non écrits, modifiés et non modifiés
- **volatility -f dump.mem shimcachemem -
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

{% onglet title="vol2" %}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

Les commandes exécutées dans `cmd.exe` sont gérées par **`conhost.exe`** (ou `csrss.exe` sur les systèmes antérieurs à Windows 7). Cela signifie que si **`cmd.exe`** est terminé par un attaquant avant qu'un vidage mémoire ne soit obtenu, il est toujours possible de récupérer l'historique des commandes de la session à partir de la mémoire de **`conhost.exe`**. Pour ce faire, si une activité inhabituelle est détectée dans les modules de la console, la mémoire du processus **`conhost.exe`** associé doit être vidée. Ensuite, en recherchant des **chaînes de caractères** dans ce vidage, les lignes de commande utilisées dans la session peuvent potentiellement être extraites.

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

{% tab title="vol2" %} 

### Feuille de triche Volatility

#### Commandes de base

- **volatility -f dump.raw imageinfo** : Affiche des informations générales sur l'image mémoire.
- **volatility -f dump.raw pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.raw psscan** : Examine les processus inactifs.
- **volatility -f dump.raw dlllist -p PID** : Liste les DLL chargées par un processus spécifique.
- **volatility -f dump.raw cmdscan** : Recherche les commandes exécutées.
- **volatility -f dump.raw filescan** : Recherche les fichiers ouverts par les processus.
- **volatility -f dump.raw netscan** : Affiche les connexions réseau.
- **volatility -f dump.raw connections** : Affiche les connexions réseau.
- **volatility -f dump.raw malfind** : Recherche les injections de code malveillant.
- **volatility -f dump.raw cmdline** : Affiche les lignes de commande des processus.
- **volatility -f dump.raw consoles** : Affiche les consoles des processus.
- **volatility -f dump.raw hivelist** : Liste les hives de registre.
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les valeurs de clé de registre.
- **volatility -f dump.raw userassist** : Affiche les éléments récemment ouverts par l'utilisateur.
- **volatility -f dump.raw shimcache** : Affiche les entrées de la cache de compatibilité des applications.
- **volatility -f dump.raw ldrmodules** : Affiche les modules chargés par les processus.
- **volatility -f dump.raw modscan** : Recherche les modules noyau chargés.
- **volatility -f dump.raw getsids** : Affiche les SID des processus.
- **volatility -f dump.raw getservicesids** : Affiche les SID des services.
- **volatility -f dump.raw svcscan** : Enumère les services.
- **volatility -f dump.raw driverirp** : Affiche les IRP des pilotes.
- **volatility -f dump.raw callbacks** : Affiche les callbacks du noyau.
- **volatility -f dump.raw mutantscan** : Recherche les objets de mutation.
- **volatility -f dump.raw envars** : Affiche les variables d'environnement des processus.
- **volatility -f dump.raw atomscan** : Recherche les objets atomiques.
- **volatility -f dump.raw handles** : Affiche les handles des processus.
- **volatility -f dump.raw vadinfo -p PID** : Affiche les informations VAD d'un processus.
- **volatility -f dump.raw vadtree -p PID** : Affiche l'arborescence VAD d'un processus.
- **volatility -f dump.raw vadwalk -p PID -a ADDRESS** : Affiche les informations VAD à partir d'une adresse.
- **volatility -f dump.raw memmap** : Affiche la carte mémoire.
- **volatility -f dump.raw memdump -p PID -D output_directory** : Effectue un vidage mémoire d'un processus.
- **volatility -f dump.raw memdump -p PID -o OFFSET -D output_directory** : Effectue un vidage mémoire à partir d'une adresse.
- **volatility -f dump.raw memstrings -p PID** : Recherche les chaînes dans l'espace mémoire d'un processus.
- **volatility -f dump.raw memstrings -o OFFSET** : Recherche les chaînes dans l'espace mémoire à partir d'une adresse.
- **volatility -f dump.raw yarascan -Y "rule_file"** : Recherche des motifs YARA dans l'image mémoire.
- **volatility -f dump.raw yarascan -p PID -Y "rule_file"** : Recherche des motifs YARA dans l'espace mémoire d'un processus.
- **volatility -f dump.raw yarascan -f "file_path" -Y "rule_file"** : Recherche des motifs YARA dans un fichier mémoire.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory** : Extrait les fichiers en mémoire à partir d'une adresse.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -n -D output_directory** : Extrait les fichiers en mémoire à partir d'une adresse sans les reconstruire.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -S 0xSIZE -D output_directory** : Extrait les fichiers en mémoire à partir d'une adresse avec une taille spécifiée.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -U -D output_directory** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant l'extension.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -n -U -D output_directory** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant l'extension sans les reconstruire.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -S 0xSIZE -U -D output_directory** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant l'extension avec une taille spécifiée.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -r "regex_pattern"** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant une expression régulière.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -i "file_extension"** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant une extension spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -t "file_type"** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant un type de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -A** : Extrait tous les fichiers en mémoire à partir d'une adresse.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -b "file_basename"** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant un nom de base de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -s "file_size"** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant une taille de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -l "file_location"** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant un emplacement de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -e "file_extension"** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant une extension de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -m "file_magic"** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant une signature magique de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -c "file_count"** : Extrait un nombre spécifié de fichiers en mémoire à partir d'une adresse.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -z** : Extrait les fichiers compressés en mémoire à partir d'une adresse.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -g "file_extension"** : Extrait les fichiers en mémoire à partir d'une adresse en utilisant une extension de fichier générique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -w** : Extrait les fichiers en mémoire à partir d'une adresse en les écrivant dans un fichier.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -x** : Extrait les fichiers en mémoire à partir d'une adresse en les exécutant.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -j "file_path"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant l'extension.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -n** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant l'extension sans les reconstruire.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -S 0xSIZE** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant l'extension avec une taille spécifiée.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -r "regex_pattern"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant une expression régulière.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -i "file_extension"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant une extension spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -t "file_type"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant un type de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -A** : Extrait tous les fichiers en mémoire à partir d'une adresse en les injectant dans un processus.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -b "file_basename"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant un nom de base de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -s "file_size"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant une taille de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -l "file_location"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant un emplacement de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -e "file_extension"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant une extension de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -m "file_magic"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant une signature magique de fichier spécifique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -c "file_count"** : Extrait un nombre spécifié de fichiers en mémoire à partir d'une adresse en les injectant dans un processus.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -z** : Extrait les fichiers compressés en mémoire à partir d'une adresse en les injectant dans un processus.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -g "file_extension"** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en utilisant une extension de fichier générique.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -w** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en les écrivant dans un fichier.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D output_directory -y "file_path" -x** : Extrait les fichiers en mémoire à partir d'une adresse en les injectant dans un processus en les exécutant.

#### Plugins supplémentaires

- **volatility -f dump.raw malfind** : Recherche les injections de code malveillant.
- **volatility -f dump.raw malfind -p PID** : Recherche les injections de code malveillant dans un processus spécifique.
- **volatility -f dump.raw malfind -D output_directory** : Recherche les injections de code malveillant et les extrait dans un répertoire.
- **volatility -f dump.raw malfind -p PID -D output_directory** : Recherche les injections de code malveillant dans un processus spécifique et les extrait dans un répertoire.
- **volatility -f dump.raw malfind -Y "rule_file"** : Recherche les injections de code malveillant en utilisant des règles YARA.
- **volatility -f dump.raw malfind -p PID -Y "rule_file"** : Recherche les injections de code malveillant dans un processus spécifique en utilisant des règles YARA.
- **volatility -f dump.raw malfind -D output_directory -Y "rule_file"** : Recherche les injections de code malveillant et les extrait dans un répertoire en utilisant des règles YARA.
- **volatility -f dump.raw malfind -p PID -D output_directory -Y "rule_file"** : Recherche les injections de code malveillant dans un processus spécifique et les extrait dans un répertoire en utilisant des règles YARA.

{% endtab %}
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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.mem imageinfo** : Affiche des informations générales sur le dump mémoire.
- **volatility -f dump.mem pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.mem psscan** : Examine les processus à partir des structures EPROCESS.
- **volatility -f dump.mem pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.mem dlllist -p PID** : Liste les DLL chargées par un processus spécifique.
- **volatility -f dump.mem cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique.
- **volatility -f dump.mem filescan** : Analyse les handles de fichiers.
- **volatility -f dump.mem netscan** : Examine les connexions réseau.
- **volatility -f dump.mem connections** : Affiche les connexions réseau.
- **volatility -f dump.mem malfind** : Recherche de code malveillant dans les processus.
- **volatility -f dump.mem apihooks** : Recherche les hooks d'API dans les processus.
- **volatility -f dump.mem ldrmodules** : Liste les modules chargés dans les processus.
- **volatility -f dump.mem modscan** : Analyse les modules noyau.
- **volatility -f dump.mem shimcache** : Extrait les entrées de la base de données ShimCache.
- **volatility -f dump.mem userassist** : Extrait les entrées UserAssist.
- **volatility -f dump.mem hivelist** : Liste les hives du registre.
- **volatility -f dump.mem printkey -o OFFSET** : Affiche les sous-clés et valeurs d'une clé de registre.
- **volatility -f dump.mem hashdump** : Dump les hachages de mots de passe.
- **volatility -f dump.mem truecryptpassphrase** : Extrait les passphrases TrueCrypt.

### Plugins supplémentaires

- **[Volatility Plugins](https://github.com/volatilityfoundation/volatility/wiki/CommandReference-V2.6)** : Référence des plugins supplémentaires disponibles.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### Poignées

Utile pour savoir à quels autres fichiers, clés, threads, processus... un **processus a une poignée** (a ouvert)
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.raw imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.raw pslist** : Liste des processus en cours d'exécution
- **volatility -f dump.raw psscan** : Analyse des processus non alloués
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence
- **volatility -f dump.raw dlllist -p PID** : Liste des DLL chargées par un processus
- **volatility -f dump.raw filescan** : Analyse des fichiers non alloués
- **volatility -f dump.raw cmdline -p PID** : Ligne de commande d'un processus
- **volatility -f dump.raw netscan** : Liste des connexions réseau
- **volatility -f dump.raw connections** : Analyse des connexions réseau
- **volatility -f dump.raw malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.raw userassist** : Informations sur les programmes utilisés par l'utilisateur
- **volatility -f dump.raw hivelist** : Liste des hives de registre
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les valeurs d'une clé de registre
- **volatility -f dump.raw hashdump** : Dump des mots de passe en mémoire
- **volatility -f dump.raw shimcache** : Analyse du cache de compatibilité des applications
- **volatility -f dump.raw ldrmodules** : Liste des modules chargés par les processus
- **volatility -f dump.raw modscan** : Analyse des modules noyau non alloués
- **volatility -f dump.raw mutantscan** : Analyse des objets de synchronisation
- **volatility -f dump.raw svcscan** : Liste des services système
- **volatility -f dump.raw getsids** : Liste des SID des processus
- **volatility -f dump.raw apihooks** : Recherche de hooks dans les processus
- **volatility -f dump.raw envars** : Variables d'environnement des processus
- **volatility -f dump.raw dumpfiles -Q chemin_dossier** : Extraction des fichiers en mémoire
- **volatility -f dump.raw memdump -p PID -D chemin_dossier** : Extraction de la mémoire d'un processus
- **volatility -f dump.raw memmap** : Cartographie de la mémoire
- **volatility -f dump.raw timeliner** : Création d'une timeline des événements
- **volatility -f dump.raw screenshot -D chemin_dossier** : Capture d'écran de l'écran mémoire
- **volatility -f dump.raw procdump -p PID -D chemin_dossier** : Dump du processus mémoire
- **volatility -f dump.raw procdump -p PID -D chemin_dossier --dump-dir autre_chemin** : Dump du processus mémoire dans un répertoire spécifique
- **volatility -f dump.raw memstrings -p PID** : Recherche de chaînes ASCII et Unicode en mémoire
- **volatility -f dump.raw yarascan -Y chemin_regles** : Analyse avec Yara
- **volatility -f dump.raw yarascan -Y chemin_regles --yara-file fichier_yara** : Analyse avec Yara en utilisant un fichier Yara spécifique
- **volatility -f dump.raw shimcachemem -s chemin_fichier** : Analyse du cache de compatibilité des applications en mémoire
- **volatility -f dump.raw shimcachemem -s chemin_fichier --output-file fichier_sortie** : Analyse du cache de compatibilité des applications en mémoire avec sauvegarde dans un fichier de sortie

### Plugins supplémentaires

- **volatility --plugins=/chemin_vers_plugins -f dump.raw plugin_name** : Utilisation de plugins personnalisés
- **volatility --info | grep -i plugin_name** : Recherche d'informations sur un plugin
- **volatility --info | grep -i profile_name** : Recherche d'informations sur un profil

{% endtab %}
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

- **volatility -f dump.mem imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.mem pslist** : Liste des processus en cours d'exécution
- **volatility -f dump.mem psscan** : Analyse des processus non affichés dans la liste des tâches
- **volatility -f dump.mem pstree** : Affiche les processus sous forme d'arborescence
- **volatility -f dump.mem dlllist -p PID** : Liste des DLL chargées par un processus
- **volatility -f dump.mem filescan** : Analyse des fichiers ouverts par les processus
- **volatility -f dump.mem cmdline -p PID** : Ligne de commande d'un processus
- **volatility -f dump.mem consoles** : Recherche de consoles virtuelles
- **volatility -f dump.mem connections** : Liste des connexions réseau
- **volatility -f dump.mem netscan** : Analyse des connexions réseau
- **volatility -f dump.mem svcscan** : Liste des services
- **volatility -f dump.mem malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.mem apihooks** : Recherche de hooks API dans les processus
- **volatility -f dump.mem shimcache** : Extraction de la base de données Shimcache
- **volatility -f dump.mem hivelist** : Liste des hives de registre
- **volatility -f dump.mem printkey -o OFFSET** : Affiche une clé de registre à partir d'un offset donné
- **volatility -f dump.mem userassist** : Extraction des entrées UserAssist
- **volatility -f dump.mem getsids** : Liste des SID des processus
- **volatility -f dump.mem modscan** : Analyse des modules noyau chargés
- **volatility -f dump.mem driverirp** : Analyse des IRP des pilotes
- **volatility -f dump.mem ssdt** : Recherche des adresses de la SSDT
- **volatility -f dump.mem callbacks** : Recherche des adresses de callbacks
- **volatility -f dump.mem mutantscan** : Analyse des objets mutant
- **volatility -f dump.mem ldrmodules** : Liste des modules chargés par le loader
- **volatility -f dump.mem atomscan** : Analyse des objets atom
- **volatility -f dump.mem deskscan** : Analyse des objets de bureau
- **volatility -f dump.mem hivescan** : Analyse des hives de registre
- **volatility -f dump.mem printkey -K KEY** : Affiche une clé de registre à partir d'un chemin donné
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY** : Extraction d'une partie de la base de registre
- **volatility -f dump.mem dumpfiles -Q PATH** : Extraction des fichiers en mémoire
- **volatility -f dump.mem dumpfiles -D DIR -Q PATH** : Extraction des fichiers en mémoire dans un répertoire donné
- **volatility -f dump.mem dumpfiles -S PATH -Q PATH** : Extraction des fichiers en mémoire avec un nom spécifique
- **volatility -f dump.mem dumpfiles -n -Q PATH** : Extraction des fichiers en mémoire sans les en-têtes
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR** : Extraction des fichiers en mémoire dans un répertoire spécifique
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR -D DIR** : Extraction des fichiers en mémoire dans un répertoire spécifique avec un préfixe
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR -n** : Extraction des fichiers en mémoire sans les en-têtes dans un répertoire spécifique
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR -n -S PATH** : Extraction des fichiers en mémoire sans les en-têtes dans un répertoire spécifique avec un nom spécifique
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR -n -D DIR** : Extraction des fichiers en mémoire sans les en-têtes dans un répertoire spécifique avec un préfixe
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR -n -D DIR -S PATH** : Extraction des fichiers en mémoire sans les en-têtes dans un répertoire spécifique avec un préfixe et un nom spécifique
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY --dump-dir OUTPUT_DIR** : Extraction d'une partie de la base de registre dans un répertoire spécifique
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY --dump-dir OUTPUT_DIR -D DIR** : Extraction d'une partie de la base de registre dans un répertoire spécifique avec un préfixe
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY --dump-dir OUTPUT_DIR -n** : Extraction d'une partie de la base de registre sans les en-têtes dans un répertoire spécifique
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY --dump-dir OUTPUT_DIR -n -D DIR** : Extraction d'une partie de la base de registre sans les en-têtes dans un répertoire spécifique avec un préfixe
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY --dump-dir OUTPUT_DIR -n -D DIR -S PATH** : Extraction d'une partie de la base de registre sans les en-têtes dans un répertoire spécifique avec un préfixe et un nom spécifique

### Plugins supplémentaires

- **volatility -f dump.mem shimcachemem** : Extraction de la base de données Shimcache en mémoire
- **volatility -f dump.mem mftparser** : Analyse du Master File Table (MFT)
- **volatility -f dump.mem hivelist** : Liste des hives de registre
- **volatility -f dump.mem printkey -o OFFSET** : Affiche une clé de registre à partir d'un offset donné
- **volvolatility -f dump.mem userassist** : Extraction des entrées UserAssist
- **volatility -f dump.mem getsids** : Liste des SID des processus
- **volatility -f dump.mem modscan** : Analyse des modules noyau chargés
- **volatility -f dump.mem driverirp** : Analyse des IRP des pilotes
- **volatility -f dump.mem ssdt** : Recherche des adresses de la SSDT
- **volatility -f dump.mem callbacks** : Recherche des adresses de callbacks
- **volatility -f dump.mem mutantscan** : Analyse des objets mutant
- **volatility -f dump.mem ldrmodules** : Liste des modules chargés par le loader
- **volatility -f dump.mem atomscan** : Analyse des objets atom
- **volatility -f dump.mem deskscan** : Analyse des objets de bureau
- **volatility -f dump.mem hivescan** : Analyse des hives de registre
- **volatility -f dump.mem printkey -K KEY** : Affiche une clé de registre à partir d'un chemin donné
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY** : Extraction d'une partie de la base de registre
- **volatility -f dump.mem dumpfiles -Q PATH** : Extraction des fichiers en mémoire
- **volatility -f dump.mem dumpfiles -D DIR -Q PATH** : Extraction des fichiers en mémoire dans un répertoire donné
- **volatility -f dump.mem dumpfiles -S PATH -Q PATH** : Extraction des fichiers en mémoire avec un nom spécifique
- **volatility -f dump.mem dumpfiles -n -Q PATH** : Extraction des fichiers en mémoire sans les en-têtes
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR** : Extraction des fichiers en mémoire dans un répertoire spécifique
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR -D DIR** : Extraction des fichiers en mémoire dans un répertoire spécifique avec un préfixe
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR -n** : Extraction des fichiers en mémoire sans les en-têtes dans un répertoire spécifique
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR -n -S PATH** : Extraction des fichiers en mémoire sans les en-têtes dans un répertoire spécifique avec un nom spécifique
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR -n -D DIR** : Extraction des fichiers en mémoire sans les en-têtes dans un répertoire spécifique avec un préfixe
- **volatility -f dump.mem dumpfiles -Q PATH --dump-dir OUTPUT_DIR -n -D DIR -S PATH** : Extraction des fichiers en mémoire sans les en-têtes dans un répertoire spécifique avec un préfixe et un nom spécifique
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY --dump-dir OUTPUT_DIR** : Extraction d'une partie de la base de registre dans un répertoire spécifique
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY --dump-dir OUTPUT_DIR -D DIR** : Extraction d'une partie de la base de registre dans un répertoire spécifique avec un préfixe
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY --dump-dir OUTPUT_DIR -n** : Extraction d'une partie de la base de registre sans les en-têtes dans un répertoire spécifique
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY --dump-dir OUTPUT_DIR -n -D DIR** : Extraction d'une partie de la base de registre sans les en-têtes dans un répertoire spécifique avec un préfixe
- **volatility -f dump.mem dumpregistry -o OFFSET -s SIZE -k KEY --dump-dir OUTPUT_DIR -n -D DIR -S PATH** : Extraction d'une partie de la base de registre sans les en-têtes dans un répertoire spécifique avec un préfixe et un nom spécifique

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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.mem imageinfo** : Affiche des informations générales sur le dump mémoire.
- **volatility -f dump.mem pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.mem psscan** : Examine les processus à partir de la mémoire physique.
- **volatility -f dump.mem pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.mem dlllist** : Liste les DLL chargées dans les processus.
- **volatility -f dump.mem filescan** : Recherche les handles de fichiers ouverts.
- **volatility -f dump.mem cmdline** : Affiche les lignes de commande des processus.
- **volatility -f dump.mem netscan** : Recherche les connexions réseau.
- **volatility -f dump.mem connections** : Affiche les connexions réseau.
- **volatility -f dump.mem malfind** : Recherche les indicateurs de code malveillant.
- **volatility -f dump.mem apihooks** : Recherche les hooks API.
- **volatility -f dump.mem ldrmodules** : Liste les modules chargés dynamiquement.
- **volatility -f dump.mem modscan** : Recherche les modules noyau.
- **volatility -f dump.mem ssdt** : Affiche la table de service du noyau.
- **volatility -f dump.mem callbacks** : Affiche les callbacks du noyau.
- **volatility -f dump.mem driverirp** : Affiche les dispatch routines des pilotes.
- **volatility -f dump.mem devicetree** : Affiche l'arborescence des périphériques.
- **volatility -f dump.mem hivelist** : Liste les hives de registre.
- **volatility -f dump.mem printkey** : Affiche les valeurs de clé de registre.
- **volatility -f dump.mem userassist** : Affiche les entrées UserAssist.
- **volatility -f dump.mem shimcache** : Affiche les entrées ShimCache.
- **volatility -f dump.mem getsids** : Affiche les SID des processus.
- **volatility -f dump.mem getservicesids** : Affiche les SID des services.
- **volatility -f dump.mem getsidsandprivs** : Affiche les SID et privilèges des processus.
- **volatility -f dump.mem envars** : Affiche les variables d'environnement des processus.
- **volatility -f dump.mem consoles** : Affiche les consoles des processus.
- **volatility -f dump.mem mutantscan** : Recherche les objets mutant.
- **volatility -f dump.mem handles** : Affiche les handles des processus.
- **volatility -f dump.mem vadinfo** : Affiche les informations VAD.
- **volatility -f dump.mem vadtree** : Affiche l'arborescence VAD.
- **volatility -f dump.mem vadwalk** : Affiche les pages VAD.
- **volatility -f dump.mem memmap** : Affiche la carte mémoire.
- **volatility -f dump.mem memdump -p PID -D dossier** : Effectue un dump de la mémoire d'un processus spécifique.
- **volatility -f dump.mem memdump -p PID -D dossier --name** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus.
- **volatility -f dump.mem memdump -p PID -D dossier --name --dump-dir** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus dans un répertoire spécifique.
- **volatility -f dump.mem memdump -p PID -D dossier --name --dump-dir --output** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus dans un répertoire spécifique et affiche les informations de progression.
- **volatility -f dump.mem memdump -p PID -D dossier --name --dump-dir --output --phys-offset** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus dans un répertoire spécifique, affiche les informations de progression et l'offset physique.
- **volatility -f dump.mem memdump -p PID -D dossier --name --dump-dir --output --phys-offset --memory** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus dans un répertoire spécifique, affiche les informations de progression, l'offset physique et la mémoire physique.
- **volvolatility -f dump.mem memdump -p PID -D dossier --name --dump-dir --output --phys-offset --memory --format** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus dans un répertoire spécifique, affiche les informations de progression, l'offset physique, la mémoire physique et le format de sortie.

### Plugins supplémentaires

- **volatility -f dump.mem kdbgscan** : Recherche le KDBG.
- **volatility -f dump.mem kpcrscan** : Recherche le KPCR.
- **volatility -f dump.mem psxview** : Affiche les processus cachés.
- **volatility -f dump.mem ldrmodules -p PID** : Liste les modules chargés dynamiquement pour un processus spécifique.
- **volatility -f dump.mem malfind -p PID** : Recherche les indicateurs de code malveillant pour un processus spécifique.
- **volatility -f dump.mem dlllist -p PID** : Liste les DLL chargées dans un processus spécifique.
- **volatility -f dump.mem handles -p PID** : Affiche les handles d'un processus spécifique.
- **volatility -f dump.mem cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique.
- **volatility -f dump.mem filescan -p PID** : Recherche les handles de fichiers ouverts pour un processus spécifique.
- **volatility -f dump.mem vadinfo -p PID** : Affiche les informations VAD pour un processus spécifique.
- **volatility -f dump.mem vadtree -p PID** : Affiche l'arborescence VAD pour un processus spécifique.
- **volatility -f dump.mem vadwalk -p PID** : Affiche les pages VAD pour un processus spécifique.
- **volatility -f dump.mem memdump -p PID -D dossier --name** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus.
- **volatility -f dump.mem memdump -p PID -D dossier --name --dump-dir** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus dans un répertoire spécifique.
- **volatility -f dump.mem memdump -p PID -D dossier --name --dump-dir --output** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus dans un répertoire spécifique et affiche les informations de progression.
- **volatility -f dump.mem memdump -p PID -D dossier --name --dump-dir --output --phys-offset** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus dans un répertoire spécifique, affiche les informations de progression et l'offset physique.
- **volatility -f dump.mem memdump -p PID -D dossier --name --dump-dir --output --phys-offset --memory** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus dans un répertoire spécifique, affiche les informations de progression, l'offset physique et la mémoire physique.
- **volatility -f dump.mem memdump -p PID -D dossier --name --dump-dir --output --phys-offset --memory --format** : Effectue un dump de la mémoire d'un processus spécifique avec le nom du processus dans un répertoire spécifique, affiche les informations de progression, l'offset physique, la mémoire physique et le format de sortie.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

**Windows** garde une trace des programmes que vous exécutez en utilisant une fonctionnalité dans le registre appelée clés **UserAssist**. Ces clés enregistrent combien de fois chaque programme est exécuté et quand il a été exécuté pour la dernière fois.
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

{% tab title="vol2" %} 

### Feuille de triche Volatility

#### Commandes de base

- **volatility -f dump.mem imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.mem --profile=PROFILE pslist** : Liste des processus
- **volatility -f dump.mem --profile=PROFILE pstree** : Arborescence des processus
- **volatility -f dump.mem --profile=PROFILE psscan** : Analyse des processus
- **volatility -f dump.mem --profile=PROFILE netscan** : Analyse des connexions réseau
- **volatility -f dump.mem --profile=PROFILE connections** : Liste des connexions réseau
- **volatility -f dump.mem --profile=PROFILE cmdscan** : Analyse des commandes exécutées
- **volatility -f dump.mem --profile=PROFILE consoles** : Liste des consoles interactives
- **volatility -f dump.mem --profile=PROFILE filescan** : Analyse des fichiers ouverts
- **volatility -f dump.mem --profile=PROFILE dlllist** : Liste des DLL chargées
- **volatility -f dump.mem --profile=PROFILE getsids** : Liste des SID
- **volatility -f dump.mem --profile=PROFILE hivelist** : Liste des hôtes de registre
- **volatility -f dump.mem --profile=PROFILE userassist** : Liste des éléments UserAssist
- **volatility -f dump.mem --profile=PROFILE shimcache** : Liste des entrées ShimCache
- **volatility -f dump.mem --profile=PROFILE mftparser** : Analyse du Master File Table
- **volatility -f dump.mem --profile=PROFILE ldrmodules** : Liste des modules chargés
- **volatility -f dump.mem --profile=PROFILE modscan** : Analyse des modules
- **volatility -f dump.mem --profile=PROFILE mutantscan** : Analyse des objets Mutant
- **volatility -f dump.mem --profile=PROFILE svcscan** : Analyse des services
- **volatility -f dump.mem --profile=PROFILE envars** : Liste des variables d'environnement
- **volatility -f dump.mem --profile=PROFILE cmdline** : Lignes de commande des processus
- **volatility -f dump.mem --profile=PROFILE consoles** : Liste des consoles interactives
- **volatility -f dump.mem --profile=PROFILE hivelist** : Liste des hôtes de registre
- **volatility -f dump.mem --profile=PROFILE userassist** : Liste des éléments UserAssist
- **volatility -f dump.mem --profile=PROFILE shimcache** : Liste des entrées ShimCache
- **volatility -f dump.mem --profile=PROFILE mftparser** : Analyse du Master File Table
- **volatility -f dump.mem --profile=PROFILE ldrmodules** : Liste des modules chargés
- **volatility -f dump.mem --profile=PROFILE modscan** : Analyse des modules
- **volatility -f dump.mem --profile=PROFILE mutantscan** : Analyse des objets Mutant
- **volatility -f dump.mem --profile=PROFILE svcscan** : Analyse des services
- **volatility -f dump.mem --profile=PROFILE envars** : Liste des variables d'environnement
- **volatility -f dump.mem --profile=PROFILE cmdline** : Lignes de commande des processus

#### Plugins supplémentaires

- **volatility -f dump.mem --profile=PROFILE timeliner** : Crée une timeline des activités
- **volatility -f dump.mem --profile=PROFILE dumpfiles -Q ADDRESS -D /path/to/dump/** : Extraction de fichiers
- **volatility -f dump.mem --profile=PROFILE memdump -p PID -D /path/to/dump/** : Extraction de l'espace mémoire d'un processus
- **voljson -f dump.mem --profile=PROFILE pslist** : Exporter la sortie en JSON
- **volatility -f dump.mem --profile=PROFILE linux_bash** : Analyse des artefacts Bash sur Linux
- **volatility -f dump.mem --profile=PROFILE linux_netstat** : Analyse des connexions réseau sur Linux
- **volatility -f dump.mem --profile=PROFILE linux_lsof** : Liste des fichiers ouverts sur Linux
- **volatility -f dump.mem --profile=PROFILE linux_yarascan** : Analyse des fichiers avec Yara sur Linux

{% endtab %}
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
## Registre

### Afficher les ruches disponibles

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
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
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil filescan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil cmdline**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil consoles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil connections**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil netscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil hivelist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil userassist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil shimcache**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ldrmodules**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil getsids**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil modscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **
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

{% onglet title="vol2" %}
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
- **volatility -f dump.raw malfind** : Recherche les indicateurs de programmes malveillants.
- **volatility -f dump.raw apihooks** : Recherche les hooks d'API.
- **volatility -f dump.raw ldrmodules** : Liste les modules chargés par les processus.
- **volatility -f dump.raw handles** : Affiche les handles des processus.
- **volatility -f dump.raw mutantscan** : Recherche les objets de type mutant.
- **volatility -f dump.raw svcscan** : Recherche les services.
- **volatility -f dump.raw modscan** : Recherche les modules noyau.
- **volatility -f dump.raw driverirp** : Affiche les IRP des pilotes.
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques.
- **volatility -f dump.raw printkey -K "ControlSet001\services"** : Affiche les clés de registre.
- **volatility -f dump.raw hivelist** : Affiche les hives de registre.
- **volatility -f dump.raw userassist** : Affiche les entrées UserAssist.
- **volatility -f dump.raw shimcache** : Affiche les entrées ShimCache.
- **volatility -f dump.raw getsids** : Affiche les SID des processus.
- **volatility -f dump.raw getservicesids** : Affiche les SID des services.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"** : Affiche les programmes au démarrage.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\RunOnce"** : Affiche les programmes au démarrage (une seule fois).
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"** : Affiche les programmes approuvés au démarrage.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"** : Affiche les programmes approuvés au démarrage (32 bits).
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"** : Affiche les programmes du dossier de démarrage approuvés.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"** : Affiche les programmes du dossier de démarrage approuvés (32 bits).
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU"** : Affiche les derniers fichiers ouverts.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU"** : Affiche les fichiers ouverts et enregistrés récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"** : Affiche les documents récemment ouverts.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"** : Affiche les chemins d'accès tapés récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"** : Affiche les commandes exécutées récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"** : Affiche les PIDL des fichiers ouverts et enregistrés récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"** : Affiche les PIDL des derniers fichiers ouverts.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"** : Affiche les commandes exécutées récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"** : Affiche les PIDL des fichiers ouverts et enregistrés récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"** : Affiche les PIDL des derniers fichiers ouverts.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"** : Affiche les commandes exécutées récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"** : Affiche les PIDL des fichiers ouverts et enregistrés récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"** : Affiche les PIDL des derniers fichiers ouverts.

### Plugins supplémentaires

- **volatility -f dump.raw mimikatz** : Exécute Mimikatz sur l'image mémoire.
- **volatility -f dump.raw truecryptpassphrase** : Recherche les passphrases TrueCrypt.
- **volatility -f dump.raw hashdump** : Dump les hachages de mots de passe.
- **volatility -f dump.raw hivelist** : Affiche les hives de registre.
- **volatility -f dump.raw userassist** : Affiche les entrées UserAssist.
- **volatility -f dump.raw shimcache** : Affiche les entrées ShimCache.
- **volatility -f dump.raw getsids** : Affiche les SID des processus.
- **volatility -f dump.raw getservicesids** : Affiche les SID des services.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"** : Affiche les programmes au démarrage.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\RunOnce"** : Affiche les programmes au démarrage (une seule fois).
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"** : Affiche les programmes approuvés au démarrage.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"** : Affiche les programmes approuvés au démarrage (32 bits).
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"** : Affiche les programmes du dossier de démarrage approuvés.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"** : Affiche les programmes du dossier de démarrage approuvés (32 bits).
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU"** : Affiche les derniers fichiers ouverts.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU"** : Affiche les fichiers ouverts et enregistrés récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"** : Affiche les documents récemment ouverts.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"** : Affiche les chemins d'accès tapés récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"** : Affiche les commandes exécutées récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"** : Affiche les PIDL des fichiers ouverts et enregistrés récemment.
- **volatility -f dump.raw printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"** : Affiche les PIDL des derniers fichiers ouverts.

{% endtab %}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
### Analyse de la mémoire

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
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
- **volatility -f dump.mem netscan** : Analyse des connexions réseau
- **volatility -f dump.mem connections** : Liste des connexions réseau
- **volatility -f dump.mem malfind** : Recherche de code malveillant
- **volatility -f dump.mem apihooks** : Détection des hooks API
- **volatility -f dump.mem ldrmodules** : Liste des modules chargés
- **volatility -f dump.mem modscan** : Analyse des modules
- **volatility -f dump.mem shimcache** : Analyse du cache de compatibilité des applications
- **volatility -f dump.mem userassist** : Analyse des éléments récemment utilisés par l'utilisateur
- **volatility -f dump.mem hivelist** : Liste des hives de registre
- **volatility -f dump.mem printkey -o OFFSET** : Affichage du contenu d'une clé de registre
- **volatility -f dump.mem cmdline** : Affichage des lignes de commande des processus
- **volatility -f dump.mem consoles** : Analyse des consoles
- **volatility -f dump.mem getsids** : Affichage des SID des processus
- **volatility -f dump.mem envars** : Affichage des variables d'environnement des processus
- **volatility -f dump.mem mutantscan** : Analyse des objets de mutation
- **volatility -f dump.mem svcscan** : Analyse des services
- **volatility -f dump.mem driverirp** : Analyse des IRP des pilotes
- **volatility -f dump.mem devicetree** : Affichage de l'arborescence des périphériques
- **volatility -f dump.mem handles** : Analyse des handles
- **volatility -f dump.mem vadinfo -o OFFSET** : Informations sur une plage d'adresses virtuelles
- **volatility -f dump.mem vadtree -o OFFSET** : Arborescence des plages d'adresses virtuelles
- **volatility -f dump.mem vadwalk -o OFFSET** : Parcours des plages d'adresses virtuelles
- **volatility -f dump.mem dlldump -p PID -D dossier** : Extraction d'une DLL en mémoire
- **volatility -f dump.mem procdump -p PID -D dossier** : Extraction d'un processus en mémoire
- **volatility -f dump.mem memdump -p PID -D dossier** : Extraction de la mémoire d'un processus
- **volatility -f dump.mem memmap -p PID** : Cartographie de la mémoire d'un processus
- **volatility -f dump.mem memstrings -p PID** : Recherche de chaînes dans la mémoire d'un processus
- **volatility -f dump.mem memscan -p PID** : Analyse de la mémoire d'un processus
- **volatility -f dump.mem yarascan -Y dossier_de_règles** : Analyse de la mémoire avec Yara
- **volatility -f dump.mem procmemdump -p PID -D dossier** : Extraction de la mémoire d'un processus en utilisant Memdump
- **volatility -f dump.mem malfind -p PID** : Recherche de code malveillant dans un processus
- **volatility -f dump.mem malfind -D dossier** : Recherche de code malveillant dans tous les processus
- **volatility -f dump.mem malfind -p PID -D dossier** : Recherche de code malveillant dans un processus et extraction
- **volatility -f dump.mem malfind -D dossier -Y dossier_de_règles** : Recherche de code malveillant dans tous les processus avec Yara
- **volatility -f dump.mem malfind -p PID -D dossier -Y dossier_de_règles** : Recherche de code malveillant dans un processus avec Yara
- **volatility -f dump.mem malfind -D dossier --dump-dir dossier_de_sortie** : Recherche de code malveillant dans tous les processus avec extraction dans un dossier spécifique
- **volatility -f dump.mem malfind -p PID -D dossier --dump-dir dossier_de_sortie** : Recherche de code malveillant dans un processus avec extraction dans un dossier spécifique

#### Plugins supplémentaires

- **volatility -f dump.mem shimcachemem** : Analyse du cache de compatibilité des applications en mémoire
- **volatility -f dump.mem userassist -D dossier** : Extraction des éléments récemment utilisés par l'utilisateur
- **volatility -f dump.mem userassist -p PID** : Affichage des éléments récemment utilisés par un processus
- **volatility -f dump.mem userassist -p PID -D dossier** : Extraction des éléments récemment utilisés par un processus
- **volatility -f dump.mem userassist -D dossier -Y dossier_de_règles** : Recherche d'éléments récemment utilisés avec Yara
- **volatility -f dump.mem userassist -p PID -D dossier -Y dossier_de_règles** : Recherche d'éléments récemment utilisés par un processus avec Yara
- **volatility -f dump.mem userassist -D dossier --dump-dir dossier_de_sortie** : Extraction des éléments récemment utilisés dans un dossier spécifique
- **volatility -f dump.mem userassist -p PID -D dossier --dump-dir dossier_de_sortie** : Extraction des éléments récemment utilisés par un processus dans un dossier spécifique

{% endtab %}
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

Le **système de fichiers NTFS** utilise un composant critique connu sous le nom de _table des fichiers principale_ (MFT). Cette table comprend au moins une entrée pour chaque fichier sur un volume, couvrant également la MFT elle-même. Des détails essentiels sur chaque fichier, tels que **la taille, les horodatages, les autorisations et les données réelles**, sont encapsulés dans les entrées de la MFT ou dans des zones externes à la MFT mais référencées par ces entrées. Plus de détails peuvent être trouvés dans la [documentation officielle](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### Clés/Certificats SSL

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% onglet title="vol2" %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

## Logiciel malveillant
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

{% tab title="vol2" %} 

### Feuille de triche Volatility

#### Commandes de base

- **volatility -f dump.raw imageinfo** : Affiche des informations générales sur l'image mémoire.
- **volatility -f dump.raw pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.raw psscan** : Examine les processus inactifs.
- **volatility -f dump.raw dlllist -p PID** : Liste les DLL chargées par un processus spécifique.
- **volatility -f dump.raw cmdscan** : Recherche les commandes exécutées.
- **volatility -f dump.raw filescan** : Recherche les fichiers ouverts par les processus.
- **volatility -f dump.raw netscan** : Affiche les connexions réseau.
- **volatility -f dump.raw connections** : Affiche les connexions réseau.
- **volatility -f dump.raw malfind** : Recherche les injections de code malveillant.
- **volatility -f dump.raw shimcache** : Examine le cache de compatibilité des applications.
- **volatility -f dump.raw userassist** : Examine les éléments récemment utilisés par l'utilisateur.
- **volatility -f dump.raw hivelist** : Liste les hôtes de registre actifs.
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les sous-clés et les valeurs d'une clé de registre.
- **volatility -f dump.raw cmdline** : Affiche les lignes de commande des processus.
- **volatility -f dump.raw consoles** : Examine les consoles virtuelles.
- **volatility -f dump.raw getsids** : Affiche les SID des processus.
- **volatility -f dump.raw envars** : Affiche les variables d'environnement des processus.
- **volatility -f dump.raw modscan** : Recherche les modules du noyau.
- **volatility -f dump.raw mutantscan** : Recherche les objets de mutation.
- **volatility -f dump.raw svcscan** : Recherche les services.
- **volatility -f dump.raw driverirp** : Examine les IRP des pilotes.
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques.
- **volatility -f dump.raw idt** : Affiche la table des descripteurs d'interruption.
- **volatility -f dump.raw gdt** : Affiche la table des descripteurs globaux.
- **volatility -f dump.raw threads** : Affiche les threads du système.
- **volatility -f dump.raw handles** : Affiche les handles du système.
- **volatility -f dump.raw callbacks** : Examine les callbacks du noyau.
- **volatility -f dump.raw ssdt** : Affiche la table des descripteurs de services.
- **volatility -f dump.raw drivermodule** : Examine les modules des pilotes.
- **volatility -f dump.raw modules** : Affiche les modules chargés.
- **volatility -f dump.raw moddump -b BASE -m MODULE -D output_directory** : Extrait un module du noyau.
- **volatility -f dump.raw procdump -p PID -D output_directory** : Crée un dump mémoire d'un processus spécifique.
- **volatility -f dump.raw memdump -p PID -D output_directory** : Crée un dump mémoire d'un processus spécifique.
- **volatility -f dump.raw memmap** : Affiche la carte mémoire.
- **volatility -f dump.raw memmap --profile=PROFILE** : Affiche la carte mémoire avec un profil spécifique.
- **volatility -f dump.raw raw2dmp -i INPUT -o OUTPUT** : Convertit un fichier de volatilité brut en un fichier de volatilité.
- **volatility -f dump.raw raw2dmp --profile=PROFILE -i INPUT -o OUTPUT** : Convertit un fichier de volatilité brut en un fichier de volatilité avec un profil spécifique.

#### Plugins supplémentaires

- **volatility -f dump.raw plugin_name** : Exécute un plugin spécifique.
- **volatility -f dump.raw --plugins=directory/ plugin_name** : Exécute un plugin spécifique à partir d'un répertoire personnalisé.

#### Profils

- **volatility -f dump.raw --profile=PROFILE** : Spécifie un profil pour l'analyse.

#### Autres options

- **-v** : Augmente le niveau de verbosité.
- **-h** : Affiche l'aide pour la commande donnée.

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
{% endtabs %}

### Analyse de la mémoire avec Volatility

Utilisez ce script pour télécharger et fusionner toutes les règles de malware yara depuis github : [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Créez le répertoire _**rules**_ et exécutez-le. Cela créera un fichier appelé _**malware\_rules.yar**_ qui contient toutes les règles yara pour les malwares.
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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.mem imageinfo** : Affiche des informations générales sur l'image mémoire
- **volatility -f dump.mem pslist** : Liste les processus en cours d'exécution
- **volatility -f dump.mem pstree** : Affiche les processus sous forme d'arborescence
- **volatility -f dump.mem psscan** : Recherche les processus supprimés
- **volatility -f dump.mem dlllist -p PID** : Liste les DLL chargées par un processus spécifique
- **volatility -f dump.mem cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique
- **volatility -f dump.mem filescan** : Recherche les fichiers ouverts par les processus
- **volatility -f dump.mem netscan** : Affiche les connexions réseau
- **volatility -f dump.mem connections** : Affiche les connexions réseau (alternative)
- **volatility -f dump.mem timeliner** : Crée une timeline des activités du système
- **volatility -f dump.mem malfind** : Recherche les injections de code malveillant
- **volatility -f dump.mem yarascan** : Recherche de motifs avec Yara
- **volatility -f dump.mem dumpfiles -Q 0xADDRESS -D /path/to/dump/** : Extrait les fichiers en mémoire à partir d'une adresse spécifique
- **volatility -f dump.mem memdump -p PID -D /path/to/dump/** : Crée un dump de la mémoire d'un processus spécifique

### Plugins supplémentaires

- **apihooks**
- **malfind**
- **mftparser**
- **modscan**
- **timeliner**
- **truecrypt**
- **userassist**
- **yarascan**

{% endtab %}
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

{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
### Liens symboliques

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

Il est possible de **lire l'historique bash en mémoire.** Vous pourriez également extraire le fichier _.bash\_history_, mais s'il est désactivé, vous serez heureux de pouvoir utiliser ce module de volatilité.
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- `volatility -f <dumpfile> imageinfo` : Informations sur l'image mémoire
- `volatility -f <dumpfile> pslist` : Liste des processus en cours d'exécution
- `volatility -f <dumpfile> psscan` : Analyse des processus supprimés
- `volatility -f <dumpfile> pstree` : Affichage de l'arborescence des processus
- `volatility -f <dumpfile> dlllist -p <PID>` : Liste des DLL chargées par un processus
- `volatility -f <dumpfile> cmdline -p <PID>` : Ligne de commande d'un processus
- `volatility -f <dumpfile> filescan` : Analyse des fichiers ouverts
- `volatility -f <dumpfile> netscan` : Analyse des connexions réseau
- `volatility -f <dumpfile> connections` : Liste des connexions réseau
- `volatility -f <dumpfile> timeliner` : Lister les événements temporels
- `volatility -f <dumpfile> malfind` : Recherche de code malveillant en mémoire
- `volatility -f <dumpfile> apihooks` : Recherche de hooks API
- `volatility -f <dumpfile> ldrmodules` : Liste des modules chargés dynamiquement
- `volatility -f <dumpfile> modscan` : Analyse des modules noyau
- `volatility -f <dumpfile> ssdt` : Affichage de la table de service du système
- `volatility -f <dumpfile> callbacks` : Liste des callbacks du noyau
- `volatility -f <dumpfile> driverirp` : Analyse des requêtes de paquets IRP des pilotes
- `volatility -f <dumpfile> devicetree` : Affichage de l'arborescence des périphériques
- `volatility -f <dumpfile> hivelist` : Liste des hives de registre
- `volatility -f <dumpfile> printkey -o <offset>` : Affichage du contenu d'une clé de registre
- `volatility -f <dumpfile> userassist` : Analyse des entrées UserAssist
- `volatility -f <dumpfile> shimcache` : Analyse du cache de compatibilité des applications
- `volatility -f <dumpfile> getsids` : Liste des SID des processus
- `volatility -f <dumpfile> getservicesids` : Liste des SID des services
- `volatility -f <dumpfile> envars` : Affichage des variables d'environnement
- `volatility -f <dumpfile> consoles` : Liste des consoles
- `volatility -f <dumpfile> deskscan` : Analyse des objets de bureau
- `volatility -f <dumpfile> hivescan` : Analyse des hives de registre
- `volatility -f <dumpfile> userhandles` : Liste des handles utilisateur
- `volatility -f <dumpfile> mutantscan` : Analyse des objets mutant
- `volatility -f <dumpfile> svcscan` : Analyse des services
- `volatility -f <dumpfile> yarascan --yara-file=<rules.yara>` : Analyse avec Yara
- `volatility -f <dumpfile> dumpfiles -Q <address>` : Extraction de fichiers en mémoire
- `volatility -f <dumpfile> dumpregistry -o <output_directory>` : Extraction de la base de registre
- `volatility -f <dumpfile> memdump -p <PID> -D <output_directory>` : Extraction de la mémoire d'un processus
- `volatility -f <dumpfile> memmap --profile=<profile>` : Affichage de la carte mémoire
- `volatility -f <dumpfile> mftparser` : Analyse du Master File Table
- `volatility -f <dumpfile> shimcachemem` : Analyse du cache de compatibilité des applications en mémoire
- `volatility -f <dumpfile> userassist -output=csv` : Exporter les entrées UserAssist au format CSV
- `volatility -f <dumpfile> hivelist -o <output_directory>` : Exporter les hives de registre dans un répertoire
- `volatility -f <dumpfile> dumpfiles -Q <address> -D <output_directory>` : Extraction de fichiers en mémoire dans un répertoire
- `volatility -f <dumpfile> dumpregistry -o <output_directory>` : Extraction de la base de registre dans un répertoire
- `volatility -f <dumpfile> memdump -p <PID> -D <output_directory>` : Extraction de la mémoire d'un processus dans un répertoire

### Plugins supplémentaires

- **VolUtility** : Interface graphique pour Volatility
- **VolDiff** : Comparaison de deux images mémoire
- **Volshell** : Shell interactif pour Volatility
- **YaraScan** : Analyse avec Yara
- **Malware** : Analyse de logiciels malveillants
- **TrueCrypt** : Analyse de volumes TrueCrypt
- **Malfind** : Recherche de code malveillant
- **MemDmp** : Extraction de la mémoire d'un processus
- **MemMap** : Affichage de la carte mémoire
- **MFTParser** : Analyse du Master File Table
- **APIHooks** : Recherche de hooks API
- **SSDT** : Affichage de la table de service du système
- **DriverIRP** : Analyse des requêtes de paquets IRP des pilotes
- **Devicetree** : Affichage de l'arborescence des périphériques
- **HiveList** : Liste des hives de registre
- **PrintKey** : Affichage du contenu d'une clé de registre
- **DumpFiles** : Extraction de fichiers en mémoire
- **DumpRegistry** : Extraction de la base de registre
- **UserAssist** : Analyse des entrées UserAssist
- **ShimCache** : Analyse du cache de compatibilité des applications
- **GetSids** : Liste des SID des processus
- **GetServicesSids** : Liste des SID des services
- **Envars** : Affichage des variables d'environnement
- **Consoles** : Liste des consoles
- **DeskScan** : Analyse des objets de bureau
- **HiveScan** : Analyse des hives de registre
- **UserHandles** : Liste des handles utilisateur
- **MutantScan** : Analyse des objets mutant
- **SvcScan** : Analyse des services

{% endtab %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### Chronologie

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.mem imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.mem hivelist** : Liste des hives de registre
- **volatility -f dump.mem --profile=ProfileName cmdscan** : Analyse des commandes exécutées
- **volatility -f dump.mem --profile=ProfileName consoles** : Liste des consoles interactives
- **volatility -f dump.mem --profile=ProfileName pstree** : Affichage de l'arborescence des processus
- **volatility -f dump.mem --profile=ProfileName netscan** : Analyse des connexions réseau
- **volatility -f dump.mem --profile=ProfileName filescan** : Analyse des fichiers ouverts
- **volatility -f dump.mem --profile=ProfileName malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.mem --profile=ProfileName getsids** : Liste des SID des processus
- **volatility -f dump.mem --profile=ProfileName pslist** : Liste des processus actifs
- **volatility -f dump.mem --profile=ProfileName dlllist -p ProcessID** : Liste des DLL chargées par un processus
- **volatility -f dump.mem --profile=ProfileName cmdline -p ProcessID** : Ligne de commande d'un processus
- **volatility -f dump.mem --profile=ProfileName memdump -p ProcessID -D /destination/folder/** : Extraction de la mémoire d'un processus
- **volatility -f dump.mem --profile=ProfileName memmap** : Cartographie de la mémoire physique
- **volatility -f dump.mem --profile=ProfileName modscan** : Recherche de modules noyau chargés
- **volatility -f dump.mem --profile=ProfileName userassist** : Analyse des éléments UserAssist
- **volatility -f dump.mem --profile=ProfileName shimcache** : Analyse du cache de compatibilité des applications
- **volatility -f dump.mem --profile=ProfileName ldrmodules** : Liste des modules chargés par les processus
- **volatility -f dump.mem --profile=ProfileName apihooks** : Recherche de hooks API
- **volatility -f dump.mem --profile=ProfileName mutantscan** : Analyse des objets de synchronisation
- **volatility -f dump.mem --profile=ProfileName ssdt** : Affichage de la table de service du noyau
- **volatility -f dump.mem --profile=ProfileName callbacks** : Recherche de callbacks du noyau
- **volatility -f dump.mem --profile=ProfileName driverirp** : Analyse des IRP des pilotes
- **volatility -f dump.mem --profile=ProfileName devicetree** : Affichage de l'arborescence des périphériques
- **volatility -f dump.mem --profile=ProfileName threads** : Liste des threads actifs
- **volatility -f dump.mem --profile=ProfileName handles** : Liste des handles ouverts
- **volatility -f dump.mem --profile=ProfileName mutantscan** : Analyse des objets de synchronisation
- **volatility -f dump.mem --profile=ProfileName svcscan** : Analyse des services
- **volatility -f dump.mem --profile=ProfileName printkey -K KeyPath** : Affichage du contenu d'une clé de registre
- **volatility -f dump.mem --profile=ProfileName hashdump** : Extraction des hachages de mots de passe
- **volatility -f dump.mem --profile=ProfileName truecryptpassphrase** : Recherche de phrases de passe TrueCrypt
- **volatility -f dump.mem --profile=ProfileName envars** : Affichage des variables d'environnement
- **volatility -f dump.mem --profile=ProfileName consoles** : Liste des consoles interactives
- **volatility -f dump.mem --profile=ProfileName clipboard** : Analyse du presse-papiers
- **volatility -f dump.mem --profile=ProfileName screenshot** : Capture d'écran de la session utilisateur
- **volatility -f dump.mem --profile=ProfileName memdump -p ProcessID -D /destination/folder/** : Extraction de la mémoire d'un processus
- **volatility -f dump.mem --profile=ProfileName dumpfiles -Q AddressRange -D /destination/folder/** : Extraction de fichiers en mémoire
- **volatility -f dump.mem --profile=ProfileName dumpregistry -o /destination/folder/** : Extraction de la base de registre
- **volatility -f dump.mem --profile=ProfileName dumpcerts -D /destination/folder/** : Extraction des certificats
- **volvatility -f dump.mem --profile=ProfileName yarascan -Y RuleFile** : Analyse avec Yara
- **volatility -f dump.mem --profile=ProfileName yarascan -Y RuleFile -f AddressRange** : Analyse avec Yara sur une plage mémoire
- **volatility -f dump.mem --profile=ProfileName yarascan -Y RuleFile -p ProcessID** : Analyse avec Yara sur un processus
- **volatility -f dump.mem --profile=ProfileName yarascan -Y RuleFile -f AddressRange -p ProcessID** : Analyse avec Yara sur une plage mémoire et un processus
- **volatility -f dump.mem --profile=ProfileName malfind -D /destination/folder/** : Recherche de code malveillant dans les processus et extraction
- **volatility -f dump.mem --profile=ProfileName malfind -p ProcessID -D /destination/folder/** : Recherche de code malveillant dans un processus et extraction
- **volatility -f dump.mem --profile=ProfileName malfind -Y RuleFile** : Recherche de code malveillant avec Yara
- **volatility -f dump.mem --profile=ProfileName malfind -Y RuleFile -D /destination/folder/** : Recherche de code malveillant avec Yara et extraction
- **volatility -f dump.mem --profile=ProfileName malfind -Y RuleFile -p ProcessID -D /destination/folder/** : Recherche de code malveillant avec Yara dans un processus et extraction
- **volatility -f dump.mem --profile=ProfileName malfind -D /destination/folder/** : Recherche de code malveillant dans les processus et extraction
- **volatility -f dump.mem --profile=ProfileName malfind -p ProcessID -D /destination/folder/** : Recherche de code malveillant dans un processus et extraction
- **volatility -f dump.mem --profile=ProfileName malfind -Y RuleFile** : Recherche de code malveillant avec Yara
- **volatility -f dump.mem --profile=ProfileName malfind -Y RuleFile -D /destination/folder/** : Recherche de code malveillant avec Yara et extraction
- **volatility -f dump.mem --profile=ProfileName malfind -Y RuleFile -p ProcessID -D /destination/folder/** : Recherche de code malveillant avec Yara dans un processus et extraction

### Plugins supplémentaires

- **[Volatility Plugins](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)** : Référence des commandes supplémentaires
- **[Volatility Foundation](https://www.volatilityfoundation.org/)** : Site officiel de Volatility
- **[Volatility GitHub](https://github.com/volatilityfoundation/volatility)** : Dépôt GitHub de Volatility

{% endtab %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### Pilotes
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
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
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
Le **Master Boot Record (MBR)** joue un rôle crucial dans la gestion des partitions logiques d'un support de stockage, qui sont structurées avec différents [systèmes de fichiers](https://fr.wikipedia.org/wiki/Syst%C3%A8me_de_fichiers). Il contient non seulement des informations sur la disposition des partitions, mais également du code exécutable agissant comme un chargeur de démarrage. Ce chargeur de démarrage initie directement le processus de chargement de la deuxième étape du système d'exploitation (voir [chargeur de démarrage de deuxième étape](https://fr.wikipedia.org/wiki/Chargeur_de_d%C3%A9marrage_de_deuxi%C3%A8me_%C3%A9tape)) ou fonctionne en harmonie avec l'enregistrement de démarrage de volume ([Volume Boot Record](https://fr.wikipedia.org/wiki/Volume_boot_record)) (VBR) de chaque partition. Pour des connaissances approfondies, consultez la [page Wikipedia sur le MBR](https://fr.wikipedia.org/wiki/Master_boot_record).

## Références
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
​* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement le plus pertinent en matière de cybersécurité en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez** 💬 le groupe Discord](https://discord.gg/hRep4RUj7f) ou le groupe [**telegram**](https://t.me/peass) ou suivez-nous sur Twitter 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
