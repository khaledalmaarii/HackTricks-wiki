# Volatility - Feuille de triche

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

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

[**À partir d'ici**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Contrairement à imageinfo qui fournit simplement des suggestions de profil, **kdbgscan** est conçu pour identifier positivement le profil correct et l'adresse KDBG correcte (s'il y en a plusieurs). Ce plugin recherche les signatures KDBGHeader liées aux profils de Volatility et applique des vérifications de cohérence pour réduire les faux positifs. La verbosité de la sortie et le nombre de vérifications de cohérence pouvant être effectuées dépendent de la capacité de Volatility à trouver un DTB, donc si vous connaissez déjà le bon profil (ou si vous avez une suggestion de profil à partir de imageinfo), assurez-vous de l'utiliser à partir de .

Jetez toujours un œil au **nombre de processus trouvés par kdbgscan**. Parfois, imageinfo et kdbgscan peuvent trouver **plus d'un** **profil** approprié, mais seul le **bon aura des processus associés** (Cela est dû au fait que pour extraire des processus, l'adresse KDBG correcte est nécessaire)
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

Le dump de mémoire d'un processus va **extraire tout** de l'état actuel du processus. Le module **procdump** va seulement **extraire** le **code**.
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
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil filescan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil cmdline**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil consoles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil connections**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil modscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ldrmodules**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil userassist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil shimcache**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil hivelist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil printkey**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil hivedump -o OffSet -s 0x1000 -l 1000 -D Dossier_de_sortie**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil dumpfiles -Q OffSet -D Dossier_de_sortie**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil memdump -p PID -D Dossier_de_sortie**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil memmap**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil memstrings -s Chaine_de_recherche**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Analyse du dump de mémoire

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
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
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil netscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil connections**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil consoles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil getsids**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil hivelist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil printkey**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil hashdump**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil userassist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil shimcache**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ldrmodules**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil modscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil apihooks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil timers**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### Ligne de commande

Est-ce que quelque chose de suspect a été exécuté ? 

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %} 

### Feuille de triche Volatility

#### Commandes de base

- **volatility -f dump.raw imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.raw pslist** : Liste des processus en cours d'exécution
- **volatility -f dump.raw pstree** : Arborescence des processus
- **volatility -f dump.raw psscan** : Analyse des processus supprimés
- **volatility -f dump.raw dlllist -p PID** : Liste des DLL chargées par un processus
- **volatility -f dump.raw filescan** : Analyse des fichiers ouverts
- **volatility -f dump.raw cmdline -p PID** : Ligne de commande d'un processus
- **volatility -f dump.raw netscan** : Liste des connexions réseau
- **volatility -f dump.raw connections** : Analyse des connexions réseau
- **volatility -f dump.raw malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.raw autoruns** : Liste des programmes s'exécutant au démarrage
- **volatility -f dump.raw timeliner** : Chronologie des événements
- **volatility -f dump.raw hivelist** : Liste des fichiers de registre chargés en mémoire
- **volatility -f dump.raw printkey -o OFFSET** : Afficher les valeurs d'une clé de registre
- **volatility -f dump.raw userassist** : Liste des programmes utilisés par l'utilisateur
- **volatility -f dump.raw clipboard** : Analyse du presse-papiers
- **volatility -f dump.raw screenshot** : Capture d'écran de l'interface graphique
- **volatility -f dump.raw memdump -p PID -D /path/to/dump/** : Extraction de la mémoire d'un processus

#### Plugins supplémentaires

- **volatility -f dump.raw shimcacheparser** : Analyse de la base de données de compatibilité des applications
- **volatility -f dump.raw ldrmodules** : Liste des modules chargés dynamiquement
- **volatility -f dump.raw modscan** : Analyse des modules noyau
- **volatility -f dump.raw getsids** : Liste des SID des processus
- **volatility -f dump.raw envars** : Variables d'environnement des processus
- **volatility -f dump.raw vadinfo -p PID** : Informations sur les espaces d'adressage virtuel d'un processus
- **volatility -f dump.raw mutantscan** : Analyse des objets de mutation
- **volatility -f dump.raw atomscan** : Analyse des objets atomiques
- **volatility -f dump.raw driverirp** : Liste des IRP gérés par les pilotes
- **volatility -f dump.raw devicetree** : Arborescence des périphériques
- **volatility -f dump.raw ssdt** : Table des services du noyau
- **volatility -f dump.raw callbacks** : Liste des callbacks du noyau
- **volatility -f dump.raw gdt** : Table globale des descripteurs
- **volatility -f dump.raw idt** : Table des descripteurs d'interruption
- **volatility -f dump.raw threads** : Liste des threads
- **volatility -f dump.raw handles** : Liste des handles système
- **volatility -f dump.raw mutantscan** : Analyse des objets de mutation
- **volatility -f dump.raw atomscan** : Analyse des objets atomiques
- **volatility -f dump.raw driverirp** : Liste des IRP gérés par les pilotes
- **volatility -f dump.raw devicetree** : Arborescence des périphériques
- **volatility -f dump.raw ssdt** : Table des services du noyau
- **volatility -f dump.raw callbacks** : Liste des callbacks du noyau
- **volatility -f dump.raw gdt** : Table globale des descripteurs
- **volatility -f dump.raw idt** : Table des descripteurs d'interruption
- **volatility -f dump.raw threads** : Liste des threads
- **volatility -f dump.raw handles** : Liste des handles système

{% endtab %}
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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- `volatility -f <dumpfile> imageinfo` : Afficher les informations de l'image mémoire
- `volatility -f <dumpfile> pslist` : Afficher la liste des processus
- `volatility -f <dumpfile> pstree` : Afficher l'arborescence des processus
- `volatility -f <dumpfile> psscan` : Analyser les processus inactifs
- `volatility -f <dumpfile> dlllist -p <PID>` : Afficher les DLL chargées par un processus
- `volatility -f <dumpfile> cmdline -p <PID>` : Afficher la ligne de commande d'un processus
- `volatility -f <dumpfile> filescan` : Analyser les fichiers ouverts
- `volatility -f <dumpfile> netscan` : Analyser les connexions réseau
- `volatility -f <dumpfile> connections` : Afficher les connexions réseau
- `volatility -f <dumpfile> timeliner` : Analyser les artefacts temporels
- `volatility -f <dumpfile> malfind` : Identifier les injections de code malveillant
- `volatility -f <dumpfile> yarascan` : Analyser la mémoire à l'aide de règles YARA
- `volatility -f <dumpfile> dumpfiles -Q <address>` : Extraire un fichier en mémoire
- `volatility -f <dumpfile> memdump -p <PID> -D <output_directory>` : Extraire l'espace mémoire d'un processus

### Plugins supplémentaires

- `apihooks` : Identifier les hooks d'API
- `malfind` : Identifier les injections de code malveillant
- `mimikatz` : Rechercher les traces de Mimikatz
- `autoruns` : Identifier les programmes s'exécutant au démarrage
- `svcscan` : Analyser les services
- `modscan` : Analyser les modules noyau
- `driverirp` : Analyser les requêtes IRP des pilotes
- `ssdt` : Afficher la table de service du système
- `callbacks` : Identifier les callbacks du noyau
- `devicetree` : Afficher l'arborescence des périphériques
- `printkey` : Afficher les clés de registre
- `hivelist` : Afficher les hives de registre chargées
- `hashdump` : Extraire les hachages de mots de passe
- `userassist` : Analyser les entrées UserAssist
- `shellbags` : Analyser les informations des dossiers Windows
- `getsids` : Afficher les SID des processus
- `getsids` : Afficher les SID des processus
- `getsids` : Afficher les SID des processus

{% endtab %}
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
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

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

- **volatility -f dump.raw imageinfo** : Affiche des informations générales sur l'image mémoire.
- **volatility -f dump.raw pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.raw psscan** : Recherche les processus supprimés.
- **volatility -f dump.raw dlllist -p PID** : Liste les DLL chargées par un processus spécifique.
- **volatility -f dump.raw filescan** : Recherche les fichiers ouverts par les processus.
- **volatility -f dump.raw cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique.
- **volatility -f dump.raw netscan** : Recherche les connexions réseau.
- **volatility -f dump.raw connections** : Affiche les connexions réseau.
- **volatility -f dump.raw timeliner** : Crée une timeline des activités du système.
- **volatility -f dump.raw malfind** : Recherche les injections de code malveillant.
- **volatility -f dump.raw apihooks** : Recherche les hooks d'API.
- **volatility -f dump.raw ldrmodules** : Liste les modules chargés par les processus.
- **volatility -f dump.raw mutantscan** : Recherche les objets de synchronisation (mutants).
- **volatility -f dump.raw yarascan** : Recherche de motifs Yara dans l'image mémoire.
- **volatility -f dump.raw screenshot** : Prend une capture d'écran du bureau.
- **volatility -f dump.raw hivelist** : Liste les hives de registre.
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les sous-clés et valeurs d'une clé de registre.
- **volatility -f dump.raw userassist** : Affiche les entrées UserAssist.
- **volatility -f dump.raw shimcache** : Affiche les entrées ShimCache.
- **volatility -f dump.raw getsids** : Affiche les SID des processus.
- **volatility -f dump.raw modscan** : Recherche les modules noyau.
- **volatility -f dump.raw driverirp** : Affiche les IRPHandlers des drivers.
- **volatility -f dump.raw ssdt** : Affiche la table de services du noyau (SSDT).
- **volatility -f dump.raw callbacks** : Affiche les callbacks du noyau.
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques.
- **volatility -f dump.raw hivescan** : Recherche les hives de registre non rattachés.
- **volatility -f dump.raw poolscanner** : Recherche les allocations de pool.
- **volatility -f dump.raw envars** : Affiche les variables d'environnement.
- **volatility -f dump.raw vadinfo -p PID** : Affiche les informations VAD d'un processus.
- **volatility -f dump.raw vadtree -p PID** : Affiche l'arborescence VAD d'un processus.
- **volatility -f dump.raw handles -p PID** : Affiche les handles d'un processus.
- **volatility -f dump.raw dumpfiles -Q PATH** : Extrait les fichiers en mémoire correspondant à un chemin spécifique.
- **volatility -f dump.raw memdump -p PID -D /path/to/dump/** : Effectue un dump de la mémoire d'un processus.
- **volatility -f dump.raw memmap** : Affiche la carte mémoire du système.
- **volatility -f dump.raw mftparser** : Analyse le Master File Table (MFT).
- **volatility -f dump.raw shimcachemem** : Recherche les entrées ShimCache en mémoire.
- **volatility -f dump.raw userhandles -p PID** : Affiche les handles utilisateur d'un processus.
- **volatility -f dump.raw userhandles** : Affiche les handles utilisateur.
- **volatility -f dump.raw vadwalk -p PID** : Effectue une marche VAD pour un processus.
- **volatility -f dump.raw dumpregistry -o OFFSET -D /path/to/dump/** : Extrait une ruche de registre en mémoire.
- **volatility -f dump.raw dumpcerts -D /path/to/dump/** : Extrait les certificats en mémoire.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -D /path/to/dump/** : Extrait une ruche de registre en mémoire avec une taille spécifique.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f hive -D /path/to/dump/** : Extrait une ruche de registre en mémoire avec une taille spécifique et un format spécifique.

### Plugins supplémentaires

- **volatility -f dump.raw --profile=PROFILE pluginname** : Utilise un plugin spécifique avec un profil spécifié.
- **volatility -f dump.raw --plugins=/path/to/plugins/ pluginname** : Charge des plugins supplémentaires à partir d'un répertoire spécifique.
- **volatility -f dump.raw --conf=/path/to/volatility.conf pluginname** : Utilise une configuration spécifique pour le plugin.

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

- **volatility -f dump.raw imageinfo** : Affiche des informations générales sur l'image mémoire.
- **volatility -f dump.raw pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.raw psscan** : Recherche les processus supprimés.
- **volatility -f dump.raw dlllist -p PID** : Liste les DLL chargées par un processus spécifique.
- **volatility -f dump.raw filescan** : Recherche les fichiers ouverts par les processus.
- **volatility -f dump.raw cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique.
- **volatility -f dump.raw netscan** : Recherche les connexions réseau.
- **volatility -f dump.raw connections** : Affiche les connexions réseau.
- **volatility -f dump.raw timeliner** : Crée une timeline des activités du système.
- **volatility -f dump.raw malfind** : Recherche les injections de code malveillant.
- **volatility -f dump.raw apihooks** : Recherche les hooks API.
- **volatility -f dump.raw ldrmodules** : Liste les modules chargés par les processus.
- **volatility -f dump.raw mutantscan** : Recherche les objets de mutation.
- **volatility -f dump.raw yarascan** : Recherche les correspondances YARA.
- **volatility -f dump.raw screenshot** : Capture un screenshot de l'écran.
- **volatility -f dump.raw hivelist** : Liste les hives de registre.
- **volatility -f dump.raw printkey -o OFFSET** : Affiche le contenu d'une clé de registre.
- **volatility -f dump.raw userassist** : Affiche les entrées UserAssist.
- **volatility -f dump.raw shimcache** : Affiche les entrées ShimCache.
- **volatility -f dump.raw getsids** : Affiche les SID des processus.
- **volatility -f dump.raw modscan** : Recherche les modules noyau.
- **volatility -f dump.raw driverirp** : Affiche les IRP des pilotes.
- **volatility -f dump.raw ssdt** : Affiche la table de service du noyau.
- **volatility -f dump.raw callbacks** : Affiche les callbacks du noyau.
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques.
- **volatility -f dump.raw hivescan** : Recherche les hives de registre non rattachées.
- **volatility -f dump.raw userhandles -p PID** : Affiche les handles utilisateur d'un processus.
- **volatility -f dump.raw vadinfo -p PID** : Affiche les informations VAD d'un processus.
- **volatility -f dump.raw vadtree -p PID** : Affiche l'arborescence VAD d'un processus.
- **volatility -f dump.raw vadwalk -p PID** : Affiche les régions VAD d'un processus.
- **volatility -f dump.raw dlldump -p PID -D /path/to/dumpdir/** : Dump les DLL d'un processus.
- **volatility -f dump.raw procdump -p PID -D /path/to/dumpdir/** : Dump un processus.
- **volatility -f dump.raw memdump -p PID -D /path/to/dumpdir/** : Dump la mémoire d'un processus.
- **volatility -f dump.raw memmap -p PID** : Affiche la carte mémoire d'un processus.
- **volatility -f dump.raw memmap** : Affiche la carte mémoire de l'ensemble du système.

### Plugins supplémentaires

- **volatility -f dump.raw plugin_name** : Exécute un plugin spécifique.

### Astuces

- Utilisez les plugins supplémentaires pour une analyse plus approfondie.
- Comparez les résultats avec des sources fiables pour valider les informations extraites.
- Documentez soigneusement chaque étape de l'analyse pour référence future.

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

{% onglet title="vol2" %}
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
{% endtab %}
{% endtabs %}

Il permet également de rechercher des chaînes de caractères à l'intérieur d'un processus en utilisant le module yarascan:
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

**Windows** garde une trace des programmes que vous exécutez en utilisant une fonctionnalité dans le registre appelée **clés UserAssist**. Ces clés enregistrent combien de fois chaque programme est exécuté et quand il a été lancé pour la dernière fois.
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

​​​​[**RootedCON**](https://www.rootedcon.com/) est l'événement le plus pertinent en matière de cybersécurité en **Espagne** et l'un des plus importants en **Europe**. Avec pour **mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

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
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil printkey**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil hashdump**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil userassist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil shimcache**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
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
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**

#### Plugins supplémentaires

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil plugin_name options**

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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.mem imageinfo** : Affiche des informations générales sur l'image mémoire
- **volatility -f dump.mem pslist** : Liste les processus en cours d'exécution
- **volatility -f dump.mem psscan** : Examine les processus inactifs
- **volatility -f dump.mem pstree** : Affiche les processus sous forme d'arborescence
- **volatility -f dump.mem dlllist -p PID** : Liste les DLL chargées par un processus spécifique
- **volatility -f dump.mem cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique
- **volatility -f dump.mem filescan** : Analyse les fichiers ouverts par les processus
- **volatility -f dump.mem netscan** : Recherche les connexions réseau actives
- **volatility -f dump.mem connections** : Affiche les connexions réseau
- **volatility -f dump.mem timeliner** : Crée une chronologie des activités à partir de l'image mémoire
- **volatility -f dump.mem malfind** : Recherche les indicateurs de programmes malveillants
- **volatility -f dump.mem cmdline** : Affiche les commandes exécutées
- **volatility -f dump.mem consoles** : Recherche les consoles virtuelles
- **volatility -f dump.mem hivelist** : Liste les hôtes de registre
- **volatility -f dump.mem printkey -o OFFSET** : Affiche les valeurs de clé de registre à partir d'un décalage spécifique
- **volatility -f dump.mem userassist** : Extrait les entrées UserAssist du registre
- **volatility -f dump.mem shimcache** : Extrait les entrées de la cache de compatibilité des applications
- **volatility -f dump.mem ldrmodules** : Liste les modules chargés
- **volatility -f dump.mem modscan** : Recherche les modules noyau
- **volatility -f dump.mem getsids** : Affiche les SID des processus
- **volatility -f dump.mem apihooks** : Recherche les hooks API
- **volatility -f dump.mem mutantscan** : Recherche les objets de mutation
- **volatility -f dump.mem svcscan** : Recherche les services
- **volatility -f dump.mem driverirp** : Recherche les objets IRP des pilotes
- **volatility -f dump.mem ssdt** : Recherche la table de service du noyau
- **volatility -f dump.mem callbacks** : Recherche les callbacks du noyau
- **volatility -f dump.mem drivermodule** : Recherche les modules de pilote
- **volatility -f dump.mem devicetree** : Affiche l'arborescence des périphériques
- **volatility -f dump.mem threads** : Liste les threads
- **volatility -f dump.mem handles** : Recherche les descripteurs de fichiers et les objets
- **volatility -f dump.mem mutantscan** : Recherche les objets de mutation
- **volatility -f dump.mem yarascan** : Recherche les motifs Yara
- **volatility -f dump.mem dumpfiles -Q OFFSET -D /path/to/dump/dir/** : Extrait les fichiers à partir d'un décalage spécifique
- **volatility -f dump.mem memdump -p PID -D /path/to/dump/dir/** : Effectue un vidage mémoire d'un processus spécifique
- **volatility -f dump.mem memmap** : Affiche la carte mémoire
- **volatility -f dump.mem memstrings** : Recherche les chaînes dans la mémoire
- **volatility -f dump.mem mftparser** : Analyse le fichier MFT
- **volatility -f dump.mem hivelist** : Liste les hôtes de registre
- **volatility -f dump.mem printkey -o OFFSET** : Affiche les valeurs de clé de registre à partir d'un décalage spécifique
- **volatility -f dump.mem userassist** : Extrait les entrées UserAssist du registre
- **volatility -f dump.mem shimcache** : Extrait les entrées de la cache de compatibilité des applications
- **volatility -f dump.mem ldrmodules** : Liste les modules chargés
- **volatility -f dump.mem modscan** : Recherche les modules noyau
- **volatility -f dump.mem getsids** : Affiche les SID des processus
- **volatility -f dump.mem apihooks** : Recherche les hooks API
- **volatility -f dump.mem mutantscan** : Recherche les objets de mutation
- **volatility -f dump.mem svcscan** : Recherche les services
- **volatility -f dump.mem driverirp** : Recherche les objets IRP des pilotes
- **volatility -f dump.mem ssdt** : Recherche la table de service du noyau
- **volatility -f dump.mem callbacks** : Recherche les callbacks du noyau
- **volatility -f dump.mem drivermodule** : Recherche les modules de pilote
- **volatility -f dump.mem devicetree** : Affiche l'arborescence des périphériques
- **volatility -f dump.mem threads** : Liste les threads
- **volatility -f dump.mem handles** : Recherche les descripteurs de fichiers et les objets
- **volatility -f dump.mem mutantscan** : Recherche les objets de mutation
- **volatility -f dump.mem yarascan** : Recherche les motifs Yara
- **volatility -f dump.mem dumpfiles -Q OFFSET -D /path/to/dump/dir/** : Extrait les fichiers à partir d'un décalage spécifique
- **volatility -f dump.mem memdump -p PID -D /path/to/dump/dir/** : Effectue un vidage mémoire d'un processus spécifique
- **volatility -f dump.mem memmap** : Affiche la carte mémoire
- **volatility -f dump.mem memstrings** : Recherche les chaînes dans la mémoire
- **volatility -f dump.mem mftparser** : Analyse le fichier MFT

### Plugins supplémentaires

- **volatility -f dump.mem kdbgscan** : Recherche le KDBG
- **volatility -f dump.mem psxview** : Affiche les processus cachés
- **volatility -f dump.mem malfind** : Recherche les indicateurs de programmes malveillants
- **volatility -f dump.mem ldrmodules** : Liste les modules chargés
- **volatility -f dump.mem modscan** : Recherche les modules noyau
- **volatility -f dump.mem getsids** : Affiche les SID des processus
- **volatility -f dump.mem apihooks** : Recherche les hooks API
- **volatility -f dump.mem mutantscan** : Recherche les objets de mutation
- **volatility -f dump.mem svcscan** : Recherche les services
- **volatility -f dump.mem driverirp** : Recherche les objets IRP des pilotes
- **volatility -f dump.mem ssdt** : Recherche la table de service du noyau
- **volatility -f dump.mem callbacks** : Recherche les callbacks du noyau
- **volatility -f dump.mem drivermodule** : Recherche les modules de pilote
- **volatility -f dump.mem devicetree** : Affiche l'arborescence des périphériques
- **volatility -f dump.mem threads** : Liste les threads
- **volatility -f dump.mem handles** : Recherche les descripteurs de fichiers et les objets
- **volatility -f dump.mem mutantscan** : Recherche les objets de mutation
- **volatility -f dump.mem yarascan** : Recherche les motifs Yara
- **volatility -f dump.mem dumpfiles -Q OFFSET -D /path/to/dump/dir/** : Extrait les fichiers à partir d'un décalage spécifique
- **volatility -f dump.mem memdump -p PID -D /path/to/dump/dir/** : Effectue un vidage mémoire d'un processus spécifique
- **volatility -f dump.mem memmap** : Affiche la carte mémoire
- **volatility -f dump.mem memstrings** : Recherche les chaînes dans la mémoire
- **volatility -f dump.mem mftparser** : Analyse le fichier MFT

{% endtab %}
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

### Capture
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

{% onglet title="vol2" %}
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

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### Tableau principal des fichiers

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.raw imageinfo** : Afficher les informations de l'image mémoire
- **volatility -f dump.raw pslist** : Afficher la liste des processus
- **volatility -f dump.raw pstree** : Afficher l'arborescence des processus
- **volatility -f dump.raw psscan** : Scanner les processus cachés
- **volatility -f dump.raw dlllist -p PID** : Afficher les DLL chargées par un processus
- **volatility -f dump.raw filescan** : Scanner les fichiers ouverts
- **volatility -f dump.raw cmdline -p PID** : Afficher la ligne de commande d'un processus
- **volatility -f dump.raw netscan** : Scanner les connexions réseau
- **volatility -f dump.raw connections** : Afficher les connexions réseau
- **volatility -f dump.raw malfind** : Identifier les injections de code malveillant
- **volatility -f dump.raw shimcache** : Analyser le cache de compatibilité des applications
- **volatility -f dump.raw hivelist** : Afficher la liste des hôtes de registre
- **volatility -f dump.raw printkey -o OFFSET** : Afficher les valeurs d'une clé de registre
- **volatility -f dump.raw userassist** : Analyser les entrées UserAssist
- **volatility -f dump.raw timeliner** : Créer une timeline des activités
- **volatility -f dump.raw memdump -p PID -D /path/to/dump/** : Créer un dump de mémoire pour un processus spécifique

### Plugins supplémentaires

- **volatility -f dump.raw plugin_name** : Utiliser un plugin spécifique
- **volatility --plugins=/path/to/plugins -f dump.raw plugin_name** : Spécifier un chemin pour les plugins

### Analyse avancée

- **volatility -f dump.raw --profile=ProfileName cmd** : Utiliser un profil spécifique pour l'analyse
- **volatility -f dump.raw --profile=ProfileName -h** : Afficher les plugins disponibles pour un profil spécifique

{% endtab %}
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

- **volatility -f dump.mem shimcachemem** : Analyse la mémoire pour les entrées ShimCache
- **volatility -f dump.mem timeliner** : Crée une timeline des activités basée sur les horodatages
- **volatility -f dump.mem dumpregistry -o /path/to/output/** : Extrait la base de registre
- **volatility -f dump.mem dumpfiles -Q /path/to/output/** : Extrait les fichiers modifiés récemment
- **volatility -f dump.mem dumpcerts -D /path/to/output/** : Extrait les certificats
- **volatility -f dump.mem dumpcache -D /path/to/output/** : Extrait les fichiers en cache
- **volatility -f dump.mem dumpvad -D /path/to/output/** : Extrait les zones d'allocation virtuelle
- **volatility -f dump.mem yarascan -Y "rule_file.yar"** : Recherche de motifs avec YARA
- **volatility -f dump.mem malfind -Y "rule_file.yar"** : Recherche de code malveillant avec YARA

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

{% tab title="vol2" %} 

### Feuille de triche Volatility

#### Commandes de base

- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil commandes_volatility**

#### Analyse de la mémoire

- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil imageinfo**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil pslist**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil pstree**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil psscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil dlllist**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil getsids**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil filescan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil cmdline**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil consoles**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil connections**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil hivelist**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil printkey**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil hashdump -y 0xffffc00002f8e010**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil userassist**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil ldrmodules**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil modscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil fileinfo -f chemin_vers_le_fichier**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil dumpfiles -Q chemin_dossier_de_sortie -D chemin_dossier_de_sortie**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memdump -p PID -D chemin_dossier_de_sortie**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memmap**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memstrings -s chaine_de_recherche**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memhistory**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memtasks**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memmodules**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memsections**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memmap**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memstrings -s chaine_de_recherche**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memhistory**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memtasks**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memmodules**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memsections**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memmap**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memstrings -s chaine_de_recherche**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memhistory**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memtasks**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memmodules**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memsections**

#### Plugins supplémentaires

- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil kdbgscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil kpcrscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil hivescan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil shimcache**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil ldrmodules**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil modscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil fileinfo -f chemin_vers_le_fichier**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil dumpfiles -Q chemin_dossier_de_sortie -D chemin_dossier_de_sortie**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memdump -p PID -D chemin_dossier_de_sortie**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memmap**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memstrings -s chaine_de_recherche**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memhistory**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memtasks**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memmodules**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil memsections**

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

### Feuille de triche Volatility

#### Commandes de base

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
- **volatility -f dump.raw hivelist** : Liste des hives de registre
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les valeurs d'une clé de registre
- **volatility -f dump.raw userassist** : Informations sur les programmes utilisés par l'utilisateur
- **volatility -f dump.raw shimcache** : Liste des fichiers exécutés récemment
- **volatility -f dump.raw timeliner** : Lister les événements temporels
- **volatility -f dump.raw memdump -p PID -D /path/to/dump/** : Crée un dump mémoire d'un processus

#### Plugins supplémentaires

- **volatility -f dump.raw mimikatz** : Exécute Mimikatz sur l'image mémoire
- **volatility -f dump.raw truecryptmaster** : Récupère les clés TrueCrypt
- **volatility -f dump.raw hashdump** : Dump les mots de passe en mémoire
- **volatility -f dump.raw lsa_secrets** : Récupère les secrets LSA
- **volatility -f dump.raw apihooks** : Liste les API hookées
- **volatility -f dump.raw driverirp** : Analyse les IRP des drivers
- **volatility -f dump.raw ssdt** : Liste les adresses de la SSDT
- **volatility -f dump.raw callbacks** : Liste les callbacks du kernel
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques
- **volatility -f dump.raw modscan** : Analyse les modules noyau chargés
- **volatility -f dump.raw mutantscan** : Liste les objets de synchronisation
- **volatility -f dump.raw getsids** : Liste les SID des processus
- **volatility -f dump.raw envars** : Liste les variables d'environnement des processus
- **volatility -f dump.raw handles** : Liste les handles des processus
- **volatility -f dump.raw privs** : Liste les privilèges des processus
- **volatility -f dump.raw cmdline** : Liste les lignes de commande des processus
- **volatility -f dump.raw consoles** : Liste les consoles allouées
- **volatility -f dump.raw deskscan** : Liste les objets de bureau
- **volatility -f dump.raw idt** : Affiche la table d'adresses IDT
- **volatility -f dump.raw gdt** : Affiche la table de descripteurs GDT
- **volatility -f dump.raw threads** : Liste les threads
- **volatility -f dump.raw mutantscan** : Liste les objets de synchronisation
- **volatility -f dump.raw svcscan** : Liste les services
- **volatility -f dump.raw ssdeep** : Calcul de hash SSDeep pour les sections PE
- **volatility -f dump.raw yarascan** : Recherche de motifs Yara
- **volatility -f dump.raw autoruns** : Liste les programmes exécutés au démarrage
- **volatility -f dump.raw printkey -K 'ControlSet001\Control\ComputerName\ComputerName'** : Affiche la valeur d'une clé de registre spécifique

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

### Feuille de triche Volatility

#### Commandes de base

- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil command_name**

#### Analyse de la mémoire

- **imageinfo :** Affiche des informations générales sur l'image mémoire.
- **pslist :** Liste les processus en cours d'exécution.
- **pstree :** Affiche les processus sous forme d'arborescence.
- **psscan :** Recherche les processus supprimés.
- **dlllist :** Liste les DLL chargées pour chaque processus.
- **handles :** Affiche les handles ouverts par chaque processus.
- **cmdline :** Affiche les lignes de commande des processus.
- **filescan :** Recherche les fichiers ouverts par les processus.
- **netscan :** Recherche les connexions réseau.
- **connections :** Affiche les connexions réseau.
- **svcscan :** Recherche les services.
- **malfind :** Recherche les injections de code malveillant.
- **ldrmodules :** Liste les modules chargés.
- **apihooks :** Recherche les hooks d'API.
- **callbacks :** Recherche les callbacks du noyau.
- **devicetree :** Affiche l'arborescence des périphériques.
- **modscan :** Recherche les modules noyau.
- **ssdt :** Affiche la table de service du noyau.
- **driverirp :** Recherche les dispatch routines des pilotes.
- **printkey :** Affiche les clés de registre modifiées.
- **privs :** Affiche les privilèges des processus.
- **getsids :** Affiche les SID des processus.
- **dumpfiles :** Extrait les fichiers mémoire.
- **yarascan :** Recherche les motifs Yara.
- **memmap :** Affiche la carte mémoire.
- **vadinfo :** Affiche les informations sur les zones d'allocation virtuelle.
- **vaddump :** Extrait les zones d'allocation virtuelle.
- **vadtree :** Affiche les zones d'allocation virtuelle sous forme d'arborescence.
- **dlldump :** Extrait les DLL d'un processus.
- **dumpregistry :** Extrait les clés de registre.
- **dumpcerts :** Extrait les certificats.
- **consoles :** Affiche les consoles allouées.
- **hivelist :** Affiche les hives du registre.
- **hivedump :** Extrait un hive du registre.
- **hashdump :** Extrait les hachages de mots de passe.
- **userassist :** Affiche les entrées UserAssist.
- **shellbags :** Affiche les entrées ShellBags.
- **mbrparser :** Analyse le Master Boot Record.
- **mftparser :** Analyse la Master File Table.
- **usnparser :** Analyse le journal USN.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Recherche les atomes du système.
- **atomscan :** Re
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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.mem imageinfo** : Affiche des informations générales sur le dump mémoire
- **volatility -f dump.mem pslist** : Liste les processus en cours d'exécution
- **volatility -f dump.mem pstree** : Affiche les processus sous forme d'arborescence
- **volatility -f dump.mem psscan** : Recherche les processus dans le dump mémoire
- **volatility -f dump.mem dlllist -p PID** : Liste les DLL chargées par un processus spécifique
- **volatility -f dump.mem filescan** : Recherche les fichiers ouverts dans le dump mémoire
- **volatility -f dump.mem cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique
- **volatility -f dump.mem netscan** : Recherche les connexions réseau
- **volatility -f dump.mem connections** : Affiche les connexions réseau
- **volatility -f dump.mem malfind** : Recherche les injections de code malveillant
- **volatility -f dump.mem apihooks** : Recherche les hooks API
- **volatility -f dump.mem ldrmodules** : Liste les modules chargés
- **volatility -f dump.mem modscan** : Recherche les modules noyau
- **volatility -f dump.mem ssdt** : Affiche la table de service du noyau
- **volatility -f dump.mem callbacks** : Affiche les callbacks du noyau
- **volatility -f dump.mem driverirp** : Affiche les IRP gérés par les pilotes
- **volatility -f dump.mem devicetree** : Affiche l'arborescence des périphériques
- **volatility -f dump.mem printkey -K "ControlSet001\services"** : Affiche les clés de registre
- **volatility -f dump.mem hivelist** : Affiche les hives de registre
- **volatility -f dump.mem userassist** : Affiche les entrées UserAssist
- **volatility -f dump.mem shimcache** : Affiche les entrées ShimCache
- **volatility -f dump.mem getsids** : Affiche les SID des processus
- **volatility -f dump.mem getservicesids** : Affiche les SID des services
- **volatility -f dump.mem getsids -p PID** : Affiche les SID d'un processus spécifique
- **volatility -f dump.mem getsids -s SERVICE_NAME** : Affiche les SID d'un service spécifique

### Plugins supplémentaires

- **[Volatility Plugins](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)**: Référence des plugins supplémentaires disponibles

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

Il est possible de **lire l'historique bash en mémoire.** Vous pourriez également extraire le fichier _.bash\_history_, mais s'il est désactivé, vous serez heureux de pouvoir utiliser ce module de volatilité
```
./vol.py -f file.dmp linux.bash.Bash
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
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil netscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil connections**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil consoles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil getsids**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil hivelist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil printkey**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil hashdump**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil userassist**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil shimcache**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mftparser**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ldrmodules**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil modscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil yarascan**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil apihooks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil mutants**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil sockets**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil devicetree**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil drivermodule**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil ssdt**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_memoire --profile=Nom_du_profil handles**
- **vol
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

{% tab title="vol2" %}

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.raw imageinfo** : Affiche des informations générales sur l'image mémoire.
- **volatility -f dump.raw pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.raw psscan** : Recherche les processus supprimés.
- **volatility -f dump.raw dlllist -p PID** : Liste les DLL chargées par un processus spécifique.
- **volatility -f dump.raw filescan** : Recherche les fichiers ouverts par les processus.
- **volatility -f dump.raw cmdline -p PID** : Affiche la ligne de commande d'un processus.
- **volatility -f dump.raw netscan** : Recherche les connexions réseau.
- **volatility -f dump.raw connections** : Affiche les connexions réseau.
- **volatility -f dump.raw timeliner** : Crée une timeline des activités du système.
- **volatility -f dump.raw malfind** : Recherche les injections de code malveillant.
- **volatility -f dump.raw apihooks** : Recherche les hooks d'API.
- **volatility -f dump.raw ldrmodules** : Liste les modules chargés par les processus.
- **volatility -f dump.raw mutantscan** : Recherche les objets de synchronisation (mutants).
- **volatility -f dump.raw userassist** : Extrait les informations de l'UserAssist.
- **volatility -f dump.raw shimcache** : Extrait les entrées de la ShimCache.
- **volatility -f dump.raw hivelist** : Liste les hives du Registre.
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les sous-clés et valeurs d'une clé de Registre.
- **volatility -f dump.raw hashdump** : Extrait les hachages des mots de passe.
- **volatility -f dump.raw truecryptpassphrase** : Extrait les passphrases TrueCrypt.

### Plugins supplémentaires

- **volatility -f dump.raw --profile=PROFILE plugin_name** : Utilise un plugin spécifique avec un profil spécifié.
- **volatility -f dump.raw --plugins=PATH plugin_name** : Charge des plugins supplémentaires à partir d'un chemin spécifié.

### Analyse avancée

- **volatility -f dump.raw kdbgscan** : Recherche le KDBG (Kernel Debugger Block).
- **volatility -f dump.raw vadinfo -p PID** : Affiche des informations sur les espaces d'adressage virtuel d'un processus.
- **volatility -f dump.raw memmap** : Affiche la carte mémoire du système.
- **volatility -f dump.raw memdump -p PID -D /path/to/dump/** : Effectue un dump de la mémoire d'un processus spécifique.
- **volatility -f dump.raw memdump -p PID --dump-dir=/path/to/dump/** : Effectue un dump de la mémoire d'un processus spécifique dans un répertoire spécifié.

{% endtab %}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
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
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
Le **Master Boot Record (MBR)** joue un rôle crucial dans la gestion des partitions logiques d'un support de stockage, qui sont structurées avec différents [systèmes de fichiers](https://fr.wikipedia.org/wiki/Syst%C3%A8me_de_fichiers). Il contient non seulement des informations sur la disposition des partitions, mais également du code exécutable agissant comme un chargeur de démarrage. Ce chargeur de démarrage initie soit directement le processus de chargement de la deuxième étape du système d'exploitation (voir [deuxième chargeur de démarrage](https://fr.wikipedia.org/wiki/Deuxi%C3%A8me_chargeur_de_d%C3%A9marrage)) soit fonctionne en harmonie avec l'enregistrement d'amorçage de volume ([volume boot record](https://fr.wikipedia.org/wiki/Volume_boot_record)) (VBR) de chaque partition. Pour une connaissance approfondie, consultez la [page Wikipedia sur le MBR](https://fr.wikipedia.org/wiki/Master_boot_record).

# Références
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
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
* **Rejoignez** 💬 le groupe Discord](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
