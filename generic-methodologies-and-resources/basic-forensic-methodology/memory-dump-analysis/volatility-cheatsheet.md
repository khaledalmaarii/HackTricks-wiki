# Volatility - Fiche de triche

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
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

[**À partir d'ici**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Contrairement à imageinfo qui fournit simplement des suggestions de profil, **kdbgscan** est conçu pour identifier positivement le profil correct et l'adresse KDBG correcte (s'il y a plusieurs). Ce plugin recherche les signatures KDBGHeader liées aux profils de Volatility et applique des vérifications de cohérence pour réduire les faux positifs. La verbosité de la sortie et le nombre de vérifications de cohérence pouvant être effectuées dépendent de la capacité de Volatility à trouver un DTB, donc si vous connaissez déjà le profil correct (ou si vous avez une suggestion de profil à partir de imageinfo), assurez-vous de l'utiliser à partir de .

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

Le **bloc de débogage du noyau**, appelé **KDBG** par Volatility, est crucial pour les tâches forensiques effectuées par Volatility et divers débogueurs. Identifié sous le nom de `KdDebuggerDataBlock` et du type `_KDDEBUGGER_DATA64`, il contient des références essentielles comme `PsActiveProcessHead`. Cette référence spécifique pointe vers l'en-tête de la liste des processus, permettant ainsi l'énumération de tous les processus, ce qui est fondamental pour une analyse approfondie de la mémoire.

## Informations sur le système d'exploitation
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Le plugin `banners.Banners` peut être utilisé dans **vol3 pour essayer de trouver des bannières linux** dans le dump.

## Hashes/Mots de passe

Extraire les hachages SAM, les [informations d'identification mises en cache du domaine](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) et les [secrets lsa](../../../windows-hardening/authentication-credentials-uac-and-efs/#lsa-secrets).

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

- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil commandes_volatility**

### Analyse de la mémoire

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
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil netscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil hivelist**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil printkey**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil hashdump**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil userassist**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil shimcache**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil ldrmodules**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil modscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil malfind**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil apihooks**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil callbacks**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil svcscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil driverirp**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil idt**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil gdt**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil threads**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
- **volatility.exe -f chemin_vers_le_fichier_dumps --profile=Nom_du_profil mutantscan**
-
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Analyse du dump mémoire

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
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
- **volatility -f dump.raw getsids** : Liste les SID des processus
- **volatility -f dump.raw hivelist** : Liste les hives du Registre
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les informations d'une clé de Registre
- **volatility -f dump.raw userassist** : Liste les éléments UserAssist
- **volatility -f dump.raw shimcache** : Liste les entrées de la cache de compatibilité des applications
- **volatility -f dump.raw ldrmodules** : Liste les modules chargés par les processus
- **volatility -f dump.raw modscan** : Analyse des modules noyau non alloués
- **volatility -f dump.raw mutantscan** : Analyse des objets de synchronisation
- **volatility -f dump.raw svcscan** : Liste les services
- **volatility -f dump.raw driverirp** : Liste les IRP des pilotes
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques
- **volatility -f dump.raw handles** : Liste les handles des processus
- **volatility -f dump.raw vadinfo -p PID** : Informations sur les zones d'allocation virtuelle d'un processus
- **volatility -f dump.raw vadtree -p PID** : Affiche l'arborescence des zones d'allocation virtuelle d'un processus
- **volatility -f dump.raw cmdline** : Liste les lignes de commande des processus
- **volatility -f dump.raw consoles** : Liste les consoles des processus
- **volatility -f dump.raw envars** : Liste les variables d'environnement des processus
- **volatility -f dump.raw hivescan** : Analyse des hives du Registre non allouées
- **volatility -f dump.raw printkey -K KEY** : Affiche les informations d'une clé de Registre spécifique
- **volatility -f dump.raw printkey -f FILENAME** : Affiche les informations d'une clé de Registre à partir d'un fichier hive
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les informations d'une clé de Registre à partir d'un offset
- **volatility -f dump.raw printkey -k KEY** : Affiche les informations d'une clé de Registre spécifique
- **volatility -f dump.raw printkey -o OFFSET -s** : Affiche les informations d'une clé de Registre à partir d'un offset en mode silencieux
- **volatility -f dump.raw printkey -K KEY -s** : Affiche les informations d'une clé de Registre spécifique en mode silencieux
- **volatility -f dump.raw printkey -f FILENAME -s** : Affiche les informations d'une clé de Registre à partir d'un fichier hive en mode silencieux
- **volatility -f dump.raw printkey -o OFFSET -s -v** : Affiche les informations d'une clé de Registre à partir d'un offset en mode silencieux et verbeux
- **volatility -f dump.raw printkey -K KEY -s -v** : Affiche les informations d'une clé de Registre spécifique en mode silencieux et verbeux
- **volatility -f dump.raw printkey -f FILENAME -s -v** : Affiche les informations d'une clé de Registre à partir d'un fichier hive en mode silencieux et verbeux

#### Plugins supplémentaires

- **volatility -f dump.raw shimcachemem** : Analyse la mémoire de la cache de compatibilité des applications
- **volatility -f dump.raw userassist -profile=Win7SP1x64** : Liste les éléments UserAssist en spécifiant un profil
- **volatility -f dump.raw mftparser -o OFFSET** : Analyse la table de fichiers maîtres (MFT) à partir d'un offset
- **volatility -f dump.raw mftparser -f FILENAME** : Analyse la table de fichiers maîtres (MFT) à partir d'un fichier
- **volatility -f dump.raw mftparser -o OFFSET -s** : Analyse la table de fichiers maîtres (MFT) à partir d'un offset en mode silencieux
- **volatility -f dump.raw mftparser -f FILENAME -s** : Analyse la table de fichiers maîtres (MFT) à partir d'un fichier en mode silencieux
- **volatility -f dump.raw mftparser -o OFFSET -v** : Analyse la table de fichiers maîtres (MFT) à partir d'un offset en mode verbeux
- **volatility -f dump.raw mftparser -f FILENAME -v** : Analyse la table de fichiers maîtres (MFT) à partir d'un fichier en mode verbeux

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### Ligne de commande

Est-ce qu'il y a eu des exécutions suspectes ?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %} 

### Feuille de triche Volatility

#### Commandes de base

- **volatility -f dump.mem imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.mem hivelist** : Listes des hôtes de registre
- **volatility -f dump.mem --profile=Profile pslist** : Liste des processus en cours d'exécution
- **volatility -f dump.mem --profile=Profile pstree** : Affiche les processus sous forme d'arborescence
- **volatility -f dump.mem --profile=Profile psscan** : Recherche des processus supprimés
- **volatility -f dump.mem --profile=Profile dlllist -p PID** : Liste des DLL chargées par un processus
- **volatility -f dump.mem --profile=Profile cmdline -p PID** : Ligne de commande d'un processus
- **volatility -f dump.mem --profile=Profile filescan** : Recherche des fichiers ouverts
- **volatility -f dump.mem --profile=Profile netscan** : Recherche des connexions réseau
- **volatility -f dump.mem --profile=Profile connections** : Liste des connexions réseau
- **volatility -f dump.mem --profile=Profile sockets** : Liste des sockets réseau
- **volatility -f dump.mem --profile=Profile malfind** : Recherche de processus suspects
- **volatility -f dump.mem --profile=Profile cmdline** : Liste des commandes exécutées
- **volatility -f dump.mem --profile=Profile consoles** : Liste des consoles interactives
- **volatility -f dump.mem --profile=Profile getsids** : Liste des SID des processus
- **volatility -f dump.mem --profile=Profile userassist** : Liste des éléments UserAssist
- **volatility -f dump.mem --profile=Profile shimcache** : Liste des entrées ShimCache
- **volatility -f dump.mem --profile=Profile ldrmodules** : Liste des modules chargés
- **volatility -f dump.mem --profile=Profile modscan** : Recherche des modules noyau
- **volatility -f dump.mem --profile=Profile mutantscan** : Recherche des objets de synchronisation
- **volatility -f dump.mem --profile=Profile ssdt** : Liste des fonctions de la table SSDT
- **volatility -f dump.mem --profile=Profile driverscan** : Recherche des pilotes chargés
- **volatility -f dump.mem --profile=Profile svcscan** : Recherche des services
- **volatility -f dump.mem --profile=Profile devicetree** : Affiche l'arborescence des périphériques
- **volatility -f dump.mem --profile=Profile printkey -o "REGISTRY_PATH"** : Affiche les valeurs d'une clé de registre
- **volatility -f dump.mem --profile=Profile screenshot -D /path/to/dump/screenshots/** : Capture d'écran du bureau
- **volatility -f dump.mem --profile=Profile memdump -p PID -D /path/to/dump/process/** : Extraction de la mémoire d'un processus
- **volatility -f dump.mem --profile=Profile memmap** : Cartographie de la mémoire physique
- **volatility -f dump.mem --profile=Profile memdump -D /path/to/dump/full/** : Extraction complète de la mémoire
- **volatility -f dump.mem --profile=Profile dumpfiles -Q 0xADDRESS -D /path/to/dump/files/** : Extraction de fichiers à partir d'une adresse mémoire
- **volatility -f dump.mem --profile=Profile dumpregistry -D /path/to/dump/registry/** : Extraction de la base de registre
- **volatility -f dump.mem --profile=Profile yarascan -Y "RULES_FILE"** : Analyse avec Yara
- **volatility -f dump.mem --profile=Profile procdump -p PID -D /path/to/dump/directory/** : Création d'un dump de processus
- **volatility -f dump.mem --profile=Profile dumpcerts -D /path/to/dump/certificates/** : Extraction des certificats
- **volatility -f dump.mem --profile=Profile dumpfiles -Q 0xADDRESS -D /path/to/dump/files/** : Extraction de fichiers à partir d'une adresse mémoire
- **volatility -f dump.mem --profile=Profile dumpregistry -D /path/to/dump/registry/** : Extraction de la base de registre
- **volatility -f dump.mem --profile=Profile yarascan -Y "RULES_FILE"** : Analyse avec Yara
- **volatility -f dump.mem --profile=Profile procdump -p PID -D /path/to/dump/directory/** : Création d'un dump de processus
- **volatility -f dump.mem --profile=Profile dumpcerts -D /path/to/dump/certificates/** : Extraction des certificats

#### Plugins supplémentaires

- **apihooks**
- **auditpol**
- **bigpools**
- **callbacks**
- **clipboard**
- **cmdscan**
- **consoles**
- **deskscan**
- **driverirp**
- **drivermodule**
- **driverscan**
- **envars**
- **eventhooks**
- **getsids**
- **handles**
- **hashdump**
- **hollowfind**
- **idt**
- **ldrmodules**
- **malfind**
- **memmap**
- **messagehooks**
- **moddump**
- **modscan**
- **mutantscan**
- **notepad**
- **objtypescan**
- **poolscanner**
- **printkey**
- **privs**
- **psxview**
- **qemuinfo**
- **screenshot**
- **shellbags**
- **shimcache**
- **sockets**
- **ssdt**
- **strings**
- **svcscan**
- **symlinkscan**
- **thrdscan**
- **threads**
- **timeliner**
- **unloadedmodules**
- **userassist**
- **userhandles**
- **vadinfo**
- **vaddump**
- **vadtree**
- **vadwalk**
- **verinfo**
- **windows**
- **wndscan**
- **yarascan**

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

### Feuille de triche Volatility

#### Commandes de base

- `volatility -f <dumpfile> imageinfo` : Afficher les informations de l'image mémoire
- `volatility -f <dumpfile> pslist` : Afficher la liste des processus
- `volatility -f <dumpfile> pstree` : Aff display the process tree
- `volatility -f <dumpfile> psscan` : Analyser les processus supprimés
- `volatility -f <dumpfile> dlllist -p <PID>` : Afficher les DLL chargées par un processus
- `volatility -f <dumpfile> cmdline -p <PID>` : Afficher la ligne de commande d'un processus
- `volatility -f <dumpfile> filescan` : Analyser les fichiers ouverts
- `volatility -f <dumpfile> netscan` : Analyser les connexions réseau
- `volatility -f <dumpfile> connections` : Afficher les connexions réseau
- `volatility -f <dumpfile> malfind` : Identifier les injections de code malveillant
- `volatility -f <dumpfile> apihooks` : Identifier les hooks API
- `volatility -f <dumpfile> ldrmodules` : Afficher les modules chargés
- `volatility -f <dumpfile> modscan` : Analyser les modules du noyau
- `volatility -f <dumpfile> shimcache` : Analyser le cache de compatibilité des applications
- `volatility -f <dumpfile> userassist` : Analyser les entrées UserAssist
- `volatility -f <dumpfile> hivelist` : Afficher les hôtes de registre
- `volatility -f <dumpfile> printkey -o <offset>` : Afficher les valeurs de clé de registre
- `volatility -f <dumpfile> hashdump` : Extraire les hachages de mot de passe
- `volatility -f <dumpfile> truecryptpassphrase` : Extraire les phrases de passe TrueCrypt
- `volatility -f <dumpfile> clipboard` : Analyser le contenu du presse-papiers
- `volatility -f <dumpfile> screenshot` : Capturer des captures d'écran
- `volatility -f <dumpfile> memdump -p <PID> -D <output_directory>` : Extraire le dump de mémoire d'un processus
- `volatility -f <dumpfile> memdump -p <PID> --output-file <output_file>` : Extraire le dump de mémoire d'un processus dans un fichier spécifique

#### Plugins supplémentaires

- `malfind` : Identifier les injections de code malveillant
- `apihooks` : Identifier les hooks API
- `ldrmodules` : Afficher les modules chargés
- `modscan` : Analyser les modules du noyau
- `shimcache` : Analyser le cache de compatibilité des applications
- `userassist` : Analyser les entrées UserAssist
- `hivelist` : Afficher les hôtes de registre
- `printkey` : Afficher les valeurs de clé de registre
- `hashdump` : Extraire les hachages de mot de passe
- `truecryptpassphrase` : Extraire les phrases de passe TrueCrypt
- `clipboard` : Analyser le contenu du presse-papiers
- `screenshot` : Capturer des captures d'écran
- `memdump` : Extraire le dump de mémoire d'un processus

{% endtab %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### Privilèges des jetons

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

- `volatility -f <dumpfile> imageinfo` : Informations sur l'image mémoire
- `volatility -f <dumpfile> pslist` : Liste des processus en cours d'exécution
- `volatility -f <dumpfile> psscan` : Analyse des processus supprimés
- `volatility -f <dumpfile> pstree` : Afficher les processus sous forme d'arborescence
- `volatility -f <dumpfile> dlllist -p <pid>` : Liste des DLL chargées par un processus
- `volatility -f <dumpfile> cmdline -p <pid>` : Ligne de commande d'un processus
- `volatility -f <dumpfile> filescan` : Analyse des fichiers ouverts
- `volatility -f <dumpfile> netscan` : Analyse des connexions réseau
- `volatility -f <dumpfile> connections` : Analyse des connexions réseau (alternative)
- `volatility -f <dumpfile> timeliner` : Lister les événements temporels
- `volatility -f <dumpfile> malfind` : Recherche de code malveillant dans les processus
- `volatility -f <dumpfile> yarascan` : Analyse de la mémoire à l'aide de règles Yara
- `volatility -f <dumpfile> dumpfiles -Q <address>` : Extraire un fichier en mémoire
- `volatility -f <dumpfile> memdump -p <pid> -D <output_directory>` : Extraire la mémoire d'un processus dans un répertoire de sortie

#### Plugins supplémentaires

- `apihooks` : Recherche de hooks dans les API
- `malfind` : Recherche de code malveillant dans les processus
- `malthfind` : Recherche de code malveillant dans l'espace utilisateur
- `apihooks` : Recherche de hooks dans les API
- `ldrmodules` : Afficher les modules chargés par les processus
- `svcscan` : Analyse des services
- `modscan` : Analyse des modules noyau
- `driverirp` : Afficher les IRP des pilotes
- `ssdt` : Afficher la table de services du noyau
- `callbacks` : Afficher les callbacks du noyau
- `devicetree` : Afficher l'arborescence des périphériques
- `printkey` : Afficher les clés de registre
- `hivelist` : Afficher les hives de registre
- `hashdump` : Extraire les hachages de mots de passe
- `userassist` : Afficher les entrées UserAssist
- `shellbags` : Afficher les entrées ShellBags
- `getsids` : Afficher les SID des processus
- `getsids` : Afficher les SID des processus
- `getsids` : Afficher les SID des processus

{% endtab %}
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

### Feuille de triche Volatility

#### Commandes de base

- `volatility -f <dumpfile> imageinfo` : Affiche des informations générales sur le dump mémoire.
- `volatility -f <dumpfile> pslist` : Liste les processus en cours d'exécution.
- `volatility -f <dumpfile> psscan` : Analyse les processus à partir de la mémoire physique.
- `volatility -f <dumpfile> pstree` : Affiche les processus sous forme d'arborescence.
- `volatility -f <dumpfile> dlllist -p <pid>` : Liste les DLL chargées par un processus spécifique.
- `volatility -f <dumpfile> cmdline -p <pid>` : Affiche la ligne de commande d'un processus spécifique.
- `volatility -f <dumpfile> filescan` : Analyse les fichiers ouverts par les processus.
- `volatility -f <dumpfile> netscan` : Analyse les connexions réseau.
- `volatility -f <dumpfile> connections` : Affiche les connexions réseau.
- `volatility -f <dumpfile> malfind` : Recherche de code malveillant dans les processus.
- `volatility -f <dumpfile> apihooks` : Recherche les hooks d'API dans les processus.
- `volatility -f <dumpfile> ldrmodules` : Liste les modules chargés par les processus.
- `volatility -f <dumpfile> modscan` : Analyse les modules du noyau.
- `volatility -f <dumpfile> shimcache` : Analyse le cache de compatibilité des applications.
- `volatility -f <dumpfile> userassist` : Analyse les entrées UserAssist.
- `volatility -f <dumpfile> hivelist` : Liste les hives de registre.
- `volatility -f <dumpfile> printkey -o <offset>` : Affiche les sous-clés et valeurs d'une clé de registre.
- `volatility -f <dumpfile> hashdump` : Extrait les hachages de mots de passe.
- `volatility -f <dumpfile> truecryptpassphrase` : Recherche les passphrases TrueCrypt.
- `volatility -f <dumpfile> clipboard` : Extrait le contenu du presse-papiers.
- `volatility -f <dumpfile> screenshot` : Capture un instantané de l'écran.
- `volatility -f <dumpfile> memdump -p <pid> -D <output_directory>` : Effectue un dump mémoire d'un processus spécifique.
- `volatility -f <dumpfile> memmap` : Affiche la carte mémoire du système.
- `volatility -f <dumpfile> memstrings` : Recherche de chaînes ASCII dans la mémoire.
- `volatility -f <dumpfile> yarascan -Y "<rule>"` : Analyse la mémoire à l'aide de règles YARA.
- `volatility -f <dumpfile> cmdline` : Affiche les commandes exécutées.
- `volatility -f <dumpfile> consoles` : Affiche les consoles interactives.
- `volatility -f <dumpfile> getsids` : Affiche les SID des processus.
- `volatility -f <dumpfile> handles` : Affiche les handles des processus.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant.
- `volatility -f <dumpfile> mutantscan` : Analyse les objets mutant
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

{% onglet title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### Bibliothèques Dynamiques (DLL)

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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.raw imageinfo** : Affiche des informations générales sur l'image mémoire.
- **volatility -f dump.raw pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.raw psscan** : Examine les processus inactifs.
- **volatility -f dump.raw dlllist -p PID** : Liste les DLL chargées par un processus spécifique.
- **volatility -f dump.raw filescan** : Recherche les handles de fichiers.
- **volatility -f dump.raw cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique.
- **volatility -f dump.raw netscan** : Recherche les connexions réseau.
- **volatility -f dump.raw connections** : Affiche les connexions réseau.
- **volatility -f dump.raw timeliner** : Crée une timeline des activités du système.
- **volatility -f dump.raw malfind** : Recherche les indicateurs de fichiers malveillants.
- **volatility -f dump.raw apihooks** : Recherche les hooks d'API.
- **volatility -f dump.raw ldrmodules** : Liste les modules chargés par les processus.
- **volatility -f dump.raw mutantscan** : Recherche les objets de mutation.
- **volatility -f dump.raw yarascan** : Recherche les indicateurs Yara.
- **volatility -f dump.raw modscan** : Recherche les modules noyau.
- **volatility -f dump.raw ssdt** : Affiche la table de service du noyau.
- **volatility -f dump.raw callbacks** : Affiche les callbacks du noyau.
- **volatility -f dump.raw driverirp** : Affiche les IRP des pilotes.
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques.
- **volatility -f dump.raw hivelist** : Liste les hives de registre.
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les valeurs de clé de registre.
- **volatility -f dump.raw userassist** : Affiche les entrées UserAssist.
- **volatility -f dump.raw shimcache** : Affiche les entrées de la cache de compatibilité des applications.
- **volatility -f dump.raw getsids** : Affiche les SID des processus.
- **volatility -f dump.raw getservicesids** : Affiche les SID des services.
- **volatility -f dump.raw svcscan** : Recherche les services.
- **volatility -f dump.raw svcscan --verbose** : Recherche les services avec des informations détaillées.
- **volatility -f dump.raw envars** : Affiche les variables d'environnement des processus.
- **volatility -f dump.raw consoles** : Affiche les consoles des processus.
- **volatility -f dump.raw deskscan** : Recherche les objets de bureau.
- **volatility -f dump.raw hivescan** : Recherche les hives de registre non rattachées.
- **volatility -f dump.raw userhandles -p PID** : Affiche les handles utilisateur d'un processus spécifique.
- **volatility -f dump.raw vadinfo -p PID** : Affiche les informations VAD d'un processus spécifique.
- **volatility -f dump.raw vadtree -p PID** : Affiche l'arborescence VAD d'un processus spécifique.
- **volatility -f dump.raw vadwalk -p PID** : Affiche les régions VAD d'un processus spécifique.
- **volatility -f dump.raw dlldump -p PID -D /path/to/dumpdir/** : Extrait les DLL d'un processus spécifique.
- **volatility -f dump.raw procdump -p PID -D /path/to/dumpdir/** : Crée un dump mémoire d'un processus spécifique.
- **volatility -f dump.raw memdump -p PID -D /path/to/dumpdir/** : Crée un dump mémoire physique d'un processus spécifique.
- **volatility -f dump.raw memmap** : Affiche la carte mémoire.
- **volatility -f dump.raw memmap --profile=PROFILE** : Affiche la carte mémoire avec un profil spécifique.
- **volatility -f dump.raw memdump --dump-dir=/path/to/dumpdir/** : Crée un dump mémoire de l'ensemble de l'image.
- **volatility -f dump.raw memdump --dump-dir=/path/to/dumpdir/** --name=FILENAME.raw** : Crée un dump mémoire de l'ensemble de l'image avec un nom de fichier personnalisé.
- **volatility -f dump.raw hashdump** : Extrait les hachages de mots de passe.
- **volatility -f dump.raw hashdump --system=SYSTEM --sam=SAM** : Extrait les hachages de mots de passe à partir des fichiers SYSTEM et SAM.
- **volatility -f dump.raw truecryptpassphrase** : Extrait les passphrases TrueCrypt.
- **volatility -f dump.raw truecryptmaster** : Extrait la clé maître TrueCrypt.
- **volatility -f dump.raw bitlocker** : Extrait les clés de récupération BitLocker.
- **volatility -f dump.raw mimikatz** : Exécute Mimikatz dans l'espace mémoire.
- **volatility -f dump.raw mimikatz --command="command to execute"** : Exécute une commande Mimikatz spécifique dans l'espace mémoire.
- **volatility -f dump.raw shimcachemem** : Extrait la cache de compatibilité des applications en mémoire.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -D /path/to/dumpdir/** : Extrait une partie du registre.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f FILENAME** : Extrait une partie du registre dans un fichier spécifique.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f FILENAME --hive-offset=HIVEOFFSET** : Extrait une partie du registre dans un fichier spécifique avec un décalage de hive personnalisé.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f FILENAME --hive-offset=HIVEOFFSET --format=REG** : Extrait une partie du registre dans un fichier spécifique avec un format REG.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f FILENAME --hive-offset=HIVEOFFSET --format=REG --output=print** : Extrait une partie du registre dans un fichier spécifique avec un format REG et affiche le contenu.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f FILENAME --hive-offset=HIVEOFFSET --format=REG --output=print --output-file=OUTPUTFILE** : Extrait une partie du registre dans un fichier spécifique avec un format REG, affiche le contenu et enregistre la sortie dans un fichier.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f FILENAME --hive-offset=HIVEOFFSET --format=REG --output=print --output-file=OUTPUTFILE --no-output** : Extrait une partie du registre dans un fichier spécifique avec un format REG sans afficher le contenu.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f FILENAME --hive-offset=HIVEOFFSET --format=REG --output=print --output-file=OUTPUTFILE --no-output --no-strings** : Extrait une partie du registre dans un fichier spécifique avec un format REG sans afficher le contenu ni les chaînes.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f FILENAME --hive-offset=HIVEOFFSET --format=REG --output=print --output-file=OUTPUTFILE --no-output --no-strings --no-hexdump** : Extrait une partie du registre dans un fichier spécifique avec un format REG sans afficher le contenu, les chaînes ni le hexdump.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f FILENAME --hive-offset=HIVEOFFSET --format=REG --output=print --output-file=OUTPUTFILE --no-output --no-strings --no-hexdump --no-header** : Extrait une partie du registre dans un fichier spécifique avec un format REG sans afficher le contenu, les chaînes, le hexdump ni l'en-tête.
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f FILENAME --hive-offset=HIVEOFFSET --format=REG --output=print --output-file=OUTPUTFILE --no-output --no-strings --no-hexdump --no-header --no-banner** : Extrait une partie du registre dans un fichier spécifique avec un format REG sans afficher le contenu, les chaînes, le hexdump, l'en-tête ni la bannière.

### Plugins supplémentaires

- **volatility -f dump.raw windows.lsadump.Lsadump** : Extrait les hachages de mots de passe à partir de LSASS.
- **volatility -f dump.raw windows.lsadump.Lsadump --sam SAM --system SYSTEM** : Extrait les hachages de mots de passe à partir de LSASS en spécifiant les fichiers SAM et SYSTEM.
- **volatility -f dump.raw windows.mimikatz.Mimikatz** : Exécute Mimikatz dans l'espace mémoire.
- **volatility -f dump.raw windows.mimikatz.Mimikatz --command "command to execute"** : Exécute une commande Mimikatz spécifique dans l'espace mémoire.
- **volatility -f dump.raw windows.hashdump.Hashdump** : Extrait les hachages de mots de passe.
- **volatility -f dump.raw windows.registry.Registry -o OFFSET -s SIZE -f FILENAME** : Extrait une partie du registre.
- **volatility -f dump.raw windows.registry.Registry -o OFFSET -s SIZE -f FILENAME --hive-offset HIVEOFFSET** : Extrait une partie du registre en spécifiant un décalage de hive personnalisé.
- **volatility -f dump.raw windows.registry.Registry -o OFFSET -s SIZE -f FILENAME --hive-offset HIVEOFFSET --format REG** : Extrait une partie du registre avec un format REG.
- **volatility -f dump.raw windows.registry.Registry -o OFFSET -s SIZE -f FILENAME --hive-offset HIVEOFFSET --format REG --output print** : Extrait une partie du registre avec un format REG et affiche le contenu.
- **volatility -f dump.raw windows.registry.Registry -o OFFSET -s SIZE -f FILENAME --hive-offset HIVEOFFSET --format REG --output print --output-file OUTPUTFILE** : Extrait une partie du registre avec un format REG, affiche le contenu et enregistre la sortie dans un fichier.
- **volatility -f dump.raw windows.registry.Registry -o OFFSET -s SIZE -f FILENAME --hive-offset HIVEOFFSET --format REG --output print --output-file OUTPUTFILE --no-output** : Extrait une partie du registre avec un format REG sans afficher le contenu.
- **volatility -f dump.raw windows.registry.Registry -o OFFSET -s SIZE -f FILENAME --hive-offset HIVEOFFSET --format REG --output print --output-file OUTPUTFILE --no-output --no-strings** : Extrait une partie du registre avec un format REG sans afficher le contenu ni les chaînes.
- **volatility -f dump.raw windows.registry.Registry -o OFFSET -s SIZE -f FILENAME --hive-offset HIVEOFFSET --format REG --output print --output-file OUTPUTFILE --no-output --no-strings --no-hexdump** : Extrait une partie du registre avec un format REG sans afficher le contenu, les chaînes ni le hexdump.
- **volatility -f dump.raw windows.registry.Registry -o OFFSET -s SIZE -f FILENAME --hive-offset HIVEOFFSET --format REG --output print --output-file OUTPUTFILE --no-output --no-strings --no-hexdump --no-header** : Extrait une partie du registre avec un format REG sans afficher le contenu, les chaînes, le hexdump ni l'en-tête.
- **volatility -f dump.raw windows.registry.Registry -o OFFSET -s SIZE -f FILENAME --hive-offset HIVEOFFSET --format REG --output print --output-file OUTPUTFILE --no-output --no-strings --no-hexdump --no-header --no-banner** : Extrait une partie du registre avec un format REG sans afficher le contenu, les chaînes, le hexdump, l'en-tête ni la bannière.

{% endtab %}
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

- `volatility -f <dumpfile> imageinfo` : Informations sur l'image mémoire
- `volatility -f <dumpfile> pslist` : Liste des processus en cours d'exécution
- `volatility -f <dumpfile> pstree` : Arborescence des processus
- `volatility -f <dumpfile> psscan` : Analyse des processus
- `volatility -f <dumpfile> dlllist -p <PID>` : Liste des DLL chargées par un processus
- `volatility -f <dumpfile> cmdline -p <PID>` : Ligne de commande d'un processus
- `volatility -f <dumpfile> filescan` : Analyse des fichiers ouverts
- `volatility -f <dumpfile> netscan` : Analyse des connexions réseau
- `volatility -f <dumpfile> connections` : Analyse des connexions réseau (alternative)
- `volatility -f <dumpfile> malfind` : Recherche de code malveillant dans les processus
- `volatility -f <dumpfile> apihooks` : Détection des hooks API
- `volatility -f <dumpfile> ldrmodules` : Modules chargés par les processus
- `volatility -f <dumpfile> modscan` : Analyse des modules du noyau
- `volatility -f <dumpfile> shimcache` : Analyse du cache de compatibilité des applications
- `volatility -f <dumpfile> userassist` : Analyse des éléments récemment utilisés par l'utilisateur
- `volatility -f <dumpfile> hivelist` : Liste des hôtes de registre
- `volatility -f <dumpfile> printkey -o <offset>` : Affichage du contenu d'une clé de registre
- `volatility -f <dumpfile> hashdump` : Extraction des hachages de mots de passe
- `volatility -f <dumpfile> truecryptpassphrase` : Récupération des phrases de passe TrueCrypt
- `volatility -f <dumpfile> clipboard` : Analyse du presse-papiers
- `volatility -f <dumpfile> screenshot` : Capture d'écran de l'interface graphique
- `volatility -f <dumpfile> memdump -p <PID> -D <output_directory>` : Extraction de la mémoire d'un processus
- `volatility -f <dumpfile> memdump -p <PID> --output-file <output_file>` : Extraction de la mémoire d'un processus vers un fichier
- `volatility -f <dumpfile> memmap` : Cartographie de la mémoire physique
- `volatility -f <dumpfile> memmap --dump-dir <output_directory>` : Extraction de la mémoire physique
- `volatility -f <dumpfile> linux_bash` : Analyse de la mémoire d'un shell Bash Linux
- `volatility -f <dumpfile> linux_yarascan -Y <yara_rule_file>` : Analyse de la mémoire Linux avec YARA
- `volatility -f <dumpfile> linux_psaux` : Liste des processus Linux en cours d'exécution
- `volatility -f <dumpfile> linux_proc_maps -p <PID>` : Cartographie des segments mémoire d'un processus Linux
- `volatility -f <dumpfile> linux_proc_maps -p <PID> --dump-dir <output_directory>` : Extraction des segments mémoire d'un processus Linux
- `volatility -f <dumpfile> linux_check_afinfo` : Recherche de structures de données réseau Linux
- `volatility -f <dumpfile> linux_netscan` : Analyse des connexions réseau Linux
- `volatility -f <dumpfile> linux_ifconfig` : Affichage de la configuration réseau Linux
- `volatility -f <dumpfile> linux_route` : Affichage de la table de routage Linux
- `volatility -f <dumpfile> linux_netstat` : Affichage des statistiques réseau Linux
- `volatility -f <dumpfile> linux_dmesg` : Affichage des messages du noyau Linux
- `volatility -f <dumpfile> linux_lsmod` : Liste des modules Linux chargés
- `volatility -f <dumpfile> linux_check_creds` : Recherche des informations d'identification Linux
- `volatility -f <dumpfile> linux_check_syscall` : Recherche des appels système Linux
- `volatility -f <dumpfile> linux_list_files` : Liste des fichiers ouverts par les processus Linux
- `volatility -f <dumpfile> linux_pslist` : Liste des processus Linux en cours d'exécution
- `volatility -f <dumpfile> linux_pstree` : Arborescence des processus Linux
- `volatility -f <dumpfile> linux_cmdline -p <PID>` : Ligne de commande d'un processus Linux
- `volatility -f <dumpfile> linux_bash_history` : Historique des commandes Bash Linux
- `volatility -f <dumpfile> linux_hashdump` : Extraction des hachages de mots de passe Linux
- `volatility -f <dumpfile> linux_check_fop` : Recherche des opérations de fichiers Linux
- `volatility -f <dumpfile> linux_find_file -i <filename>` : Recherche de fichiers Linux
- `volatility -f <dumpfile> linux_find_file -i <filename> --dump-dir <output_directory>` : Extraction de fichiers Linux
- `volatility -f <dumpfile> linux_find_file -S <search_string>` : Recherche de chaînes dans les fichiers Linux
- `volatility -f <dumpfile> linux_find_file -S <search_string> --dump-dir <output_directory>` : Extraction de fichiers Linux contenant une chaîne
- `volatility -f <dumpfile> linux_check_evt` : Recherche des événements Linux
- `volatility -f <dumpfile> linux_check_inotify` : Recherche des notifications de système de fichiers Linux
- `volatility -f <dumpfile> linux_check_modules` : Recherche des modules Linux
- `volatility -f <dumpfile> linux_check_syscalltbl` : Recherche de la table des appels système Linux
- `volatility -f <dumpfile> linux_check_syscalltbl -D <output_directory>` : Extraction de la table des appels système Linux
- `volatility -f <dumpfile> linux_check_syscalltbl --output-file <output_file>` : Extraction de la table des appels système Linux vers un fichier
- `volatility -f <dumpfile> linux_check_tty` : Recherche des terminaux Linux
- `volatility -f <dumpfile> linux_check_creds` : Recherche des informations d'identification Linux
- `volatility -f <dumpfile> linux_check_afinfo` : Recherche des informations de socket réseau Linux
- `volatility -f <dumpfile> linux_check_fop` : Recherche des opérations de fichiers Linux
- `volatility -f <dumpfile> linux_check_idt` : Recherche de la table des descripteurs d'interruption Linux
- `volatility -f <dumpfile> linux_check_syscall` : Recherche des appels système Linux
- `volatility -f <dumpfile> linux_check_syscalltbl` : Recherche de la table des appels système Linux
- `volatility -f <dumpfile> linux_check_tty` : Recherche des terminaux Linux
- `volatility -f <dumpfile> linux_check_modules` : Recherche des modules Linux
- `volatility -f <dumpfile> linux_check_sysctl` : Recherche des paramètres du noyau Linux
- `volatility -f <dumpfile> linux_check_mount` : Recherche des points de montage Linux
- `volatility -f <dumpfile> linux_check_crash` : Recherche des informations de crash Linux
- `volatility -f <dumpfile> linux_check_dentry` : Recherche des entrées de répertoire Linux
- `volatility -f <dumpfile> linux_check_fileobject` : Recherche des objets de fichiers Linux
- `volatility -f <dumpfile> linux_check_fileobject -i <inode>` : Recherche des objets de fichiers Linux par inode
- `volatility -f <dumpfile> linux_check_fileobject -i <inode> --dump-dir <output_directory>` : Extraction des objets de fichiers Linux par inode
- `volatility -f <dumpfile> linux_check_fileobject -f <file>` : Recherche des objets de fichiers Linux par nom de fichier
- `volatility -f <dumpfile> linux_check_fileobject -f <file> --dump-dir <output_directory>` : Extraction des objets de fichiers Linux par nom de fichier
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string>` : Recherche des objets de fichiers Linux contenant une chaîne
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> --dump-dir <output_directory>` : Extraction des objets de fichiers Linux contenant une chaîne
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -f <file>` : Recherche des objets de fichiers Linux contenant une chaîne et correspondant à un nom de fichier
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -f <file> --dump-dir <output_directory>` : Extraction des objets de fichiers Linux correspondant à une chaîne et un nom de fichier
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -i <inode>` : Recherche des objets de fichiers Linux contenant une chaîne et correspondant à un inode
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -i <inode> --dump-dir <output_directory>` : Extraction des objets de fichiers Linux correspondant à une chaîne et un inode
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -i <inode> -f <file>` : Recherche des objets de fichiers Linux contenant une chaîne, un inode et correspondant à un nom de fichier
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -i <inode> -f <file> --dump-dir <output_directory>` : Extraction des objets de fichiers Linux correspondant à une chaîne, un inode et un nom de fichier
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -i <inode> -f <file> -t <type>` : Recherche des objets de fichiers Linux contenant une chaîne, un inode, un nom de fichier et un type
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -i <inode> -f <file> -t <type> --dump-dir <output_directory>` : Extraction des objets de fichiers Linux correspondant à une chaîne, un inode, un nom de fichier et un type
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -i <inode> -f <file> -t <type> -o <offset>` : Recherche des objets de fichiers Linux contenant une chaîne, un inode, un nom de fichier, un type et un offset
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -i <inode> -f <file> -t <type> -o <offset> --dump-dir <output_directory>` : Extraction des objets de fichiers Linux correspondant à une chaîne, un inode, un nom de fichier, un type et un offset
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -i <inode> -f <file> -t <type> -o <offset> -p <pid>` : Recherche des objets de fichiers Linux contenant une chaîne, un inode, un nom de fichier, un type, un offset et un PID
- `volatility -f <dumpfile> linux_check_fileobject -S <search_string> -i <inode> -f <file> -t <type> -o <offset> -p <pid> --dump-dir <output_directory>` : Extraction des objets de fichiers Linux correspondant à une chaîne, un inode, un nom de fichier, un type, un offset et un PID

### Plugins supplémentaires

- **Volatility** propose de nombreux autres plugins pour l'analyse de la mémoire. Consultez la documentation officielle pour une liste complète. 

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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.raw imageinfo** : Informations générales sur l'image mémoire
- **volatility -f dump.raw pslist** : Liste des processus en cours d'exécution
- **volatility -f dump.raw pstree** : Arborescence des processus
- **volatility -f dump.raw psscan** : Analyse des processus cachés
- **volatility -f dump.raw dlllist -p PID** : Liste des DLL chargées par un processus
- **volatility -f dump.raw filescan** : Analyse des fichiers ouverts
- **volatility -f dump.raw cmdline -p PID** : Ligne de commande d'un processus
- **volatility -f dump.raw netscan** : Liste des connexions réseau
- **volatility -f dump.raw connections** : Analyse des connexions réseau
- **volatility -f dump.raw malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.raw hivelist** : Liste des hives de registre
- **volatility -f dump.raw printkey -o OFFSET** : Afficher les valeurs d'une clé de registre
- **volatility -f dump.raw userassist** : Analyse des éléments récemment ouverts par l'utilisateur
- **volatility -f dump.raw shimcache** : Analyse du cache de compatibilité d'application
- **volatility -f dump.raw getsids** : Liste des SID des utilisateurs
- **volatility -f dump.raw apihooks** : Recherche de hooks d'API
- **volatility -f dump.raw mutantscan** : Analyse des objets de synchronisation
- **volatility -f dump.raw ldrmodules** : Liste des modules chargés
- **volatility -f dump.raw modscan** : Analyse des modules noyau
- **volatility -f dump.raw driverirp** : Analyse des IRP des pilotes
- **volatility -f dump.raw ssdt** : Analyse de la table de service du noyau
- **volatility -f dump.raw callbacks** : Analyse des callbacks du noyau
- **volatility -f dump.raw idt** : Afficher la table des descripteurs d'interruption
- **volatility -f dump.raw gdt** : Afficher la table des descripteurs globaux
- **volatility -f dump.raw threads** : Liste des threads
- **volatility -f dump.raw handles** : Liste des handles
- **volatility -f dump.raw mutantscan** : Analyse des objets de synchronisation
- **volatility -f dump.raw ldrmodules** : Liste des modules chargés
- **volatility -f dump.raw modscan** : Analyse des modules noyau
- **volatility -f dump.raw driverirp** : Analyse des IRP des pilotes
- **volatility -f dump.raw ssdt** : Analyse de la table de service du noyau
- **volatility -f dump.raw callbacks** : Analyse des callbacks du noyau
- **volatility -f dump.raw idt** : Afficher la table des descripteurs d'interruption
- **volatility -f dump.raw gdt** : Afficher la table des descripteurs globaux
- **volatility -f dump.raw threads** : Liste des threads
- **volatility -f dump.raw handles** : Liste des handles

### Plugins supplémentaires

- **volatility -f dump.raw shimcachemem** : Analyse du cache de compatibilité d'application en mémoire
- **volatility -f dump.raw mftparser** : Analyse du Master File Table (MFT)
- **volatility -f dump.raw hivelist -o OFFSET** : Afficher les valeurs d'une hive de registre spécifique
- **volvolatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f output.reg** : Extraire une hive de registre spécifique
- **volatility -f dump.raw dumpfiles -Q OFFSET -D dumpdir/** : Extraire des fichiers à partir d'une offset spécifique
- **volatility -f dump.raw dumpcerts -D dumpdir/** : Extraire des certificats
- **volatility -f dump.raw dumpregistry -o OFFSET -s SIZE -f output.reg** : Extraire une hive de registre spécifique
- **volatility -f dump.raw dumpfiles -Q OFFSET -D dumpdir/** : Extraire des fichiers à partir d'une offset spécifique
- **volatility -f dump.raw dumpcerts -D dumpdir/** : Extraire des certificats

{% endtab %}
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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- `volatility -f <dumpfile> imageinfo` : Affiche des informations générales sur le dump mémoire.
- `volatility -f <dumpfile> pslist` : Liste les processus en cours d'exécution.
- `volatility -f <dumpfile> pstree` : Affiche les processus sous forme d'arborescence.
- `volatility -f <dumpfile> psscan` : Recherche les processus supprimés.
- `volatility -f <dumpfile> dlllist -p <pid>` : Liste les DLL chargées par un processus.
- `volatility -f <dumpfile> cmdline -p <pid>` : Affiche la ligne de commande d'un processus.
- `volatility -f <dumpfile> filescan` : Recherche les handles de fichiers.
- `volatility -f <dumpfile> netscan` : Recherche les connexions réseau.
- `volatility -f <dumpfile> connections` : Affiche les connexions réseau.
- `volatility -f <dumpfile> timeliner` : Crée une timeline des activités du système.
- `volatility -f <dumpfile> malfind` : Recherche les indicateurs de fichiers malveillants.
- `volatility -f <dumpfile> yarascan` : Recherche les indicateurs Yara.

### Plugins supplémentaires

- `mimikatz` : Extrait les informations d'identification en mémoire.
- `dumpfiles` : Extrait les fichiers en mémoire.
- `apihooks` : Recherche les hooks d'API.
- `ldrmodules` : Affiche les modules chargés par les processus.
- `modscan` : Recherche les modules noyau chargés.
- `ssdt` : Affiche la table de service du système.
- `callbacks` : Recherche les callbacks du noyau.
- `driverirp` : Recherche les dispatch routines des pilotes.
- `printkey` : Affiche les clés de registre imprimées.
- `svcscan` : Recherche les services du système.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}

### Table des matières principale

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
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
- **volatility -f dump.raw filescan** : Recherche des handles de fichiers.
- **volatility -f dump.raw cmdline -p PID** : Affiche la ligne de commande d'un processus.
- **volatility -f dump.raw netscan** : Recherche les connexions réseau.
- **volatility -f dump.raw connections** : Affiche les connexions réseau.
- **volatility -f dump.raw timeliner** : Crée une timeline des activités du système.
- **volatility -f dump.raw malfind** : Recherche les injections de code malveillant.
- **volatility -f dump.raw apihooks** : Recherche les hooks d'API.
- **volatility -f dump.raw ldrmodules** : Liste les modules chargés dynamiquement.
- **volatility -f dump.raw mutantscan** : Recherche les objets de synchronisation mutante.
- **volatility -f dump.raw userassist** : Examine les éléments récemment utilisés par l'utilisateur.
- **volatility -f dump.raw shimcache** : Examine la base de données de compatibilité des applications.
- **volatility -f dump.raw getsids** : Liste les SID des processus.
- **volatility -f dump.raw hivelist** : Liste les hives du Registre.
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les valeurs d'une clé de Registre.
- **volatility -f dump.raw hashdump** : Extrait les hachages de mots de passe.
- **volatility -f dump.raw truecryptpassphrase** : Recherche les passphrases TrueCrypt.
- **volatility -f dump.raw clipboard** : Examine le contenu du presse-papiers.
- **volatility -f dump.raw screenshot** : Prend une capture d'écran de l'écran mémoire.
- **volatility -f dump.raw memdump -p PID -D /path/to/dump/** : Effectue un dump de la mémoire d'un processus spécifique.
- **volatility -f dump.raw memmap** : Affiche la carte mémoire du système.

#### Plugins supplémentaires

- **volatility -f dump.raw --profile=PROFILE plugin_name** : Utilise un profil spécifique pour exécuter un plugin.
- **volatility -f dump.raw --plugins=/path/to/plugins/ plugin_name** : Charge des plugins personnalisés à partir d'un répertoire spécifique.

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

Le **système de fichiers NTFS** utilise un composant critique connu sous le nom de _table des fichiers principaux_ (MFT). Cette table comprend au moins une entrée pour chaque fichier sur un volume, couvrant également le MFT lui-même. Des détails essentiels sur chaque fichier, tels que **la taille, les horodatages, les autorisations et les données réelles**, sont encapsulés dans les entrées du MFT ou dans des zones externes au MFT mais référencées par ces entrées. Plus de détails peuvent être trouvés dans la [documentation officielle](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

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

- **volatility -f dump.raw imageinfo** : Affiche des informations générales sur l'image mémoire.
- **volatility -f dump.raw pslist** : Liste les processus en cours d'exécution.
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence.
- **volatility -f dump.raw psscan** : Recherche les processus supprimés.
- **volatility -f dump.raw dlllist -p PID** : Liste les DLL chargées par un processus spécifique.
- **volatility -f dump.raw cmdline -p PID** : Affiche la ligne de commande d'un processus spécifique.
- **volatility -f dump.raw filescan** : Recherche les fichiers ouverts par les processus.
- **volatility -f dump.raw netscan** : Affiche les connexions réseau.
- **volatility -f dump.raw connections** : Affiche les connexions réseau en détail.
- **volatility -f dump.raw timeliner** : Crée une timeline des activités du système.
- **volatility -f dump.raw malfind** : Recherche les injections de code malveillant.
- **volatility -f dump.raw yarascan** : Recherche de motifs YARA dans l'image mémoire.
- **volatility -f dump.raw dumpfiles -Q 0xADDRESS -D /path/to/dumpfiles/** : Extrait les fichiers en mémoire à partir d'une adresse spécifique.
- **volatility -f dump.raw memdump -p PID -D /path/to/dumpfiles/** : Crée un dump mémoire d'un processus spécifique.

### Plugins supplémentaires

- **apihooks** : Recherche les hooks d'API.
- **malfind** : Recherche les injections de code malveillant.
- **svcscan** : Enumère les services.
- **modscan** : Recherche les modules noyau chargés.
- **driverirp** : Affiche les IRP des pilotes.
- **ssdt** : Affiche la table de services du noyau.
- **callbacks** : Affiche les callbacks du noyau.
- **devicetree** : Affiche l'arborescence des périphériques.
- **printkey** : Affiche les clés de registre imprimées.
- **userassist** : Affiche les entrées UserAssist du registre.
- **mftparser** : Analyse le Master File Table (MFT).
- **hivelist** : Affiche les hives du registre.
- **hashdump** : Extrait les hachages de mots de passe.

{% endtab %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## Malware

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

{% tab title="vol2" %} 

### Feuille de triche Volatility

#### Commandes de base

- **volatility -f dump.raw imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.raw pslist** : Liste des processus en cours d'exécution
- **volatility -f dump.raw psscan** : Analyse des processus non affichés dans la liste des tâches
- **volatility -f dump.raw pstree** : Affiche les processus sous forme d'arborescence
- **volatility -f dump.raw dlllist -p PID** : Liste des DLL chargées par un processus
- **volatility -f dump.raw cmdline -p PID** : Ligne de commande d'un processus
- **volatility -f dump.raw filescan** : Analyse des fichiers ouverts
- **volatility -f dump.raw netscan** : Liste des connexions réseau
- **volatility -f dump.raw connections** : Analyse des connexions réseau
- **volatility -f dump.raw malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.raw apihooks** : Recherche des hooks API dans les processus
- **volatility -f dump.raw ldrmodules** : Liste des modules chargés par les processus
- **volatility -f dump.raw modscan** : Analyse des modules noyau
- **volatility -f dump.raw ssdt** : Affiche la table de service du noyau
- **volatility -f dump.raw callbacks** : Liste des callbacks du noyau
- **volatility -f dump.raw driverirp** : Analyse des pilotes et des IRP
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques
- **volatility -f dump.raw hivelist** : Liste les hives de registre
- **volatility -f dump.raw printkey -o OFFSET** : Affiche les valeurs d'une clé de registre
- **volatility -f dump.raw userassist** : Liste des programmes récemment exécutés
- **volatility -f dump.raw shimcache** : Liste des fichiers exécutés stockés dans le cache de compatibilité
- **volatility -f dump.raw getsids** : Liste des SID des utilisateurs
- **volatility -f dump.raw getservicesids** : Liste des SID des services
- **volatility -f dump.raw getsids -p PID** : SID d'un processus
- **volatility -f dump.raw hivescan** : Analyse des hives de registre
- **volatility -f dump.raw hashdump** : Extraction des hachages de mots de passe
- **volatility -f dump.raw truecryptpassphrase** : Recherche de phrases de passe TrueCrypt
- **volatility -f dump.raw envars** : Variables d'environnement d'un processus
- **volatility -f dump.raw consoles** : Liste des consoles interactives
- **volatility -f dump.raw consoles -p PID** : Console d'un processus
- **volatility -f dump.raw screenshot -D /path/to/dump/screenshots/** : Capture d'écran du bureau
- **volatility -f dump.raw screenshot -p PID -D /path/to/dump/screenshots/** : Capture d'écran d'un processus
- **volatility -f dump.raw memdump -p PID -D /path/to/dump/memdumps/** : Extraction de la mémoire d'un processus
- **volatility -f dump.raw memdump -p PID -D /path/to/dump/memdumps/ -r /path/to/volatility/plugins/** : Extraction de la mémoire d'un processus en utilisant un plugin

#### Plugins

- **volatility --plugins=/path/to/volatility/plugins/ -f dump.raw pluginname** : Utilisation d'un plugin spécifique
- **volatility --info | grep -i windows** : Liste des plugins Windows disponibles

#### Profilage

- **volatility -f dump.raw --profile=WinXPSP2x86 cmdscan** : Analyse des commandes exécutées sur un système Windows XP SP2 32 bits
- **volatility -f dump.raw --profile=Win7SP0x64 cmdscan** : Analyse des commandes exécutées sur un système Windows 7 SP0 64 bits

#### Autres

- **volatility -f dump.raw kdbgscan** : Recherche du KDBG
- **volatility -f dump.raw kpcrscan** : Recherche du KPCR
- **volatility -f dump.raw kpcrscan -p PID** : Recherche du KPCR d'un processus
- **volatility -f dump.raw vadinfo -p PID** : Informations sur les zones d'allocation virtuelle d'un processus
- **volatility -f dump.raw vadtree -p PID** : Arborescence des zones d'allocation virtuelle d'un processus
- **volatility -f dump.raw vadwalk -p PID** : Parcours des zones d'allocation virtuelle d'un processus
- **volatility -f dump.raw mutantscan** : Recherche des objets de mutation
- **volatility -f dump.raw mutantscan -s** : Recherche des objets de mutation partagés
- **volatility -f dump.raw mutantscan -p PID** : Recherche des objets de mutation d'un processus
- **volatility -f dump.raw ldrmodules -p PID** : Liste des modules chargés par un processus
- **volatility -f dump.raw malfind -p PID** : Recherche de code malveillant dans un processus
- **volatility -f dump.raw malfind -p PID --dump-dir=/path/to/dump/malfind/** : Extraction du code malveillant d'un processus

{% endtab %}
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
- **volatility -f dump.raw netscan** : Informations sur les connexions réseau
- **volatility -f dump.raw connections** : Connexions réseau actives
- **volatility -f dump.raw timeliner** : Chronologie des événements
- **volatility -f dump.raw malfind** : Recherche de code malveillant
- **volatility -f dump.raw hivelist** : Liste des hives de registre
- **volatility -f dump.raw printkey -o OFFSET** : Afficher les valeurs de clé de registre
- **volatility -f dump.raw userassist** : Informations sur les programmes utilisés par l'utilisateur
- **volatility -f dump.raw clipboard** : Contenu du presse-papiers
- **volatility -f dump.raw screenshot** : Capturer un instantané de l'écran

#### Plugins supplémentaires

- **volatility -f dump.raw --profile=PROFILE plugin_name** : Utiliser un plugin spécifique
- **volatility -f dump.raw --profile=PROFILE -f dump.raw --output-file=output.txt plugin_name** : Enregistrer la sortie dans un fichier

{% endtab %}
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
### Bash

Il est possible de **lire l'historique bash en mémoire.** Vous pourriez également extraire le fichier _.bash\_history_, mais s'il est désactivé, vous serez heureux de pouvoir utiliser ce module de volatilité
```
./vol.py -f file.dmp linux.bash.Bash
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
- **volatility -f dump.raw hivescan** : Analyse des fichiers de registre non chargés
- **volatility -f dump.raw shimcache** : Liste des programmes exécutés récemment
- **volatility -f dump.raw ldrmodules** : Liste des modules chargés par les processus
- **volatility -f dump.raw modscan** : Analyse des modules noyau
- **volatility -f dump.raw mutantscan** : Analyse des objets de synchronisation
- **volatility -f dump.raw svcscan** : Liste des services système
- **volatility -f dump.raw driverirp** : Analyse des requêtes de paquets des pilotes
- **volatility -f dump.raw devicetree** : Arborescence des périphériques
- **volatility -f dump.raw handles** : Liste des handles système
- **volatility -f dump.raw vadinfo -p PID** : Informations sur les espaces d'adressage virtuel d'un processus
- **volatility -f dump.raw vadtree -p PID** : Arborescence des espaces d'adressage virtuel d'un processus
- **volatility -f dump.raw yarascan -Y "rule_file.yar"** : Analyse avec YARA
- **volatility -f dump.raw dumpfiles -Q OFFSET -D folder_path/** : Extraction de fichiers en mémoire
- **volatility -f dump.raw procdump -p PID -D folder_path/** : Extraction du processus en mémoire
- **volatility -f dump.raw memdump -p PID -D folder_path/** : Extraction de la mémoire d'un processus
- **volatility -f dump.raw memmap** : Cartographie de la mémoire
- **volatility -f dump.raw mftparser** : Analyse du Master File Table (MFT)
- **volatility -f dump.raw shimcachemem** : Analyse du cache de compatibilité d'application
- **volatility -f dump.raw userhandles -p PID** : Liste des handles utilisés par un processus
- **volatility -f dump.raw dumpregistry -o OFFSET -D folder_path/** : Extraction du registre en mémoire
- **volatility -f dump.raw dumpcerts -D folder_path/** : Extraction des certificats en mémoire
- **volatility -f dump.raw dumpregistryhive -o OFFSET -D folder_path/** : Extraction d'une ruche de registre en mémoire
- **volatility -f dump.raw dumpvad -D folder_path/** : Extraction des espaces d'adressage virtuel en mémoire
- **volatility -f dump.raw dumpfiles -Q OFFSET -D folder_path/** : Extraction de fichiers en mémoire
- **volatility -f dump.raw dumpcache -D folder_path/** : Extraction du cache en mémoire
- **volatility -f dump.raw dumpnetscan -D folder_path/** : Extraction des informations de scan réseau en mémoire
- **volatility -f dump.raw dumpconn -D folder_path/** : Extraction des informations de connexion en mémoire
- **volatility -f dump.raw dumpclipboard -D folder_path/** : Extraction du presse-papiers en mémoire
- **volatility -f dump.raw dumpregistry -o OFFSET -D folder_path/** : Extraction du registre en mémoire
- **volatility -f dump.raw dumpregistryhive -o OFFSET -D folder_path/** : Extraction d'une ruche de registre en mémoire
- **volatility -f dump.raw dumpvad -D folder_path/** : Extraction des espaces d'adressage virtuel en mémoire
- **volatility -f dump.raw dumpfiles -Q OFFSET -D folder_path/** : Extraction de fichiers en mémoire
- **volatility -f dump.raw dumpcache -D folder_path/** : Extraction du cache en mémoire
- **volatility -f dump.raw dumpnetscan -D folder_path/** : Extraction des informations de scan réseau en mémoire
- **volatility -f dump.raw dumpconn -D folder_path/** : Extraction des informations de connexion en mémoire
- **volatility -f dump.raw dumpclipboard -D folder_path/** : Extraction du presse-papiers en mémoire

#### Plugins supplémentaires

- **volatility -f dump.raw plugin_name** : Utilisation d'un plugin supplémentaire
- **volatility -f dump.raw --profile=ProfileName plugin_name** : Utilisation d'un plugin avec un profil spécifique

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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.raw imageinfo** : Affiche des informations générales sur le dump mémoire.
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
- **volatility -f dump.raw printkey -o OFFSET** : Affiche le contenu d'une clé de registre à partir d'un offset donné.
- **volatility -f dump.raw userassist** : Affiche les programmes les plus utilisés par les utilisateurs.
- **volatility -f dump.raw hashdump** : Extrait les hachages de mots de passe.
- **volatility -f dump.raw truecryptpassphrase** : Extrait les passphrases TrueCrypt.

### Plugins supplémentaires

- **volatility -f dump.raw shimcacheparser** : Analyse le cache de compatibilité des applications.
- **volatility -f dump.raw ldrmodules** : Liste les modules chargés dynamiquement.
- **volatility -f dump.raw apihooks** : Recherche les hooks d'API.
- **volatility -f dump.raw getsids** : Affiche les SID des processus.
- **volatility -f dump.raw mutantscan** : Recherche les objets de synchronisation (mutants).
- **volatility -f dump.raw ssdt** : Affiche la table de service du noyau (SSDT).
- **volatility -f dump.raw callbacks** : Recherche les callbacks du noyau.
- **volatility -f dump.raw driverirp** : Affiche les IRP gérés par les pilotes.
- **volatility -f dump.raw modscan** : Recherche les modules du noyau.
- **volatility -f dump.raw threads** : Affiche les threads du système.
- **volatility -f dump.raw handles** : Affiche les handles du système.
- **volatility -f dump.raw devicetree** : Affiche l'arborescence des périphériques.
- **volatility -f dump.raw idt** : Affiche la table des descripteurs d'interruption (IDT).
- **volatility -f dump.raw gdt** : Affiche la table des descripteurs de tâche globale (GDT).
- **volatility -f dump.raw driverscan** : Recherche les pilotes chargés.
- **volatility -f dump.raw psxview** : Détecte les rootkits en examinant les processus cachés.
- **volatility -f dump.raw yarascan** : Recherche des motifs Yara dans la mémoire.
- **volatility -f dump.raw dumpregistry -o OFFSET** : Extrait une ruche de registre à partir d'un offset donné.
- **volatility -f dump.raw dumpfiles -Q PATH** : Extrait des fichiers à partir d'un chemin spécifique.
- **volatility -f dump.raw screenshot** : Capture une capture d'écran du bureau.
- **volatility -f dump.raw memdump -p PID -D /path/to/dump/** : Effectue un dump mémoire d'un processus spécifique.
- **volatility -f dump.raw memmap** : Affiche la carte mémoire du système.
- **volatility -f dump.raw mbrparser** : Analyse le Master Boot Record (MBR).
- **volatility -f dump.raw shimcachemem** : Recherche le cache de compatibilité des applications en mémoire.
- **volatility -f dump.raw hibinfo** : Affiche des informations sur le fichier hibernation.
- **volatility -f dump.raw hibscan** : Recherche des signatures de fichiers hibernation.
- **volatility -f dump.raw hibp2bin -O output_directory** : Convertit un fichier hibernation en binaire.
- **volatility -f dump.raw hibprefs** : Affiche les préférences de veille prolongée.
- **volatility -f dump.raw hibparse -O output_directory** : Analyse un fichier hibernation.
- **volatility -f dump.raw hiblist** : Liste les fichiers hibernation.
- **volatility -f dump.raw hibinfo -o OFFSET** : Affiche des informations sur un fichier hibernation à partir d'un offset donné.

{% endtab %}
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

{% tab title="vol2" %} 

## Feuille de triche Volatility

### Commandes de base

- **volatility -f dump.mem imageinfo** : Informations sur l'image mémoire
- **volatility -f dump.mem pslist** : Liste des processus en cours d'exécution
- **volatility -f dump.mem psscan** : Analyse des processus cachés
- **volatility -f dump.mem pstree** : Affichage de l'arborescence des processus
- **volatility -f dump.mem dlllist -p PID** : Liste des DLL chargées par un processus
- **volatility -f dump.mem filescan** : Analyse des fichiers ouverts
- **volatility -f dump.mem cmdline -p PID** : Ligne de commande d'un processus
- **volatility -f dump.mem netscan** : Analyse des connexions réseau
- **volatility -f dump.mem connections** : Affichage des connexions réseau
- **volatility -f dump.mem malfind** : Recherche de code malveillant dans les processus
- **volatility -f dump.mem apihooks** : Détection des hooks d'API
- **volatility -f dump.mem ldrmodules** : Liste des modules chargés par les processus
- **volatility -f dump.mem modscan** : Analyse des modules noyau chargés
- **volatility -f dump.mem shimcache** : Extraction de la base de données Shimcache
- **volatility -f dump.mem userassist** : Extraction des entrées UserAssist
- **volatility -f dump.mem hivelist** : Liste des hives de registre
- **volatility -f dump.mem printkey -o OFFSET** : Affichage du contenu d'une clé de registre
- **volatility -f dump.mem hashdump** : Extraction des hachages de mots de passe
- **volatility -f dump.mem truecryptpassphrase** : Récupération des phrases de passe TrueCrypt
- **volatility -f dump.mem clipboard** : Extraction du contenu du presse-papiers
- **volatility -f dump.mem screenshot** : Capture d'écran de la session
- **volatility -f dump.mem memdump -p PID -D /path/to/dump/** : Extraction de la mémoire d'un processus
- **volatility -f dump.mem memdump -p PID --dump-dir /path/to/dump/** : Extraction de la mémoire d'un processus avec un répertoire de destination spécifié

### Plugins supplémentaires

- **volatility -f dump.mem kdbgscan** : Recherche du KDBG
- **volatility -f dump.mem kpcrscan** : Recherche du KPCR
- **volatility -f dump.mem ssdt** : Affichage de la table SSDT
- **volatility -f dump.mem driverirp** : Analyse des dispatch routines des pilotes
- **volatility -f dump.mem callbacks** : Affichage des callbacks du noyau
- **volatility -f dump.mem devicetree** : Affichage de l'arborescence des périphériques
- **volatility -f dump.mem handles** : Affichage des handles du noyau
- **volatility -f dump.mem mutantscan** : Analyse des objets mutant
- **volatility -f dump.mem mutantscan -s** : Analyse des objets mutant partagés
- **volatility -f dump.mem getsids** : Affichage des SID des processus
- **volatility -f dump.mem getsids -p PID** : Affichage du SID d'un processus
- **volatility -f dump.mem envars** : Affichage des variables d'environnement des processus
- **volatility -f dump.mem envars -p PID** : Affichage des variables d'environnement d'un processus
- **volatility -f dump.mem cmdline** : Affichage de toutes les lignes de commande des processus
- **volatility -f dump.mem consoles** : Affichage des consoles allouées aux processus
- **volatility -f dump.mem consoles -p PID** : Affichage de la console allouée à un processus
- **volatility -f dump.mem dumpregistry -o OFFSET** : Extraction du contenu d'une ruche de registre
- **volatility -f dump.mem dumpregistry -s** : Extraction de toutes les ruches de registre
- **volatility -f dump.mem dumpregistry -s -y** : Extraction de toutes les ruches de registre, y compris les ruches système
- **volatility -f dump.mem dumpregistry -s -y -i** : Extraction de toutes les ruches de registre, y compris les ruches système et les ruches inactives
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/** : Extraction de toutes les ruches de registre avec un répertoire de sortie spécifié
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE** : Extraction d'une ruche de registre spécifique
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft** : Extraction d'une clé de registre spécifique
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows** : Extraction d'une valeur de registre spécifique
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows -f** : Extraction du contenu de la valeur de registre
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows -f -d** : Extraction des données de la valeur de registre
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows -f -d -x** : Extraction des données de la valeur de registre en hexadécimal
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows -f -d -x -a** : Extraction de toutes les valeurs de la clé de registre
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows -f -d -x -a -j** : Extraction de toutes les valeurs de la clé de registre en JSON
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows -f -d -x -a -j -t** : Extraction de toutes les valeurs de la clé de registre en JSON avec le type de données
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows -f -d -x -a -j -t -e** : Extraction de toutes les valeurs de la clé de registre en JSON avec le type de données et les données encodées
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows -f -d -x -a -j -t -e -c** : Extraction de toutes les valeurs de la clé de registre en JSON avec le type de données, les données encodées et les commentaires
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows -f -d -x -a -j -t -e -c -m** : Extraction de toutes les valeurs de la clé de registre en JSON avec le type de données, les données encodées, les commentaires et les métadonnées
- **volatility -f dump.mem dumpregistry -s -y -i -o /path/to/output/ -r SOFTWARE -k Microsoft -v Windows -f -d -x -a -j -t -e -c -m -l** : Extraction de toutes les valeurs de la clé de registre en JSON avec le type de données, les données encodées, les commentaires, les métadonnées et les liens symboliques

{% endtab %}
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
Le **Master Boot Record (MBR)** joue un rôle crucial dans la gestion des partitions logiques d'un support de stockage, qui sont structurées avec différents [systèmes de fichiers](https://fr.wikipedia.org/wiki/Syst%C3%A8me_de_fichiers). Il contient non seulement des informations sur la disposition des partitions, mais également du code exécutable agissant en tant que chargeur d'amorçage. Ce chargeur d'amorçage initie soit directement le processus de chargement de la deuxième étape du système d'exploitation (voir [chargeur d'amorçage de deuxième étape](https://fr.wikipedia.org/wiki/Chargeur_d%27amor%C3%A7age_de_deuxi%C3%A8me_%C3%A9tape)) soit fonctionne en harmonie avec l'enregistrement d'amorçage de volume ([volume boot record](https://en.wikipedia.org/wiki/Volume_boot_record)) (VBR) de chaque partition. Pour des connaissances approfondies, consultez la [page Wikipedia sur le MBR](https://fr.wikipedia.org/wiki/Master_boot_record).

## Références

* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys) ​\* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
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
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
