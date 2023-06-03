# Analyse de firmware

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introduction

Le firmware est un type de logiciel qui assure la communication et le contrôle des composants matériels d'un appareil. C'est le premier code qu'un appareil exécute. Habituellement, il **amorce le système d'exploitation** et fournit des services d'exécution très spécifiques pour les programmes en **communiquant avec divers composants matériels**. La plupart, sinon tous, les appareils électroniques ont un firmware.

Les appareils stockent le firmware dans une **mémoire non volatile**, telle que ROM, EPROM ou mémoire flash.

Il est important d'**examiner** le **firmware** et d'essayer de le **modifier**, car nous pouvons découvrir de nombreux problèmes de sécurité au cours de ce processus.

## **Collecte d'informations et reconnaissance**

Au cours de cette étape, collectez autant d'informations que possible sur la cible pour comprendre sa composition globale et sa technologie sous-jacente. Essayez de collecter les éléments suivants :

* Architecture(s) de CPU prise(s) en charge
* Plateforme de système d'exploitation
* Configurations de chargeur d'amorçage
* Schémas matériels
* Fiches techniques
* Estimations de lignes de code (LoC)
* Emplacement du référentiel de code source
* Composants tiers
* Licences open source (par exemple GPL)
* Journaux des modifications
* Identifiants FCC
* Diagrammes de conception et de flux de données
* Modèles de menace
* Rapports de test de pénétration précédents
* Tickets de suivi de bogues (par exemple Jira et des plateformes de chasse aux bugs telles que BugCrowd ou HackerOne)

Lorsque cela est possible, acquérez des données à l'aide d'outils et de techniques de renseignement sur les sources ouvertes (OSINT). Si un logiciel open source est utilisé, téléchargez le référentiel et effectuez une analyse statique manuelle et automatisée du code source. Parfois, les projets de logiciels open source utilisent déjà des outils d'analyse statique gratuits fournis par des fournisseurs qui fournissent des résultats de scan tels que [Coverity Scan](https://scan.coverity.com) et [Semmle’s LGTM](https://lgtm.com/#explore).

## Obtenir le firmware

Il existe différentes façons, avec différents niveaux de difficulté, de télécharger le firmware :

* **Directement** auprès de l'équipe de développement, du fabricant/fournisseur ou du client
* **Construire à partir de zéro** en utilisant les guides fournis par le fabricant
* À partir du **site de support** du fournisseur
* Recherches **Google dork** ciblant les extensions de fichiers binaires et les plateformes de partage de fichiers telles que Dropbox, Box et Google Drive
  * Il est courant de trouver des images de firmware via des clients qui téléchargent du contenu sur des forums, des blogs ou qui commentent des sites où ils ont contacté le fabricant pour résoudre un problème et ont reçu un firmware via un zip ou une clé USB envoyée.
  * Exemple : `intitle:"Netgear" intext:"Firmware Download"`
* Télécharger des versions à partir d'emplacements de stockage de fournisseurs de cloud exposés tels que les compartiments Amazon Web Services (AWS) S3 (avec des outils tels que [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner))
* Communication de l'appareil **man-in-the-middle** (MITM) pendant les **mises à jour**
* Extraire directement **à partir du matériel** via **UART**, **JTAG**, **PICit**, etc.
* Sniffer la **communication série** au sein des composants matériels pour les **demandes de serveur de mise à jour**
* Via un **point d'extrémité codé en dur** dans les applications mobiles ou épaisses
* **Dumping** du firmware à partir du **chargeur d'amorçage** (par exemple U-boot) vers le stockage flash ou via le **réseau** via **tftp**
* Retrait de la **puce flash** (par exemple SPI) ou du MCU de la carte pour une analyse hors ligne et l'extraction de données (DERNIER RECOURS).
  * Vous aurez besoin d'un programmeur de puce pris en charge pour le stockage flash et/ou le MCU.

## Analyse du firmware

Maintenant que vous **avez le firmware**, vous devez extraire des informations à son sujet pour savoir comment le traiter. Différents outils que vous pouvez utiliser pour cela :
```bash
file <bin>  
strings -n8 <bin> 
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out  
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l'**entropie** de l'image avec `binwalk -E <bin>`. Si l'entropie est faible, il est peu probable que le fichier soit chiffré. Si l'entropie est élevée, il est probablement chiffré (ou compressé d'une certaine manière).

De plus, vous pouvez utiliser ces outils pour extraire les **fichiers intégrés dans le firmware** :

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Obtenir le système de fichiers

Avec les outils précédemment commentés tels que `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l'extrait généralement dans un **dossier nommé d'après le type de système de fichiers**, qui est généralement l'un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk n'aura **pas l'octet magique du système de fichiers dans ses signatures**. Dans ces cas, utilisez binwalk pour **trouver l'offset du système de fichiers et extraire le système de fichiers compressé** du binaire et **extraire manuellement** le système de fichiers selon son type en suivant les étapes ci-dessous.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Exécutez la commande **dd** suivante pour extraire le système de fichiers Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs 

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativement, la commande suivante peut également être exécutée.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Pour les systèmes de fichiers squashfs (utilisés dans l'exemple ci-dessus)

`$ unsquashfs dir.squashfs`

Les fichiers seront dans le répertoire "`squashfs-root`" par la suite.

* Fichiers d'archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Pour les systèmes de fichiers jffs2

`$ jefferson rootfsfile.jffs2`

* Pour les systèmes de fichiers ubifs avec flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Analyse du système de fichiers

Maintenant que vous avez le système de fichiers, il est temps de commencer à chercher des pratiques dangereuses telles que :

* Des **daemons réseau obsolètes et non sécurisés** tels que telnetd (parfois les fabricants renomment les binaires pour les dissimuler)
* Des **informations d'identification codées en dur** (noms d'utilisateur, mots de passe, clés API, clés SSH et variantes de backdoor)
* Des points de terminaison d'API codés en dur et des détails du serveur backend
* Des fonctionnalités de **serveur de mise à jour** qui pourraient être utilisées comme point d'entrée
* **Examiner le code non compilé et les scripts de démarrage** pour l'exécution de code à distance
* **Extraire les binaires compilés** pour une analyse hors ligne avec un désassembleur pour les étapes futures

Certaines **choses intéressantes à rechercher** dans le firmware :

* etc/shadow et etc/passwd
* lister le répertoire etc/ssl
* rechercher des fichiers liés à SSL tels que .pem, .crt, etc.
* rechercher des fichiers de configuration
* rechercher des fichiers de script
* rechercher d'autres fichiers .bin
* rechercher des mots-clés tels que admin, password, remote, clés AWS, etc.
* rechercher des serveurs Web couramment utilisés sur les appareils IoT
* rechercher des binaires courants tels que ssh, tftp, dropbear, etc.
* rechercher des fonctions c interdites
* rechercher des fonctions vulnérables courantes d'injection de commandes
* rechercher des URL, des adresses e-mail et des adresses IP
* et plus encore...

Des outils qui recherchent ce type d'informations (même si vous devriez toujours jeter un coup d'œil manuellement et vous familiariser avec la structure du système de fichiers, les outils peuvent vous aider à trouver des **choses cachées**) :

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)**:** Script bash impressionnant qui, dans ce cas, est utile pour rechercher des **informations sensibles** dans le système de fichiers. Il suffit de **chrooter dans le système de fichiers du firmware et de l'exécuter**.
* [**Firmwalker**](https://github.com/craigz28/firmwalker)**:** Script bash pour rechercher des informations potentiellement sensibles
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) :
  * Identification des composants logiciels tels que le système d'exploitation, l'architecture CPU et les composants tiers ainsi que leurs informations de version associées
  * Extraction du (des) système(s) de fichiers du firmware à partir des images
  * Détection des certificats et des clés privées
  * Détection des implémentations faibles correspondant à l'énumération des faiblesses communes (CWE)
  * Détection de vulnérabilités basées sur des signatures et des flux
  * Analyse comportementale statique de base
  * Comparaison (diff) des versions et des fichiers du firmware
  * Émulation en mode utilisateur des binaires du système de fichiers à l'aide de QEMU
  * Détection des atténuations binaires telles que NX, DEP, ASLR, canaris de pile, RELRO et FORTIFY\_SOURCE
  * REST API
  * et plus encore...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer) : FwAnalyzer est un outil d'analyse des images de systèmes de fichiers (ext2/3/4), FAT/VFat, SquashFS, UBIFS, des archives cpio et du contenu des répertoires à l'aide d'un ensemble de règles configurables.
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep) : Un outil d'analyse de sécurité des firmwares IoT gratuit
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) : Il s'agit d'une réécriture complète du projet ByteSweep original en Go.
* [**EMBA**](https://github.com/e-m-b-a/emba) : _EMBA_ est conçu comme l'outil d'analyse de firmware central pour les testeurs de pénétration. Il prend en charge l'ensemble du processus d'analyse de sécurité, en commençant par le processus d'extraction du firmware, en passant par l'analyse statique et l'analyse dynamique via l'émulation, jusqu'à la génération d'un rapport. _EMBA_ découvre automatiquement les points faibles et les vulnérabilités possibles dans le firmware. Les exemples incluent les binaires non sécurisés, les composants logiciels obsolètes et dépassés, les scripts potentiellement vulnérables ou les mots de passe codés en dur.

{% hint style="warning" %}
Dans le système de fichiers, vous pouvez également trouver le **code source** des programmes (que vous devriez toujours **vérifier**), mais aussi des **binaires compilés**. Ces programmes pourraient être exposés d'une certaine manière et vous devriez les **décompiler** et les **vérifier** pour détecter d'éventuelles vulnérabilités.

Des outils tels que [**checksec.sh**](https://github.com/slimm609/checksec.sh) peuvent être utiles pour trouver des binaires non protégés. Pour les binaires Windows, vous pourriez utiliser [**PESecurity**](https://github.com/NetSPI/PESecurity).
{% endhint %}

## Émulation de firmware

L'idée d'émuler le firmware est de pouvoir effectuer une **analyse dynamique** de l'appareil **en cours d'exécution** ou d'un **programme unique**.

{% hint style="info" %}
Parfois, l'émulation partielle ou complète **peut ne pas fonctionner en raison de dépendances matérielles ou d'architecture**. Si l'architecture et l'endianness correspondent à un appareil possédé tel qu'un Raspberry Pi, le système de fichiers racine ou un binaire spécifique peut être transféré vers l'appareil pour des tests ultérieurs. Cette méthode s'applique également aux machines virtuelles pré-construites utilisant la même architecture et le même endianness que la cible.
{% endhint %}

### Émulation binaire

Si vous voulez simplement émuler un programme pour rechercher des vulnérabilités, vous devez d'abord identifier son endianness et l'architecture CPU pour laquelle il a été compilé.

#### Exemple MIPS
```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```
Maintenant, vous pouvez **émuler** l'exécutable busybox en utilisant **QEMU**.
```bash
 sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Comme l'exécutable est compilé pour MIPS et suit l'ordre des octets **big-endian**, nous utiliserons l'émulateur **`qemu-mips`** de QEMU. Pour émuler des exécutables **little-endian**, nous devrions sélectionner l'émulateur avec le suffixe `el` (`qemu-mipsel`).
```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```
#### Exemple ARM

---

#### Firmware Analysis

#### Analyse de Firmware

##### ARM Example

##### Exemple ARM

###### Extracting the firmware

###### Extraction du firmware

To extract the firmware from the device we can use different techniques:

Pour extraire le firmware de l'appareil, nous pouvons utiliser différentes techniques :

- Dumping the SPI flash memory
- Dumping the NAND flash memory
- Dumping the NOR flash memory
- Dumping the EEPROM memory
- Dumping the firmware from the bootloader

- Dumping de la mémoire flash SPI
- Dumping de la mémoire flash NAND
- Dumping de la mémoire flash NOR
- Dumping de la mémoire EEPROM
- Dumping du firmware à partir du bootloader

###### Identifying the architecture

###### Identification de l'architecture

Once we have the firmware, we need to identify the architecture of the device. In this case, we will use an ARM architecture as an example.

Une fois que nous avons le firmware, nous devons identifier l'architecture de l'appareil. Dans ce cas, nous utiliserons l'architecture ARM comme exemple.

###### Disassembling the firmware

###### Désassemblage du firmware

To disassemble the firmware we can use different tools, in this case, we will use Ghidra.

Pour désassembler le firmware, nous pouvons utiliser différents outils, dans ce cas, nous utiliserons Ghidra.

###### Analyzing the firmware

###### Analyse du firmware

Once we have the disassembled firmware, we can start analyzing it to find vulnerabilities or interesting functions.

Une fois que nous avons le firmware désassemblé, nous pouvons commencer à l'analyser pour trouver des vulnérabilités ou des fonctions intéressantes.
```bash
file bin/busybox                
bin/busybox: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-armhf.so.1, no section header
```
Emulation:

L'émulation est une technique couramment utilisée pour analyser les firmwares. Elle consiste à exécuter le firmware sur un environnement virtuel, ce qui permet de comprendre son fonctionnement sans risquer de l'exécuter sur un système physique. Cette technique est particulièrement utile pour les firmwares qui ne sont pas destinés à être exécutés sur des systèmes x86, car elle permet de les exécuter sur un système x86 standard. L'émulation peut également être utilisée pour contourner les mécanismes de protection du firmware, tels que les vérifications de signature et les contrôles d'intégrité.
```bash
qemu-arm -L ./squashfs-root/ ./squashfs-root/bin/ls
1C00000.squashfs  B80B6C            C41DD6.xz         squashfs-root     squashfs-root-0
```
### Émulation complète du système

Il existe plusieurs outils, basés sur **qemu** en général, qui vous permettront d'émuler le firmware complet :

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)** :**
  * Vous devez installer plusieurs choses, configurer postgres, puis exécuter le script extractor.py pour extraire le firmware, utiliser le script getArch.sh pour obtenir l'architecture. Ensuite, utilisez les scripts tar2db.py et makeImage.sh pour stocker les informations de l'image extraite dans la base de données et générer une image QEMU que nous pouvons émuler. Ensuite, utilisez le script inferNetwork.sh pour obtenir les interfaces réseau, et enfin utilisez le script run.sh, qui est automatiquement créé dans le dossier ./scratch/1/.
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)** :**
  * Cet outil dépend de firmadyne et automatise le processus d'émulation du firmware en utilisant firmadyne. Vous devez configurer `fat.config` avant de l'utiliser : `sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **Analyse dynamique**

À ce stade, vous devriez avoir soit un appareil exécutant le firmware à attaquer, soit le firmware étant émulé à attaquer. Dans tous les cas, il est fortement recommandé d'avoir **un shell dans le système d'exploitation et le système de fichiers qui s'exécute**.

Notez que parfois, si vous émulez le firmware, **certaines activités à l'intérieur de l'émulation échoueront** et vous devrez peut-être redémarrer l'émulation. Par exemple, une application Web pourrait avoir besoin d'obtenir des informations à partir d'un appareil avec lequel l'appareil d'origine est intégré, mais l'émulation ne l'émule pas.

Vous devriez **revérifier le système de fichiers** comme nous l'avons déjà fait dans une **étape précédente car dans l'environnement d'exécution, de nouvelles informations pourraient être accessibles**.

Si des **pages Web** sont exposées, en lisant le code et en y ayant accès, vous devriez les **tester**. Dans hacktricks, vous pouvez trouver beaucoup d'informations sur différentes techniques de piratage Web.

Si des **services réseau** sont exposés, vous devriez essayer de les attaquer. Dans hacktricks, vous pouvez trouver beaucoup d'informations sur différentes techniques de piratage de services réseau. Vous pouvez également essayer de les fuzz avec des fuzzers de réseau et de protocole tels que [Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer), [boofuzz](https://github.com/jtpereyda/boofuzz) et [kitty](https://github.com/cisco-sas/kitty).

Vous devriez vérifier si vous pouvez **attaquer le chargeur de démarrage** pour obtenir un shell root :

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

Vous devriez tester si l'appareil effectue des tests d'intégrité du firmware, sinon cela permettrait aux attaquants d'offrir des firmwares backdoor, de les installer dans des appareils appartenant à d'autres personnes ou même de les déployer à distance s'il existe une vulnérabilité de mise à jour du firmware :

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

Les vulnérabilités de mise à jour du firmware surviennent généralement parce que l'**intégrité** du **firmware** pourrait **ne pas être validée**, l'utilisation de protocoles de **réseau** **non chiffrés**, l'utilisation de **crédits codés en dur**, une **authentification non sécurisée** pour le composant cloud qui héberge le firmware, et même des **logs** excessifs et non sécurisés (données sensibles), permettent des **mises à jour physiques** sans vérifications.

## **Analyse en temps d'exécution**

L'analyse en temps d'exécution consiste à se connecter à un processus ou à un binaire en cours d'exécution pendant que l'appareil fonctionne dans son environnement normal ou émulé. Les étapes de base de l'analyse en temps d'exécution sont fournies ci-dessous :

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. Attachez gdb-multiarch ou utilisez IDA pour émuler le binaire
3. Définissez des points d'arrêt pour les fonctions identifiées lors de l'étape 4 telles que memcpy, strncpy, strcmp, etc.
4. Exécutez de grandes chaînes de charge utile pour identifier les débordements ou les plantages de processus à l'aide d'un fuzzer
5. Passez à l'étape 8 si une vulnérabilité est identifiée

Les outils qui peuvent être utiles sont (non exhaustifs) :

* gdb-multiarch
* [Peda](https://github.com/longld/peda)
* Frida
* ptrace
* strace
* IDA Pro
* Ghidra
* Binary Ninja
* Hopper

## **Exploitation binaire**

Après avoir identifié une vulnérabilité dans un binaire à partir des étapes précédentes, une preuve de concept (PoC) appropriée est nécessaire pour démontrer l'impact et le risque réels dans le monde réel. Le développement de code d'exploit nécessite une expérience de programmation dans des langages de niveau inférieur (par exemple ASM, C/C++, shellcode, etc.) ainsi qu'une expérience dans l'architecture cible particulière (par exemple MIPS, ARM, x86, etc.). Le code PoC implique l'obtention d'une exécution arbitraire sur un appareil ou une application en contrôlant une instruction en mémoire.

Il n'est pas courant que les protections de temps d'exécution binaire (par exemple NX, DEP, ASLR, etc.) soient en place dans
