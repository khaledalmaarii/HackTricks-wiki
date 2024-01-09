# Analyse du Firmware

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introduction

Le firmware est un type de logiciel qui assure la communication et le contrôle des composants matériels d'un appareil. C'est le premier code exécuté par un appareil. Habituellement, il **démarre le système d'exploitation** et fournit des services d'exécution très spécifiques pour les programmes en **communiquant avec divers composants matériels**. La plupart, sinon tous, les appareils électroniques possèdent un firmware.

Les appareils stockent le firmware dans une **mémoire non volatile**, telle que ROM, EPROM ou mémoire flash.

Il est important d'**examiner** le **firmware** puis de tenter de le **modifier**, car nous pouvons découvrir de nombreux problèmes de sécurité au cours de ce processus.

## **Collecte d'informations et reconnaissance**

Pendant cette étape, collectez autant d'informations que possible sur la cible pour comprendre sa composition globale et la technologie sous-jacente. Essayez de rassembler les éléments suivants :

* Architectures de CPU prises en charge
* Plateforme du système d'exploitation
* Configurations du bootloader
* Schémas matériels
* Fiches techniques
* Estimations du nombre de lignes de code (LoC)
* Emplacement du dépôt de code source
* Composants tiers
* Licences open source (par exemple, GPL)
* Journaux de modifications
* Identifiants FCC
* Diagrammes de conception et de flux de données
* Modèles de menaces
* Rapports de pentesting antérieurs
* Tickets de suivi des bugs (par exemple, Jira et plateformes de bug bounty telles que BugCrowd ou HackerOne)

Lorsque c'est possible, acquérez des données en utilisant des outils et techniques d'intelligence open source (OSINT). Si un logiciel open source est utilisé, téléchargez le dépôt et effectuez une analyse statique manuelle ainsi qu'automatisée sur la base de code. Parfois, les projets de logiciels open source utilisent déjà des outils d'analyse statique gratuits fournis par des fournisseurs qui fournissent des résultats de scan tels que [Coverity Scan](https://scan.coverity.com) et [LGTM de Semmle](https://lgtm.com/#explore).

## Obtenir le Firmware

Il existe différentes manières avec différents niveaux de difficulté pour télécharger le firmware

* **Directement** de l'équipe de développement, du fabricant/vendeur ou du client
* **Construire à partir de zéro** en utilisant les tutoriels fournis par le fabricant
* Depuis le **site de support du vendeur**
* Requêtes **Google dork** ciblées vers les extensions de fichiers binaires et les plateformes de partage de fichiers telles que Dropbox, Box et Google Drive
* Il est courant de tomber sur des images de firmware par le biais de clients qui téléchargent du contenu sur des forums, des blogs ou commentent sur des sites où ils ont contacté le fabricant pour résoudre un problème et ont reçu le firmware via un zip ou une clé USB envoyée.
* Exemple : `intitle:"Netgear" intext:"Firmware Download"`
* Télécharger des builds depuis des emplacements de stockage de fournisseurs cloud exposés tels que les seaux Amazon Web Services (AWS) S3 (avec des outils tels que [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner))
* **Intercepter** la communication de l'appareil pendant les **mises à jour**
* Extraire directement **du matériel** via **UART**, **JTAG**, **PICit**, etc.
* Sniffer la **communication série** au sein des composants matériels pour les **requêtes de serveur de mise à jour**
* Via un **point d'accès codé en dur** dans les applications mobiles ou épaisses
* **Dumping** du firmware depuis le **bootloader** (par exemple, U-boot) vers le stockage flash ou sur le **réseau** via **tftp**
* Retirer la **puce flash** (par exemple, SPI) ou le MCU de la carte pour une analyse hors ligne et une extraction de données (DERNIER RECOURS).
* Vous aurez besoin d'un programmeur de puce pris en charge pour le stockage flash et/ou le MCU.

## Analyser le firmware

Maintenant que vous **avez le firmware**, vous devez extraire des informations à son sujet pour savoir comment le traiter. Différents outils que vous pouvez utiliser pour cela :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l'**entropie** de l'image avec `binwalk -E <bin>`. Si l'entropie est faible, il est peu probable qu'elle soit chiffrée. Si l'entropie est élevée, il est probable qu'elle soit chiffrée (ou compressée d'une certaine manière).

De plus, vous pouvez utiliser ces outils pour extraire **les fichiers intégrés dans le firmware** :

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Obtenir le Système de Fichiers

Avec les outils précédemment commentés comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk extrait généralement dans un **dossier nommé selon le type de système de fichiers**, qui est généralement l'un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction Manuelle du Système de Fichiers

Parfois, binwalk **n'aura pas l'octet magique du système de fichiers dans ses signatures**. Dans ces cas, utilisez binwalk pour **trouver le décalage du système de fichiers et découper le système de fichiers compressé** du binaire et **extraire manuellement** le système de fichiers selon son type en utilisant les étapes ci-dessous.
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
```markdown
Alternativement, la commande suivante peut également être exécutée.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Pour squashfs (utilisé dans l'exemple ci-dessus)

`$ unsquashfs dir.squashfs`

Les fichiers seront dans le répertoire "`squashfs-root`" par la suite.

* Pour les archives CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Pour les systèmes de fichiers jffs2

`$ jefferson rootfsfile.jffs2`

* Pour les systèmes de fichiers ubifs avec flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Analyse du système de fichiers

Maintenant que vous avez le système de fichiers, il est temps de commencer à chercher des mauvaises pratiques telles que :

* Les **daemons réseau non sécurisés** tels que telnetd (parfois les fabricants renomment les binaires pour les dissimuler)
* Les **identifiants codés en dur** (noms d'utilisateur, mots de passe, clés API, clés SSH et variantes de backdoor)
* Les **points de terminaison API codés en dur** et les détails du serveur backend
* La **fonctionnalité de serveur de mise à jour** qui pourrait être utilisée comme point d'entrée
* **Examiner le code non compilé et les scripts de démarrage** pour l'exécution de code à distance
* **Extraire les binaires compilés** pour une analyse hors ligne avec un désassembleur pour les étapes futures

Quelques **éléments intéressants à rechercher** dans le firmware :

* etc/shadow et etc/passwd
* lister le répertoire etc/ssl
* rechercher des fichiers liés à SSL tels que .pem, .crt, etc.
* rechercher des fichiers de configuration
* chercher des fichiers de script
* rechercher d'autres fichiers .bin
* chercher des mots-clés tels que admin, password, remote, clés AWS, etc.
* rechercher des serveurs web courants utilisés sur les appareils IoT
* rechercher des binaires courants tels que ssh, tftp, dropbear, etc.
* rechercher des fonctions interdites en C
* rechercher des fonctions vulnérables à l'injection de commandes
* rechercher des URL, des adresses e-mail et des adresses IP
* et plus encore…

Des outils qui recherchent ce type d'informations (même si vous devriez toujours jeter un œil manuel et vous familiariser avec la structure du système de fichiers, les outils peuvent vous aider à trouver des **choses cachées**) :

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)** :** Un script bash impressionnant qui dans ce cas est utile pour rechercher des **informations sensibles** à l'intérieur du système de fichiers. Il suffit de **chroot à l'intérieur du système de fichiers du firmware et de l'exécuter**.
* [**Firmwalker**](https://github.com/craigz28/firmwalker)** :** Script bash pour rechercher des informations sensibles potentielles
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) :
* Identification des composants logiciels tels que le système d'exploitation, l'architecture CPU et les composants tiers avec leurs informations de version associées
* Extraction du (des) système(s) de fichiers du firmware à partir d'images
* Détection de certificats et de clés privées
* Détection de mises en œuvre faibles mappées à l'Enumeration des Faiblesses Communes (CWE)
* Détection de vulnérabilités basée sur des flux et des signatures
* Analyse comportementale statique de base
* Comparaison (diff) des versions de firmware et des fichiers
* Émulation en mode utilisateur des binaires du système de fichiers en utilisant QEMU
* Détection de mesures d'atténuation binaires telles que NX, DEP, ASLR, canaris de pile, RELRO et FORTIFY_SOURCE
* API REST
* et plus encore...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer) : FwAnalyzer est un outil pour analyser des images de systèmes de fichiers (ext2/3/4), FAT/VFat, SquashFS, UBIFS, des archives cpio et le contenu des répertoires en utilisant un ensemble de règles configurables.
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep) : Un outil d'analyse de sécurité du firmware IoT en logiciel libre
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) : Il s'agit d'une réécriture complète du projet original ByteSweep en Go.
* [**EMBA**](https://github.com/e-m-b-a/emba) : _EMBA_ est conçu comme l'outil central d'analyse du firmware pour les pentesters. Il prend en charge l'ensemble du processus d'analyse de la sécurité, en commençant par le processus d'_extraction du firmware_, en effectuant une _analyse statique_ et une _analyse dynamique_ via l'émulation et enfin en générant un rapport. _EMBA_ découvre automatiquement les points faibles et les vulnérabilités possibles dans le firmware. Des exemples sont les binaires non sécurisés, les composants logiciels anciens et obsolètes, les scripts potentiellement vulnérables ou les mots de passe codés en dur.

{% hint style="warning" %}
À l'intérieur du système de fichiers, vous pouvez également trouver le **code source** des programmes (que vous devriez toujours **vérifier**), mais aussi des **binaires compilés**. Ces programmes pourraient être exposés d'une manière ou d'une autre et vous devriez les **décompiler** et les **vérifier** pour d'éventuelles vulnérabilités.

Des outils comme [**checksec.sh**](https://github.com/slimm609/checksec.sh) peuvent être utiles pour trouver des binaires non protégés. Pour les binaires Windows, vous pourriez utiliser [**PESecurity**](https://github.com/NetSPI/PESecurity).
{% endhint %}

## Émulation du Firmware

L'idée d'émuler le Firmware est de pouvoir effectuer une **analyse dynamique** de l'appareil **en fonctionnement** ou d'un **programme unique**.

{% hint style="info" %}
Parfois, l'émulation partielle ou complète **peut ne pas fonctionner en raison de dépendances matérielles ou architecturales**. Si l'architecture et l'endianness correspondent à un appareil possédé tel qu'un raspberry pi, le système de fichiers racine ou un binaire spécifique peut être transféré sur l'appareil pour des tests plus approfondis. Cette méthode s'applique également aux machines virtuelles préconstruites utilisant la même architecture et endianness que la cible.
{% endhint %}

### Émulation Binaire

Si vous souhaitez simplement émuler un programme pour rechercher des vulnérabilités, vous devez d'abord identifier son endianness et l'architecture CPU pour laquelle il a été compilé.

#### Exemple MIPS
```
```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```
Maintenant, vous pouvez **émuler** l'exécutable busybox en utilisant **QEMU**.
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Parce que l'exécutable **est** compilé pour **MIPS** et suit l'ordre des octets **big-endian**, nous utiliserons l'émulateur **`qemu-mips`** de QEMU. Pour émuler des exécutables **little-endian**, nous devrions sélectionner l'émulateur avec le suffixe `el` (`qemu-mipsel`) :
```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```
#### Exemple ARM
```bash
file bin/busybox
bin/busybox: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-armhf.so.1, no section header
```
Émulation :
```bash
qemu-arm -L ./squashfs-root/ ./squashfs-root/bin/ls
1C00000.squashfs  B80B6C            C41DD6.xz         squashfs-root     squashfs-root-0
```
### Émulation complète du système

Il existe plusieurs outils, basés sur **qemu** en général, qui vous permettront d'émuler le firmware complet :

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)** :**
* Vous devez installer plusieurs choses, configurer postgres, puis exécuter le script extractor.py pour extraire le firmware, utiliser le script getArch.sh pour obtenir l'architecture. Ensuite, utilisez les scripts tar2db.py et makeImage.sh pour stocker les informations de l'image extraite dans la base de données et générer une image QEMU que nous pouvons émuler. Puis, utilisez le script inferNetwork.sh pour obtenir les interfaces réseau, et enfin utilisez le script run.sh, qui est automatiquement créé dans le dossier ./scratch/1/.
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)** :**
* Cet outil dépend de firmadyne et automatise le processus d'émulation du firmware en utilisant firmadynee. vous devez configurer `fat.config` avant de l'utiliser : `sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **Analyse dynamique**

À ce stade, vous devriez avoir soit un appareil exécutant le firmware à attaquer, soit le firmware émulé à attaquer. Dans tous les cas, il est fortement recommandé que vous ayez également **un shell dans l'OS et le système de fichiers en cours d'exécution**.

Notez que parfois, si vous émulez le firmware, **certaines activités à l'intérieur de l'émulation peuvent échouer** et vous pourriez avoir besoin de redémarrer l'émulation. Par exemple, une application web pourrait avoir besoin d'obtenir des informations d'un appareil avec lequel l'appareil d'origine est intégré, mais l'émulation ne l'émule pas.

Vous devriez **revérifier le système de fichiers** comme nous l'avons déjà fait dans une **étape précédente car dans l'environnement en cours d'exécution, de nouvelles informations pourraient être accessibles.**

Si des **pages web** sont exposées, en lisant le code et en ayant accès à celles-ci, vous devriez **les tester**. Sur hacktricks, vous pouvez trouver beaucoup d'informations sur différentes techniques de piratage web.

Si des **services réseau** sont exposés, vous devriez essayer de les attaquer. Sur hacktricks, vous pouvez trouver beaucoup d'informations sur différentes techniques de piratage de services réseau. Vous pourriez également essayer de les fuzz avec des **fuzzers** de réseau et de protocole tels que [Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer), [boofuzz](https://github.com/jtpereyda/boofuzz), et [kitty](https://github.com/cisco-sas/kitty).

Vous devriez vérifier si vous pouvez **attaquer le bootloader** pour obtenir un shell root :

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

Vous devriez tester si l'appareil effectue des tests d'**intégrité du firmware**. Si ce n'est pas le cas, cela permettrait aux attaquants de proposer des firmwares compromis, de les installer sur des appareils appartenant à d'autres personnes ou même de les déployer à distance s'il existe une vulnérabilité de mise à jour du firmware :

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

Les vulnérabilités de mise à jour du firmware surviennent généralement parce que l'**intégrité** du **firmware** peut **ne pas** être **validée**, l'utilisation de **protocoles réseau** **non chiffrés**, l'utilisation de **crédentials codées en dur**, une **authentification non sécurisée** au composant cloud qui héberge le firmware, et même une **journalisation excessive et non sécurisée** (données sensibles), permettent des **mises à jour physiques** sans vérifications.

## **Analyse en temps réel**

L'analyse en temps réel implique de se connecter à un processus ou un binaire en cours d'exécution pendant qu'un appareil fonctionne dans son environnement normal ou émulé. Les étapes de base de l'analyse en temps réel sont fournies ci-dessous :

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. Attacher gdb-multiarch ou utiliser IDA pour émuler le binaire
3. Définir des points d'arrêt pour les fonctions identifiées lors de l'étape 4 telles que memcpy, strncpy, strcmp, etc.
4. Exécuter des chaînes de charge utile importantes pour identifier les dépassements de capacité ou les plantages de processus à l'aide d'un fuzzer
5. Passer à l'étape 8 si une vulnérabilité est identifiée

Les outils qui peuvent être utiles sont (liste non exhaustive) :

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

Après avoir identifié une vulnérabilité au sein d'un binaire lors des étapes précédentes, une preuve de concept (PoC) appropriée est requise pour démontrer l'impact et le risque réels. Le développement de code d'exploitation nécessite une expérience de programmation dans des langages de bas niveau (par exemple, ASM, C/C++, shellcode, etc.) ainsi qu'une connaissance de l'architecture cible particulière (par exemple, MIPS, ARM, x86, etc.). Le code PoC implique d'obtenir une exécution arbitraire sur un appareil ou une application en contrôlant une instruction en mémoire.

Il n'est pas courant que des protections d'exécution binaire (par exemple, NX, DEP, ASLR, etc.) soient en place dans les systèmes embarqués, cependant, lorsque cela se produit, des techniques supplémentaires peuvent être nécessaires telles que la programmation orientée retour (ROP). ROP permet à un attaquant d'implémenter une fonctionnalité malveillante arbitraire en chaînant du code existant dans le code du processus/binaire cible connu sous le nom de gadgets. Des étapes devront être prises pour exploiter une vulnérabilité identifiée telle qu'un débordement de tampon en formant une chaîne ROP. Un outil qui peut être utile dans des situations comme celles-ci est le gadget finder de Capstone ou ROPGadget - [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget).

Utilisez les références suivantes pour plus de conseils :

* [https://azeria-labs.com/writing-arm-shellcode/](https://azeria-labs.com/writing-arm-shellcode/)
* [https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/](https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/)

## OS préparés pour analyser le Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos) : AttifyOS est une distribution destinée à vous aider à effectuer l'évaluation de la sécurité et les tests d'intrusion des appareils Internet des objets (IoT). Elle vous fait gagner beaucoup de temps en fournissant un environnement préconfiguré avec tous les outils nécessaires chargés.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS) : Système d'exploitation de test de sécurité embarqué basé sur Ubuntu 18.04 préchargé avec des outils de test de sécurité du firmware.

## Firmware vulnérable pour la pratique

Pour pratiquer la découverte de vulnérabilités dans le firmware, utilisez les projets de firmware vulnérables suivants comme point de départ.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Références

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Formation et Certification

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
