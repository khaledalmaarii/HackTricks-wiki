# Analyse du micrologiciel

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## **Introduction**

Le micrologiciel est un logiciel essentiel qui permet aux appareils de fonctionner correctement en gérant et en facilitant la communication entre les composants matériels et le logiciel avec lequel les utilisateurs interagissent. Il est stocké en mémoire permanente, garantissant que l'appareil peut accéder aux instructions vitales dès sa mise sous tension, ce qui conduit au lancement du système d'exploitation. Examiner et éventuellement modifier le micrologiciel est une étape critique pour identifier les vulnérabilités de sécurité.

## **Collecte d'informations**

La **collecte d'informations** est une étape initiale critique pour comprendre la composition d'un appareil et les technologies qu'il utilise. Ce processus implique la collecte de données sur :

- L'architecture du processeur et le système d'exploitation qu'il exécute
- Spécificités du chargeur d'amorçage
- Configuration matérielle et fiches techniques
- Métriques de la base de code et emplacements des sources
- Bibliothèques externes et types de licences
- Historiques de mises à jour et certifications réglementaires
- Diagrammes architecturaux et de flux
- Évaluations de sécurité et vulnérabilités identifiées

À cette fin, les outils de **renseignement en source ouverte (OSINT)** sont inestimables, tout comme l'analyse de tout composant logiciel en source ouverte disponible via des processus d'examen manuels et automatisés. Des outils comme [Coverity Scan](https://scan.coverity.com) et [LGTM de Semmle](https://lgtm.com/#explore) offrent une analyse statique gratuite qui peut être exploitée pour trouver des problèmes potentiels.

## **Acquisition du micrologiciel**

L'obtention du micrologiciel peut être abordée de diverses manières, chacune avec son propre niveau de complexité :

- **Directement** auprès de la source (développeurs, fabricants)
- **Le construire** à partir des instructions fournies
- **Télécharger** depuis les sites de support officiels
- Utiliser des requêtes **Google dork** pour trouver des fichiers de micrologiciel hébergés
- Accéder au **stockage cloud** directement, avec des outils comme [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepter les **mises à jour** via des techniques de l'homme du milieu
- **Extraire** du périphérique via des connexions comme **UART**, **JTAG** ou **PICit**
- **Sniffer** les demandes de mise à jour dans la communication de l'appareil
- Identifier et utiliser des **points de terminaison de mise à jour codés en dur**
- **Extraire** du chargeur d'amorçage ou du réseau
- **Retirer et lire** la puce de stockage, en dernier recours, en utilisant des outils matériels appropriés

## Analyse du micrologiciel

Maintenant que vous **avez le micrologiciel**, vous devez extraire des informations à son sujet pour savoir comment le traiter. Différents outils que vous pouvez utiliser à cet effet :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si vous ne trouvez pas grand-chose avec ces outils, vérifiez l'**entropie** de l'image avec `binwalk -E <bin>`, si l'entropie est faible, il est peu probable qu'elle soit chiffrée. Si l'entropie est élevée, il est probable qu'elle soit chiffrée (ou compressée de quelque manière).

De plus, vous pouvez utiliser ces outils pour extraire des **fichiers intégrés dans le firmware**:

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) pour inspecter le fichier.

### Obtenir le système de fichiers

Avec les outils précédemment commentés comme `binwalk -ev <bin>`, vous devriez avoir pu **extraire le système de fichiers**.\
Binwalk l'extrait généralement dans un **dossier nommé comme le type de système de fichiers**, qui est généralement l'un des suivants : squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extraction manuelle du système de fichiers

Parfois, binwalk n'aura pas l'octet magique du système de fichiers dans ses signatures. Dans ces cas, utilisez binwalk pour **trouver l'offset du système de fichiers et découper le système de fichiers compressé** du binaire et **extraire manuellement** le système de fichiers selon son type en suivant les étapes ci-dessous.
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
Alternativement, la commande suivante pourrait également être exécutée.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Pour squashfs (utilisé dans l'exemple ci-dessus)

`$ unsquashfs dir.squashfs`

Les fichiers seront dans le répertoire "`squashfs-root`" par la suite.

* Fichiers d'archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Pour les systèmes de fichiers jffs2

`$ jefferson rootfsfile.jffs2`

* Pour les systèmes de fichiers ubifs avec flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`


## Analyse du Firmware

Une fois le firmware obtenu, il est essentiel de le disséquer pour comprendre sa structure et ses vulnérabilités potentielles. Ce processus implique l'utilisation de divers outils pour analyser et extraire des données précieuses de l'image du firmware.

### Outils d'Analyse Initiale

Un ensemble de commandes est fourni pour l'inspection initiale du fichier binaire (appelé `<bin>`). Ces commandes aident à identifier les types de fichiers, extraire des chaînes, analyser des données binaires et comprendre les détails des partitions et des systèmes de fichiers :
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Pour évaluer le statut de chiffrement de l'image, l'**entropie** est vérifiée avec `binwalk -E <bin>`. Une faible entropie suggère un manque de chiffrement, tandis qu'une entropie élevée indique un possible chiffrement ou compression.

Pour extraire des **fichiers intégrés**, des outils et des ressources comme la documentation sur les **outils de récupération de données de découpe de fichiers** et **binvis.io** pour l'inspection des fichiers sont recommandés.

### Extraction du système de fichiers

En utilisant `binwalk -ev <bin>`, on peut généralement extraire le système de fichiers, souvent dans un répertoire nommé d'après le type de système de fichiers (par exemple, squashfs, ubifs). Cependant, lorsque **binwalk** échoue à reconnaître le type de système de fichiers en raison de l'absence d'octets magiques, une extraction manuelle est nécessaire. Cela implique d'utiliser `binwalk` pour localiser le décalage du système de fichiers, suivi de la commande `dd` pour découper le système de fichiers:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
### Analyse du système de fichiers

Une fois le système de fichiers extrait, la recherche de failles de sécurité commence. Une attention particulière est portée aux démons réseau non sécurisés, aux identifiants codés en dur, aux points d'API, aux fonctionnalités de serveur de mise à jour, au code non compilé, aux scripts de démarrage et aux binaires compilés pour une analyse hors ligne.

Les **emplacements clés** et les **éléments** à inspecter comprennent :

- **etc/shadow** et **etc/passwd** pour les identifiants d'utilisateur
- Certificats SSL et clés dans **etc/ssl**
- Fichiers de configuration et de script pour des vulnérabilités potentielles
- Binaires intégrés pour une analyse plus approfondie
- Serveurs web d'appareils IoT courants et binaires

Plusieurs outils aident à découvrir des informations sensibles et des vulnérabilités dans le système de fichiers :

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) et [**Firmwalker**](https://github.com/craigz28/firmwalker) pour la recherche d'informations sensibles
- [**L'outil d'analyse et de comparaison de firmware (FACT)**](https://github.com/fkie-cad/FACT\_core) pour une analyse complète du firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) et [**EMBA**](https://github.com/e-m-b-a/emba) pour une analyse statique et dynamique

### Vérifications de sécurité sur les binaires compilés

Le code source et les binaires compilés trouvés dans le système de fichiers doivent être examinés pour détecter des vulnérabilités. Des outils comme **checksec.sh** pour les binaires Unix et **PESecurity** pour les binaires Windows aident à identifier les binaires non protégés qui pourraient être exploités.

## Émulation de firmware pour une analyse dynamique

Le processus d'émulation de firmware permet une **analyse dynamique** du fonctionnement d'un appareil ou d'un programme individuel. Cette approche peut rencontrer des défis liés aux dépendances matérielles ou architecturales, mais le transfert du système de fichiers racine ou de binaires spécifiques vers un appareil avec une architecture et une endianness correspondantes, tel qu'un Raspberry Pi, ou vers une machine virtuelle pré-construite, peut faciliter les tests ultérieurs.

### Émulation de binaires individuels

Pour examiner des programmes individuels, il est crucial d'identifier l'endianness et l'architecture du processeur du programme.

#### Exemple avec l'architecture MIPS

Pour émuler un binaire d'architecture MIPS, on peut utiliser la commande :
```bash
file ./squashfs-root/bin/busybox
```
Et pour installer les outils d'émulation nécessaires :
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### Emulation de l'architecture ARM

Pour les binaires ARM, le processus est similaire, avec l'émulateur `qemu-arm` étant utilisé pour l'émulation.

### Emulation du système complet

Des outils comme [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), et d'autres, facilitent l'émulation complète du firmware, automatisant le processus et aidant dans l'analyse dynamique.

## Analyse Dynamique en Pratique

À ce stade, un environnement de dispositif réel ou émulé est utilisé pour l'analyse. Il est essentiel de maintenir l'accès à l'interface en ligne de commande de l'OS et au système de fichiers. L'émulation peut ne pas reproduire parfaitement les interactions matérielles, nécessitant parfois des redémarrages de l'émulation. L'analyse devrait revisiter le système de fichiers, exploiter les pages web exposées et les services réseau, et explorer les vulnérabilités du chargeur d'amorçage. Les tests d'intégrité du firmware sont essentiels pour identifier les potentielles vulnérabilités de porte dérobée.

## Techniques d'Analyse en Temps d'Exécution

L'analyse en temps d'exécution implique d'interagir avec un processus ou un binaire dans son environnement d'exploitation, en utilisant des outils comme gdb-multiarch, Frida, et Ghidra pour définir des points d'arrêt et identifier les vulnérabilités à travers le fuzzing et d'autres techniques.

## Exploitation Binaire et Preuve de Concept

Développer une PoC pour les vulnérabilités identifiées nécessite une compréhension approfondie de l'architecture cible et de la programmation en langages de bas niveau. Les protections d'exécution binaire dans les systèmes embarqués sont rares, mais lorsque présentes, des techniques comme la Programmation Orientée Retour (ROP) peuvent être nécessaires.

## Systèmes d'Exploitation Préparés pour l'Analyse de Firmware

Des systèmes d'exploitation comme [AttifyOS](https://github.com/adi0x90/attifyos) et [EmbedOS](https://github.com/scriptingxss/EmbedOS) fournissent des environnements préconfigurés pour les tests de sécurité des firmwares, équipés des outils nécessaires.

## OS Préparés pour Analyser les Firmwares

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS est une distribution conçue pour vous aider à réaliser des évaluations de sécurité et des tests de pénétration des dispositifs Internet des Objets (IoT). Il vous fait gagner du temps en fournissant un environnement préconfiguré avec tous les outils nécessaires chargés.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Système d'exploitation de test de sécurité embarqué basé sur Ubuntu 18.04 préchargé avec des outils de test de sécurité des firmwares.

## Firmwares Vulnérables pour la Pratique

Pour pratiquer la découverte de vulnérabilités dans les firmwares, utilisez les projets de firmwares vulnérables suivants comme point de départ.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* Le Projet de Firmware de Routeur Vulnérable Damn (DVRF)
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Routeur ARM Vulnérable Damn (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Dispositif IoT Vulnérable Damn (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Références

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Hacking IoT Pratique : Le Guide Définitif pour Attaquer l'Internet des Objets](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Formation et Certificat

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)
