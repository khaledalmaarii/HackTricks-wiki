# Partitions/Systèmes de fichiers/Carving

## Partitions/Systèmes de fichiers/Carving

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Partitions

Un disque dur ou un **SSD peut contenir différentes partitions** dans le but de séparer les données physiquement.\
L'unité **minimale** d'un disque est le **secteur** (normalement composé de 512B). Ainsi, la taille de chaque partition doit être un multiple de cette taille.

### MBR (Master Boot Record)

Il est alloué dans le **premier secteur du disque après les 446B du code de démarrage**. Ce secteur est essentiel pour indiquer au PC quoi et d'où une partition doit être montée.\
Il permet jusqu'à **4 partitions** (au maximum **seulement 1** peut être active/**bootable**). Cependant, si vous avez besoin de plus de partitions, vous pouvez utiliser des **partitions étendues**. Le **dernier octet** de ce premier secteur est la signature du record de démarrage **0x55AA**. Seule une partition peut être marquée comme active.\
MBR permet un **maximum de 2.2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Du **octet 440 au 443** du MBR, vous pouvez trouver la **Signature de Disque Windows** (si Windows est utilisé). La lettre de lecteur logique du disque dur dépend de la Signature de Disque Windows. Changer cette signature pourrait empêcher Windows de démarrer (outil : [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Format**

| Décalage   | Longueur  | Élément              |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Code de démarrage    |
| 446 (0x1BE) | 16 (0x10)  | Première Partition  |
| 462 (0x1CE) | 16 (0x10)  | Deuxième Partition  |
| 478 (0x1DE) | 16 (0x10)  | Troisième Partition |
| 494 (0x1EE) | 16 (0x10)  | Quatrième Partition |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Format d'enregistrement de partition**

| Décalage | Longueur | Élément                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Drapeau actif (0x80 = bootable)                          |
| 1 (0x01)  | 1 (0x01) | Tête de départ                                           |
| 2 (0x02)  | 1 (0x01) | Secteur de départ (bits 0-5); bits supérieurs du cylindre (6- 7) |
| 3 (0x03)  | 1 (0x01) | Cylindre de départ 8 bits inférieurs                     |
| 4 (0x04)  | 1 (0x01) | Code de type de partition (0x83 = Linux)                 |
| 5 (0x05)  | 1 (0x01) | Tête de fin                                              |
| 6 (0x06)  | 1 (0x01) | Secteur de fin (bits 0-5); bits supérieurs du cylindre (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Cylindre de fin 8 bits inférieurs                        |
| 8 (0x08)  | 4 (0x04) | Secteurs précédant la partition (little endian)          |
| 12 (0x0C) | 4 (0x04) | Secteurs dans la partition                               |

Pour monter un MBR sous Linux, vous devez d'abord obtenir le décalage de départ (vous pouvez utiliser `fdisk` et la commande `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

Et ensuite utiliser le code suivant
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**L'adressage par bloc logique** (**LBA**) est un schéma courant utilisé pour **spécifier l'emplacement des blocs** de données stockées sur des dispositifs de stockage informatique, généralement des systèmes de stockage secondaire tels que les disques durs. LBA est un schéma d'adressage linéaire particulièrement simple ; **les blocs sont localisés par un indice entier**, avec le premier bloc étant LBA 0, le second LBA 1, et ainsi de suite.

### GPT (GUID Partition Table)

Il est appelé Table de Partition GUID parce que chaque partition de votre disque a un **identifiant unique global**.

Comme MBR, il commence dans le **secteur 0**. Le MBR occupe 32bits tandis que **GPT** utilise **64bits**.\
GPT **permet jusqu'à 128 partitions** sous Windows et jusqu'à **9.4ZB**.\
De plus, les partitions peuvent avoir un nom Unicode de 36 caractères.

Sur un disque MBR, les données de partitionnement et de démarrage sont stockées à un seul endroit. Si ces données sont écrasées ou corrompues, vous avez un problème. En revanche, **GPT stocke plusieurs copies de ces données sur le disque**, il est donc beaucoup plus robuste et peut récupérer si les données sont corrompues.

GPT stocke également des valeurs de **vérification de redondance cyclique (CRC)** pour vérifier que ses données sont intactes. Si les données sont corrompues, GPT peut détecter le problème et **tenter de récupérer les données endommagées** à partir d'un autre emplacement sur le disque.

**MBR de protection (LBA0)**

Pour une compatibilité arrière limitée, l'espace du MBR hérité est toujours réservé dans la spécification GPT, mais il est maintenant utilisé d'une **manière qui empêche les utilitaires de disque basés sur MBR de méconnaître et éventuellement d'écraser les disques GPT**. Cela est appelé un MBR de protection.

![](<../../../.gitbook/assets/image (491).png>)

**MBR hybride (LBA 0 + GPT)**

Dans les systèmes d'exploitation qui prennent en charge le **démarrage basé sur GPT via les services BIOS** plutôt que EFI, le premier secteur peut également être utilisé pour stocker la première étape du **code du chargeur de démarrage**, mais **modifié** pour reconnaître les **partitions GPT**. Le chargeur de démarrage dans le MBR ne doit pas supposer une taille de secteur de 512 octets.

**En-tête de la table de partition (LBA 1)**

L'en-tête de la table de partition définit les blocs utilisables sur le disque. Il définit également le nombre et la taille des entrées de partition qui composent la table de partition (décalages 80 et 84 dans le tableau).

| Décalage   | Longueur | Contenu                                                                                                                                                                        |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0 (0x00)   | 8 octets | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ou 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8) sur des machines little-endian) |
| 8 (0x08)   | 4 octets | Révision 1.0 (00h 00h 01h 00h) pour UEFI 2.8                                                                                                                                  |
| 12 (0x0C)  | 4 octets | Taille de l'en-tête en little endian (en octets, généralement 5Ch 00h 00h 00h ou 92 octets)                                                                                   |
| 16 (0x10)  | 4 octets | [CRC32](https://en.wikipedia.org/wiki/CRC32) de l'en-tête (décalage +0 jusqu'à la taille de l'en-tête) en little endian, avec ce champ remis à zéro pendant le calcul          |
| 20 (0x14)  | 4 octets | Réservé ; doit être zéro                                                                                                                                                       |
| 24 (0x18)  | 8 octets | LBA actuel (emplacement de cette copie de l'en-tête)                                                                                                                           |
| 32 (0x20)  | 8 octets | LBA de sauvegarde (emplacement de l'autre copie de l'en-tête)                                                                                                                  |
| 40 (0x28)  | 8 octets | Premier LBA utilisable pour les partitions (dernier LBA de la table de partition principale + 1)                                                                               |
| 48 (0x30)  | 8 octets | Dernier LBA utilisable (premier LBA de la table de partition secondaire − 1)                                                                                                   |
| 56 (0x38)  | 16 octets| GUID du disque en mixed endian                                                                                                                                                 |
| 72 (0x48)  | 8 octets | LBA de départ d'un tableau d'entrées de partition (toujours 2 dans la copie principale)                                                                                        |
| 80 (0x50)  | 4 octets | Nombre d'entrées de partition dans le tableau                                                                                                                                  |
| 84 (0x54)  | 4 octets | Taille d'une seule entrée de partition (généralement 80h ou 128)                                                                                                               |
| 88 (0x58)  | 4 octets | CRC32 du tableau des entrées de partition en little endian                                                                                                                     |
| 92 (0x5C)  | \*       | Réservé ; doit être des zéros pour le reste du bloc (420 octets pour une taille de secteur de 512 octets ; mais peut être plus avec des tailles de secteur plus grandes)       |

**Entrées de partition (LBA 2–33)**

| Format d'entrée de partition GUID |          |                                                                                                                   |
| --------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Décalage                          | Longueur | Contenu                                                                                                           |
| 0 (0x00)                          | 16 octets| [GUID de type de partition](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (mixed endian) |
| 16 (0x10)                         | 16 octets| GUID de partition unique (mixed endian)                                                                           |
| 32 (0x20)                         | 8 octets | Premier LBA ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                       |
| 40 (0x28)                         | 8 octets | Dernier LBA (inclus, généralement impair)                                                                         |
| 48 (0x30)                         | 8 octets | Drapeaux d'attributs (par exemple, le bit 60 indique en lecture seule)                                            |
| 56 (0x38)                         | 72 octets| Nom de la partition (36 unités de code [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                          |

**Types de Partitions**

![](<../../../.gitbook/assets/image (492).png>)

Plus de types de partitions sur [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspection

Après avoir monté l'image forensique avec [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), vous pouvez inspecter le premier secteur en utilisant l'outil Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Dans l'image suivante, un **MBR** a été détecté sur le **secteur 0** et interprété :

![](<../../../.gitbook/assets/image (494).png>)

Si c'était une **table GPT au lieu d'un MBR**, la signature _EFI PART_ devrait apparaître dans le **secteur 1** (qui dans l'image précédente est vide).

## Systèmes de Fichiers

### Liste des systèmes de fichiers Windows

* **FAT12/16** : MSDOS, WIN95/98/NT/200
* **FAT32** : 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT** : 2008/2012/2016/VISTA/7/8/10
* **NTFS** : XP/2003/2008/2012/VISTA/7/8/10
* **ReFS** : 2012/2016

### FAT

Le système de fichiers **FAT (File Allocation Table)** est nommé pour sa méthode d'organisation, la table d'allocation de fichiers, qui se trouve au début du volume. Pour protéger le volume, **deux copies** de la table sont conservées, au cas où l'une serait endommagée. De plus, les tables d'allocation de fichiers et le dossier racine doivent être stockés dans un **emplacement fixe** afin que les fichiers nécessaires au démarrage du système puissent être correctement localisés.

![](<../../../.gitbook/assets/image (495).png>)

L'unité d'espace minimale utilisée par ce système de fichiers est un **cluster, généralement 512B** (qui est composé d'un certain nombre de secteurs).

Le plus ancien **FAT12** avait des **adresses de cluster à 12 bits** avec jusqu'à **4078** **clusters** ; il permettait jusqu'à 4084 clusters avec UNIX. Le **FAT16** plus efficace est passé à une adresse de cluster **16 bits** permettant jusqu'à **65 517 clusters** par volume. FAT32 utilise une adresse de cluster 32 bits permettant jusqu'à **268 435 456 clusters** par volume.

La **taille maximale de fichier autorisée par FAT est de 4 Go** (moins un octet) car le système de fichiers utilise un champ de 32 bits pour stocker la taille du fichier en octets, et 2^32 octets = 4 Gio. Cela se produit pour FAT12, FAT16 et FAT32.

Le **répertoire racine** occupe une **position spécifique** pour FAT12 et FAT16 (dans FAT32, il occupe une position comme tout autre dossier). Chaque entrée de fichier/dossier contient ces informations :

* Nom du fichier/dossier (8 caractères max)
* Attributs
* Date de création
* Date de modification
* Date du dernier accès
* Adresse de la table FAT où commence le premier cluster du fichier
* Taille

Lorsqu'un fichier est "supprimé" en utilisant un système de fichiers FAT, l'entrée de répertoire reste presque **inchangée** à l'exception du **premier caractère du nom de fichier** (modifié en 0xE5), préservant la plupart du nom du fichier "supprimé", ainsi que son horodatage, sa longueur de fichier et — le plus important — son emplacement physique sur le disque. La liste des clusters de disque occupés par le fichier sera cependant effacée de la Table d'Allocation de Fichiers, marquant ces secteurs disponibles pour une utilisation par d'autres fichiers créés ou modifiés par la suite. Dans le cas de FAT32, il y a également un champ effacé responsable des 16 bits supérieurs de la valeur de cluster de départ du fichier.

### **NTFS**

{% content-ref url="ntfs.md" %}
[ntfs.md](ntfs.md)
{% endcontent-ref %}

### EXT

**Ext2** est le système de fichiers le plus courant pour les partitions **sans journalisation** (**partitions qui ne changent pas beaucoup**) comme la partition de démarrage. **Ext3/4** sont **avec journalisation** et sont généralement utilisés pour les **autres partitions**.

{% content-ref url="ext.md" %}
[ext.md](ext.md)
{% endcontent-ref %}

## **Métadonnées**

Certains fichiers contiennent des métadonnées. Cette information concerne le contenu du fichier qui parfois peut être intéressant pour un analyste car selon le type de fichier, il peut contenir des informations comme :

* Titre
* Version de MS Office utilisée
* Auteur
* Dates de création et de dernière modification
* Modèle de l'appareil photo
* Coordonnées GPS
* Informations sur l'image

Vous pouvez utiliser des outils comme [**exiftool**](https://exiftool.org) et [**Metadiver**](https://www.easymetadata.com/metadiver-2/) pour obtenir les métadonnées d'un fichier.

## **Récupération de Fichiers Supprimés**

### Fichiers Supprimés Enregistrés

Comme on l'a vu précédemment, il existe plusieurs endroits où le fichier est encore sauvegardé après avoir été "supprimé". C'est parce que généralement la suppression d'un fichier d'un système de fichiers le marque simplement comme supprimé mais les données ne sont pas touchées. Ensuite, il est possible d'inspecter les registres des fichiers (comme le MFT) et de trouver les fichiers supprimés.

De plus, le système d'exploitation enregistre généralement beaucoup d'informations sur les changements du système de fichiers et les sauvegardes, il est donc possible d'essayer de les utiliser pour récupérer le fichier ou autant d'informations que possible.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **File Carving**

**Le File Carving** est une technique qui essaie de **trouver des fichiers dans la masse de données**. Il existe 3 principales façons dont les outils de ce type fonctionnent : **Basés sur les en-têtes et les pieds de page des types de fichiers**, basés sur les **structures** des types de fichiers et basés sur le **contenu** lui-même.

Notez que cette technique **ne fonctionne pas pour récupérer des fichiers fragmentés**. Si un fichier **n'est pas stocké dans des secteurs contigus**, alors cette technique ne pourra pas le trouver ou du moins une partie de celui-ci.

Il existe plusieurs outils que vous pouvez utiliser pour le File Carving en indiquant les types de fichiers que vous souhaitez rechercher

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Carving de Flux de Données

Le Carving de Flux de Données est similaire au File Carving mais **au lieu de chercher des fichiers complets, il cherche des fragments d'informations intéressants**.\
Par exemple, au lieu de chercher un fichier complet contenant des URL enregistrées, cette technique recherchera des URL.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Suppression Sécurisée

Évidemment, il existe des moyens de **supprimer "sécuritairement" des fichiers et des parties des journaux à leur sujet**. Par exemple, il est possible d'**écraser le contenu** d'un fichier avec des données inutiles plusieurs fois, puis de **supprimer** les **journaux** du **$MFT** et **$LOGFILE** concernant le fichier, et de **supprimer les Copies de Volume d'Ombre**.\
Vous pouvez remarquer que même en effectuant cette action, il pourrait y avoir **d'autres parties où l'existence du fichier est encore enregistrée**, et c'est vrai et une partie du travail du professionnel de la forensique est de les trouver.

## Références

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4
