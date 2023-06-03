# Partitions/Systèmes de fichiers/Carving

## Partitions

Un disque dur ou un **SSD peut contenir différentes partitions** dans le but de séparer physiquement les données.\
L'unité **minimale** d'un disque est le **secteur** (généralement composé de 512B). Ainsi, la taille de chaque partition doit être un multiple de cette taille.

### MBR (Master Boot Record)

Il est alloué dans le **premier secteur du disque après les 446B du code de démarrage**. Ce secteur est essentiel pour indiquer au PC ce qu'est une partition et d'où elle doit être montée.\
Il permet jusqu'à **4 partitions** (au plus **1 seule** peut être active/**amorçable**). Cependant, si vous avez besoin de plus de partitions, vous pouvez utiliser des **partitions étendues**. Le **dernier octet** de ce premier secteur est la signature d'enregistrement de démarrage **0x55AA**. Une seule partition peut être marquée comme active.\
MBR permet **max 2,2 To**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Des **octets 440 à 443** du MBR, vous pouvez trouver la **signature de disque Windows** (si Windows est utilisé). La lettre de lecteur logique du disque dur dépend de la signature de disque Windows. Changer cette signature pourrait empêcher Windows de démarrer (outil : [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Format**

| Offset      | Longueur   | Élément             |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Code de démarrage   |
| 446 (0x1BE) | 16 (0x10)  | Première partition  |
| 462 (0x1CE) | 16 (0x10)  | Deuxième partition  |
| 478 (0x1DE) | 16 (0x10)  | Troisième partition |
| 494 (0x1EE) | 16 (0x10)  | Quatrième partition |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Format d'enregistrement de partition**

| Offset    | Longueur | Élément                                                                 |
| --------- | -------- | ------------------------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Drapeau actif (0x80 = amorçable)                                         |
| 1 (0x01)  | 1 (0x01) | Tête de départ                                                         |
| 2 (0x02)  | 1 (0x01) | Secteur de départ (bits 0-5) ; bits supérieurs du cylindre (6-7)         |
| 3 (0x03)  | 1 (0x01) | Les 8 bits les moins significatifs du cylindre de départ                 |
| 4 (0x04)  | 1 (0x01) | Code de type de partition (0x83 = Linux)                                 |
| 5 (0x05)  | 1 (0x01) | Tête de fin                                                             |
| 6 (0x06)  | 1 (0x01) | Secteur de fin (bits 0-5) ; bits supérieurs du cylindre (6-7)             |
| 7 (0x07)  | 1 (0x01) | Les 8 bits les moins significatifs du cylindre de fin                     |
| 8 (0x08)  | 4 (0x04) | Secteurs précédant la partition (petit boutiste)                          |
| 12 (0x0C) | 4 (0x04) | Secteurs dans la partition                                               |

Pour monter un MBR sous Linux, vous devez d'abord obtenir le décalage de départ (vous pouvez utiliser `fdisk` et la commande `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10).png>)

Et ensuite utiliser le code suivant
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (adressage de bloc logique)**

L'adressage de bloc logique (LBA) est un schéma couramment utilisé pour spécifier l'emplacement des blocs de données stockés sur des dispositifs de stockage informatique, généralement des systèmes de stockage secondaires tels que les disques durs. LBA est un schéma d'adressage linéaire particulièrement simple ; les blocs sont localisés par un index entier, le premier bloc étant LBA 0, le deuxième LBA 1, et ainsi de suite.

### GPT (Table de partition GUID)

Elle est appelée table de partition GUID car chaque partition sur votre disque a un identifiant unique global.

Tout comme MBR, elle commence dans le secteur 0. Le MBR occupe 32 bits tandis que GPT utilise 64 bits.\
GPT permet jusqu'à 128 partitions sous Windows et jusqu'à 9,4 ZB.\
De plus, les partitions peuvent avoir un nom Unicode de 36 caractères.

Sur un disque MBR, le partitionnement et les données de démarrage sont stockés au même endroit. Si ces données sont écrasées ou corrompues, vous êtes en difficulté. En revanche, GPT stocke plusieurs copies de ces données sur le disque, il est donc beaucoup plus robuste et peut récupérer les données endommagées si nécessaire.

GPT stocke également des valeurs de contrôle de redondance cyclique (CRC) pour vérifier que ses données sont intactes. Si les données sont corrompues, GPT peut détecter le problème et tenter de récupérer les données endommagées à partir d'un autre emplacement sur le disque.

**MBR protecteur (LBA0)**

Pour une compatibilité limitée avec les anciens systèmes, l'espace du MBR hérité est toujours réservé dans la spécification GPT, mais il est maintenant utilisé de manière à empêcher les utilitaires de disque basés sur MBR de mal reconnaître et de potentiellement écraser les disques GPT. Cela est appelé un MBR protecteur.

![](<../../../.gitbook/assets/image (491).png>)

**MBR hybride (LBA 0 + GPT)**

Dans les systèmes d'exploitation qui prennent en charge le démarrage basé sur GPT via les services BIOS plutôt que EFI, le premier secteur peut également être utilisé pour stocker le premier stade du code de chargeur de démarrage, mais modifié pour reconnaître les partitions GPT. Le chargeur de démarrage dans le MBR ne doit pas supposer une taille de secteur de 512 octets.

**En-tête de table de partition (LBA 1)**

L'en-tête de table de partition définit les blocs utilisables sur le disque. Il définit également le nombre et la taille des entrées de partition qui composent la table de partition (décalages 80 et 84 dans la table).

| Décalage   | Longueur | Contenu                                                                                                                                                                         |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)   | 8 octets | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ou 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8) sur les machines little-endian) |
| 8 (0x08)   | 4 octets | Révision 1.0 (00h 00h 01h 00h) pour UEFI 2.8                                                                                                                                     |
| 12 (0x0C)  | 4 octets | Taille de l'en-tête en little endian (en octets, généralement 5Ch 00h 00h 00h ou 92 octets)                                                                                      |
| 16 (0x10)  | 4 octets | [CRC32](https://en.wikipedia.org/wiki/CRC32) de l'en-tête (décalage +0 jusqu'à la taille de l'en-tête) en little endian, avec ce champ mis à zéro pendant le calcul         |
| 20 (0x14)  | 4 octets | Réservé ; doit être zéro                                                                                                                                                        |
| 24 (0x18)  | 8 octets | LBA actuel (emplacement de cette copie d'en-tête)                                                                                                                                |
| 32 (0x20)  | 8 octets | LBA de sauvegarde (emplacement de l'autre copie d'en-tête)                                                                                                                       |
| 40 (0x28)  | 8 octets | Premier LBA utilisable pour les partitions (dernier LBA de la table de partition primaire + 1)                                                                                    |
| 48 (0x30)  | 8 octets | Dernier LBA utilisable (premier LBA de la table de partition secondaire - 1)                                                                                                     |
| 56 (0x38)  | 16 octets | GUID de disque en endian mixte                                                                                                                                                  |
| 72 (0x48)  | 8 octets | LBA de départ d'un tableau d'entrées de partition (toujours 2 dans la copie primaire)                                                                                           |
| 80 (0x50)  | 4 octets | Nombre d'entrées de partition dans le tableau                                                                                                                                    |
| 84 (0x54)  | 4 octets | Taille d'une seule entrée de partition (généralement 80h ou 128)                                                                                                                |
| 88 (0x58)  | 4 octets | CRC32 du tableau d'entrées de partition en little endian                                                                                                                         |
| 92 (0x5C)  | \*       | Réservé ; doit être zéro pour le reste du bloc (420 octets pour une taille de secteur de 512 octets ; mais peut être plus avec des tailles de secteur plus grandes)           |

**Entrées de partition (LBA 2-33)**

| Format d'entrée de partition GUID |          |
### **Sculpture de fichiers**

La **sculpture de fichiers** est une technique qui tente de **trouver des fichiers dans une masse de données**. Il existe 3 façons principales dont les outils comme celui-ci fonctionnent : **en se basant sur les en-têtes et les pieds de page des types de fichiers**, en se basant sur les **structures** des types de fichiers et en se basant sur le **contenu** lui-même.

Notez que cette technique **ne fonctionne pas pour récupérer des fichiers fragmentés**. Si un fichier **n'est pas stocké dans des secteurs contigus**, alors cette technique ne pourra pas le trouver ou du moins une partie de celui-ci.

Il existe plusieurs outils que vous pouvez utiliser pour la sculpture de fichiers en indiquant les types de fichiers que vous souhaitez rechercher.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Sculpture de flux de données

La sculpture de flux de données est similaire à la sculpture de fichiers, mais **au lieu de chercher des fichiers complets, elle cherche des fragments intéressants** d'informations.\
Par exemple, au lieu de chercher un fichier complet contenant des URL enregistrées, cette technique recherchera des URL.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Suppression sécurisée

De toute évidence, il existe des moyens de **supprimer "de manière sécurisée" des fichiers et des parties de journaux à leur sujet**. Par exemple, il est possible de **écraser le contenu** d'un fichier avec des données inutiles plusieurs fois, puis **supprimer** les **journaux** du **$MFT** et du **$LOGFILE** à propos du fichier, et **supprimer les copies d'ombre de volume**.\
Vous pouvez remarquer que même en effectuant cette action, il peut y avoir **d'autres parties où l'existence du fichier est encore enregistrée**, et c'est vrai et une partie du travail professionnel de la criminalistique est de les trouver.

## Références

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
