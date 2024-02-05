# NTFS

## NTFS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## **NTFS**

**NTFS** (**Nouveau système de fichiers technologique**) est un système de fichiers journalisé propriétaire développé par Microsoft.

Le cluster est l'unité de taille la plus petite dans NTFS et la taille du cluster dépend de la taille d'une partition.

| Taille de la partition    | Secteurs par cluster | Taille du cluster |
| ------------------------ | ------------------- | ------------ |
| 512 Mo ou moins            | 1                   | 512 octets    |
| 513 Mo-1024 Mo (1 Go)       | 2                   | 1 Ko          |
| 1025 Mo-2048 Mo (2 Go)      | 4                   | 2 Ko          |
| 2049 Mo-4096 Mo (4 Go)      | 8                   | 4 Ko          |
| 4097 Mo-8192 Mo (8 Go)      | 16                  | 8 Ko          |
| 8193 Mo-16,384 Mo (16 Go)   | 32                  | 16 Ko         |
| 16,385 Mo-32,768 Mo (32 Go) | 64                  | 32 Ko         |
| Supérieur à 32,768 Mo    | 128                 | 64 Ko         |

### **Espace de jeu**

Comme la taille d'unité la plus petite de NTFS est un **cluster**. Chaque fichier occupera plusieurs clusters complets. Ainsi, il est très probable que **chaque fichier occupe plus d'espace que nécessaire**. Ces **espaces inutilisés** **réservés** par un fichier sont appelés **espaces de jeu** et les gens pourraient en profiter pour **cacher** **des informations**.

![](<../../../.gitbook/assets/image (498).png>)

### **Secteur d'amorçage NTFS**

Lorsque vous formatez un volume NTFS, le programme de formatage alloue les 16 premiers secteurs pour le fichier de métadonnées d'amorçage. Le premier secteur est un secteur d'amorçage avec un code "bootstrap" et les 15 secteurs suivants sont le chargeur de programme initial (IPL) du secteur d'amorçage. Pour augmenter la fiabilité du système de fichiers, le tout dernier secteur d'une partition NTFS contient une copie de secours du secteur d'amorçage.

### **Table des fichiers principaux (MFT)**

Le système de fichiers NTFS contient un fichier appelé Table des fichiers principaux (MFT). Il y a au moins **une entrée dans la MFT pour chaque fichier sur un volume de système de fichiers NTFS**, y compris la MFT elle-même. Toutes les informations sur un fichier, y compris sa **taille, ses horodatages, ses autorisations et son contenu de données**, sont stockées soit dans les entrées de la MFT, soit dans l'espace en dehors de la MFT décrit par les entrées de la MFT.

Au fur et à mesure que des **fichiers sont ajoutés** à un volume de système de fichiers NTFS, d'autres entrées sont ajoutées à la MFT et la **MFT augmente en taille**. Lorsque des **fichiers** sont **supprimés** d'un volume de système de fichiers NTFS, leurs **entrées de MFT sont marquées comme libres** et peuvent être réutilisées. Cependant, l'espace disque qui a été alloué pour ces entrées n'est pas réalloué, et la taille de la MFT ne diminue pas.

Le système de fichiers NTFS **réserve de l'espace pour la MFT pour la maintenir aussi contiguë que possible** à mesure qu'elle grandit. L'espace réservé par le système de fichiers NTFS pour la MFT dans chaque volume est appelé la **zone MFT**. L'espace pour les fichiers et répertoires est également alloué à partir de cet espace, mais seulement après que tout l'espace du volume en dehors de la zone MFT a été alloué.

En fonction de la taille moyenne des fichiers et d'autres variables, **soit la zone MFT réservée, soit l'espace non réservé sur le disque peut être alloué en premier** lorsque le disque se remplit. Les volumes avec un petit nombre de fichiers relativement volumineux alloueront d'abord l'espace non réservé, tandis que les volumes avec un grand nombre de fichiers relativement petits alloueront d'abord la zone MFT. Dans les deux cas, la fragmentation de la MFT commence à se produire lorsque l'une ou l'autre région est entièrement allouée. Si l'espace non réservé est complètement alloué, l'espace pour les fichiers et répertoires d'utilisateurs sera alloué à partir de la zone MFT. Si la zone MFT est complètement allouée, l'espace pour de nouvelles entrées MFT sera alloué à partir de l'espace non réservé.

Les systèmes de fichiers NTFS génèrent également un **$MFTMirror**. Il s'agit d'une **copie des 4 premières entrées** de la MFT : $MFT, $MFT Mirror, $Log, $Volume.

NTFS réserve les 16 premiers enregistrements de la table pour des informations spéciales :

| Fichier système           | Nom de fichier | Enregistrement MFT | But du fichier                                                                                                                                                                                                           |
| --------------------- | --------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Table des fichiers principaux     | $Mft      | 0          | Contient un enregistrement de fichier de base pour chaque fichier et dossier sur un volume NTFS. Si les informations d'allocation pour un fichier ou un dossier sont trop grandes pour tenir dans un seul enregistrement, d'autres enregistrements de fichiers sont également alloués.            |
| Table des fichiers principaux 2   | $MftMirr  | 1          | Une image en double des quatre premiers enregistrements de la MFT. Ce fichier garantit l'accès à la MFT en cas de défaillance d'un seul secteur.                                                                                            |
| Fichier journal              | $LogFile  | 2          | Contient une liste des étapes de transaction utilisées pour la récupérabilité NTFS. La taille du fichier journal dépend de la taille du volume et peut atteindre 4 Mo. Il est utilisé par Windows NT/2000 pour restaurer la cohérence de NTFS après une défaillance du système. |
| Volume                | $Volume   | 3          | Contient des informations sur le volume, telles que l'étiquette du volume et la version du volume.                                                                                                                                       |
| Définitions d'attributs | $AttrDef  | 4          | Une table des noms, numéros et descriptions d'attributs.                                                                                                                                                                        |
| Index du nom de fichier racine  | $         | 5          | Le dossier racine.                                                                                                                                                                                                              |
| Bitmap de cluster        | $Bitmap   | 6          | Une représentation du volume montrant quels clusters sont utilisés.                                                                                                                                                             |
| Secteur d'amorçage           | $Boot     | 7          | Inclut le BPB utilisé pour monter le volume et un code de chargeur d'amorçage supplémentaire utilisé si le volume est bootable.                                                                                                                |
| Fichier de clusters défectueux      | $BadClus  | 8          | Contient des clusters défectueux pour le volume.                                                                                                                                                                                         |
| Fichier de sécurité         | $Secure   | 9          | Contient des descripteurs de sécurité uniques pour tous les fichiers dans un volume.                                                                                                                                                           |
| Table de conversion majuscules  | $Upcase   | 10         | Convertit les caractères minuscules en caractères majuscules Unicode correspondants.                                                                                                                                                       |
| Fichier d'extension NTFS   | $Extend   | 11         | Utilisé pour diverses extensions facultatives telles que les quotas, les données de points de reproche et les identifiants d'objet.                                                                                                                              |
|                       |           | 12-15      | Réservé pour une utilisation future.                                                                                                                                                                                                      |
| Fichier de gestion des quotas | $Quota    | 24         | Contient les limites de quota attribuées par l'utilisateur sur l'espace du volume.                                                                                                                                                                      |
| Fichier d'identifiant d'objet        | $ObjId    | 25         | Contient les identifiants d'objet de fichier.                                                                                                                                                                                                     |
| Fichier de point de reproche    | $Reparse  | 26         | Ce fichier contient des informations sur les fichiers et dossiers sur le volume, y compris les données de point de reproche.                                                                                                                            |

### Chaque entrée de la MFT ressemble à ce qui suit :

![](<../../../.gitbook/assets/image (499).png>)

Notez comment chaque entrée commence par "FILE". Chaque entrée occupe 1024 bits. Ainsi, après 1024 bits à partir du début d'une entrée MFT, vous trouverez la suivante.

En utilisant l'[**Active Disk Editor**](https://www.disk-editor.org/index.html), il est très facile d'inspecter l'entrée d'un fichier dans la MFT. Cliquez avec le bouton droit sur le fichier, puis cliquez sur "Inspecter l'enregistrement de fichier"

![](<../../../.gitbook/assets/image (500).png>)

![](<../../../.gitbook/assets/image (501).png>)

En vérifiant le drapeau **"En cours d'utilisation**", il est très facile de savoir si un fichier a été supprimé (une valeur de **0x0 signifie supprimé**).

![](<../../../.gitbook/assets/image (510).png>)

Il est également possible de récupérer des fichiers supprimés en utilisant FTKImager :

![](<../../../.gitbook/assets/image (502).png>)

### Attributs MFT

Chaque entrée MFT a plusieurs attributs comme l'indique l'image suivante :

![](<../../../.gitbook/assets/image (506).png>)

Chaque attribut indique des informations d'entrée identifiées par le type :

| Identifiant de type | Nom                     | Description                                                                                                       |
| --------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| 16              | $STANDARD\_INFORMATION   | Informations générales, telles que les indicateurs ; les dernières dates d'accès, d'écriture et de création ; et le propriétaire et l'ID de sécurité. |
| 32              | $ATTRIBUTE\_LIST         | Liste où d'autres attributs pour un fichier peuvent être trouvés.                                                              |
| 48              | $FILE\_NAME              | Nom de fichier, en Unicode, et les dernières dates d'accès, d'écriture et de création.                                         |
| 64              | $VOLUME\_VERSION         | Informations sur le volume. Existe uniquement en version 1.2 (Windows NT).                                                      |
| 64              | $OBJECT\_ID              | Un identifiant unique de 16 octets pour le fichier ou le répertoire. Existe uniquement dans les versions 3.0+ et ultérieures (Windows 2000+).    |
| 80              | $SECURITY\_ DESCRIPTOR   | Les propriétés de contrôle d'accès et de sécurité du fichier.                                                           |
| 96              | $VOLUME\_NAME            | Nom du volume.                                                                                                      |
| 112             | $VOLUME\_ INFORMATION    | Version du système de fichiers et autres indicateurs.                                                                              |
| 128             | $DATA                    | Contenu du fichier.                                                                                                    |
| 144             | $INDEX\_ROOT             | Nœud racine d'un arbre d'index.                                                                                       |
| 160             | $INDEX\_ALLOCATION       | Nœuds d'un arbre d'index enraciné dans l'attribut $INDEX\_ROOT.                                                          |
| 176             | $BITMAP                  | Une carte pour le fichier $MFT et pour les index.                                                                       |
| 192             | $SYMBOLIC\_LINK          | Informations de lien symbolique. Existe uniquement en version 1.2 (Windows NT).                                                   |
| 192             | $REPARSE\_POINT          | Contient des données sur un point de reproche, qui est utilisé comme un lien symbolique dans la version 3.0+ (Windows 2000+).                |
| 208             | $EA\_INFORMATION         | Utilisé pour la compatibilité ascendante avec les applications OS/2 (HPFS).                                                    |
| 224             | $EA                      | Utilisé pour la compatibilité ascendante avec les applications OS/2 (HPFS).                                                    |
| 256             | $LOGGED\_UTILITY\_STREAM | Contient des clés et des informations sur les attributs chiffrés en version 3.0+ (Windows 2000+).                         |

Par exemple, le **type 48 (0x30)** identifie le **nom de fichier** :

![](<../../../.gitbook/assets/image (508).png>)

Il est également utile de comprendre que **ces attributs peuvent être résidents** (ce qui signifie qu'ils existent dans un enregistrement MFT donné) ou **non résidents** (ce qui signifie qu'ils existent en dehors d'un enregistrement MFT donné, ailleurs sur le disque, et sont simplement référencés dans l'enregistrement). Par exemple, si l'attribut **$Data est résident**, cela signifie que le **fichier entier est enregistré dans la MFT**, s'il est non résident, alors le contenu du fichier se trouve dans une autre partie du système de fichiers.

Certains attributs intéressants :

- [$STANDARD\_INFORMATION](https://flatcap.org/linux-ntfs/ntfs/attributes/standard\_information.html) (entre autres) :
  - Date de création
  - Date de modification
  - Date d'accès
  - Date de mise à jour de la MFT
  - Autorisations de fichier DOS
- [$FILE\_NAME](https://flatcap.org/linux-ntfs/ntfs/attributes/file\_name.html) (entre autres) :
  - Nom de fichier
  - Date de création
  - Date de modification
  - Date d'accès
  - Date de mise à jour de la MFT
  - Taille allouée
  - Taille réelle
  - [Référence de fichier](https://flatcap.org/linux-ntfs/ntfs/concepts/file\_reference.html) au répertoire parent.
- [$Data](https://flatcap.org/linux-ntfs/ntfs/attributes/data.html) (entre autres) :
  - Contient les données du fichier ou l'indication des secteurs où se trouvent les données. Dans l'exemple suivant, l'attribut de données n'est pas résident, donc l'attribut donne des informations sur les secteurs où se trouvent les données.

![](<../../../.gitbook/assets/image (507) (1) (1).png>)

![](<../../../.gitbook/assets/image (509).png>)

### Horodatages NTFS

![](<../../../.gitbook/assets/image (512).png>)

Un autre outil utile pour analyser la MFT est [**MFT2csv**](https://github.com/jschicht/Mft2Csv) (sélectionnez le fichier MFT ou l'image et appuyez sur tout extraire et extraire pour extraire tous les objets).\
Ce programme extraira toutes les données de la MFT et les présentera au format CSV. Il peut également être utilisé pour extraire des fichiers.

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

Le fichier **`$LOGFILE`** contient des **journaux** sur les **actions** qui ont été **effectuées** **sur** **les fichiers**. Il **enregistre** également l'**action** qu'il devrait effectuer en cas de **reprise** et l'action nécessaire pour **revenir** à l'**état précédent**.\
Ces journaux sont utiles pour que la MFT reconstruise le système de fichiers en cas d'erreur. La taille maximale de ce fichier est de **65536 Ko**.

Pour inspecter le fichier `$LOGFILE`, vous devez
