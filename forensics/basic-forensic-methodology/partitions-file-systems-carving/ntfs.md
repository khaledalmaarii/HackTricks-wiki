# NTFS

## NTFS

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **NTFS**

**NTFS** (**New Technology File System**) est un système de fichiers journalisé propriétaire développé par Microsoft.

Le cluster est l'unité de taille la plus petite dans NTFS et la taille du cluster dépend de la taille d'une partition.

| Taille de la partition      | Secteurs par cluster | Taille du cluster |
| --------------------------- | -------------------- | ----------------- |
| 512 Mo ou moins             | 1                    | 512 octets        |
| 513 Mo-1024 Mo (1 Go)       | 2                    | 1 Ko              |
| 1025 Mo-2048 Mo (2 Go)      | 4                    | 2 Ko              |
| 2049 Mo-4096 Mo (4 Go)      | 8                    | 4 Ko              |
| 4097 Mo-8192 Mo (8 Go)      | 16                   | 8 Ko              |
| 8193 Mo-16 384 Mo (16 Go)   | 32                   | 16 Ko             |
| 16 385 Mo-32 768 Mo (32 Go) | 64                   | 32 Ko             |
| Plus de 32 768 Mo           | 128                  | 64 Ko             |

### **Espace de bourrage**

Comme le **cluster** est l'unité de taille **la plus petite** de NTFS, chaque fichier occupera plusieurs clusters complets. Il est donc très probable que **chaque fichier occupe plus d'espace que nécessaire**. Ces **espaces inutilisés** **réservés** par un fichier sont appelés **espace de bourrage** et les gens pourraient profiter de cette zone pour **cacher** **des informations**.

![](<../../../.gitbook/assets/image (498).png>)

### **Secteur de démarrage NTFS**

Lorsque vous formatez un volume NTFS, le programme de formatage alloue les 16 premiers secteurs pour le fichier métadonnées de démarrage. Le premier secteur est un secteur de démarrage avec un code "bootstrap" et les 15 secteurs suivants sont l'IPL (Initial Program Loader) du secteur de démarrage. Pour augmenter la fiabilité du système de fichiers, le tout dernier secteur d'une partition NTFS contient une copie de secours du secteur de démarrage.

### **Table des fichiers maîtres (MFT)**

Le système de fichiers NTFS contient un fichier appelé Table des fichiers maîtres (MFT). Il y a au moins **une entrée dans la MFT pour chaque fichier sur un volume de système de fichiers NTFS**, y compris la MFT elle-même. Toutes les informations sur un fichier, y compris sa **taille, les horodatages, les permissions et le contenu des données**, sont stockées soit dans les entrées de la MFT, soit dans un espace extérieur à la MFT décrit par les entrées de la MFT.

À mesure que **des fichiers sont ajoutés** à un volume de système de fichiers NTFS, de nouvelles entrées sont ajoutées à la MFT et la **MFT augmente en taille**. Lorsque **des fichiers** sont **supprimés** d'un volume de système de fichiers NTFS, leurs **entrées MFT sont marquées comme libres** et peuvent être réutilisées. Cependant, l'espace disque qui a été alloué pour ces entrées n'est pas réalloué, et la taille de la MFT ne diminue pas.

Le système de fichiers NTFS **réserve de l'espace pour la MFT afin de la garder aussi contiguë que possible** à mesure qu'elle grandit. L'espace réservé par le système de fichiers NTFS pour la MFT dans chaque volume est appelé la **zone MFT**. L'espace pour les fichiers et les répertoires est également alloué à partir de cet espace, mais seulement après que tout l'espace du volume en dehors de la zone MFT a été alloué.

Selon la taille moyenne des fichiers et d'autres variables, **soit la zone MFT réservée, soit l'espace non réservé sur le disque peut être alloué en premier à mesure que le disque se remplit**. Les volumes avec un petit nombre de fichiers relativement grands alloueront l'espace non réservé en premier, tandis que les volumes avec un grand nombre de fichiers relativement petits alloueront la zone MFT en premier. Dans les deux cas, la fragmentation de la MFT commence à se produire lorsque l'une ou l'autre région est entièrement allouée. Si l'espace non réservé est complètement alloué, l'espace pour les fichiers et répertoires des utilisateurs sera alloué à partir de la zone MFT. Si la zone MFT est complètement allouée, l'espace pour les nouvelles entrées MFT sera alloué à partir de l'espace non réservé.

Les systèmes de fichiers NTFS génèrent également un **$MFTMirror**. Il s'agit d'une **copie** des **quatre premières entrées** de la MFT : $MFT, $MFT Mirror, $Log, $Volume.

NTFS réserve les 16 premiers enregistrements de la table pour des informations spéciales :

| Fichier système            | Nom de fichier | Enregistrement MFT | But du fichier                                                                                                                                                                                                           |
| -------------------------- | -------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Table des fichiers maîtres | $Mft           | 0                  | Contient un enregistrement de fichier de base pour chaque fichier et dossier sur un volume NTFS. Si les informations d'allocation pour un fichier ou un dossier sont trop grandes pour tenir dans un seul enregistrement, d'autres enregistrements de fichiers sont alloués également. |
| Table des fichiers maîtres 2 | $MftMirr       | 1                  | Une image en double des quatre premiers enregistrements de la MFT. Ce fichier garantit l'accès à la MFT en cas de défaillance d'un seul secteur.                                                                         |
| Fichier journal            | $LogFile       | 2                  | Contient une liste des étapes de transaction utilisées pour la récupérabilité de NTFS. La taille du fichier journal dépend de la taille du volume et peut atteindre 4 Mo. Il est utilisé par Windows NT/2000 pour restaurer la cohérence de NTFS après une défaillance du système. |
| Volume                     | $Volume        | 3                  | Contient des informations sur le volume, telles que l'étiquette du volume et la version du volume.                                                                                                                       |
| Définitions d'attributs    | $AttrDef       | 4                  | Un tableau des noms, numéros et descriptions des attributs.                                                                                                                                                              |
| Index de nom de fichier racine | $              | 5                  | Le dossier racine.                                                                                                                                                                                                       |
| Bitmap de cluster          | $Bitmap        | 6                  | Une représentation du volume montrant quels clusters sont utilisés.                                                                                                                                                      |
| Secteur de démarrage       | $Boot          | 7                  | Comprend le BPB utilisé pour monter le volume et le code de chargeur de démarrage supplémentaire utilisé si le volume est amorçable.                                                                                     |
| Fichier de cluster défectueux | $BadClus       | 8                  | Contient les clusters défectueux pour le volume.                                                                                                                                                                         |
| Fichier de sécurité        | $Secure        | 9                  | Contient des descripteurs de sécurité uniques pour tous les fichiers d'un volume.                                                                                                                                        |
| Table de conversion        | $Upcase        | 10                 | Convertit les caractères minuscules en caractères majuscules Unicode correspondants.                                                                                                                                      |
| Fichier d'extension NTFS   | $Extend        | 11                 | Utilisé pour diverses extensions optionnelles telles que les quotas, les données de point de reparse et les identifiants d'objet.                                                                                       |
|                            |                | 12-15              | Réservé pour une utilisation future.                                                                                                                                                                                     |
| Fichier de gestion des quotas | $Quota         | 24                 | Contient les limites de quota assignées par l'utilisateur sur l'espace du volume.                                                                                                                                        |
| Fichier d'identifiant d'objet | $ObjId         | 25                 | Contient les identifiants d'objet des fichiers.                                                                                                                                                                          |
| Fichier de point de reparse | $Reparse       | 26                 | Ce fichier contient des informations sur les fichiers et dossiers du volume, y compris les données de point de reparse.                                                                                                  |

### Chaque entrée de la MFT ressemble à ce qui suit :

![](<../../../.gitbook/assets/image (499).png>)

Notez comment chaque entrée commence par "FILE". Chaque entrée occupe 1024 bits. Donc après 1024 bits à partir du début d'une entrée MFT, vous trouverez la suivante.

En utilisant [**Active Disk Editor**](https://www.disk-editor.org/index.html), il est très facile d'inspecter l'entrée d'un fichier dans la MFT. Cliquez simplement avec le bouton droit sur le fichier, puis cliquez sur "Inspecter l'enregistrement de fichier"

![](<../../../.gitbook/assets/image (500).png>)

![](<../../../.gitbook/assets/image (501).png>)

En vérifiant le drapeau **"En usage"**, il est très facile de savoir si un fichier a été supprimé (une valeur de **0x0 signifie supprimé**).

![](<../../../.gitbook/assets/image (510).png>)

Il est également possible de récupérer des fichiers supprimés en utilisant FTKImager :

![](<../../../.gitbook/assets/image (502).png>)

### Attributs MFT

Chaque entrée MFT a plusieurs attributs comme l'indique l'image suivante :

![](<../../../.gitbook/assets/image (506).png>)

Chaque attribut indique des informations d'entrée identifiées par le type :

| Identifiant de type | Nom                       | Description                                                                                                       |
| ------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| 16                  | $STANDARD\_INFORMATION     | Informations générales, telles que les drapeaux ; les derniers temps d'accès, d'écriture et de création ; et l'ID de propriétaire et de sécurité. |
| 32                  | $ATTRIBUTE\_LIST           | Liste où d'autres attributs pour un fichier peuvent être trouvés.                                                  |
| 48                  | $FILE\_NAME                | Nom de fichier, en Unicode, et les derniers temps d'accès, d'écriture et de création.                              |
| 64                  | $VOLUME\_VERSION           | Informations sur le volume. Existe uniquement dans la version 1.2 (Windows NT).                                    |
| 64                  | $OBJECT\_ID                | Un identifiant unique de 16 octets pour le fichier ou le répertoire. Existe uniquement dans les versions 3.0+ et après (Windows 2000+).    |
| 80                  | $SECURITY\_ DESCRIPTOR     | Les propriétés de contrôle d'accès et de sécurité du fichier.                                                      |
| 96                  | $VOLUME\_NAME              | Nom du volume.                                                                                                     |
| 112                 | $VOLUME\_ INFORMATION      | Version du système de fichiers et autres drapeaux.                                                                 |
| 128                 | $DATA                      | Contenu du fichier.                                                                                                 |
| 144                 | $INDEX\_ROOT               | Nœud racine d'un arbre d'index.                                                                                     |
| 160                 | $INDEX\_ALLOCATION         | Nœuds d'un arbre d'index enraciné dans l'attribut $INDEX\_ROOT.                                                    |
| 176                 | $BITMAP                    | Un bitmap pour le fichier $MFT et pour les index.                                                                   |
| 192                 | $SYMBOLIC\_LINK            | Informations sur le lien symbolique. Existe uniquement dans la version 1.2 (Windows NT).                            |
| 192                 | $REPARSE\_POINT            | Contient des données sur un point de reparse, qui est utilisé comme un lien symbolique dans la version 3.0+ (Windows 2000+).                  |
| 208                 | $EA\_INFORMATION           | Utilisé pour la compatibilité avec les applications OS/2 (HPFS).                                                    |
| 224                 | $EA                        | Utilisé pour la compatibilité avec les applications OS/2 (HPFS).                                                    |
| 256                 | $LOGGED\_UTILITY\_STREAM   | Contient des clés et des informations sur les attributs chiffrés dans la version 3.0+ (Windows 2000+).               |

Par exemple, le **type 48 (0x30)** identifie le **nom de fichier** :

![](<../../../.gitbook/assets/image (508).png>)

Il est également utile de comprendre que **ces attributs peuvent être résidents** (c'est-à-dire, ils existent dans un enregistrement MFT donné) ou **non résidents** (c'est-à-dire, ils existent en dehors d'un enregistrement MFT donné, ailleurs sur le disque, et sont simplement référencés dans l'enregistrement). Par exemple, si l'attribut **$Data est résident**, cela signifie que **le fichier entier est enregistré dans la MFT**, s'il est non résident, alors le contenu du fichier se trouve dans une autre partie du système de fichiers.

Quelques attributs intéressants :

* [$STANDARD\_INFORMATION](https://flatcap.org/linux-ntfs/ntfs/attributes/standard\_information.html) (entre autres) :
  * Date de création
  * Date de modification
  * Date d'accès
  * Date de mise à jour de la MFT
  * Permissions de fichier DOS
* [$FILE\_NAME](https://flatcap.org/linux-ntfs/ntfs/attributes/file\_name.html) (entre autres) :
  * Nom de fichier
  * Date de création
  * Date de modification
  * Date d'accès
  * Date de mise à jour de la MFT
  * Taille allouée
  * Taille réelle
  * [Référence de fichier](https://flatcap.org/linux-ntfs/ntfs/concepts/file\_reference.html) au répertoire parent.
* [$Data](https://flatcap.org/linux-ntfs/ntfs/attributes/data.html) (entre autres) :
  * Contient les données du fichier ou l'indication des secteurs où les données résident. Dans l'exemple suivant, l'attribut de données n'est pas résident, donc l'attribut donne des informations sur les secteurs où les données résident.

![](<../../../.gitbook/assets/image (507) (1) (1).png>)

![](<../../../.gitbook/assets/image (509).png>)

### Horodatages NTFS

![](<../../../.gitbook/assets/image (512).png>)

Un autre outil utile pour analyser la MFT est [**MFT2csv**](https://github.com/jschicht/Mft2Csv) (sélectionnez le fichier mft ou l'image et appuyez sur dump all et extract pour extraire tous les objets).\
Ce programme extraira toutes les données MFT et les présentera au format CSV. Il peut également être utilisé pour extraire des fichiers.

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

Le fichier **`$LOGFILE`** contient **des journaux** sur les **actions** qui ont été **effectuées** **sur** **les fichiers**. Il **sauvegarde** également l'**action** qu'il devrait effectuer en cas de **refaire** et l'action nécessaire pour **revenir** à l'**état précédent**.\
Ces journaux sont utiles pour la MFT pour reconstruire le système de fichiers en cas d'erreur. La taille maximale de ce fichier est de **65536 Ko**.

Pour inspecter le `$LOGFILE`, vous devez l'extraire et inspecter le `$MFT` au préalable avec [**MFT2csv**](https://github.com/jschicht/M
