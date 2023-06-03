<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité? Voulez-vous voir votre entreprise annoncée dans HackTricks? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF? Consultez les [PLANS D'ABONNEMENT](https://github.com/sponsors/carlospolop)!

- Découvrez [La famille PEASS](https://opensea.io/collection/the-peass-family), notre collection d'exclusivités [NFTs](https://opensea.io/collection/the-peass-family)

- Obtenez le [swag officiel PEASS & HackTricks](https://peass.creator-spring.com)

- Rejoignez le [💬](https://emojipedia.org/speech-balloon/) groupe Discord ou le groupe [telegram](https://t.me/peass) ou suivez-moi sur Twitter [🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[@carlospolopm](https://twitter.com/hacktricks_live).

- Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Ext - Système de fichiers étendu

**Ext2** est le système de fichiers le plus courant pour les partitions **sans journalisation** (**partitions qui ne changent pas beaucoup**) comme la partition de démarrage. **Ext3/4** sont **journalisés** et sont utilisés généralement pour les **autres partitions**.

Tous les groupes de blocs du système de fichiers ont la même taille et sont stockés séquentiellement. Cela permet au noyau de déduire facilement l'emplacement d'un groupe de blocs sur un disque à partir de son index entier.

Chaque groupe de blocs contient les éléments d'information suivants :

* Une copie du superblock du système de fichiers
* Une copie des descripteurs de groupe de blocs
* Une carte de bits de blocs de données qui est utilisée pour identifier les blocs libres à l'intérieur du groupe
* Une carte de bits d'inode, qui est utilisée pour identifier les inodes libres à l'intérieur du groupe
* Table d'inodes : elle se compose d'une série de blocs consécutifs, chacun contenant un nombre prédéfini Figure 1 Ext2 d'inodes. Tous les inodes ont la même taille : 128 octets. Un bloc de 1 024 octets contient 8 inodes, tandis qu'un bloc de 4 096 octets contient 32 inodes. Notez qu'en Ext2, il n'est pas nécessaire de stocker sur le disque une correspondance entre un numéro d'inode et le numéro de bloc correspondant car cette dernière valeur peut être déduite du numéro de groupe de blocs et de la position relative à l'intérieur de la table d'inodes. Par exemple, supposons que chaque groupe de blocs contient 4 096 inodes et que nous voulons connaître l'adresse sur le disque de l'inode 13 021. Dans ce cas, l'inode appartient au troisième groupe de blocs et son adresse sur le disque est stockée dans la 733ème entrée de la table d'inodes correspondante. Comme vous pouvez le voir, le numéro d'inode est simplement une clé utilisée par les routines Ext2 pour récupérer rapidement le descripteur d'inode approprié sur le disque.
* blocs de données, contenant des fichiers. Tout bloc qui ne contient aucune information significative est dit être libre.

![](<../../../.gitbook/assets/image (406).png>)

## Fonctionnalités optionnelles d'Ext

Les **fonctionnalités affectent l'emplacement** des données, **la façon dont** les données sont stockées dans les inodes et certaines d'entre elles peuvent fournir des **métadonnées supplémentaires** pour l'analyse, donc les fonctionnalités sont importantes dans Ext.

Ext a des fonctionnalités optionnelles que votre système d'exploitation peut ou non prendre en charge, il y a 3 possibilités :

* Compatible
* Incompatible
* Compatible en lecture seule : il peut être monté mais pas pour l'écriture

S'il y a des fonctionnalités **incompatibles**, vous ne pourrez pas monter le système de fichiers car le système d'exploitation ne saura pas comment accéder aux données.

{% hint style="info" %}
Un attaquant présumé pourrait avoir des extensions non standard
{% endhint %}

**Tout utilitaire** qui lit le **superblock** sera en mesure d'indiquer les **fonctionnalités** d'un **système de fichiers Ext**, mais vous pouvez également utiliser `file -sL /dev/sd*` pour obtenir cette information à partir d'un fichier système de fichiers Ext.
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
Vous pouvez également utiliser l'application GUI gratuite : [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
Ou vous pouvez également utiliser **python** pour obtenir les informations de superblock : [https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inodes

Les **inodes** contiennent la liste des **blocs** qui **contiennent** les **données** réelles d'un **fichier**.\
Si le fichier est grand, un inode **peut contenir des pointeurs** vers d'autres inodes qui pointent vers les blocs/autres inodes contenant les données du fichier.

![](<../../../.gitbook/assets/image (416).png>)

Dans **Ext2** et **Ext3**, les inodes ont une taille de **128B**, **Ext4** utilise actuellement **156B** mais alloue **256B** sur le disque pour permettre une expansion future.

Structure d'un inode :

| Offset | Taille | Nom              | Description                                      |
| ------ | ------ | ---------------- | ------------------------------------------------ |
| 0x0    | 2      | Mode de fichier  | Mode de fichier et type                          |
| 0x2    | 2      | UID              | 16 bits inférieurs de l'ID du propriétaire        |
| 0x4    | 4      | Taille Il        | 32 bits inférieurs de la taille du fichier       |
| 0x8    | 4      | Atime            | Temps d'accès en secondes depuis l'époque         |
| 0xC    | 4      | Ctime            | Temps de modification en secondes depuis l'époque |
| 0x10   | 4      | Mtime            | Temps de modification en secondes depuis l'époque |
| 0x14   | 4      | Dtime            | Temps de suppression en secondes depuis l'époque  |
| 0x18   | 2      | GID              | 16 bits inférieurs de l'ID de groupe              |
| 0x1A   | 2      | Compteur de lien | Nombre de liens rigides                           |
| 0xC    | 4      | Blocs Io         | 32 bits inférieurs du nombre de blocs             |
| 0x20   | 4      | Drapeaux         | Drapeaux                                          |
| 0x24   | 4      | Union osd1       | Linux : version I                                 |
| 0x28   | 69     | Bloc\[15]        | 15 points vers le bloc de données                 |
| 0x64   | 4      | Version          | Version de fichier pour NFS                       |
| 0x68   | 4      | ACL de fichier bas | 32 bits inférieurs des attributs étendus (ACL, etc.) |
| 0x6C   | 4      | Taille de fichier hi | 32 bits supérieurs de la taille du fichier (ext4 uniquement) |
| 0x70   | 4      | Fragment obsolète | Une adresse de fragment obsolète                  |
| 0x74   | 12     | Osd 2            | Deuxième union dépendante du système d'exploitation |
| 0x74   | 2      | Blocs hi         | 16 bits supérieurs du nombre de blocs             |
| 0x76   | 2      | ACL de fichier hi | 16 bits supérieurs des attributs étendus (ACL, etc.) |
| 0x78   | 2      | UID hi           | 16 bits supérieurs de l'ID du propriétaire        |
| 0x7A   | 2      | GID hi           | 16 bits supérieurs de l'ID de groupe              |
| 0x7C   | 2      | Somme de contrôle Io | 16 bits inférieurs de la somme de contrôle d'inode |

"Modifier" est l'horodatage de la dernière fois que le contenu du fichier a été modifié. On l'appelle souvent "_mtime_".\
"Changer" est l'horodatage de la dernière fois que l'_inode_ du fichier a été modifié, par exemple en modifiant les autorisations, la propriété, le nom de fichier et le nombre de liens rigides. On l'appelle souvent "_ctime_".

Structure étendue d'un inode (Ext4) :

| Offset | Taille | Nom         | Description                                 |
| ------ | ------ | ----------- | ------------------------------------------- |
| 0x80   | 2      | Taille supplémentaire | Combien d'octets au-delà des 128 standard sont utilisés |
| 0x82   | 2      | Somme de contrôle hi | 16 bits supérieurs de la somme de contrôle d'inode |
| 0x84   | 4      | Ctime extra | Bits supplémentaires de temps de modification |
| 0x88   | 4      | Mtime extra | Bits supplémentaires de temps de modification |
| 0x8C   | 4      | Atime extra | Bits supplémentaires de temps d'accès        |
| 0x90   | 4      | Crtime      | Temps de création de fichier (secondes depuis l'époque) |
| 0x94   | 4      | Crtime extra | Bits supplémentaires de temps de création de fichier |
| 0x98   | 4      | Version hi  | 32 bits supérieurs de la version             |
| 0x9C   |        | Inutilisé   | Espace réservé pour les futures extensions    |

Inodes spéciaux :

| Inode | Objectif spécial                                     |
| ----- | ---------------------------------------------------- |
| 0     | Aucun inode de ce type, la numérotation commence à 1 |
| 1     | Liste de blocs défectueux                            |
| 2     | Répertoire racine                                    |
| 3     | Quotas utilisateur                                   |
| 4     | Quotas de groupe                                     |
| 5     | Chargeur de démarrage                                 |
| 6     | Répertoire de récupération                           |
| 7     | Descripteurs de groupe réservés (pour redimensionner le système de fichiers) |
| 8     | Journal                                              |
| 9     | Exclure l'inode (pour les instantanés)               |
| 10    | Inode de réplica                                     |
| 11    | Premier inode non réservé (souvent perdu + trouvé)   |

{% hint style="info" %}
Notez que l'heure de création n'apparaît que dans Ext4.
{% endhint %}

En connaissant le numéro d'inode, vous pouvez facilement trouver son index :

* **Groupe de blocs** où appartient un inode : (Numéro d'inode - 1) / (Inodes par groupe)
* **Index à l'intérieur de son groupe** : (Numéro d'inode - 1) mod (Inodes/groupes)
* **Décalage** dans la **table d'inodes** : Numéro d'inode \* (Taille d'inode)
* Le "-1" est dû au fait que l'inode 0 est indéfini (non utilisé)
```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```
Mode de fichier

| Numéro | Description                                                                                         |
| ------ | --------------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **Répertoire/Bit de bloc 13**                                                                      |
| **13** | **Périphérique de caractère/Bit de bloc 14**                                                       |
| **12** | **FIFO**                                                                                            |
| 11     | Set UID                                                                                             |
| 10     | Set GID                                                                                             |
| 9      | Bit collant (sans cela, toute personne ayant des autorisations d'écriture et d'exécution sur un répertoire peut supprimer et renommer des fichiers) |
| 8      | Lecture propriétaire                                                                                |
| 7      | Écriture propriétaire                                                                               |
| 6      | Exécution propriétaire                                                                              |
| 5      | Lecture de groupe                                                                                    |
| 4      | Écriture de groupe                                                                                   |
| 3      | Exécution de groupe                                                                                  |
| 2      | Lecture autres                                                                                       |
| 1      | Écriture autres                                                                                      |
| 0      | Exécution autres                                                                                     |

Les bits en gras (12, 13, 14, 15) indiquent le type de fichier (un répertoire, une socket...) seul l'une des options en gras peut exister.

Répertoires

| Offset | Taille | Nom       | Description                                                                                                                                                  |
| ------ | ------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 4      | Inode     |                                                                                                                                                              |
| 0x4    | 2      | Longueur d'enregistrement | Longueur de l'enregistrement                                                                                                                                                |
| 0x6    | 1      | Longueur du nom | Longueur du nom                                                                                                                                                  |
| 0x7    | 1      | Type de fichier | <p>0x00 Inconnu<br>0x01 Régulier</p><p>0x02 Répertoire</p><p>0x03 Périphérique de caractère</p><p>0x04 Périphérique de bloc</p><p>0x05 FIFO</p><p>0x06 Socket</p><p>0x07 Lien symbolique</p> |
| 0x8    |        | Nom       | Chaîne de nom (jusqu'à 255 caractères)                                                                                                                           |

**Pour augmenter les performances, les blocs de hachage racine du répertoire peuvent être utilisés.**

**Attributs étendus**

Peut être stocké dans

* Espace supplémentaire entre les inodes (256 - taille de l'inode, généralement = 100)
* Un bloc de données pointé par file\_acl dans l'inode

Peut être utilisé pour stocker n'importe quoi en tant qu'attribut d'utilisateur si le nom commence par "user". Les données peuvent donc être cachées de cette manière.

Entrées d'attributs étendus

| Offset | Taille | Nom          | Description                                                                                                                                                                                                        |
| ------ | ------ | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 1      | Longueur du nom     | Longueur du nom d'attribut                                                                                                                                                                                           |
| 0x1    | 1      | Index de nom   | <p>0x0 = pas de préfixe</p><p>0x1 = préfixe utilisateur</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = trusted.</p><p>0x6 = security.</p><p>0x7 = system.</p><p>0x8 = system.richacl</p> |
| 0x2    | 2      | Décalage de la valeur   | Décalage depuis la première entrée d'inode ou le début du bloc                                                                                                                                                                    |
| 0x4    | 4      | Blocs de valeur | Bloc de disque où la valeur est stockée ou zéro pour ce bloc                                                                                                                                                               |
| 0x8    | 4      | Taille de la valeur   | Longueur de la valeur                                                                                                                                                                                                    |
| 0xC    | 4      | Hachage         | Hachage pour les attributs dans le bloc ou zéro s'ils sont dans l'inode                                                                                                                                                                      |
| 0x10   |        | Nom          | Nom d'attribut sans NULL final                                                                                                                                                                                   |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## Vue du système de fichiers

Pour voir le contenu du système de fichiers, vous pouvez **utiliser l'outil gratuit** : [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
Ou vous pouvez le monter dans votre linux en utilisant la commande `mount`.

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=Le%20syst%C3%A8me%20de%20fichiers%20Ext2%20divise,temps%20de%20recherche%20de%20disque%20moyen.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=Le%20syst%C3%A8me%20de%20fichiers%20Ext2%20divise,temps%20de%20recherche%20de%20disque%20moyen.)
