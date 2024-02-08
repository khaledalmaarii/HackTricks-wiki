# macOS AppleFS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Système de fichiers propriétaire Apple (APFS)

**Apple File System (APFS)** est un système de fichiers moderne conçu pour remplacer le Hierarchical File System Plus (HFS+). Son développement a été motivé par la nécessité d'**améliorer les performances, la sécurité et l'efficacité**.

Certaines caractéristiques notables de l'APFS comprennent :

1. **Partage d'espace** : L'APFS permet à plusieurs volumes de **partager le même espace de stockage libre sous-jacent** sur un seul périphérique physique. Cela permet une utilisation plus efficace de l'espace car les volumes peuvent croître et rétrécir dynamiquement sans nécessiter de redimensionnement manuel ou de repartitionnement.
1. Cela signifie, par rapport aux partitions traditionnelles dans les disques de fichiers, **qu'en APFS, différentes partitions (volumes) partagent tout l'espace disque**, tandis qu'une partition régulière avait généralement une taille fixe.
2. **Instantanés** : L'APFS prend en charge la **création d'instantanés**, qui sont des instances **en lecture seule** du système de fichiers à un moment donné. Les instantanés permettent des sauvegardes efficaces et des retours en arrière faciles du système, car ils consomment un espace de stockage minimal supplémentaire et peuvent être créés ou rétablis rapidement.
3. **Clones** : L'APFS peut **créer des clones de fichiers ou de répertoires qui partagent le même espace de stockage** que l'original jusqu'à ce que le clone ou le fichier original soit modifié. Cette fonctionnalité offre un moyen efficace de créer des copies de fichiers ou de répertoires sans dupliquer l'espace de stockage.
4. **Chiffrement** : L'APFS **prend en charge nativement le chiffrement complet du disque** ainsi que le chiffrement par fichier et par répertoire, renforçant la sécurité des données dans différents cas d'utilisation.
5. **Protection contre les crashs** : L'APFS utilise un **schéma de métadonnées de copie sur écriture qui garantit la cohérence du système de fichiers** même en cas de perte soudaine de courant ou de plantage du système, réduisant le risque de corruption des données.

Dans l'ensemble, l'APFS offre un système de fichiers plus moderne, flexible et efficace pour les appareils Apple, avec un accent sur l'amélioration des performances, de la fiabilité et de la sécurité.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Le volume `Data` est monté dans **`/System/Volumes/Data`** (vous pouvez vérifier cela avec `diskutil apfs list`).

La liste des firmlinks peut être trouvée dans le fichier **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
Sur la **gauche**, il y a le chemin du répertoire sur le **volume Système**, et sur la **droite**, le chemin du répertoire où il est mappé sur le **volume Données**. Ainsi, `/library` --> `/system/Volumes/data/library`
