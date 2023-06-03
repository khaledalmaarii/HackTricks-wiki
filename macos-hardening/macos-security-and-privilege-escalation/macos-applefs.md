## Système de fichiers propriétaire Apple (APFS)

APFS, ou Apple File System, est un système de fichiers moderne développé par Apple Inc. qui a été conçu pour remplacer l'ancien système de fichiers hiérarchique plus (HFS+) en mettant l'accent sur **l'amélioration des performances, de la sécurité et de l'efficacité**.

Certaines caractéristiques notables d'APFS comprennent :

1. **Partage d'espace** : APFS permet à plusieurs volumes de **partager le même espace de stockage libre sous-jacent** sur un seul dispositif physique. Cela permet une utilisation de l'espace plus efficace car les volumes peuvent se développer et se réduire dynamiquement sans avoir besoin de redimensionnement ou de repartitionnement manuel.
   1. Cela signifie, par rapport aux partitions traditionnelles dans les disques de fichiers, que dans APFS, différentes partitions (volumes) partagent tout l'espace disque, tandis qu'une partition régulière avait généralement une taille fixe.
2. **Instantanés** : APFS prend en charge la **création d'instantanés**, qui sont des instances **en lecture seule** du système de fichiers à un moment donné. Les instantanés permettent des sauvegardes efficaces et des retours système faciles, car ils consomment un espace de stockage minimal supplémentaire et peuvent être rapidement créés ou rétablis.
3. **Clones** : APFS peut **créer des clones de fichiers ou de répertoires qui partagent le même stockage** que l'original jusqu'à ce que le clone ou le fichier original soit modifié. Cette fonctionnalité offre un moyen efficace de créer des copies de fichiers ou de répertoires sans dupliquer l'espace de stockage.
4. **Chiffrement** : APFS prend en charge **nativement le chiffrement complet du disque** ainsi que le chiffrement par fichier et par répertoire, améliorant la sécurité des données dans différents cas d'utilisation.
5. **Protection contre les pannes** : APFS utilise un **schéma de métadonnées de copie sur écriture qui garantit la cohérence du système de fichiers** même en cas de perte de puissance soudaine ou de plantage du système, réduisant ainsi le risque de corruption des données.

Dans l'ensemble, APFS offre un système de fichiers plus moderne, flexible et efficace pour les appareils Apple, avec un accent sur l'amélioration des performances, de la fiabilité et de la sécurité.
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
À gauche, il y a le chemin du répertoire sur le volume système, et à droite, le chemin du répertoire où il est mappé sur le volume de données. Ainsi, `/library` --> `/system/Volumes/data/library`.
