# macOS AppleFS

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Système de fichiers propriétaire d'Apple (APFS)

APFS, ou Apple File System, est un système de fichiers moderne développé par Apple Inc. conçu pour remplacer l'ancien Hierarchical File System Plus (HFS+) en mettant l'accent sur des **performances, une sécurité et une efficacité améliorées**.

Parmi les caractéristiques notables d'APFS, on trouve :

1. **Partage d'espace** : APFS permet à plusieurs volumes de **partager le même espace de stockage libre sous-jacent** sur un seul dispositif physique. Cela permet une utilisation de l'espace plus efficace, car les volumes peuvent croître et décroître dynamiquement sans nécessiter de redimensionnement manuel ou de repartitionnement.
2. Cela signifie, par rapport aux partitions traditionnelles dans les disques de fichiers, **que dans APFS différentes partitions (volumes) partagent tout l'espace disque**, tandis qu'une partition régulière avait généralement une taille fixe.
3. **Instantanés** : APFS prend en charge la **création d'instantanés**, qui sont des instances **en lecture seule** et ponctuelles du système de fichiers. Les instantanés permettent des sauvegardes efficaces et des retours en arrière système faciles, car ils consomment un espace de stockage supplémentaire minimal et peuvent être rapidement créés ou rétablis.
4. **Clones** : APFS peut **créer des clones de fichiers ou de répertoires qui partagent le même stockage** que l'original jusqu'à ce que le clone ou le fichier original soit modifié. Cette fonctionnalité offre un moyen efficace de créer des copies de fichiers ou de répertoires sans dupliquer l'espace de stockage.
5. **Chiffrement** : APFS **prend en charge nativement le chiffrement complet du disque** ainsi que le chiffrement par fichier et par répertoire, améliorant la sécurité des données pour différents cas d'utilisation.
6. **Protection contre les crashs** : APFS utilise un schéma de métadonnées **copy-on-write qui assure la cohérence du système de fichiers** même en cas de perte de courant soudaine ou de crash du système, réduisant le risque de corruption des données.

Dans l'ensemble, APFS offre un système de fichiers plus moderne, flexible et efficace pour les appareils Apple, avec un accent sur des performances, une fiabilité et une sécurité améliorées.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Le volume `Data` est monté dans **`/System/Volumes/Data`** (vous pouvez vérifier cela avec `diskutil apfs list`).

La liste des firmlinks se trouve dans le fichier **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
À **gauche**, il y a le chemin du répertoire sur le **volume Système**, et à **droite**, le chemin du répertoire où il se mappe sur le **volume Données**. Donc, `/library` --> `/system/Volumes/data/library`

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
