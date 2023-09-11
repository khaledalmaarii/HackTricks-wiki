# macOS AppleFS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Système de fichiers propriétaire Apple (APFS)

APFS, ou Apple File System, est un système de fichiers moderne développé par Apple Inc. qui a été conçu pour remplacer l'ancien système de fichiers hiérarchique Plus (HFS+) en mettant l'accent sur **les performances améliorées, la sécurité et l'efficacité**.

Certaines caractéristiques notables d'APFS comprennent :

1. **Partage d'espace** : APFS permet à plusieurs volumes de **partager le même espace de stockage libre** sur un seul dispositif physique. Cela permet une utilisation plus efficace de l'espace car les volumes peuvent se développer et se réduire dynamiquement sans nécessiter de redimensionnement manuel ou de repartitionnement.
1. Cela signifie, par rapport aux partitions traditionnelles dans les disques de fichiers, **que dans APFS, différentes partitions (volumes) partagent tout l'espace disque**, tandis qu'une partition régulière avait généralement une taille fixe.
2. **Instantanés** : APFS prend en charge la **création d'instantanés**, qui sont des instances **en lecture seule** du système de fichiers à un moment donné. Les instantanés permettent des sauvegardes efficaces et des retours système faciles, car ils consomment un espace de stockage minimal supplémentaire et peuvent être créés ou rétablis rapidement.
3. **Clones** : APFS peut **créer des clones de fichiers ou de répertoires qui partagent le même espace de stockage** que l'original jusqu'à ce que le clone ou le fichier original soit modifié. Cette fonctionnalité permet de créer efficacement des copies de fichiers ou de répertoires sans dupliquer l'espace de stockage.
4. **Cryptage** : APFS prend en charge **nativement le cryptage complet du disque** ainsi que le cryptage par fichier et par répertoire, améliorant la sécurité des données dans différents cas d'utilisation.
5. **Protection contre les pannes** : APFS utilise un **schéma de métadonnées de copie sur écriture qui garantit la cohérence du système de fichiers** même en cas de perte de courant soudaine ou de plantage du système, réduisant ainsi le risque de corruption des données.

Dans l'ensemble, APFS offre un système de fichiers plus moderne, flexible et efficace pour les appareils Apple, avec une attention particulière portée aux performances améliorées, à la fiabilité et à la sécurité.
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
À gauche, il y a le chemin du répertoire sur le volume système, et à droite, le chemin du répertoire où il est mappé sur le volume de données. Ainsi, `/library` --> `/system/Volumes/data/library`

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
