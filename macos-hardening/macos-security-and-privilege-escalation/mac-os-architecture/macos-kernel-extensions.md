# Extensions du noyau macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous pour une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée sur HackTricks**? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel de PEASS et HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en envoyant une PR à** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **et** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Les extensions du noyau (Kexts) sont des **paquets** avec une extension **`.kext`** qui sont **chargés directement dans l'espace noyau de macOS**, fournissant des fonctionnalités supplémentaires au système d'exploitation principal.

### Exigences

De toute évidence, il est tellement puissant qu'il est **compliqué de charger une extension du noyau**. Voici les **exigences** qu'une extension du noyau doit remplir pour être chargée :

* Lorsque vous **entrez en mode de récupération**, les **extensions du noyau doivent être autorisées** à être chargées :

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* L'extension du noyau doit être **signée avec un certificat de signature de code du noyau**, qui ne peut être **accordé que par Apple**. Qui examinera en détail l'entreprise et les raisons pour lesquelles elle est nécessaire.
* L'extension du noyau doit également être **notariée**, Apple pourra la vérifier pour les logiciels malveillants.
* Ensuite, l'utilisateur **root** est celui qui peut **charger l'extension du noyau** et les fichiers à l'intérieur du paquet doivent **appartenir à root**.
* Pendant le processus de chargement, le paquet doit être préparé dans un **emplacement protégé non root** : `/Library/StagedExtensions` (nécessite l'autorisation `com.apple.rootless.storage.KernelExtensionManagement`).
* Enfin, lors de la tentative de chargement, l'utilisateur recevra une [**demande de confirmation**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) et, si elle est acceptée, l'ordinateur doit être **redémarré** pour la charger.

### Processus de chargement

Dans Catalina, c'était comme ça : Il est intéressant de noter que le processus de **vérification** se produit dans l'**espace utilisateur**. Cependant, seules les applications avec l'autorisation **`com.apple.private.security.kext-management`** peuvent **demander au noyau de charger une extension** : `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** en ligne de commande **démarre** le processus de **vérification** pour charger une extension
* Il parlera à **`kextd`** en envoyant en utilisant un **service Mach**.
2. **`kextd`** vérifiera plusieurs choses, comme la **signature**
* Il parlera à **`syspolicyd`** pour **vérifier** si l'extension peut être **chargée**.
3. **`syspolicyd`** **demandera** à l'**utilisateur** si l'extension n'a pas été chargée précédemment.
* **`syspolicyd`** rapportera le résultat à **`kextd`**
4. **`kextd`** pourra enfin **dire au noyau de charger** l'extension

Si **`kextd`** n'est pas disponible, **`kextutil`** peut effectuer les mêmes vérifications.

## Références

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous pour une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée sur HackTricks**? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel de PEASS et HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en envoyant une PR à** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **et** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
