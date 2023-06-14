# Extensions de noyau macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Les extensions de noyau (Kexts) sont des **bundles** utilisant l'extension **`.kext`** qui sont **chargés directement dans l'espace du noyau** de macOS, fournissant des fonctionnalités supplémentaires au système d'exploitation de base.

### Exigences

Évidemment, c'est tellement puissant qu'il est compliqué de charger une extension de noyau. Voici les exigences d'une extension de noyau pour être chargée :

* En allant en mode de récupération, les Kexts doivent être **autorisés à être chargés** :

<figure><img src="../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

* Le Kext doit être **signé avec un certificat de signature de code de noyau**, qui ne peut être accordé que par **Apple**. Qui va **examiner** en détail la **société** et les **raisons** pour lesquelles cela est nécessaire.
* Le Kext doit également être **notarisé**, Apple pourra le vérifier pour les logiciels malveillants.
* Ensuite, l'utilisateur **root** est celui qui peut charger le Kext et les fichiers à l'intérieur du bundle doivent appartenir à root.
* Enfin, une fois qu'on essaie de le charger, l'[**utilisateur sera invité à confirmer**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) et si c'est accepté, l'ordinateur doit **redémarrer** pour le charger.

### Processus de chargement

De retour à Catalina, c'était comme ça : Il est intéressant de noter que le processus de **vérification** se produit sur **userland**. Cependant, seules les applications avec l'entitlement **`com.apple.private.security.kext-management`** peuvent **demander au noyau** de **charger une extension** : kextcache, kextload, kextutil, kextd, syspolicyd

1. **`kextutil`** cli **démarre** le processus de vérification pour charger une extension
   * Il parlera à **`kextd`** en envoyant en utilisant un service Mach
2. **`kextd`** vérifiera plusieurs choses, telles que la signature
   * Il parlera à **`syspolicyd`** pour vérifier si l'extension peut être chargée
3. **`syspolicyd`** **demandera** à l'**utilisateur** si l'extension n'a pas été chargée précédemment
   * **`syspolicyd`** indiquera le résultat à **`kextd`**
4. **`kextd`** pourra enfin indiquer au **noyau de charger l'extension**

Si kextd n'est pas disponible, kextutil peut effectuer les mêmes vérifications.

## Références

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
