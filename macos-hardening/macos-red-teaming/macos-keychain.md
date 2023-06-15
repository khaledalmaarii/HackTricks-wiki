# macOS Keychain

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Principales chaînes de clés

* La **chaîne de clés utilisateur** (`~/Library/Keychains/login.keycahin-db`), qui est utilisée pour stocker les **informations d'identification spécifiques à l'utilisateur** telles que les mots de passe d'application, les mots de passe Internet, les certificats générés par l'utilisateur, les mots de passe réseau et les clés publiques / privées générées par l'utilisateur.
* La **chaîne de clés système** (`/Library/Keychains/System.keychain`), qui stocke les **informations d'identification à l'échelle du système** telles que les mots de passe WiFi, les certificats racine du système, les clés privées du système et les mots de passe d'application du système.

### Accès aux clés de passe

Ces fichiers, bien qu'ils n'aient pas de protection inhérente et puissent être **téléchargés**, sont chiffrés et nécessitent le **mot de passe en clair de l'utilisateur pour être déchiffrés**. Un outil comme [**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour le déchiffrement.

## Protections des entrées de la chaîne de clés

### ACL

Chaque entrée dans la chaîne de clés est régie par des **listes de contrôle d'accès (ACL)** qui dictent qui peut effectuer diverses actions sur l'entrée de la chaîne de clés, notamment :

* **ACLAuhtorizationExportClear** : permet au détenteur d'obtenir le texte clair du secret.
* **ACLAuhtorizationExportWrapped** : permet au détenteur d'obtenir le texte clair chiffré avec un autre mot de passe fourni.
* **ACLAuhtorizationAny** : permet au détenteur d'effectuer n'importe quelle action.

Les ACL sont accompagnées d'une **liste d'applications de confiance** qui peuvent effectuer ces actions sans invitation. Cela pourrait être :

* &#x20;**N`il`** (aucune autorisation requise, **tout le monde est de confiance**)
* Une liste **vide** (**personne** n'est de confiance)
* **Liste** d'**applications** spécifiques.

L'entrée peut également contenir la clé **`ACLAuthorizationPartitionID`**, qui est utilisée pour identifier le **teamid, apple** et **cdhash.**

* Si le **teamid** est spécifié, alors pour **accéder** à la valeur de l'entrée **sans** invitation, l'application utilisée doit avoir le **même teamid**.
* Si l'**apple** est spécifiée, l'application doit être **signée** par **Apple**.
* Si le **cdhash** est indiqué, l'**application** doit avoir le **cdhash** spécifique.

### Création d'une entrée de chaîne de clés

Lorsqu'une **nouvelle entrée** est créée à l'aide de **`Keychain Access.app`**, les règles suivantes s'appliquent :

* Toutes les applications peuvent chiffrer.
* **Aucune application** ne peut exporter/déchiffrer (sans inviter l'utilisateur).
* Toutes les applications peuvent voir la vérification d'intégrité.
* Aucune application ne peut modifier les ACL.
* L'**ID de partition** est défini sur **`apple`**.

Lorsqu'une **application crée une entrée dans la chaîne de clés**, les règles sont légèrement différentes :

* Toutes les applications peuvent chiffrer.
* Seule l'**application créatrice** (ou toute autre application explicitement ajoutée) peut exporter/déchiffrer (sans inviter l'utilisateur).
* Toutes les applications peuvent voir la vérification d'intégrité.
* Aucune application ne peut modifier les ACL.
* L'**ID de partition** est défini sur **`teamid:[teamID ici]`**.

## Accès à la chaîne de clés

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### APIs

{% hint style="success" %}
L'**énumération et le dumping** des secrets du **trousseau de clés qui ne génèrent pas de prompt** peuvent être effectués avec l'outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Listez et obtenez des **informations** sur chaque entrée de trousseau de clés :

* L'API **`SecItemCopyMatching`** donne des informations sur chaque entrée et il y a des attributs que vous pouvez définir lors de son utilisation :
  * **`kSecReturnData`** : Si vrai, il essaiera de décrypter les données (définissez-le sur faux pour éviter les pop-ups potentiels)
  * **`kSecReturnRef`** : Obtenez également une référence à l'élément de trousseau de clés (définissez-le sur vrai au cas où vous verriez que vous pouvez décrypter sans pop-up)
  * **`kSecReturnAttributes`** : Obtenez des métadonnées sur les entrées
  * **`kSecMatchLimit`** : Combien de résultats à renvoyer
  * **`kSecClass`** : Quel type d'entrée de trousseau de clés

Obtenez les **ACL** de chaque entrée :

* Avec l'API **`SecAccessCopyACLList`**, vous pouvez obtenir l'**ACL pour l'élément de trousseau de clés**, et il renverra une liste d'ACL (comme `ACLAuhtorizationExportClear` et les autres mentionnées précédemment) où chaque liste a :
  * Description
  * **Liste d'applications de confiance**. Cela pourrait être :
    * Une application : /Applications/Slack.app
    * Un binaire : /usr/libexec/airportd
    * Un groupe : group://AirPort

Exportez les données :

* L'API **`SecKeychainItemCopyContent`** obtient le texte en clair
* L'API **`SecItemExport`** exporte les clés et les certificats mais il peut être nécessaire de définir des mots de passe pour exporter le contenu chiffré

Et voici les **exigences** pour pouvoir **exporter un secret sans invite** :

* Si **1+ applications de confiance** sont répertoriées :
  * Besoin des **autorisations appropriées** (**`Nil`**, ou être **partie** de la liste autorisée d'applications dans l'autorisation pour accéder aux informations secrètes)
  * Besoin d'une signature de code pour correspondre à **PartitionID**
  * Besoin d'une signature de code pour correspondre à celle d'une **application de confiance** (ou être membre du bon KeychainAccessGroup)
* Si **toutes les applications sont de confiance** :
  * Besoin des **autorisations appropriées**
  * Besoin d'une signature de code pour correspondre à **PartitionID**
    * Si **aucun PartitionID**, alors cela n'est pas nécessaire

{% hint style="danger" %}
Par conséquent, s'il y a **1 application répertoriée**, vous devez **injecter du code dans cette application**.

Si **apple** est indiqué dans le **partitionID**, vous pouvez y accéder avec **`osascript`** donc tout ce qui fait confiance à toutes les applications avec apple dans le partitionID. **`Python`** pourrait également être utilisé pour cela.
{% endhint %}

### Deux attributs supplémentaires

* **Invisible** : C'est un indicateur booléen pour **masquer** l'entrée de l'application **UI** Keychain
* **Général** : C'est pour stocker des **métadonnées** (donc ce n'est PAS CHIFFRÉ)
  * Microsoft stockait en texte clair tous les jetons de rafraîchissement pour accéder à des points de terminaison sensibles.

## Références

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
