# macOS Keychain

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Principaux Keychains

* Le **User Keychain** (`~/Library/Keychains/login.keycahin-db`), utilisé pour stocker les **identifiants spécifiques à l'utilisateur** tels que les mots de passe d'applications, les mots de passe internet, les certificats générés par l'utilisateur, les mots de passe réseau et les clés publiques/privées générées par l'utilisateur.
* Le **System Keychain** (`/Library/Keychains/System.keychain`), qui stocke les **identifiants à l'échelle du système** tels que les mots de passe WiFi, les certificats racine du système, les clés privées du système et les mots de passe des applications système.

### Accès au Keychain de mots de passe

Ces fichiers, bien qu'ils ne soient pas protégés par nature et puissent être **téléchargés**, sont chiffrés et nécessitent le **mot de passe en clair de l'utilisateur pour être déchiffrés**. Un outil comme [**Chainbreaker**](https://github.com/n0fate/chainbreaker) pourrait être utilisé pour le déchiffrement.

## Protections des entrées du Keychain

### ACLs

Chaque entrée dans le keychain est régie par des **Listes de contrôle d'accès (ACLs)** qui dictent qui peut effectuer diverses actions sur l'entrée du keychain, y compris :

* **ACLAuhtorizationExportClear** : Permet au détenteur d'obtenir le texte clair du secret.
* **ACLAuhtorizationExportWrapped** : Permet au détenteur d'obtenir le texte clair chiffré avec un autre mot de passe fourni.
* **ACLAuhtorizationAny** : Permet au détenteur d'effectuer n'importe quelle action.

Les ACLs sont en outre accompagnées d'une **liste d'applications de confiance** qui peuvent effectuer ces actions sans demande. Cela pourrait être :

* &#x20;**N`il`** (aucune autorisation requise, **tout le monde est de confiance**)
* Une liste **vide** (**personne** n'est de confiance)
* **Liste** d'**applications spécifiques**.

De plus, l'entrée peut contenir la clé **`ACLAuthorizationPartitionID`,** qui est utilisée pour identifier le **teamid, apple,** et **cdhash.**

* Si le **teamid** est spécifié, alors pour **accéder à la valeur de l'entrée** **sans** **invite**, l'application utilisée doit avoir le **même teamid**.
* Si **apple** est spécifié, alors l'application doit être **signée** par **Apple**.
* Si le **cdhash** est indiqué, alors l'**application** doit avoir le **cdhash** spécifique.

### Création d'une entrée Keychain

Lorsqu'une **nouvelle** **entrée** est créée en utilisant **`Keychain Access.app`**, les règles suivantes s'appliquent :

* Toutes les applications peuvent chiffrer.
* **Aucune application** ne peut exporter/déchiffrer (sans demander à l'utilisateur).
* Toutes les applications peuvent voir le contrôle d'intégrité.
* Aucune application ne peut changer les ACLs.
* Le **partitionID** est défini sur **`apple`**.

Lorsqu'une **application crée une entrée dans le keychain**, les règles sont légèrement différentes :

* Toutes les applications peuvent chiffrer.
* Seule l'**application créatrice** (ou toute autre application explicitement ajoutée) peut exporter/déchiffrer (sans demander à l'utilisateur).
* Toutes les applications peuvent voir le contrôle d'intégrité.
* Aucune application ne peut changer les ACLs.
* Le **partitionID** est défini sur **`teamid:[teamID ici]`**.

## Accéder au Keychain

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
L'**énumération des trousseaux et l'extraction** des secrets qui **ne généreront pas de demande** peuvent être effectuées avec l'outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Lister et obtenir des **informations** sur chaque entrée du trousseau :

* L'API **`SecItemCopyMatching`** fournit des informations sur chaque entrée et il y a certains attributs que vous pouvez définir lors de son utilisation :
* **`kSecReturnData`** : Si vrai, il essaiera de déchiffrer les données (mettre sur faux pour éviter les pop-ups potentiels)
* **`kSecReturnRef`** : Obtenez également une référence à l'élément du trousseau (mettre sur vrai au cas où vous verriez que vous pouvez déchiffrer sans pop-up)
* **`kSecReturnAttributes`** : Obtenez des métadonnées sur les entrées
* **`kSecMatchLimit`** : Combien de résultats retourner
* **`kSecClass`** : Quel type d'entrée de trousseau

Obtenir les **ACL** de chaque entrée :

* Avec l'API **`SecAccessCopyACLList`**, vous pouvez obtenir l'**ACL pour l'élément du trousseau**, et cela retournera une liste d'ACLs (comme `ACLAuhtorizationExportClear` et les autres mentionnés précédemment) où chaque liste a :
* Description
* **Liste d'applications de confiance**. Cela pourrait être :
* Une application : /Applications/Slack.app
* Un binaire : /usr/libexec/airportd
* Un groupe : group://AirPort

Exporter les données :

* L'API **`SecKeychainItemCopyContent`** obtient le texte en clair
* L'API **`SecItemExport`** exporte les clés et les certificats mais pourrait devoir définir des mots de passe pour exporter le contenu chiffré

Et voici les **exigences** pour pouvoir **exporter un secret sans demande** :

* Si **1+ applications de confiance** sont listées :
* Besoin des **autorisations** appropriées (**`Nil`**, ou faire **partie** de la liste des applications autorisées dans l'autorisation pour accéder aux informations secrètes)
* Besoin que la signature de code corresponde au **PartitionID**
* Besoin que la signature de code corresponde à celle d'une **application de confiance** (ou être membre du bon KeychainAccessGroup)
* Si **toutes les applications sont de confiance** :
* Besoin des **autorisations** appropriées
* Besoin que la signature de code corresponde au **PartitionID**
* Si **aucun PartitionID**, alors cela n'est pas nécessaire

{% hint style="danger" %}
Par conséquent, s'il y a **1 application listée**, vous devez **injecter du code dans cette application**.

Si **apple** est indiqué dans le **partitionID**, vous pourriez y accéder avec **`osascript`** donc tout ce qui fait confiance à toutes les applications avec apple dans le partitionID. **`Python`** pourrait également être utilisé pour cela.
{% endhint %}

### Deux attributs supplémentaires

* **Invisible** : C'est un indicateur booléen pour **cacher** l'entrée de l'application **UI** Keychain
* **Général** : C'est pour stocker des **métadonnées** (donc ce n'est PAS CHIFFRÉ)
* Microsoft stockait en texte clair tous les jetons d'actualisation pour accéder à des points de terminaison sensibles.

## Références

* [**#OBTS v5.0 : "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
