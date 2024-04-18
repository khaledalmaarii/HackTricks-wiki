# Trousseau macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **logiciels malveillants voleurs**.

Le but principal de WhiteIntel est de lutter contre les prises de contrôle de compte et les attaques de ransomware résultant de logiciels malveillants volant des informations.

Vous pouvez consulter leur site Web et essayer leur moteur **gratuitement** sur :

{% embed url="https://whiteintel.io" %}

---

## Principaux trousseaux

- Le **trousseau utilisateur** (`~/Library/Keychains/login.keycahin-db`), qui est utilisé pour stocker les **informations d'identification spécifiques à l'utilisateur** telles que les mots de passe d'application, les mots de passe Internet, les certificats générés par l'utilisateur, les mots de passe réseau et les clés publiques/privées générées par l'utilisateur.
- Le **trousseau système** (`/Library/Keychains/System.keychain`), qui stocke les **informations d'identification à l'échelle du système** telles que les mots de passe WiFi, les certificats racine du système, les clés privées du système et les mots de passe d'application du système.

### Accès au trousseau de mots de passe

Ces fichiers, bien qu'ils ne bénéficient pas d'une protection inhérente et puissent être **téléchargés**, sont chiffrés et nécessitent le **mot de passe en clair de l'utilisateur pour être déchiffrés**. Un outil comme [**Chainbreaker**](https://github.com/n0fate/chainbreaker) pourrait être utilisé pour le déchiffrement.

## Protections des entrées du trousseau

### ACLs

Chaque entrée dans le trousseau est régie par des **listes de contrôle d'accès (ACL)** qui dictent qui peut effectuer diverses actions sur l'entrée du trousseau, notamment :

- **ACLAuhtorizationExportClear** : Permet au détenteur d'obtenir le texte en clair du secret.
- **ACLAuhtorizationExportWrapped** : Permet au détenteur d'obtenir le texte en clair chiffré avec un autre mot de passe fourni.
- **ACLAuhtorizationAny** : Permet au détenteur d'effectuer n'importe quelle action.

Les ACL sont accompagnées d'une **liste d'applications de confiance** qui peuvent effectuer ces actions sans invitation. Cela pourrait être :

- &#x20;**N`il`** (aucune autorisation requise, **tout le monde est de confiance**)
- Une liste **vide** (personne n'est de confiance)
- Liste d'applications **spécifiques**.

De plus, l'entrée peut contenir la clé **`ACLAuthorizationPartitionID`,** qui est utilisée pour identifier le **teamid, apple,** et **cdhash.**

- Si le **teamid** est spécifié, alors pour **accéder à la valeur de l'entrée** sans **invitation**, l'application utilisée doit avoir le **même teamid**.
- Si l'**apple** est spécifié, alors l'application doit être **signée** par **Apple**.
- Si le **cdhash** est indiqué, alors l'**application** doit avoir le **cdhash** spécifique.

### Création d'une entrée de trousseau

Lorsqu'une **nouvelle** **entrée** est créée à l'aide de **`Keychain Access.app`**, les règles suivantes s'appliquent :

- Toutes les applications peuvent chiffrer.
- Aucune application ne peut exporter/déchiffrer (sans inviter l'utilisateur).
- Toutes les applications peuvent voir le contrôle d'intégrité.
- Aucune application ne peut modifier les ACL.
- L'**ID de partition** est défini sur **`apple`**.

Lorsqu'une **application crée une entrée dans le trousseau**, les règles sont légèrement différentes :

- Toutes les applications peuvent chiffrer.
- Seule l'**application créatrice** (ou toute autre application ajoutée explicitement) peut exporter/déchiffrer (sans inviter l'utilisateur).
- Toutes les applications peuvent voir le contrôle d'intégrité.
- Aucune application ne peut modifier les ACL.
- L'**ID de partition** est défini sur **`teamid:[teamID ici]`**.

## Accès au trousseau

### `sécurité`
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
L'**énumération et l'extraction** des secrets du trousseau qui **ne généreront pas de fenêtre contextuelle** peuvent être effectuées avec l'outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Listez et obtenez des **informations** sur chaque entrée du trousseau :

* L'API **`SecItemCopyMatching`** fournit des informations sur chaque entrée et il existe quelques attributs que vous pouvez définir lors de son utilisation :
* **`kSecReturnData`** : Si vrai, il tentera de décrypter les données (définissez-le sur faux pour éviter les fenêtres contextuelles potentielles)
* **`kSecReturnRef`** : Obtenez également la référence de l'élément du trousseau (définissez-le sur vrai au cas où vous pourriez décrypter sans fenêtre contextuelle)
* **`kSecReturnAttributes`** : Obtenez des métadonnées sur les entrées
* **`kSecMatchLimit`** : Combien de résultats renvoyer
* **`kSecClass`** : Quel type d'entrée de trousseau

Obtenez les **ACL** de chaque entrée :

* Avec l'API **`SecAccessCopyACLList`** vous pouvez obtenir l'**ACL de l'élément du trousseau**, et il renverra une liste d'ACL (comme `ACLAuhtorizationExportClear` et les autres mentionnés précédemment) où chaque liste a :
* Description
* **Liste d'applications de confiance**. Cela pourrait être :
* Une application : /Applications/Slack.app
* Un binaire : /usr/libexec/airportd
* Un groupe : group://AirPort

Exportez les données :

* L'API **`SecKeychainItemCopyContent`** obtient le texte en clair
* L'API **`SecItemExport`** exporte les clés et certificats mais il peut être nécessaire de définir des mots de passe pour exporter le contenu chiffré

Et voici les **conditions** pour pouvoir **exporter un secret sans fenêtre contextuelle** :

* Si **1+ applications de confiance** sont répertoriées :
* Besoin des **autorisations appropriées** (**`Nil`**, ou être **partie** de la liste autorisée d'applications dans l'autorisation pour accéder aux informations secrètes)
* Besoin que la signature de code corresponde à **PartitionID**
* Besoin que la signature de code corresponde à celle d'une **application de confiance** (ou être membre du bon KeychainAccessGroup)
* Si **toutes les applications sont de confiance** :
* Besoin des **autorisations appropriées**
* Besoin que la signature de code corresponde à **PartitionID**
* Si **aucun PartitionID**, alors cela n'est pas nécessaire

{% hint style="danger" %}
Par conséquent, s'il y a **1 application répertoriée**, vous devez **injecter du code dans cette application**.

Si **apple** est indiqué dans le **PartitionID**, vous pourriez y accéder avec **`osascript`** pour tout ce qui fait confiance à toutes les applications avec apple dans le PartitionID. **`Python`** pourrait également être utilisé pour cela.
{% endhint %}

### Deux attributs supplémentaires

* **Invisible** : C'est un indicateur booléen pour **masquer** l'entrée de l'application **UI** Keychain
* **Général** : C'est pour stocker des **métadonnées** (donc ce n'est PAS CHIFFRÉ)
* Microsoft stockait en texte clair tous les jetons de rafraîchissement pour accéder à des points de terminaison sensibles.

## Références

* [**#OBTS v5.0 : "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **logiciels malveillants voleurs**.

Le but principal de WhiteIntel est de lutter contre les prises de contrôle de compte et les attaques de ransomware résultant de logiciels malveillants voleurs d'informations.

Vous pouvez consulter leur site Web et essayer leur moteur **gratuitement** sur :

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez** 💬 le groupe Discord](https://discord.gg/hRep4RUj7f) ou le [groupe telegram](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
