# macOS Keychain

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark-web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **malwares voleurs**.

Le principal objectif de WhiteIntel est de lutter contre les détournements de compte et les attaques par ransomware résultant de malwares de vol d'informations.

Vous pouvez consulter leur site web et essayer leur moteur **gratuitement** à :

{% embed url="https://whiteintel.io" %}

***

## Main Keychains

* Le **User Keychain** (`~/Library/Keychains/login.keycahin-db`), qui est utilisé pour stocker des **identifiants spécifiques à l'utilisateur** tels que des mots de passe d'application, des mots de passe Internet, des certificats générés par l'utilisateur, des mots de passe réseau et des clés publiques/privées générées par l'utilisateur.
* Le **System Keychain** (`/Library/Keychains/System.keychain`), qui stocke des **identifiants à l'échelle du système** tels que des mots de passe WiFi, des certificats racine du système, des clés privées du système et des mots de passe d'application du système.

### Password Keychain Access

Ces fichiers, bien qu'ils n'aient pas de protection inhérente et puissent être **téléchargés**, sont chiffrés et nécessitent le **mot de passe en clair de l'utilisateur pour être déchiffrés**. Un outil comme [**Chainbreaker**](https://github.com/n0fate/chainbreaker) pourrait être utilisé pour le déchiffrement.

## Keychain Entries Protections

### ACLs

Chaque entrée dans le trousseau est régie par des **Listes de Contrôle d'Accès (ACLs)** qui dictent qui peut effectuer diverses actions sur l'entrée du trousseau, y compris :

* **ACLAuhtorizationExportClear** : Permet au titulaire d'obtenir le texte clair du secret.
* **ACLAuhtorizationExportWrapped** : Permet au titulaire d'obtenir le texte clair chiffré avec un autre mot de passe fourni.
* **ACLAuhtorizationAny** : Permet au titulaire d'effectuer n'importe quelle action.

Les ACLs sont également accompagnées d'une **liste d'applications de confiance** qui peuvent effectuer ces actions sans demande. Cela pourrait être :

* **N`il`** (aucune autorisation requise, **tout le monde est de confiance**)
* Une liste **vide** (**personne** n'est de confiance)
* **Liste** d'**applications** spécifiques.

De plus, l'entrée peut contenir la clé **`ACLAuthorizationPartitionID`,** qui est utilisée pour identifier le **teamid, apple,** et **cdhash.**

* Si le **teamid** est spécifié, alors pour **accéder à la valeur de l'entrée** **sans** une **demande**, l'application utilisée doit avoir le **même teamid**.
* Si le **apple** est spécifié, alors l'application doit être **signée** par **Apple**.
* Si le **cdhash** est indiqué, alors l'**application** doit avoir le **cdhash** spécifique.

### Creating a Keychain Entry

Lorsque une **nouvelle** **entrée** est créée en utilisant **`Keychain Access.app`**, les règles suivantes s'appliquent :

* Toutes les applications peuvent chiffrer.
* **Aucune application** ne peut exporter/déchiffrer (sans demander à l'utilisateur).
* Toutes les applications peuvent voir le contrôle d'intégrité.
* Aucune application ne peut changer les ACLs.
* Le **partitionID** est défini sur **`apple`**.

Lorsque une **application crée une entrée dans le trousseau**, les règles sont légèrement différentes :

* Toutes les applications peuvent chiffrer.
* Seule l'**application créatrice** (ou toute autre application explicitement ajoutée) peut exporter/déchiffrer (sans demander à l'utilisateur).
* Toutes les applications peuvent voir le contrôle d'intégrité.
* Aucune application ne peut changer les ACLs.
* Le **partitionID** est défini sur **`teamid:[teamID ici]`**.

## Accessing the Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
L'**énumération et l'extraction** de secrets qui **ne généreront pas d'invite** peuvent être effectuées avec l'outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Liste et obtention d'**informations** sur chaque entrée de trousseau :

* L'API **`SecItemCopyMatching`** fournit des informations sur chaque entrée et il y a certains attributs que vous pouvez définir lors de son utilisation :
* **`kSecReturnData`** : Si vrai, il essaiera de déchiffrer les données (définir sur faux pour éviter les pop-ups potentiels)
* **`kSecReturnRef`** : Obtenir également une référence à l'élément de trousseau (définir sur vrai si vous voyez plus tard que vous pouvez déchiffrer sans pop-up)
* **`kSecReturnAttributes`** : Obtenir des métadonnées sur les entrées
* **`kSecMatchLimit`** : Combien de résultats retourner
* **`kSecClass`** : Quel type d'entrée de trousseau

Obtenir les **ACL** de chaque entrée :

* Avec l'API **`SecAccessCopyACLList`**, vous pouvez obtenir l'**ACL pour l'élément de trousseau**, et cela renverra une liste d'ACL (comme `ACLAuhtorizationExportClear` et les autres mentionnés précédemment) où chaque liste a :
* Description
* **Liste des applications de confiance**. Cela pourrait être :
* Une application : /Applications/Slack.app
* Un binaire : /usr/libexec/airportd
* Un groupe : group://AirPort

Exporter les données :

* L'API **`SecKeychainItemCopyContent`** obtient le texte en clair
* L'API **`SecItemExport`** exporte les clés et certificats mais peut nécessiter de définir des mots de passe pour exporter le contenu chiffré

Et voici les **exigences** pour pouvoir **exporter un secret sans invite** :

* Si **1+ applications de confiance** listées :
* Besoin des **autorisations** appropriées (**`Nil`**, ou faire **partie** de la liste autorisée d'applications dans l'autorisation d'accès aux informations secrètes)
* Besoin que la signature de code corresponde à **PartitionID**
* Besoin que la signature de code corresponde à celle d'une **application de confiance** (ou faire partie du bon KeychainAccessGroup)
* Si **toutes les applications sont de confiance** :
* Besoin des **autorisations** appropriées
* Besoin que la signature de code corresponde à **PartitionID**
* Si **pas de PartitionID**, alors cela n'est pas nécessaire

{% hint style="danger" %}
Par conséquent, s'il y a **1 application listée**, vous devez **injecter du code dans cette application**.

Si **apple** est indiqué dans le **partitionID**, vous pourriez y accéder avec **`osascript`** donc tout ce qui fait confiance à toutes les applications avec apple dans le partitionID. **`Python`** pourrait également être utilisé pour cela.
{% endhint %}

### Deux attributs supplémentaires

* **Invisible** : C'est un drapeau booléen pour **cacher** l'entrée de l'application **UI** Keychain
* **Général** : C'est pour stocker des **métadonnées** (donc ce n'est PAS CHIFFRÉ)
* Microsoft stockait en texte clair tous les jetons de rafraîchissement pour accéder à des points de terminaison sensibles.

## Références

* [**#OBTS v5.0 : "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark-web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **malwares voleurs**.

Leur objectif principal avec WhiteIntel est de lutter contre les détournements de compte et les attaques par ransomware résultant de malwares de vol d'informations.

Vous pouvez consulter leur site web et essayer leur moteur **gratuitement** à :

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
