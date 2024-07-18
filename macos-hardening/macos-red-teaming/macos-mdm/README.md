# macOS MDM

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**Pour en savoir plus sur les MDM macOS, consultez :**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Fondamentaux

### **Aperçu de MDM (Gestion des appareils mobiles)**

La [Gestion des appareils mobiles](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) est utilisée pour gérer différents appareils utilisateurs tels que des smartphones, des ordinateurs portables et des tablettes. Particulièrement pour les plateformes d'Apple (iOS, macOS, tvOS), cela implique un ensemble de fonctionnalités spécialisées, d'API et de pratiques. Le fonctionnement de MDM repose sur un serveur MDM compatible, qui est soit disponible commercialement, soit open-source, et doit prendre en charge le [Protocole MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Les points clés incluent :

* Contrôle centralisé des appareils.
* Dépendance d'un serveur MDM qui respecte le protocole MDM.
* Capacité du serveur MDM à envoyer diverses commandes aux appareils, par exemple, effacement de données à distance ou installation de configurations.

### **Fondamentaux du DEP (Programme d'inscription des appareils)**

Le [Programme d'inscription des appareils](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) proposé par Apple simplifie l'intégration de la Gestion des appareils mobiles (MDM) en facilitant la configuration sans intervention pour les appareils iOS, macOS et tvOS. Le DEP automatise le processus d'inscription, permettant aux appareils d'être opérationnels dès la sortie de la boîte, avec une intervention minimale de l'utilisateur ou de l'administrateur. Les aspects essentiels incluent :

* Permet aux appareils de s'inscrire automatiquement auprès d'un serveur MDM prédéfini lors de l'activation initiale.
* Principalement bénéfique pour les appareils neufs, mais également applicable aux appareils en cours de reconfiguration.
* Facilite une configuration simple, rendant les appareils prêts à être utilisés par l'organisation rapidement.

### **Considération de sécurité**

Il est crucial de noter que la facilité d'inscription fournie par le DEP, bien que bénéfique, peut également présenter des risques de sécurité. Si des mesures de protection ne sont pas correctement appliquées pour l'inscription MDM, les attaquants pourraient exploiter ce processus simplifié pour enregistrer leur appareil sur le serveur MDM de l'organisation, se faisant passer pour un appareil d'entreprise.

{% hint style="danger" %}
**Alerte de sécurité** : L'inscription simplifiée au DEP pourrait potentiellement permettre l'enregistrement d'appareils non autorisés sur le serveur MDM de l'organisation si des mesures de sécurité adéquates ne sont pas en place.
{% endhint %}

### Fondamentaux Qu'est-ce que SCEP (Protocole d'inscription de certificat simple) ?

* Un protocole relativement ancien, créé avant que TLS et HTTPS ne soient répandus.
* Donne aux clients un moyen standardisé d'envoyer une **demande de signature de certificat** (CSR) dans le but d'obtenir un certificat. Le client demandera au serveur de lui fournir un certificat signé.

### Quels sont les profils de configuration (également appelés mobileconfigs) ?

* Méthode officielle d'**établissement/imposition de la configuration système** par Apple.
* Format de fichier pouvant contenir plusieurs charges utiles.
* Basé sur des listes de propriétés (du type XML).
* "peut être signé et chiffré pour valider leur origine, assurer leur intégrité et protéger leur contenu." Fondamentaux — Page 70, Guide de sécurité iOS, janvier 2018.

## Protocoles

### MDM

* Combinaison d'APNs (**serveurs Apple**) + API RESTful (**serveurs de fournisseurs MDM**)
* La **communication** se fait entre un **appareil** et un serveur associé à un **produit de gestion des appareils**
* Les **commandes** sont envoyées du MDM à l'appareil sous forme de **dictionnaires encodés en plist**
* Tout se fait via **HTTPS**. Les serveurs MDM peuvent être (et sont généralement) épinglés.
* Apple accorde au fournisseur MDM un **certificat APNs** pour l'authentification

### DEP

* **3 API** : 1 pour les revendeurs, 1 pour les fournisseurs MDM, 1 pour l'identité de l'appareil (non documenté) :
* La soi-disant [API "service cloud" DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Celle-ci est utilisée par les serveurs MDM pour associer des profils DEP à des appareils spécifiques.
* L'[API DEP utilisée par les revendeurs agréés Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) pour inscrire des appareils, vérifier l'état de l'inscription et vérifier l'état de la transaction.
* L'API DEP privée non documentée. Celle-ci est utilisée par les appareils Apple pour demander leur profil DEP. Sur macOS, le binaire `cloudconfigurationd` est responsable de la communication via cette API.
* Plus moderne et basé sur **JSON** (par rapport à plist)
* Apple accorde un **jeton OAuth** au fournisseur MDM

**API "service cloud" DEP**

* RESTful
* synchronise les enregistrements d'appareils d'Apple vers le serveur MDM
* synchronise les "profils DEP" vers Apple depuis le serveur MDM (fournis par Apple à l'appareil ultérieurement)
* Un "profil" DEP contient :
* URL du serveur du fournisseur MDM
* Certificats de confiance supplémentaires pour l'URL du serveur (épinglage facultatif)
* Paramètres supplémentaires (par exemple, quelles étapes sauter dans l'Assistant de configuration)

## Numéro de série

Les appareils Apple fabriqués après 2010 ont généralement des numéros de série alphanumériques de **12 caractères**, les **trois premiers chiffres représentant le lieu de fabrication**, les deux suivants indiquant l'**année** et la **semaine** de fabrication, les trois chiffres suivants fournissant un **identifiant unique**, et les **quatre derniers** chiffres représentant le **numéro de modèle**.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Étapes d'inscription et de gestion

1. Création de l'enregistrement de l'appareil (Revendeur, Apple) : L'enregistrement du nouvel appareil est créé
2. Attribution de l'enregistrement de l'appareil (Client) : L'appareil est attribué à un serveur MDM
3. Synchronisation de l'enregistrement de l'appareil (Fournisseur MDM) : Le MDM synchronise les enregistrements de l'appareil et pousse les profils DEP vers Apple
4. Vérification DEP (Appareil) : L'appareil obtient son profil DEP
5. Récupération du profil (Appareil)
6. Installation du profil (Appareil) a. incl. charges utiles MDM, SCEP et CA racine
7. Émission de commandes MDM (Appareil)

![](<../../../.gitbook/assets/image (694).png>)

Le fichier `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporte des fonctions qui peuvent être considérées comme des **étapes** **de haut niveau** du processus d'inscription.
### Étape 4: Vérification DEP - Obtenir l'enregistrement d'activation

Cette partie du processus se produit lorsque **un utilisateur démarre un Mac pour la première fois** (ou après une suppression complète)

![](<../../../.gitbook/assets/image (1044).png>)

ou lors de l'exécution de `sudo profiles show -type enrollment`

* Déterminer **si l'appareil est activé pour DEP**
* L'enregistrement d'activation est le nom interne du **"profil" DEP**
* Commence dès que l'appareil est connecté à Internet
* Piloté par **`CPFetchActivationRecord`**
* Implémenté par **`cloudconfigurationd`** via XPC. L'**"Assistant de configuration**" (lorsque l'appareil est démarré pour la première fois) ou la commande **`profiles`** contacteront ce démon pour récupérer l'enregistrement d'activation.
* LaunchDaemon (toujours exécuté en tant que root)

Il suit quelques étapes pour obtenir l'enregistrement d'activation effectué par **`MCTeslaConfigurationFetcher`**. Ce processus utilise un cryptage appelé **Absinthe**

1. Récupérer le **certificat**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialiser** l'état à partir du certificat (**`NACInit`**)
1. Utilise diverses données spécifiques à l'appareil (par exemple le **numéro de série via `IOKit`**)
3. Récupérer la **clé de session**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Établir la session (**`NACKeyEstablishment`**)
5. Faire la demande
1. POST à [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) en envoyant les données `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. La charge JSON est cryptée en utilisant Absinthe (**`NACSign`**)
3. Toutes les demandes sont effectuées via HTTPs, des certificats racine intégrés sont utilisés

![](<../../../.gitbook/assets/image (566) (1).png>)

La réponse est un dictionnaire JSON avec des données importantes telles que :

* **url** : URL de l'hôte du fournisseur MDM pour le profil d'activation
* **anchor-certs** : Tableau de certificats DER utilisés comme ancres de confiance

### **Étape 5: Récupération du profil**

![](<../../../.gitbook/assets/image (444).png>)

* Demande envoyée à l'**URL fournie dans le profil DEP**.
* Les **certificats d'ancrage** sont utilisés pour **évaluer la confiance** s'ils sont fournis.
* Rappel : la propriété **anchor\_certs** du profil DEP
* La demande est un simple fichier .plist avec l'identification de l'appareil
* Exemples : **UDID, version du système d'exploitation**.
* Signé CMS, encodé en DER
* Signé en utilisant le **certificat d'identité de l'appareil (de APNS)**
* La **chaîne de certificats** inclut le certificat expiré **Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Étape 6: Installation du profil

* Une fois récupéré, **le profil est stocké sur le système**
* Cette étape démarre automatiquement (si dans l'**assistant de configuration**)
* Piloté par **`CPInstallActivationProfile`**
* Implémenté par mdmclient via XPC
* LaunchDaemon (en tant que root) ou LaunchAgent (en tant qu'utilisateur), selon le contexte
* Les profils de configuration ont plusieurs charges utiles à installer
* Le framework a une architecture basée sur des plugins pour l'installation de profils
* Chaque type de charge utile est associé à un plugin
* Peut être XPC (dans le framework) ou Cocoa classique (dans ManagedClient.app)
* Exemple :
* Les charges utiles de certificat utilisent CertificateService.xpc

Typiquement, **le profil d'activation** fourni par un fournisseur MDM inclura **les charges utiles suivantes** :

* `com.apple.mdm` : pour **inscrire** l'appareil dans le MDM
* `com.apple.security.scep` : pour fournir de manière sécurisée un **certificat client** à l'appareil.
* `com.apple.security.pem` : pour **installer des certificats CA de confiance** dans le trousseau système de l'appareil.
* Installer la charge utile MDM équivalente à **l'enregistrement MDM dans la documentation**
* La charge utile **contient des propriétés clés** :
*
* URL de vérification MDM (**`CheckInURL`**)
* URL de sondage des commandes MDM (**`ServerURL`**) + sujet APNs pour le déclencher
* Pour installer la charge utile MDM, une demande est envoyée à **`CheckInURL`**
* Implémenté dans **`mdmclient`**
* La charge utile MDM peut dépendre d'autres charges utiles
* Permet de **définir des demandes sur des certificats spécifiques** :
* Propriété : **`CheckInURLPinningCertificateUUIDs`**
* Propriété : **`ServerURLPinningCertificateUUIDs`**
* Livré via la charge utile PEM
* Permet à l'appareil d'être attribué avec un certificat d'identité :
* Propriété : IdentityCertificateUUID
* Livré via la charge utile SCEP

### **Étape 7: Écoute des commandes MDM**

* Après l'enregistrement MDM est complet, le fournisseur peut **émettre des notifications push en utilisant APNs**
* À la réception, géré par **`mdmclient`**
* Pour interroger les commandes MDM, une demande est envoyée à ServerURL
* Utilise la charge utile MDM précédemment installée :
* **`ServerURLPinningCertificateUUIDs`** pour épingler la demande
* **`IdentityCertificateUUID`** pour le certificat client TLS

## Attaques

### Inscrire des appareils dans d'autres organisations

Comme précédemment commenté, pour essayer d'inscrire un appareil dans une organisation, **seul un numéro de série appartenant à cette organisation est nécessaire**. Une fois l'appareil inscrit, plusieurs organisations installeront des données sensibles sur le nouvel appareil : certificats, applications, mots de passe WiFi, configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela pourrait être un point d'entrée dangereux pour les attaquants si le processus d'inscription n'est pas correctement protégé:
