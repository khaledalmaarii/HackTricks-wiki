# macOS MDM

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Bases

### Qu'est-ce que MDM (Mobile Device Management) ?

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) est une technologie couramment utilisée pour **administrer les appareils informatiques des utilisateurs finaux** tels que les téléphones mobiles, les ordinateurs portables, les ordinateurs de bureau et les tablettes. Dans le cas des plateformes Apple comme iOS, macOS et tvOS, cela fait référence à un ensemble spécifique de fonctionnalités, d'API et de techniques utilisées par les administrateurs pour gérer ces appareils. La gestion des appareils via MDM nécessite un serveur MDM commercial ou open-source compatible qui implémente le support pour le [Protocole MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf).

* Une manière d'atteindre une **gestion centralisée des appareils**
* Nécessite un **serveur MDM** qui implémente le support pour le protocole MDM
* Le serveur MDM peut **envoyer des commandes MDM**, telles que l'effacement à distance ou « installer cette configuration »

### Bases Qu'est-ce que DEP (Device Enrolment Program) ?

Le [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) est un service proposé par Apple qui **simplifie** l'inscription au Mobile Device Management (MDM) en offrant une configuration **sans intervention** des appareils iOS, macOS et tvOS. Contrairement aux méthodes de déploiement plus traditionnelles, qui nécessitent que l'utilisateur final ou l'administrateur prenne des mesures pour configurer un appareil ou s'inscrire manuellement auprès d'un serveur MDM, le DEP vise à amorcer ce processus, **permettant à l'utilisateur de déballer un nouvel appareil Apple et de l'avoir configuré pour une utilisation dans l'organisation presque immédiatement**.

Les administrateurs peuvent utiliser le DEP pour inscrire automatiquement les appareils dans le serveur MDM de leur organisation. Une fois qu'un appareil est inscrit, **dans de nombreux cas, il est traité comme un appareil "de confiance"** appartenant à l'organisation, et pourrait recevoir un certain nombre de certificats, d'applications, de mots de passe WiFi, de configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).

* Permet à un appareil de s'inscrire automatiquement dans un serveur MDM préconfiguré la **première fois qu'il est allumé**
* Plus utile lorsque l'**appareil** est **tout neuf**
* Peut également être utile pour les flux de travail de **reprovisionnement** (**effacé** avec une nouvelle installation de l'OS)

{% hint style="danger" %}
Malheureusement, si une organisation n'a pas pris de mesures supplémentaires pour **protéger son inscription MDM**, un processus d'inscription simplifié pour l'utilisateur final via le DEP peut également signifier un processus simplifié pour les **attaquants pour inscrire un appareil de leur choix dans le serveur MDM de l'organisation**, en assumant l'"identité" d'un appareil d'entreprise.
{% endhint %}

### Bases Qu'est-ce que SCEP (Simple Certificate Enrolment Protocol) ?

* Un protocole relativement ancien, créé avant que TLS et HTTPS ne soient largement répandus.
* Offre aux clients un moyen standardisé d'envoyer une **Demande de Signature de Certificat** (CSR) dans le but d'obtenir un certificat. Le client demandera au serveur de lui délivrer un certificat signé.

### Quels sont les profils de configuration (alias mobileconfigs) ?

* La manière officielle d'Apple de **définir/appliquer la configuration système.**
* Format de fichier qui peut contenir plusieurs charges utiles.
* Basé sur des listes de propriétés (de type XML).
* « peut être signé et chiffré pour valider leur origine, garantir leur intégrité et protéger leur contenu. » Bases — Page 70, Guide de sécurité iOS, janvier 2018.

## Protocoles

### MDM

* Combinaison de APNs (**serveurs Apple**) + API RESTful (**serveurs de fournisseurs MDM**)
* La **communication** se produit entre un **appareil** et un serveur associé à un **produit de gestion d'appareils**
* **Commandes** livrées du MDM à l'appareil dans **des dictionnaires encodés plist**
* Tout sur **HTTPS**. Les serveurs MDM peuvent être (et sont généralement) épinglés.
* Apple accorde au fournisseur MDM un **certificat APNs** pour l'authentification

### DEP

* **3 API** : 1 pour les revendeurs, 1 pour les fournisseurs MDM, 1 pour l'identité de l'appareil (non documentée) :
* L'API dite [DEP "cloud service"](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Cela est utilisé par les serveurs MDM pour associer des profils DEP à des appareils spécifiques.
* L'[API DEP utilisée par les revendeurs agréés Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) pour inscrire des appareils, vérifier le statut d'inscription et vérifier le statut de la transaction.
* L'API DEP privée non documentée. Cela est utilisé par les appareils Apple pour demander leur profil DEP. Sur macOS, le binaire `cloudconfigurationd` est responsable de la communication via cette API.
* Plus moderne et basé sur **JSON** (vs. plist)
* Apple accorde un **token OAuth** au fournisseur MDM

**API DEP "cloud service"**

* RESTful
* synchronise les enregistrements d'appareils d'Apple vers le serveur MDM
* synchronise les « profils DEP » vers Apple depuis le serveur MDM (livrés par Apple à l'appareil plus tard)
* Un profil DEP contient :
* URL du serveur du fournisseur MDM
* Certificats de confiance supplémentaires pour l'URL du serveur (épinglage optionnel)
* Paramètres supplémentaires (par exemple, quels écrans ignorer dans l'Assistant de configuration)

## Numéro de série

Les appareils Apple fabriqués après 2010 ont généralement des numéros de série **alphanumériques de 12 caractères**, avec les **trois premiers chiffres représentant le lieu de fabrication**, les **deux suivants** indiquant l'**année** et la **semaine** de fabrication, les trois chiffres suivants fournissant un **identifiant unique**, et les **quatre derniers chiffres représentant le numéro de modèle**.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Étapes pour l'inscription et la gestion

1. Création de l'enregistrement de l'appareil (Revendeur, Apple) : L'enregistrement du nouvel appareil est créé
2. Attribution de l'enregistrement de l'appareil (Client) : L'appareil est assigné à un serveur MDM
3. Synchronisation de l'enregistrement de l'appareil (Fournisseur MDM) : MDM synchronise les enregistrements d'appareils et pousse les profils DEP vers Apple
4. Vérification DEP (Appareil) : L'appareil obtient son profil DEP
5. Récupération du profil (Appareil)
6. Installation du profil (Appareil) a. incl. MDM, SCEP et charges utiles de CA racine
7. Émission de commande MDM (Appareil)

![](<../../../.gitbook/assets/image (564).png>)

Le fichier `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporte des fonctions qui peuvent être considérées comme des **"étapes" de haut niveau** du processus d'inscription.

### Étape 4 : Vérification DEP - Obtenir l'enregistrement d'activation

Cette partie du processus se produit lorsqu'un **utilisateur démarre un Mac pour la première fois** (ou après un effacement complet)

![](<../../../.gitbook/assets/image (568).png>)

ou lors de l'exécution de `sudo profiles show -type enrollment`

* Déterminer **si l'appareil est activé DEP**
* L'enregistrement d'activation est le nom interne pour le **profil DEP**
* Commence dès que l'appareil est connecté à Internet
* Piloté par **`CPFetchActivationRecord`**
* Implémenté par **`cloudconfigurationd`** via XPC. L'**"Assistant de configuration**" (lorsque l'appareil est démarré pour la première fois) ou la commande **`profiles`** vont **contacter ce démon** pour récupérer l'enregistrement d'activation.
* LaunchDaemon (toujours exécuté en tant que root)

Il suit quelques étapes pour obtenir l'enregistrement d'activation effectuées par **`MCTeslaConfigurationFetcher`**. Ce processus utilise un chiffrement appelé **Absinthe**

1. Récupérer **certificat**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialiser** l'état à partir du certificat (**`NACInit`**)
1. Utilise diverses données spécifiques à l'appareil (c.-à-d. **Numéro de série via `IOKit`**)
3. Récupérer **clé de session**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Établir la session (**`NACKeyEstablishment`**)
5. Faire la demande
1. POST à [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) en envoyant les données `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. La charge utile JSON est chiffrée en utilisant Absinthe (**`NACSign`**)
3. Toutes les demandes sur HTTPs, les certificats racine intégrés sont utilisés

![](<../../../.gitbook/assets/image (566).png>)

La réponse est un dictionnaire JSON avec des données importantes comme :

* **url** : URL de l'hôte du fournisseur MDM pour le profil d'activation
* **anchor-certs** : Tableau de certificats DER utilisés comme ancres de confiance

### **Étape 5 : Récupération du profil**

![](<../../../.gitbook/assets/image (567).png>)

* Demande envoyée à **l'url fournie dans le profil DEP**.
* **Les certificats d'ancrage** sont utilisés pour **évaluer la confiance** s'ils sont fournis.
* Rappel : la propriété **anchor\_certs** du profil DEP
* **La demande est un simple .plist** avec identification de l'appareil
* Exemples : **UDID, version OS**.
* Signé CMS, encodé DER
* Signé en utilisant le **certificat d'identité de l'appareil (de APNS)**
* **La chaîne de certificats** comprend le **Apple iPhone Device CA** expiré

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1)
