# Inscription des appareils dans d'autres organisations

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Introduction

Comme [**mentionné précédemment**](./#what-is-mdm-mobile-device-management), pour essayer d'inscrire un appareil dans une organisation, **seul un numéro de série appartenant à cette organisation est nécessaire**. Une fois l'appareil inscrit, plusieurs organisations installeront des données sensibles sur le nouvel appareil : certificats, applications, mots de passe WiFi, configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela pourrait constituer un point d'entrée dangereux pour les attaquants si le processus d'inscription n'est pas correctement protégé.

**Ce qui suit est un résumé de la recherche [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consultez-la pour plus de détails techniques !**

## Aperçu de l'analyse binaire DEP et MDM

Cette recherche se penche sur les binaires associés au Programme d'inscription des appareils (DEP) et à la gestion des appareils mobiles (MDM) sur macOS. Les composants clés comprennent :

- **`mdmclient`** : Communique avec les serveurs MDM et déclenche les vérifications DEP sur les versions de macOS antérieures à 10.13.4.
- **`profiles`** : Gère les profils de configuration et déclenche les vérifications DEP sur les versions de macOS 10.13.4 et ultérieures.
- **`cloudconfigurationd`** : Gère les communications API DEP et récupère les profils d'inscription des appareils.

Les vérifications DEP utilisent les fonctions `CPFetchActivationRecord` et `CPGetActivationRecord` du framework privé Configuration Profiles pour récupérer l'Activation Record, `CPFetchActivationRecord` coordonnant avec `cloudconfigurationd` via XPC.

## Ingénierie inverse du protocole Tesla et du schéma Absinthe

La vérification DEP implique que `cloudconfigurationd` envoie une charge utile JSON chiffrée et signée à _iprofiles.apple.com/macProfile_. La charge utile inclut le numéro de série de l'appareil et l'action "RequestProfileConfiguration". Le schéma de chiffrement utilisé est appelé en interne "Absinthe". Démêler ce schéma est complexe et implique de nombreuses étapes, ce qui a conduit à explorer des méthodes alternatives pour insérer des numéros de série arbitraires dans la demande d'Activation Record.

## Interception des demandes DEP

Les tentatives d'interception et de modification des demandes DEP vers _iprofiles.apple.com_ à l'aide d'outils comme Charles Proxy ont été entravées par le chiffrement de la charge utile et les mesures de sécurité SSL/TLS. Cependant, activer la configuration `MCCloudConfigAcceptAnyHTTPSCertificate` permet de contourner la validation du certificat du serveur, bien que la nature chiffrée de la charge utile empêche toujours la modification du numéro de série sans la clé de déchiffrement.

## Instrumentation des binaires système interagissant avec DEP

L'instrumentation des binaires système comme `cloudconfigurationd` nécessite de désactiver la Protection de l'intégrité du système (SIP) sur macOS. Avec SIP désactivé, des outils comme LLDB peuvent être utilisés pour se connecter aux processus système et potentiellement modifier le numéro de série utilisé dans les interactions API DEP. Cette méthode est préférable car elle évite les complexités des autorisations et de la signature de code.

**Exploitation de l'instrumentation binaire :**
La modification de la charge utile de demande DEP avant la sérialisation JSON dans `cloudconfigurationd` s'est avérée efficace. Le processus impliquait :

1. Connecter LLDB à `cloudconfigurationd`.
2. Localiser le point où le numéro de série du système est récupéré.
3. Injecter un numéro de série arbitraire dans la mémoire avant que la charge utile ne soit chiffrée et envoyée.

Cette méthode a permis de récupérer des profils DEP complets pour des numéros de série arbitraires, démontrant une vulnérabilité potentielle.

### Automatisation de l'instrumentation avec Python

Le processus d'exploitation a été automatisé en utilisant Python avec l'API LLDB, ce qui permet d'injecter de manière programmée des numéros de série arbitraires et de récupérer les profils DEP correspondants.

### Impacts potentiels des vulnérabilités DEP et MDM

La recherche a mis en évidence des préoccupations de sécurité significatives :

1. **Divulgation d'informations** : En fournissant un numéro de série enregistré dans DEP, des informations organisationnelles sensibles contenues dans le profil DEP peuvent être récupérées.
2. **Inscription DEP frauduleuse** : Sans une authentification appropriée, un attaquant avec un numéro de série enregistré dans DEP peut inscrire un appareil frauduleux dans le serveur MDM d'une organisation, potentiellement accéder à des données sensibles et des ressources réseau.

En conclusion, bien que DEP et MDM offrent des outils puissants pour gérer les appareils Apple dans les environnements d'entreprise, ils présentent également des vecteurs d'attaque potentiels qui doivent être sécurisés et surveillés.
