# macOS MDM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Fondamentaux

### Qu'est-ce que MDM (Mobile Device Management) ?

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) est une technologie couramment utilisée pour **administrer les appareils informatiques des utilisateurs finaux** tels que les téléphones mobiles, les ordinateurs portables, les ordinateurs de bureau et les tablettes. Dans le cas des plates-formes Apple telles que iOS, macOS et tvOS, il fait référence à un ensemble spécifique de fonctionnalités, d'API et de techniques utilisées par les administrateurs pour gérer ces appareils. La gestion des appareils via MDM nécessite un serveur MDM commercial ou open source compatible qui implémente la prise en charge du [protocole MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf).

* Un moyen d'atteindre une **gestion centralisée des appareils**
* Nécessite un **serveur MDM** qui implémente la prise en charge du protocole MDM
* Le serveur MDM peut **envoyer des commandes MDM**, telles que l'effacement à distance ou « installer cette configuration »

### Fondamentaux Qu'est-ce que DEP (Device Enrolment Program) ?

Le [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) est un service proposé par Apple qui **
### **Étape 7: Écoute des commandes MDM**

* Après la vérification MDM, le fournisseur peut **émettre des notifications push en utilisant APNs**
* À la réception, cela est géré par **`mdmclient`**
* Pour interroger les commandes MDM, une demande est envoyée à ServerURL
* Utilise la charge utile MDM précédemment installée:
  * **`ServerURLPinningCertificateUUIDs`** pour l'épinglage de la demande
  * **`IdentityCertificateUUID`** pour le certificat client TLS

## Attaques

### Inscription de périphériques dans d'autres organisations

Comme précédemment commenté, pour essayer d'inscrire un périphérique dans une organisation, **seul un numéro de série appartenant à cette organisation est nécessaire**. Une fois le périphérique inscrit, plusieurs organisations installeront des données sensibles sur le nouveau périphérique: certificats, applications, mots de passe WiFi, configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela pourrait être un point d'entrée dangereux pour les attaquants si le processus d'inscription n'est pas correctement protégé:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

## **Références**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
