# Extensions système macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Extensions système / Cadre de sécurité de point de terminaison

Contrairement aux extensions du noyau, les **extensions système s'exécutent dans l'espace utilisateur** au lieu de l'espace du noyau, réduisant ainsi le risque de plantage du système en cas de dysfonctionnement de l'extension.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Il existe trois types d'extensions système : les extensions **DriverKit**, les extensions **Network** et les extensions **Endpoint Security**.

### **Extensions DriverKit**

DriverKit est un remplacement des extensions du noyau qui **fournit une prise en charge matérielle**. Il permet aux pilotes de périphériques (comme les pilotes USB, série, NIC et HID) de s'exécuter dans l'espace utilisateur plutôt que dans l'espace du noyau. Le framework DriverKit comprend des **versions pour l'espace utilisateur de certaines classes I/O Kit**, et le noyau transfère les événements I/O Kit normaux vers l'espace utilisateur, offrant ainsi un environnement plus sûr pour l'exécution de ces pilotes.

### **Extensions Network**

Les extensions réseau permettent de personnaliser les comportements réseau. Il existe plusieurs types d'extensions réseau :

* **Proxy d'application** : cela est utilisé pour créer un client VPN qui implémente un protocole VPN personnalisé orienté flux. Cela signifie qu'il gère le trafic réseau en fonction des connexions (ou flux) plutôt que des paquets individuels.
* **Tunnel de paquets** : cela est utilisé pour créer un client VPN qui implémente un protocole VPN personnalisé orienté paquet. Cela signifie qu'il gère le trafic réseau en fonction des paquets individuels.
* **Filtrage de données** : cela est utilisé pour filtrer les "flux" réseau. Il peut surveiller ou modifier les données réseau au niveau du flux.
* **Filtrage de paquets** : cela est utilisé pour filtrer les paquets réseau individuels. Il peut surveiller ou modifier les données réseau au niveau du paquet.
* **Proxy DNS** : cela est utilisé pour créer un fournisseur DNS personnalisé. Il peut être utilisé pour surveiller ou modifier les requêtes et réponses DNS.

## Cadre de sécurité de point de terminaison

Endpoint Security est un framework fourni par Apple dans macOS qui fournit un ensemble d'API pour la sécurité du système. Il est destiné à être utilisé par **les fournisseurs de sécurité et les développeurs pour construire des produits qui peuvent surveiller et contrôler l'activité du système** afin d'identifier et de se protéger contre les activités malveillantes.

Ce framework fournit une **collection d'API pour surveiller et contrôler l'activité du système**, telle que l'exécution des processus, les événements du système de fichiers, les événements réseau et du noyau.

Le cœur de ce framework est implémenté dans le noyau, en tant qu'extension du noyau (KEXT) située à **`/System/Library/Extensions/EndpointSecurity.kext`**. Cette KEXT est composée de plusieurs composants clés :

* **EndpointSecurityDriver** : il agit comme le "point d'entrée" de l'extension du noyau. C'est le principal point d'interaction entre le système d'exploitation et le framework Endpoint Security.
* **EndpointSecurityEventManager** : ce composant est responsable de la mise en œuvre des hooks du noyau. Les hooks du noyau permettent au framework de surveiller les événements du système en interceptant les appels système.
* **EndpointSecurityClientManager** : il gère la communication avec les clients de l'espace utilisateur, en suivant les clients connectés et qui ont besoin de recevoir des notifications d'événements.
* **EndpointSecurityMessageManager** : il envoie des messages et des notifications d'événements aux clients de l'espace utilisateur.

Les événements que le framework Endpoint Security peut surveiller sont catégorisés en :

* Événements de fichiers
* Événements de processus
* Événements de socket
* Événements du noyau (tels que le chargement/déchargement d'une extension du noyau ou l'ouverture d'un périphérique I/O Kit)

### Architecture du cadre de sécurité de point de terminaison

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

La **communication avec l'espace utilisateur** du framework Endpoint Security se fait via la classe IOUserClient. Deux sous-classes différentes sont utilisées, en fonction du type d'appelant :

* **EndpointSecurityDriverClient** : cela nécessite l'attribution `com.apple.private.endpoint-security.manager`, qui est détenue uniquement par le processus système `endpointsecurityd`.
* **EndpointSecurityExternalClient** : cela nécessite l'attribution `com.apple.developer.endpoint-security.client`. Cela serait généralement utilisé par des logiciels de sécurité tiers qui ont besoin d'interagir avec le framework Endpoint Security.

Les extensions de sécurité de point de terminaison : **`libEndpointSecurity.dylib`** est la bibliothèque C que les extensions système utilisent pour communiquer avec le noyau. Cette bibliothèque utilise I/O Kit (`IOKit`) pour communiquer avec l'extension Endpoint Security KEXT.

**`endpointsecurityd`** est un démon système clé impliqué dans la gestion et le lancement des extensions système de sécurité de point de terminaison, en particulier pendant le processus de démarrage initial. Seules les extensions système marquées avec **`NSEndpointSecurityEarlyBoot`** dans leur fichier `Info.plist` reçoivent ce traitement de démarrage initial.

Un autre démon système, **`sysextd`**, **valide les extensions système** et les déplace vers les emplacements système appropriés. Il demande ensuite au démon pertinent de charger l'extension. Le **`SystemExtensions.framework`** est responsable de l'activation et de la désactivation des extensions système.
## Contournement de l'ESF

L'ESF est utilisé par des outils de sécurité qui tentent de détecter un membre de l'équipe rouge, donc toute information sur la façon d'éviter cela est intéressante.

### CVE-2021-30965

Le problème est que l'application de sécurité doit avoir les **permissions d'accès complet au disque**. Donc, si un attaquant pouvait les supprimer, il pourrait empêcher le logiciel de s'exécuter :
```bash
tccutil reset All
```
Pour **plus d'informations** sur cette contournement et les contournements connexes, consultez la présentation [#OBTS v5.0 : "Le talon d'Achille de EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Finalement, cela a été résolu en donnant la nouvelle permission **`kTCCServiceEndpointSecurityClient`** à l'application de sécurité gérée par **`tccd`** afin que `tccutil` ne supprime pas ses autorisations, l'empêchant ainsi de s'exécuter.

## Références

* [**OBTS v3.0 : "Sécurité et insécurité des points de terminaison" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
