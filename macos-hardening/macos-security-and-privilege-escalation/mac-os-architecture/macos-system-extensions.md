# Extensions Système macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs exclusifs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Extensions Système / Cadre de Sécurité des Points de Terminaison

Contrairement aux Extensions du Noyau, les **Extensions Système s'exécutent dans l'espace utilisateur** au lieu de l'espace noyau, réduisant le risque de crash du système dû à un dysfonctionnement de l'extension.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Il existe trois types d'extensions système : les Extensions **DriverKit**, les Extensions **Réseau**, et les Extensions de **Sécurité des Points de Terminaison**.

### **Extensions DriverKit**

DriverKit est un remplacement pour les extensions du noyau qui **fournissent un support matériel**. Il permet aux pilotes de périphériques (comme les pilotes USB, Série, NIC et HID) de s'exécuter dans l'espace utilisateur plutôt que dans l'espace noyau. Le cadre DriverKit comprend des **versions en espace utilisateur de certaines classes I/O Kit**, et le noyau transmet les événements I/O Kit normaux à l'espace utilisateur, offrant un environnement plus sûr pour l'exécution de ces pilotes.

### **Extensions Réseau**

Les Extensions Réseau offrent la possibilité de personnaliser les comportements réseau. Il existe plusieurs types d'Extensions Réseau :

* **App Proxy** : Utilisé pour créer un client VPN qui implémente un protocole VPN personnalisé orienté flux. Cela signifie qu'il gère le trafic réseau basé sur les connexions (ou flux) plutôt que sur les paquets individuels.
* **Packet Tunnel** : Utilisé pour créer un client VPN qui implémente un protocole VPN personnalisé orienté paquet. Cela signifie qu'il gère le trafic réseau basé sur les paquets individuels.
* **Filter Data** : Utilisé pour filtrer les "flux" réseau. Il peut surveiller ou modifier les données réseau au niveau du flux.
* **Filter Packet** : Utilisé pour filtrer les paquets réseau individuels. Il peut surveiller ou modifier les données réseau au niveau du paquet.
* **DNS Proxy** : Utilisé pour créer un fournisseur DNS personnalisé. Il peut être utilisé pour surveiller ou modifier les requêtes et réponses DNS.

## Cadre de Sécurité des Points de Terminaison

La Sécurité des Points de Terminaison est un cadre fourni par Apple dans macOS qui offre un ensemble d'API pour la sécurité du système. Il est destiné à être utilisé par les **fournisseurs de sécurité et les développeurs pour créer des produits capables de surveiller et de contrôler l'activité du système** afin d'identifier et de protéger contre les activités malveillantes.

Ce cadre fournit une **collection d'API pour surveiller et contrôler l'activité du système**, telles que les exécutions de processus, les événements du système de fichiers, les événements réseau et noyau.

Le cœur de ce cadre est implémenté dans le noyau, sous forme d'une Extension du Noyau (KEXT) située à **`/System/Library/Extensions/EndpointSecurity.kext`**. Cette KEXT est composée de plusieurs composants clés :

* **EndpointSecurityDriver** : Agit comme le "point d'entrée" pour l'extension du noyau. C'est le principal point d'interaction entre le système d'exploitation et le cadre de Sécurité des Points de Terminaison.
* **EndpointSecurityEventManager** : Ce composant est responsable de la mise en œuvre des crochets du noyau. Les crochets du noyau permettent au cadre de surveiller les événements du système en interceptant les appels système.
* **EndpointSecurityClientManager** : Gère la communication avec les clients en espace utilisateur, en gardant une trace des clients connectés et devant recevoir des notifications d'événements.
* **EndpointSecurityMessageManager** : Envoie des messages et des notifications d'événements aux clients en espace utilisateur.

Les événements que le cadre de Sécurité des Points de Terminaison peut surveiller sont catégorisés en :

* Événements de fichiers
* Événements de processus
* Événements de socket
* Événements du noyau (tels que le chargement/déchargement d'une extension du noyau ou l'ouverture d'un périphérique I/O Kit)

### Architecture du Cadre de Sécurité des Points de Terminaison

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt=""><figcaption></figcaption></figure>

La **communication en espace utilisateur** avec le cadre de Sécurité des Points de Terminaison se fait via la classe IOUserClient. Deux sous-classes différentes sont utilisées, selon le type d'appelant :

* **EndpointSecurityDriverClient** : Nécessite l'entitlement `com.apple.private.endpoint-security.manager`, qui est uniquement détenu par le processus système `endpointsecurityd`.
* **EndpointSecurityExternalClient** : Nécessite l'entitlement `com.apple.developer.endpoint-security.client`. Cela serait typiquement utilisé par des logiciels de sécurité tiers qui ont besoin d'interagir avec le cadre de Sécurité des Points de Terminaison.

Les Extensions de Sécurité des Points de Terminaison : **`libEndpointSecurity.dylib`** est la bibliothèque C que les extensions système utilisent pour communiquer avec le noyau. Cette bibliothèque utilise l'I/O Kit (`IOKit`) pour communiquer avec la KEXT de Sécurité des Points de Terminaison.

**`endpointsecurityd`** est un daemon système clé impliqué dans la gestion et le lancement des extensions système de sécurité des points de terminaison, en particulier pendant le processus de démarrage précoce. **Seules les extensions système** marquées avec **`NSEndpointSecurityEarlyBoot`** dans leur fichier `Info.plist` reçoivent ce traitement de démarrage précoce.

Un autre daemon système, **`sysextd`**, **valide les extensions système** et les déplace dans les emplacements système appropriés. Il demande ensuite au daemon concerné de charger l'extension. Le **`SystemExtensions.framework`** est responsable de l'activation et de la désactivation des extensions système.

## Contournement de l'ESF

L'ESF est utilisé par des outils de sécurité qui essaieront de détecter un membre de l'équipe rouge, donc toute information sur la façon dont cela pourrait être évité semble intéressante.

### CVE-2021-30965

Le fait est que l'application de sécurité doit avoir des permissions **Full Disk Access**. Donc si un attaquant pouvait supprimer cela, il pourrait empêcher le logiciel de fonctionner :
```bash
tccutil reset All
```
Pour **plus d'informations** sur ce contournement et d'autres similaires, consultez la conférence [#OBTS v5.0 : "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Finalement, cela a été corrigé en accordant la nouvelle permission **`kTCCServiceEndpointSecurityClient`** à l'application de sécurité gérée par **`tccd`**, ainsi `tccutil` ne réinitialisera pas ses permissions, ce qui empêcherait son exécution.

## Références

* [**OBTS v3.0 : "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
