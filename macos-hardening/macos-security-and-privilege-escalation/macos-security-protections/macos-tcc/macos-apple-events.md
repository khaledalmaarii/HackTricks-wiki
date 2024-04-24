# macOS Événements Apple

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Informations de base

Les **Événements Apple** sont une fonctionnalité de macOS d'Apple qui permet aux applications de communiquer entre elles. Ils font partie du **Gestionnaire d'événements Apple**, qui est un composant du système d'exploitation macOS chargé de gérer la communication interprocessus. Ce système permet à une application d'envoyer un message à une autre application pour demander qu'elle effectue une opération particulière, comme ouvrir un fichier, récupérer des données ou exécuter une commande.

Le démon mina est `/System/Library/CoreServices/appleeventsd` qui enregistre le service `com.apple.coreservices.appleevents`.

Chaque application pouvant recevoir des événements vérifiera avec ce démon en fournissant son port Mach d'événements Apple. Et lorsque qu'une application souhaite envoyer un événement à une autre, l'application demandera ce port au démon.

Les applications sandboxées nécessitent des privilèges tels que `allow appleevent-send` et `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` afin de pouvoir envoyer des événements. Notez que des autorisations telles que `com.apple.security.temporary-exception.apple-events` pourraient restreindre l'accès à l'envoi d'événements, nécessitant des autorisations telles que `com.apple.private.appleevents`.

{% hint style="success" %}
Il est possible d'utiliser la variable d'environnement **`AEDebugSends`** pour enregistrer des informations sur le message envoyé :
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge HackTricks AWS)</strong></a><strong>!</strong></summary>

D'autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
