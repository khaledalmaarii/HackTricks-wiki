# macOS Autorisations dangereuses et permissions TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
Notez que les autorisations commençant par **`com.apple`** ne sont pas disponibles pour les tiers, seuls Apple peut les accorder.
{% endhint %}

## Élevé

### `com.apple.security.get-task-allow`

Cette autorisation permet d'obtenir le port de tâche du processus exécuté par le binaire avec cette autorisation et de **injecter du code** dedans. Consultez [**ceci pour plus d'informations**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### **`com.apple.system-task-ports` (anciennement appelé `task_for_pid-allow`)**

Cette autorisation permet d'obtenir le **port de tâche pour n'importe quel** processus, à l'exception du noyau. Consultez [**ceci pour plus d'informations**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Les applications avec l'autorisation d'outil de débogage peuvent appeler `task_for_pid()` pour récupérer un port de tâche valide pour les applications non signées et tierces avec l'autorisation `Get Task Allow` définie sur `true`. Cependant, même avec l'autorisation d'outil de débogage, un débogueur ne peut pas obtenir les ports de tâche des processus qui n'ont pas l'autorisation `Get Task Allow` et qui sont donc protégés par la Protection de l'intégrité du système. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Cette autorisation permet de **charger des frameworks, des plug-ins ou des bibliothèques sans qu'ils soient signés par Apple ou signés avec le même ID d'équipe** que l'exécutable principal, de sorte qu'un attaquant puisse abuser d'un chargement de bibliothèque arbitraire pour injecter du code. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.security.cs.allow-dyld-environment-variables`

Cette autorisation permet d'**utiliser des variables d'environnement DYLD** qui pourraient être utilisées pour injecter des bibliothèques et du code. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### **`kTCCServiceSystemPolicyAllFiles`**

Accorde des autorisations d'**accès complet au disque**, l'une des autorisations les plus élevées de TCC.

### **`kTCCServiceAppleEvents`**

Permet à l'application d'envoyer des événements à d'autres applications couramment utilisées pour **automatiser des tâches**. En contrôlant d'autres applications, elle peut abuser des autorisations accordées à ces autres applications.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permet de **modifier** l'attribut **`NFSHomeDirectory`** d'un utilisateur qui modifie son dossier personnel et permet donc de **contourner TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permet de modifier les applications à l'intérieur de leurs dossiers (à l'intérieur de app.app), ce qui est interdit par défaut.

## Moyen

### `com.apple.security.cs.allow-jit`

Cette autorisation permet de **créer de la mémoire qui est inscriptible et exécutable** en passant le drapeau `MAP_JIT` à la fonction système `mmap()`. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Cette autorisation permet de **remplacer ou de patcher du code C**, d'utiliser la fonction **`NSCreateObjectFileImageFromMemory`** (qui est fondamentalement non sécurisée) ou d'utiliser le framework **DVDPlayback**. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Inclure cette autorisation expose votre application à des vulnérabilités courantes dans les langages de code non sécurisés en mémoire. Réfléchissez attentivement à la nécessité de cette exception pour votre application.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Cette autorisation permet de **modifier des sections de ses propres fichiers exécutables** sur le disque pour une sortie forcée. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
L'autorisation de désactivation de la protection de la mémoire exécutable est une autorisation extrême qui supprime une protection de sécurité fondamentale de votre application, permettant à un attaquant de réécrire le code exécutable de votre application sans détection. Privilégiez des autorisations plus restreintes si possible.
{% endhint %}
### `com.apple.security.cs.allow-relative-library-loads`

TODO

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
