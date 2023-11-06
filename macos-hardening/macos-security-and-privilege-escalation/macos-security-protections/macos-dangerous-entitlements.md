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

### `com.apple.rootless.install.heritable`

L'autorisation **`com.apple.rootless.install.heritable`** permet de contourner SIP. Consultez [ce lien pour plus d'informations](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

L'autorisation **`com.apple.rootless.install`** permet de contourner SIP. Consultez [ce lien pour plus d'informations](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (anciennement appelé `task_for_pid-allow`)**

Cette autorisation permet d'obtenir le **port de tâche pour n'importe quel** processus, à l'exception du noyau. Consultez [**ce lien pour plus d'informations**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Cette autorisation permet à d'autres processus disposant de l'autorisation **`com.apple.security.cs.debugger`** d'obtenir le port de tâche du processus exécuté par le binaire avec cette autorisation et d'**injecter du code**. Consultez [**ce lien pour plus d'informations**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Les applications avec l'autorisation Debugging Tool peuvent appeler `task_for_pid()` pour récupérer un port de tâche valide pour les applications non signées et tierces avec l'autorisation `Get Task Allow` définie sur `true`. Cependant, même avec l'autorisation de l'outil de débogage, un débogueur **ne peut pas obtenir les ports de tâche** des processus qui **n'ont pas l'autorisation `Get Task Allow`**, et qui sont donc protégés par la Protection de l'intégrité du système. Consultez [**ce lien pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Cette autorisation permet de **charger des frameworks, des plug-ins ou des bibliothèques sans qu'ils soient signés par Apple ou signés avec le même ID d'équipe** que l'exécutable principal, de sorte qu'un attaquant pourrait abuser d'un chargement de bibliothèque arbitraire pour injecter du code. Consultez [**ce lien pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Cette autorisation est très similaire à **`com.apple.security.cs.disable-library-validation`** mais **au lieu de désactiver directement** la validation de la bibliothèque, elle permet au processus d'appeler un appel système `csops` pour la désactiver.\
Consultez [**ce lien pour plus d'informations**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Cette autorisation permet d'**utiliser des variables d'environnement DYLD** qui pourraient être utilisées pour injecter des bibliothèques et du code. Consultez [**ce lien pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` et `com.apple.rootless.storage`.`TCC`

[**Selon ce blog**](https://objective-see.org/blog/blog\_0x4C.html), ces autorisations permettent de **modifier** la base de données **TCC**.

### **`system.install.apple-software`** et **`system.install.apple-software.standar-user`**

Ces autorisations permettent d'**installer des logiciels sans demander la permission** de l'utilisateur, ce qui peut être utile pour une **escalade de privilèges**.

### `com.apple.private.security.kext-management`

Autorisation nécessaire pour demander au **noyau de charger une extension de noyau**.

### **`com.apple.private.icloud-account-access`**

L'autorisation **`com.apple.private.icloud-account-access`** permet de communiquer avec le service XPC **`com.apple.iCloudHelper`** qui fournira des jetons iCloud.

**iMovie** et **Garageband** avaient cette autorisation.

Pour plus d'**informations** sur l'exploitation pour **obtenir des jetons iCloud** à partir de cette autorisation, consultez la présentation : [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)
### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Je ne sais pas ce que cela permet de faire.

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Dans [**ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), il est mentionné que cela pourrait être utilisé pour mettre à jour les contenus protégés par SSV après un redémarrage. Si vous savez comment le faire, veuillez envoyer une demande de pull (PR) s'il vous plaît !

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Dans [**ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), il est mentionné que cela pourrait être utilisé pour mettre à jour les contenus protégés par SSV après un redémarrage. Si vous savez comment le faire, veuillez envoyer une demande de pull (PR) s'il vous plaît !

### `keychain-access-groups`

Cette liste d'autorisations **keychain** répertorie les groupes auxquels l'application a accès :
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Donne les permissions d'accès complet au disque, l'une des permissions les plus élevées de TCC que vous pouvez avoir.

### **`kTCCServiceAppleEvents`**

Permet à l'application d'envoyer des événements à d'autres applications couramment utilisées pour automatiser des tâches. En contrôlant d'autres applications, elle peut abuser des permissions accordées à ces autres applications.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permet de modifier l'attribut **`NFSHomeDirectory`** d'un utilisateur qui modifie son dossier personnel et permet donc de contourner TCC.

### **`kTCCServiceSystemPolicyAppBundles`**

Permet de modifier les fichiers à l'intérieur des bundles d'applications (à l'intérieur de app.app), ce qui est désactivé par défaut.

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

## Moyen

### `com.apple.security.cs.allow-jit`

Cet avantage permet de créer de la mémoire qui est inscriptible et exécutable en passant le drapeau `MAP_JIT` à la fonction système `mmap()`. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Cet avantage permet de remplacer ou de patcher du code C, d'utiliser la fonction **`NSCreateObjectFileImageFromMemory`** (qui est fondamentalement non sécurisée), ou d'utiliser le framework **DVDPlayback**. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
L'inclusion de cet avantage expose votre application à des vulnérabilités courantes dans les langages de code non sécurisés en mémoire. Réfléchissez attentivement à la nécessité de cette exception pour votre application.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Cet avantage permet de modifier des sections de ses propres fichiers exécutables sur le disque pour forcer la sortie. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
L'avantage de désactivation de la protection de la mémoire exécutable est un avantage extrême qui supprime une protection de sécurité fondamentale de votre application, permettant à un attaquant de réécrire le code exécutable de votre application sans détection. Privilégiez des avantages plus restreints si possible.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `kTCCServiceAll`

Selon cet article de blog, cette permission TCC est généralement trouvée sous la forme :
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Autorisez le processus à **demander toutes les autorisations TCC**.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
