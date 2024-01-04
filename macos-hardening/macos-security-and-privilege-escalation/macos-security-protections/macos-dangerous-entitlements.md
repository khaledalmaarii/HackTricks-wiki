# Autorisations macOS Dangereuses & Permissions TCC

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
Notez que les autorisations commençant par **`com.apple`** ne sont pas disponibles pour les tiers, seul Apple peut les accorder.
{% endhint %}

## Haut

### `com.apple.rootless.install.heritable`

L'autorisation **`com.apple.rootless.install.heritable`** permet de **contourner SIP**. Consultez [ceci pour plus d'informations](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

L'autorisation **`com.apple.rootless.install`** permet de **contourner SIP**. Consultez [ceci pour plus d'informations](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (précédemment appelé `task_for_pid-allow`)**

Cette autorisation permet d'obtenir le **port de tâche pour n'importe quel** processus, sauf le noyau. Consultez [**ceci pour plus d'informations**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Cette autorisation permet à d'autres processus avec l'autorisation **`com.apple.security.cs.debugger`** d'obtenir le port de tâche du processus exécuté par le binaire avec cette autorisation et **d'injecter du code dedans**. Consultez [**ceci pour plus d'informations**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Les applications avec l'autorisation de l'outil de débogage peuvent appeler `task_for_pid()` pour récupérer un port de tâche valide pour les applications non signées et tierces avec l'autorisation `Get Task Allow` définie sur `true`. Cependant, même avec l'autorisation de l'outil de débogage, un débogueur **ne peut pas obtenir les ports de tâche** des processus qui **n'ont pas l'autorisation `Get Task Allow`**, et qui sont donc protégés par la Protection de l'Intégrité du Système. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Cette autorisation permet de **charger des frameworks, des plug-ins ou des bibliothèques sans être signés par Apple ou avec le même ID d'équipe** que l'exécutable principal, donc un attaquant pourrait abuser d'un chargement de bibliothèque arbitraire pour injecter du code. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Cette autorisation est très similaire à **`com.apple.security.cs.disable-library-validation`** mais **au lieu de** **désactiver directement** la validation de la bibliothèque, elle permet au processus d'**appeler un appel système `csops` pour la désactiver**.\
Consultez [**ceci pour plus d'informations**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Cette autorisation permet d'**utiliser les variables d'environnement DYLD** qui pourraient être utilisées pour injecter des bibliothèques et du code. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**Selon ce blog**](https://objective-see.org/blog/blog\_0x4C.html) **et** [**ce blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ces autorisations permettent de **modifier** la base de données **TCC**.

### **`system.install.apple-software`** et **`system.install.apple-software.standar-user`**

Ces autorisations permettent d'**installer des logiciels sans demander la permission** à l'utilisateur, ce qui peut être utile pour une **escalade de privilèges**.

### `com.apple.private.security.kext-management`

Autorisation nécessaire pour demander au **noyau de charger une extension de noyau**.

### **`com.apple.private.icloud-account-access`**

Avec l'autorisation **`com.apple.private.icloud-account-access`**, il est possible de communiquer avec le service XPC **`com.apple.iCloudHelper`** qui fournira **des jetons iCloud**.

**iMovie** et **Garageband** avaient cette autorisation.

Pour plus **d'informations** sur l'exploitation pour **obtenir des jetons iCloud** à partir de cette autorisation, consultez la conférence : [**#OBTS v5.0 : "Ce qui se passe sur votre Mac, reste sur l'iCloud d'Apple ?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO : Je ne sais pas ce que cela permet de faire

### `com.apple.private.apfs.revert-to-snapshot`

TODO : Dans [**ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **il est mentionné que cela pourrait être utilisé pour** mettre à jour le contenu protégé par SSV après un redémarrage. Si vous savez comment faire, envoyez une PR s'il vous plaît !

### `com.apple.private.apfs.create-sealed-snapshot`

TODO : Dans [**ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **il est mentionné que cela pourrait être utilisé pour** mettre à jour le contenu protégé par SSV après un redémarrage. Si vous savez comment faire, envoyez une PR s'il vous plaît !

### `keychain-access-groups`

Cette autorisation liste les groupes de **trousseaux** auxquels l'application a accès :
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

Donne les permissions d'**Accès complet au disque**, l'une des plus hautes permissions TCC que vous pouvez avoir.

### **`kTCCServiceAppleEvents`**

Permet à l'application d'envoyer des événements à d'autres applications qui sont couramment utilisées pour **automatiser des tâches**. En contrôlant d'autres applications, elle peut abuser des permissions accordées à ces autres applications.

Comme les faire demander le mot de passe de l'utilisateur :

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Ou les amener à effectuer des **actions arbitraires**.

### **`kTCCServiceEndpointSecurityClient`**

Permet, entre autres permissions, d'**écrire dans la base de données TCC de l'utilisateur**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permet de **modifier** l'attribut **`NFSHomeDirectory`** d'un utilisateur, ce qui change le chemin de son dossier personnel et permet donc de **contourner TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permet de modifier des fichiers à l'intérieur du paquet d'applications (dans app.app), ce qui est **interdit par défaut**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Il est possible de vérifier qui a cet accès dans _Préférences Système_ > _Confidentialité & Sécurité_ > _Gestion des applications._

### `kTCCServiceAccessibility`

Le processus pourra **abuser des fonctionnalités d'accessibilité de macOS**, ce qui signifie qu'il pourra par exemple appuyer sur des touches. Il pourrait donc demander l'accès pour contrôler une application comme Finder et approuver la boîte de dialogue avec cette permission.

## Moyen

### `com.apple.security.cs.allow-jit`

Cette autorisation permet de **créer de la mémoire qui est inscriptible et exécutable** en passant le drapeau `MAP_JIT` à la fonction système `mmap()`. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Cette autorisation permet de **remplacer ou patcher du code C**, utiliser l'ancienne et dépréciée **`NSCreateObjectFileImageFromMemory`** (qui est fondamentalement non sécurisée), ou utiliser le framework **DVDPlayback**. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

{% hint style="danger" %}
Inclure cette autorisation expose votre application aux vulnérabilités communes dans les langages de code non sécurisés en mémoire. Considérez soigneusement si votre application a besoin de cette exception.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Cette autorisation permet de **modifier des sections de ses propres fichiers exécutables** sur disque pour forcer la sortie. Consultez [**ceci pour plus d'informations**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

{% hint style="danger" %}
L'autorisation de désactivation de la protection des pages exécutables est une autorisation extrême qui supprime une protection de sécurité fondamentale de votre application, permettant à un attaquant de réécrire le code exécutable de votre application sans détection. Préférez des autorisations plus restreintes si possible.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Cette autorisation permet de monter un système de fichiers nullfs (interdit par défaut). Outil : [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Selon ce billet de blog, cette permission TCC se trouve généralement sous la forme :
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permettre au processus de **demander toutes les permissions TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> !</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
