# macOS Dangerous Entitlements & TCC perms

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% hint style="warning" %}
Notez que les droits commençant par **`com.apple`** ne sont pas disponibles pour les tiers, seul Apple peut les accorder.
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

Le droit **`com.apple.rootless.install.heritable`** permet de **contourner SIP**. Consultez [cela pour plus d'infos](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Le droit **`com.apple.rootless.install`** permet de **contourner SIP**. Consultez [cela pour plus d'infos](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (précédemment appelé `task_for_pid-allow`)**

Ce droit permet d'obtenir le **port de tâche pour n'importe quel** processus, sauf le noyau. Consultez [**cela pour plus d'infos**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Ce droit permet à d'autres processus avec le droit **`com.apple.security.cs.debugger`** d'obtenir le port de tâche du processus exécuté par le binaire avec ce droit et **d'injecter du code dessus**. Consultez [**cela pour plus d'infos**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Les applications avec le droit d'outil de débogage peuvent appeler `task_for_pid()` pour récupérer un port de tâche valide pour les applications non signées et tierces avec le droit `Get Task Allow` défini sur `true`. Cependant, même avec le droit d'outil de débogage, un débogueur **ne peut pas obtenir les ports de tâche** des processus qui **n'ont pas le droit `Get Task Allow`**, et qui sont donc protégés par la Protection de l'Intégrité du Système. Consultez [**cela pour plus d'infos**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Ce droit permet de **charger des frameworks, des plug-ins ou des bibliothèques sans être signés par Apple ou signés avec le même ID d'équipe** que l'exécutable principal, donc un attaquant pourrait abuser de certains chargements de bibliothèques arbitraires pour injecter du code. Consultez [**cela pour plus d'infos**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Ce droit est très similaire à **`com.apple.security.cs.disable-library-validation`** mais **au lieu** de **désactiver directement** la validation des bibliothèques, il permet au processus de **faire un appel système `csops` pour la désactiver**.\
Consultez [**cela pour plus d'infos**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Ce droit permet d'**utiliser des variables d'environnement DYLD** qui pourraient être utilisées pour injecter des bibliothèques et du code. Consultez [**cela pour plus d'infos**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**Selon ce blog**](https://objective-see.org/blog/blog\_0x4C.html) **et** [**ce blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ces droits permettent de **modifier** la base de données **TCC**.

### **`system.install.apple-software`** et **`system.install.apple-software.standar-user`**

Ces droits permettent d'**installer des logiciels sans demander de permissions** à l'utilisateur, ce qui peut être utile pour une **élévation de privilèges**.

### `com.apple.private.security.kext-management`

Droit nécessaire pour demander au **noyau de charger une extension de noyau**.

### **`com.apple.private.icloud-account-access`**

Le droit **`com.apple.private.icloud-account-access`** permet de communiquer avec le service XPC **`com.apple.iCloudHelper`** qui fournira des **tokens iCloud**.

**iMovie** et **Garageband** avaient ce droit.

Pour plus **d'informations** sur l'exploit pour **obtenir des tokens icloud** à partir de ce droit, consultez la présentation : [**#OBTS v5.0 : "Que se passe-t-il sur votre Mac, reste sur l'iCloud d'Apple ?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO : Je ne sais pas ce que cela permet de faire

### `com.apple.private.apfs.revert-to-snapshot`

TODO : Dans [**ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **il est mentionné que cela pourrait être utilisé pour** mettre à jour les contenus protégés par SSV après un redémarrage. Si vous savez comment, envoyez un PR s'il vous plaît !

### `com.apple.private.apfs.create-sealed-snapshot`

TODO : Dans [**ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **il est mentionné que cela pourrait être utilisé pour** mettre à jour les contenus protégés par SSV après un redémarrage. Si vous savez comment, envoyez un PR s'il vous plaît !

### `keychain-access-groups`

Ce droit liste les groupes **keychain** auxquels l'application a accès :
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

Accorde des permissions **d'accès complet au disque**, l'une des permissions les plus élevées de TCC que vous pouvez avoir.

### **`kTCCServiceAppleEvents`**

Permet à l'application d'envoyer des événements à d'autres applications couramment utilisées pour **l'automatisation des tâches**. En contrôlant d'autres applications, elle peut abuser des permissions accordées à ces autres applications.

Comme les faire demander à l'utilisateur son mot de passe :

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Ou les amener à effectuer des **actions arbitraires**.

### **`kTCCServiceEndpointSecurityClient`**

Permet, entre autres permissions, de **modifier la base de données TCC des utilisateurs**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permet de **changer** l'attribut **`NFSHomeDirectory`** d'un utilisateur, ce qui modifie le chemin de son dossier personnel et permet donc de **contourner TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permet de modifier des fichiers à l'intérieur des bundles d'applications (à l'intérieur de app.app), ce qui est **interdit par défaut**.

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Il est possible de vérifier qui a cet accès dans _Paramètres Système_ > _Confidentialité et Sécurité_ > _Gestion des Applications._

### `kTCCServiceAccessibility`

Le processus pourra **abuser des fonctionnalités d'accessibilité de macOS**, ce qui signifie que, par exemple, il pourra appuyer sur des touches. Il pourrait donc demander l'accès pour contrôler une application comme Finder et approuver la boîte de dialogue avec cette permission.

## Moyen

### `com.apple.security.cs.allow-jit`

Cette autorisation permet de **créer de la mémoire qui est écrivable et exécutable** en passant le drapeau `MAP_JIT` à la fonction système `mmap()`. Consultez [**ceci pour plus d'infos**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Cette autorisation permet de **remplacer ou de patcher du code C**, d'utiliser le **`NSCreateObjectFileImageFromMemory`** longtemps obsolète (qui est fondamentalement peu sûr), ou d'utiliser le framework **DVDPlayback**. Consultez [**ceci pour plus d'infos**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Inclure cette autorisation expose votre application à des vulnérabilités courantes dans les langages de code non sûrs en mémoire. Considérez soigneusement si votre application a besoin de cette exception.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Cette autorisation permet de **modifier des sections de ses propres fichiers exécutables** sur le disque pour forcer la sortie. Consultez [**ceci pour plus d'infos**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
L'autorisation de désactiver la protection de la mémoire exécutable est une autorisation extrême qui supprime une protection de sécurité fondamentale de votre application, rendant possible pour un attaquant de réécrire le code exécutable de votre application sans détection. Préférez des autorisations plus étroites si possible.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Cette autorisation permet de monter un système de fichiers nullfs (interdit par défaut). Outil : [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Selon ce billet de blog, cette permission TCC se trouve généralement sous la forme :
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Autoriser le processus à **demander toutes les autorisations TCC**.

### **`kTCCServicePostEvent`**
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
</details>
