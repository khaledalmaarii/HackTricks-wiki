# macOS Kernel Extensions

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

## Basic Information

Les extensions de noyau (Kexts) sont des **paquets** avec une extension **`.kext`** qui sont **chargés directement dans l'espace noyau de macOS**, fournissant des fonctionnalités supplémentaires au système d'exploitation principal.

### Requirements

Évidemment, c'est si puissant qu'il est **compliqué de charger une extension de noyau**. Voici les **exigences** qu'une extension de noyau doit respecter pour être chargée :

* Lors de **l'entrée en mode de récupération**, les **extensions de noyau doivent être autorisées** à être chargées :

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* L'extension de noyau doit être **signée avec un certificat de signature de code de noyau**, qui ne peut être **accordé que par Apple**. Qui examinera en détail l'entreprise et les raisons pour lesquelles cela est nécessaire.
* L'extension de noyau doit également être **notariée**, Apple pourra la vérifier pour détecter des logiciels malveillants.
* Ensuite, l'utilisateur **root** est celui qui peut **charger l'extension de noyau** et les fichiers à l'intérieur du paquet doivent **appartenir à root**.
* Pendant le processus de chargement, le paquet doit être préparé dans un **emplacement protégé non-root** : `/Library/StagedExtensions` (nécessite l'octroi de `com.apple.rootless.storage.KernelExtensionManagement`).
* Enfin, lors de la tentative de chargement, l'utilisateur recevra une [**demande de confirmation**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) et, si acceptée, l'ordinateur doit être **redémarré** pour le charger.

### Loading process

Dans Catalina, c'était comme ça : Il est intéressant de noter que le processus de **vérification** se produit dans **l'espace utilisateur**. Cependant, seules les applications avec l'octroi **`com.apple.private.security.kext-management`** peuvent **demander au noyau de charger une extension** : `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **démarre** le processus de **vérification** pour charger une extension
* Il communiquera avec **`kextd`** en utilisant un **service Mach**.
2. **`kextd`** vérifiera plusieurs choses, telles que la **signature**
* Il communiquera avec **`syspolicyd`** pour **vérifier** si l'extension peut être **chargée**.
3. **`syspolicyd`** **demander** à l'**utilisateur** si l'extension n'a pas été chargée précédemment.
* **`syspolicyd`** rapportera le résultat à **`kextd`**
4. **`kextd`** pourra enfin **dire au noyau de charger** l'extension

Si **`kextd`** n'est pas disponible, **`kextutil`** peut effectuer les mêmes vérifications.

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
