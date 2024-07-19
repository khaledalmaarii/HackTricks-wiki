# Bypasses du Sandbox Office de macOS

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

### Bypass du Sandbox Word via les Agents de Lancement

L'application utilise un **Sandbox personnalisé** avec le droit **`com.apple.security.temporary-exception.sbpl`** et ce sandbox personnalisé permet d'écrire des fichiers n'importe où tant que le nom de fichier commence par `~$` : `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Par conséquent, l'évasion était aussi simple que **d'écrire un `plist`** LaunchAgent dans `~/Library/LaunchAgents/~$escape.plist`.

Consultez le [**rapport original ici**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Bypass du Sandbox Word via les Éléments de Connexion et zip

Rappelez-vous qu'à partir de la première évasion, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`, bien qu'après le correctif de la vulnérabilité précédente, il n'était plus possible d'écrire dans `/Library/Application Scripts` ou dans `/Library/LaunchAgents`.

Il a été découvert que depuis le sandbox, il est possible de créer un **Élément de Connexion** (applications qui seront exécutées lorsque l'utilisateur se connecte). Cependant, ces applications **ne s'exécuteront pas à moins** qu'elles ne soient **notariées** et il est **impossible d'ajouter des arguments** (vous ne pouvez donc pas simplement exécuter un shell inversé en utilisant **`bash`**).

À partir du précédent contournement du Sandbox, Microsoft a désactivé l'option d'écrire des fichiers dans `~/Library/LaunchAgents`. Cependant, il a été découvert que si vous mettez un **fichier zip comme Élément de Connexion**, l'`Archive Utility` va simplement **dézipper** à son emplacement actuel. Donc, parce que par défaut le dossier `LaunchAgents` de `~/Library` n'est pas créé, il était possible de **zipper un plist dans `LaunchAgents/~$escape.plist`** et **placer** le fichier zip dans **`~/Library`** afin que lors de la décompression, il atteigne la destination de persistance.

Consultez le [**rapport original ici**](https://objective-see.org/blog/blog\_0x4B.html).

### Bypass du Sandbox Word via les Éléments de Connexion et .zshenv

(Rappelez-vous qu'à partir de la première évasion, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`).

Cependant, la technique précédente avait une limitation, si le dossier **`~/Library/LaunchAgents`** existe parce qu'un autre logiciel l'a créé, cela échouerait. Donc, une chaîne d'Éléments de Connexion différente a été découverte pour cela.

Un attaquant pourrait créer les fichiers **`.bash_profile`** et **`.zshenv`** avec le payload à exécuter, puis les zipper et **écrire le zip dans le dossier de l'utilisateur de la victime** : **`~/~$escape.zip`**.

Ensuite, ajoutez le fichier zip aux **Éléments de Connexion** et ensuite à l'application **`Terminal`**. Lorsque l'utilisateur se reconnecte, le fichier zip serait décompressé dans le dossier de l'utilisateur, écrasant **`.bash_profile`** et **`.zshenv`** et donc, le terminal exécutera l'un de ces fichiers (selon que bash ou zsh est utilisé).

Consultez le [**rapport original ici**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Bypass du Sandbox Word avec Open et variables d'environnement

À partir des processus sandboxés, il est toujours possible d'invoquer d'autres processus en utilisant l'utilitaire **`open`**. De plus, ces processus s'exécuteront **dans leur propre sandbox**.

Il a été découvert que l'utilitaire open a l'option **`--env`** pour exécuter une application avec des **variables d'environnement spécifiques**. Par conséquent, il était possible de créer le **fichier `.zshenv`** dans un dossier **à l'intérieur** du **sandbox** et d'utiliser `open` avec `--env` en définissant la **variable `HOME`** sur ce dossier en ouvrant cette application `Terminal`, qui exécutera le fichier `.zshenv` (pour une raison quelconque, il était également nécessaire de définir la variable `__OSINSTALL_ENVIROMENT`).

Consultez le [**rapport original ici**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Bypass du Sandbox Word avec Open et stdin

L'utilitaire **`open`** supportait également le paramètre **`--stdin`** (et après le contournement précédent, il n'était plus possible d'utiliser `--env`).

Le fait est que même si **`python`** était signé par Apple, il **n'exécutera pas** un script avec l'attribut **`quarantine`**. Cependant, il était possible de lui passer un script depuis stdin afin qu'il ne vérifie pas s'il était mis en quarantaine ou non :&#x20;

1. Déposez un fichier **`~$exploit.py`** avec des commandes Python arbitraires.
2. Exécutez _open_ **`–stdin='~$exploit.py' -a Python`**, ce qui exécute l'application Python avec notre fichier déposé servant d'entrée standard. Python exécute joyeusement notre code, et comme c'est un processus enfant de _launchd_, il n'est pas soumis aux règles du sandbox de Word.

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
