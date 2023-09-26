# Contournement de la sandbox macOS Office

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Contournement de la sandbox Word via les Launch Agents

L'application utilise une **sandbox personnalisée** en utilisant l'autorisation **`com.apple.security.temporary-exception.sbpl`** et cette sandbox personnalisée permet d'écrire des fichiers n'importe où tant que le nom de fichier commence par `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Par conséquent, l'évasion était aussi simple que **d'écrire un fichier `plist`** LaunchAgent dans `~/Library/LaunchAgents/~$escape.plist`.

Consultez le [**rapport original ici**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Contournement de la sandbox Word via les Login Items et zip

(Rappelez-vous que depuis la première évasion, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`, bien qu'après le correctif de la vulnérabilité précédente, il n'était plus possible d'écrire dans `/Library/Application Scripts` ou dans `/Library/LaunchAgents`).

Il a été découvert qu'à partir de la sandbox, il est possible de créer un **élément de connexion** (des applications qui s'exécutent lorsque l'utilisateur se connecte). Cependant, ces applications **ne s'exécuteront pas** à moins qu'elles ne soient **notarisées** et il n'est **pas possible d'ajouter des arguments** (vous ne pouvez donc pas simplement exécuter un shell inversé en utilisant **`bash`**).

À partir de la précédente évasion de la sandbox, Microsoft a désactivé l'option d'écriture de fichiers dans `~/Library/LaunchAgents`. Cependant, il a été découvert que si vous mettez un **fichier zip en tant qu'élément de connexion**, l'`Archive Utility` le décompressera simplement à son emplacement actuel. Ainsi, comme par défaut le dossier `LaunchAgents` de `~/Library` n'est pas créé, il était possible de **compresser un fichier plist dans `LaunchAgents/~$escape.plist`** et de placer le fichier zip dans **`~/Library`** afin que lorsqu'il est décompressé, il atteigne la destination de persistance.

Consultez le [**rapport original ici**](https://objective-see.org/blog/blog\_0x4B.html).

### Contournement de la sandbox Word via les Login Items et .zshenv

(Rappelez-vous que depuis la première évasion, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`).

Cependant, la technique précédente avait une limitation : si le dossier **`~/Library/LaunchAgents`** existe parce qu'un autre logiciel l'a créé, cela échouerait. Une autre chaîne d'éléments de connexion a donc été découverte pour cela.

Un attaquant pourrait créer les fichiers **`.bash_profile`** et **`.zshenv`** avec la charge utile à exécuter, puis les compresser et **écrire le fichier zip dans le dossier de l'utilisateur** victime : **`~/~$escape.zip`**.

Ensuite, ajoutez le fichier zip aux **éléments de connexion** puis à l'application **`Terminal`**. Lorsque l'utilisateur se reconnecte, le fichier zip sera décompressé dans les fichiers de l'utilisateur, écrasant **`.bash_profile`** et **`.zshenv`** et donc, le terminal exécutera l'un de ces fichiers (selon l'utilisation de bash ou zsh).

Consultez le [**rapport original ici**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Contournement de la sandbox Word avec Open et les variables d'environnement

À partir des processus en sandbox, il est toujours possible d'appeler d'autres processus en utilisant l'utilitaire **`open`**. De plus, ces processus s'exécuteront **dans leur propre sandbox**.

Il a été découvert que l'utilitaire open dispose de l'option **`--env`** pour exécuter une application avec des **variables d'environnement spécifiques**. Par conséquent, il était possible de créer le fichier **`.zshenv`** dans un dossier **à l'intérieur** de la **sandbox** et d'utiliser `open` avec `--env` en définissant la variable **`HOME`** sur ce dossier, ouvrant ainsi l'application `Terminal` qui exécutera le fichier `.zshenv` (pour une raison quelconque, il était également nécessaire de définir la variable `__OSINSTALL_ENVIROMENT`).

Consultez le [**rapport original ici**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Contournement de la sandbox Word avec Open et stdin

L'utilitaire **`open`** prenait également en charge le paramètre **`--stdin`** (et après la précédente évasion, il n'était plus possible d'utiliser `--env`).

Le problème est que même si **`python`** était signé par Apple, il **n'exécutera pas** un script avec l'attribut **`quarantine`**. Cependant, il était possible de lui transmettre un script depuis stdin afin qu'il ne vérifie pas s'il était mis en quarantaine ou non :&#x20;

1. Déposez un fichier **`~$exploit.py`** avec des commandes Python arbitraires.
2. Exécutez _open_ **`–stdin='~$exploit.py' -a Python`**, qui exécute l'application Python avec notre fichier déposé servant de son entrée standard. Python exécute notre code sans problème, et comme c'est un processus enfant de _launchd_, il n'est pas soumis aux règles de la sandbox de Word.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>
* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
