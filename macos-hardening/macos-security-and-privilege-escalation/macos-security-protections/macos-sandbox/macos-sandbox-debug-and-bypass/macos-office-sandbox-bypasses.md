# Contournement du bac à sable de Word sur macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

### Contournement du bac à sable de Word via les Agents de lancement

L'application utilise un **bac à sable personnalisé** en utilisant le privilège **`com.apple.security.temporary-exception.sbpl`** et ce bac à sable personnalisé permet d'écrire des fichiers n'importe où tant que le nom de fichier commence par `~$` : `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Par conséquent, l'évasion était aussi simple que **écrire un fichier `plist`** LaunchAgent dans `~/Library/LaunchAgents/~$escape.plist`.

Consultez le [**rapport original ici**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Contournement du bac à sable de Word via les éléments de connexion et zip

Rappelez-vous que suite à la première évasion, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`, bien qu'après le correctif de la vulnérabilité précédente, il n'était plus possible d'écrire dans `/Library/Application Scripts` ou dans `/Library/LaunchAgents`.

Il a été découvert qu'à partir du bac à sable, il est possible de créer un **élément de connexion** (applications qui seront exécutées lorsque l'utilisateur se connecte). Cependant, ces applications **ne s'exécuteront pas** à moins d'être **notariées** et il n'est **pas possible d'ajouter des arguments** (vous ne pouvez pas simplement exécuter un shell inversé en utilisant **`bash`**).

Suite au contournement précédent du bac à sable, Microsoft a désactivé l'option d'écrire des fichiers dans `~/Library/LaunchAgents`. Cependant, il a été découvert que si vous placez un **fichier zip en tant qu'élément de connexion**, l'`Utilitaire d'archivage` le décompressera simplement à son emplacement actuel. Ainsi, comme par défaut le dossier `LaunchAgents` de `~/Library` n'est pas créé, il était possible de **mettre en zip un plist dans `LaunchAgents/~$escape.plist`** et **placer** le fichier zip dans **`~/Library`** pour qu'à la décompression, il atteigne la destination de persistance.

Consultez le [**rapport original ici**](https://objective-see.org/blog/blog\_0x4B.html).

### Contournement du bac à sable de Word via les éléments de connexion et .zshenv

(Rappelez-vous que suite à la première évasion, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`).

Cependant, la technique précédente avait une limitation : si le dossier **`~/Library/LaunchAgents`** existe car un autre logiciel l'a créé, cela échouerait. Une autre chaîne d'éléments de connexion a été découverte pour cela.

Un attaquant pourrait créer les fichiers **`.bash_profile`** et **`.zshenv`** avec la charge utile à exécuter, puis les zipper et **écrire le zip dans le dossier de l'utilisateur** victime : **`~/~$escape.zip`**.

Ensuite, ajoutez le fichier zip aux **éléments de connexion** puis à l'application **`Terminal`**. Lorsque l'utilisateur se reconnecte, le fichier zip serait décompressé dans les fichiers de l'utilisateur, écrasant **`.bash_profile`** et **`.zshenv** et donc, le terminal exécutera l'un de ces fichiers (selon que bash ou zsh est utilisé).

Consultez le [**rapport original ici**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Contournement du bac à sable de Word avec Open et les variables d'environnement

À partir des processus mis en bac à sable, il est toujours possible d'appeler d'autres processus en utilisant l'utilitaire **`open`**. De plus, ces processus s'exécuteront **dans leur propre bac à sable**.

Il a été découvert que l'utilitaire open a l'option **`--env`** pour exécuter une application avec des **variables d'environnement spécifiques**. Par conséquent, il était possible de créer le fichier **`.zshenv`** dans un dossier **à l'intérieur** du **bac à sable** et d'utiliser `open` avec `--env` en définissant la variable **`HOME`** sur ce dossier en ouvrant l'application `Terminal`, qui exécutera le fichier `.zshenv` (pour une raison quelconque, il était également nécessaire de définir la variable `__OSINSTALL_ENVIROMENT`).

Consultez le [**rapport original ici**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Contournement du bac à sable de Word avec Open et stdin

L'utilitaire **`open`** prenait également en charge le paramètre **`--stdin`** (et après le contournement précédent, il n'était plus possible d'utiliser `--env`).

Le fait est que même si **`python`** était signé par Apple, il ne **exécutera pas** un script avec l'attribut **`quarantine`**. Cependant, il était possible de lui transmettre un script depuis stdin afin qu'il ne vérifie pas s'il était mis en quarantaine ou non :&#x20;

1. Déposez un fichier **`~$exploit.py`** avec des commandes Python arbitraires.
2. Exécutez _open_ **`–stdin='~$exploit.py' -a Python`**, qui exécute l'application Python avec notre fichier déposé servant de son entrée standard. Python exécute joyeusement notre code, et comme c'est un processus enfant de _launchd_, il n'est pas lié aux règles du bac à sable de Word.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
