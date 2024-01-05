# Contournements du bac à sable macOS Office

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Contournement du bac à sable Word via les Launch Agents

L'application utilise un **bac à sable personnalisé** avec le droit **`com.apple.security.temporary-exception.sbpl`** et ce bac à sable personnalisé permet d'écrire des fichiers n'importe où tant que le nom du fichier commence par `~$` : `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Par conséquent, s'échapper était aussi simple que **d'écrire un `plist`** LaunchAgent dans `~/Library/LaunchAgents/~$escape.plist`.

Consultez le [**rapport original ici**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Contournement du bac à sable Word via les éléments de connexion et zip

Rappelez-vous que depuis la première évasion, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`, bien qu'après le correctif de la vulnérabilité précédente, il n'était plus possible d'écrire dans `/Library/Application Scripts` ou dans `/Library/LaunchAgents`.

Il a été découvert qu'à partir du bac à sable, il est possible de créer un **élément de connexion** (applications qui seront exécutées lorsque l'utilisateur se connecte). Cependant, ces applications **ne s'exécuteront pas à moins** qu'elles ne soient **notarisées** et il n'est **pas possible d'ajouter des arguments** (vous ne pouvez donc pas simplement exécuter un shell inversé en utilisant **`bash`**).

À partir du contournement précédent du bac à sable, Microsoft a désactivé l'option d'écrire des fichiers dans `~/Library/LaunchAgents`. Cependant, il a été découvert que si vous mettez un **fichier zip comme élément de connexion**, l'`Archive Utility` va juste **décompresser** le fichier à son emplacement actuel. Donc, parce que par défaut le dossier `LaunchAgents` de `~/Library` n'est pas créé, il était possible de **zipper un plist dans `LaunchAgents/~$escape.plist`** et de **placer** le fichier zip dans **`~/Library`** afin que lors de la décompression, il atteigne la destination de persistance.

Consultez le [**rapport original ici**](https://objective-see.org/blog/blog\_0x4B.html).

### Contournement du bac à sable Word via les éléments de connexion et .zshenv

(Rappelez-vous que depuis la première évasion, Word peut écrire des fichiers arbitraires dont le nom commence par `~$`).

Cependant, la technique précédente avait une limitation, si le dossier **`~/Library/LaunchAgents`** existe parce qu'un autre logiciel l'a créé, elle échouerait. Une autre chaîne d'éléments de connexion a donc été découverte pour cela.

Un attaquant pourrait créer les fichiers **`.bash_profile`** et **`.zshenv`** avec la charge utile à exécuter, puis les zipper et **écrire le zip dans le dossier utilisateur de la victime** : **`~/~$escape.zip`**.

Ensuite, ajoutez le fichier zip aux **éléments de connexion** puis à l'application **`Terminal`**. Lorsque l'utilisateur se reconnecte, le fichier zip serait décompressé dans le fichier de l'utilisateur, écrasant **`.bash_profile`** et **`.zshenv`** et donc, le terminal exécutera l'un de ces fichiers (selon si bash ou zsh est utilisé).

Consultez le [**rapport original ici**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Contournement du bac à sable Word avec Open et les variables d'environnement

Depuis des processus en bac à sable, il est toujours possible d'invoquer d'autres processus en utilisant l'utilitaire **`open`**. De plus, ces processus s'exécuteront **dans leur propre bac à sable**.

Il a été découvert que l'utilitaire open a l'option **`--env`** pour exécuter une application avec des variables d'**environnement spécifiques**. Par conséquent, il était possible de créer le fichier **`.zshenv`** dans un dossier **à l'intérieur** du **bac à sable** et d'utiliser `open` avec `--env` en définissant la variable **`HOME`** sur ce dossier en ouvrant l'application `Terminal`, qui exécutera le fichier `.zshenv` (pour une raison quelconque, il était également nécessaire de définir la variable `__OSINSTALL_ENVIROMENT`).

Consultez le [**rapport original ici**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Contournement du bac à sable Word avec Open et stdin

L'utilitaire **`open`** prenait également en charge le paramètre **`--stdin`** (et après le contournement précédent, il n'était plus possible d'utiliser `--env`).

Le fait est que même si **`python`** était signé par Apple, il **n'exécuterait pas** un script avec l'attribut **`quarantine`**. Cependant, il était possible de lui passer un script depuis stdin afin qu'il ne vérifie pas s'il était mis en quarantaine ou non :&#x20;

1. Déposez un fichier **`~$exploit.py`** avec des commandes Python arbitraires.
2. Exécutez _open_ **`–stdin='~$exploit.py' -a Python`**, qui exécute l'application Python avec notre fichier déposé servant d'entrée standard. Python exécute joyeusement notre code, et comme c'est un processus enfant de _launchd_, il n'est pas lié aux règles du bac à sable de Word.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
