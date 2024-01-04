# Abus des Installateurs macOS

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de Base sur Pkg

Un **package d'installation macOS** (également connu sous le nom de fichier `.pkg`) est un format de fichier utilisé par macOS pour **distribuer des logiciels**. Ces fichiers sont comme une **boîte contenant tout ce dont un logiciel a besoin** pour s'installer et fonctionner correctement.

Le fichier du package lui-même est une archive qui contient une **hiérarchie de fichiers et de répertoires qui seront installés sur l'ordinateur cible**. Il peut également inclure des **scripts** pour effectuer des tâches avant et après l'installation, comme la configuration de fichiers de configuration ou le nettoyage des anciennes versions du logiciel.

### Hiérarchie

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribution (xml)** : Personnalisations (titre, texte d'accueil…) et vérifications de script/installation
* **PackageInfo (xml)** : Informations, exigences d'installation, emplacement d'installation, chemins vers les scripts à exécuter
* **Bill of materials (bom)** : Liste des fichiers à installer, mettre à jour ou supprimer avec les permissions de fichier
* **Payload (archive CPIO compressée gzip)** : Fichiers à installer dans l'`emplacement d'installation` à partir de PackageInfo
* **Scripts (archive CPIO compressée gzip)** : Scripts pré et post installation et plus de ressources extraites vers un répertoire temporaire pour exécution.

### Décompression
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## Informations de base sur les DMG

Les fichiers DMG, ou images disque Apple, sont un format de fichier utilisé par le système d'exploitation macOS d'Apple pour les images disque. Un fichier DMG est essentiellement une **image disque montable** (il contient son propre système de fichiers) qui contient des données de blocs brutes généralement compressées et parfois chiffrées. Lorsque vous ouvrez un fichier DMG, macOS le **monte comme s'il s'agissait d'un disque physique**, vous permettant d'accéder à son contenu.

### Hiérarchie

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

La hiérarchie d'un fichier DMG peut varier en fonction du contenu. Cependant, pour les DMG d'applications, elle suit généralement cette structure :

* Niveau supérieur : C'est la racine de l'image disque. Elle contient souvent l'application et possiblement un lien vers le dossier Applications.
* Application (.app) : C'est l'application proprement dite. Dans macOS, une application est généralement un package qui contient de nombreux fichiers et dossiers individuels qui composent l'application.
* Lien Applications : C'est un raccourci vers le dossier Applications de macOS. Le but est de faciliter l'installation de l'application. Vous pouvez glisser le fichier .app vers ce raccourci pour installer l'application.

## Élévation de privilèges via l'abus de pkg

### Exécution à partir de répertoires publics

Si un script de pré-installation ou de post-installation s'exécute par exemple depuis **`/var/tmp/Installerutil`**, un attaquant pourrait contrôler ce script pour escalader les privilèges chaque fois qu'il est exécuté. Ou un autre exemple similaire :

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Il s'agit d'une [fonction publique](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que plusieurs installateurs et mises à jour appellent pour **exécuter quelque chose en tant que root**. Cette fonction accepte le **chemin** du **fichier** à **exécuter** en paramètre, cependant, si un attaquant pouvait **modifier** ce fichier, il serait en mesure d'**abuser** de son exécution avec root pour **escalader les privilèges**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Pour plus d'informations, consultez cette conférence : [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Exécution par montage

Si un installateur écrit dans `/tmp/fixedname/bla/bla`, il est possible de **créer un montage** sur `/tmp/fixedname` avec noowners afin que vous puissiez **modifier n'importe quel fichier pendant l'installation** pour abuser du processus d'installation.

Un exemple est le **CVE-2021-26089** qui a réussi à **écraser un script périodique** pour obtenir une exécution en tant que root. Pour plus d'informations, regardez la conférence : [**OBTS v4.0 : "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg comme malware

### Payload vide

Il est possible de simplement générer un fichier **`.pkg`** avec des **scripts de pré et post-installation** sans aucun payload.

### JS dans le xml de distribution

Il est possible d'ajouter des balises **`<script>`** dans le fichier **xml de distribution** du paquet et ce code sera exécuté et peut **exécuter des commandes** en utilisant **`system.run`** :

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Références

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
* [**OBTS v4.0 : "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> !</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
