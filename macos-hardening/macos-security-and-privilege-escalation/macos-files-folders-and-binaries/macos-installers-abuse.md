# Abus des Installateurs macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informations de Base sur les Pkg

Un **package d'installation macOS** (également connu sous le nom de fichier `.pkg`) est un format de fichier utilisé par macOS pour **distribuer des logiciels**. Ces fichiers sont comme une **boîte qui contient tout ce dont un logiciel** a besoin pour s'installer et fonctionner correctement.

Le fichier du package est en fait une archive qui contient une **hiérarchie de fichiers et de répertoires qui seront installés sur la cible**. Il peut également inclure des **scripts** pour effectuer des tâches avant et après l'installation, comme la configuration des fichiers de configuration ou le nettoyage des anciennes versions du logiciel.

### Hiérarchie

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)** : Personnalisations (titre, texte de bienvenue...) et vérifications de script/installation
* **PackageInfo (xml)** : Informations, exigences d'installation, emplacement d'installation, chemins vers les scripts à exécuter
* **Liste des matériaux (bom)** : Liste des fichiers à installer, mettre à jour ou supprimer avec les autorisations de fichier
* **Charge utile (archive CPIO compressée gzip)** : Fichiers à installer dans l'emplacement d'installation à partir de PackageInfo
* **Scripts (archive CPIO compressée gzip)** : Scripts d'installation pré et post et autres ressources extraites vers un répertoire temporaire pour l'exécution.

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
## Informations de base sur les fichiers DMG

Les fichiers DMG, ou images disque Apple, sont un format de fichier utilisé par macOS d'Apple pour les images disque. Un fichier DMG est essentiellement une **image disque montable** (il contient son propre système de fichiers) qui contient des données de bloc brut généralement compressées et parfois chiffrées. Lorsque vous ouvrez un fichier DMG, macOS le **monte comme s'il s'agissait d'un disque physique**, vous permettant d'accéder à son contenu.

### Hiérarchie

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

La hiérarchie d'un fichier DMG peut être différente en fonction du contenu. Cependant, pour les DMG d'applications, elle suit généralement cette structure :

- Niveau supérieur : C'est la racine de l'image disque. Il contient souvent l'application et éventuellement un lien vers le dossier Applications.
- Application (.app) : Il s'agit de l'application réelle. Dans macOS, une application est généralement un package qui contient de nombreux fichiers et dossiers individuels constituant l'application.
- Lien vers Applications : Il s'agit d'un raccourci vers le dossier Applications dans macOS. Le but est de faciliter l'installation de l'application. Vous pouvez faire glisser le fichier .app vers ce raccourci pour installer l'application.

## Privilège élevé via l'abus de pkg

### Exécution à partir de répertoires publics

Si un script d'installation préalable ou postérieur exécute par exemple à partir de **`/var/tmp/Installerutil`**, et qu'un attaquant peut contrôler ce script, il peut escalader les privilèges chaque fois qu'il est exécuté. Ou un autre exemple similaire :

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Il s'agit d'une [fonction publique](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que plusieurs installateurs et mises à jour appelleront pour **exécuter quelque chose en tant que root**. Cette fonction accepte le **chemin** du **fichier** à **exécuter** en tant que paramètre, cependant, si un attaquant peut **modifier** ce fichier, il pourra **abuser** de son exécution avec les privilèges root pour **escalader les privilèges**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Pour plus d'informations, consultez cette présentation : [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Exécution par montage

Si un installateur écrit dans `/tmp/fixedname/bla/bla`, il est possible de **créer un montage** sur `/tmp/fixedname` sans propriétaires afin de **modifier n'importe quel fichier pendant l'installation** pour abuser du processus d'installation.

Un exemple de ceci est **CVE-2021-26089** qui a réussi à **écraser un script périodique** pour obtenir une exécution en tant que root. Pour plus d'informations, consultez la présentation : [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg en tant que logiciel malveillant

### Charge utile vide

Il est possible de simplement générer un fichier **`.pkg`** avec des **scripts pre et post-installation** sans aucune charge utile.

### JS dans le fichier Distribution xml

Il est possible d'ajouter des balises **`<script>`** dans le fichier **distribution xml** du package et ce code sera exécuté et il peut **exécuter des commandes** en utilisant **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Références

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
