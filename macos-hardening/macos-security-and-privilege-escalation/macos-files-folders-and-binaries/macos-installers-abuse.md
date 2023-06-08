## Informations de base

Un package d'installation macOS (également connu sous le nom de fichier `.pkg`) est un format de fichier utilisé par macOS pour **distribuer des logiciels**. Ces fichiers sont comme une **boîte qui contient tout ce dont un logiciel** a besoin pour s'installer et fonctionner correctement.

Le fichier de package lui-même est une archive qui contient une **hiérarchie de fichiers et de répertoires qui seront installés sur l'ordinateur cible**. Il peut également inclure des **scripts** pour effectuer des tâches avant et après l'installation, comme la configuration de fichiers de configuration ou le nettoyage des anciennes versions du logiciel.

### Hiérarchie

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribution (xml)** : Personnalisation (titre, texte de bienvenue...) et vérifications de script/installation
* **PackageInfo (xml)** : Informations, exigences d'installation, emplacement d'installation, chemins vers les scripts à exécuter
* **Bill of materials (bom)** : Liste des fichiers à installer, mettre à jour ou supprimer avec les autorisations de fichier
* **Payload (archive CPIO compressée gzip)** : Fichiers à installer dans l'emplacement d'installation à partir de PackageInfo
* **Scripts (archive CPIO compressée gzip)** : Scripts d'installation pré et post et plus de ressources extraites dans un répertoire temporaire pour l'exécution.

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
## Privesc via l'abus de pkg

### Exécution à partir de répertoires publics

Si un script d'installation pré ou post est par exemple exécuté à partir de **`/var/tmp/Installerutil`**, un attaquant pourrait contrôler ce script pour escalader les privilèges chaque fois qu'il est exécuté. Ou un autre exemple similaire :

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Il s'agit d'une [fonction publique](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que plusieurs programmes d'installation et mises à jour appelleront pour **exécuter quelque chose en tant que root**. Cette fonction accepte le **chemin** du **fichier** à **exécuter** en tant que paramètre, cependant, si un attaquant pouvait **modifier** ce fichier, il serait en mesure d'**abuser** de son exécution avec des privilèges root pour **escalader les privilèges**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Pour plus d'informations, consultez cette présentation : [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

## Références

* [https://www.youtube.com/watch?v=iASSG0\_zobQ](https://www.youtube.com/watch?v=iASSG0\_zobQ)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
