# macOS Fichiers, Dossiers, Binaires et Mémoire

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Hiérarchie des fichiers

* **/Applications** : Les applications installées doivent être ici. Tous les utilisateurs pourront y accéder.
* **/bin** : Binaires de ligne de commande
* **/cores** : S'il existe, il est utilisé pour stocker les vidages de cœur
* **/dev** : Tout est traité comme un fichier, vous pouvez donc voir des périphériques matériels stockés ici.
* **/etc** : Fichiers de configuration
* **/Library** : De nombreux sous-répertoires et fichiers liés aux préférences, caches et journaux peuvent être trouvés ici. Un dossier Library existe dans la racine et dans le répertoire de chaque utilisateur.
* **/private** : Non documenté, mais de nombreux dossiers mentionnés sont des liens symboliques vers le répertoire privé.
* **/sbin** : Binaires système essentiels (liés à l'administration)
* **/System** : Fichier pour faire fonctionner OS X. Vous devriez trouver ici principalement des fichiers spécifiques à Apple (pas de tiers).
* **/tmp** : Les fichiers sont supprimés après 3 jours (c'est un lien symbolique vers /private/tmp)
* **/Users** : Répertoire personnel pour les utilisateurs.
* **/usr** : Configuration et binaires système
* **/var** : Fichiers journaux
* **/Volumes** : Les lecteurs montés apparaîtront ici.
* **/.vol** : En exécutant `stat a.txt`, vous obtenez quelque chose comme `16777223 7545753 -rw-r--r-- 1 username wheel ...` où le premier nombre est le numéro d'identification du volume où se trouve le fichier et le deuxième est le numéro d'inode. Vous pouvez accéder au contenu de ce fichier via /.vol/ avec ces informations en exécutant `cat /.vol/16777223/7545753`

### Dossiers d'applications

* Les **applications système** sont situées sous `/System/Applications`
* Les **applications installées** sont généralement installées dans `/Applications` ou dans `~/Applications`
* Les **données d'application** peuvent être trouvées dans `/Library/Application Support` pour les applications s'exécutant en tant que root et `~/Library/Application Support` pour les applications s'exécutant en tant qu'utilisateur.
* Les **daemons** d'applications **tiers** qui **doivent s'exécuter en tant que root** sont généralement situés dans `/Library/PrivilegedHelperTools/`
* Les applications **sandboxed** sont mappées dans le dossier `~/Library/Containers`. Chaque application a un dossier nommé selon l'ID de bundle de l'application (`com.apple.Safari`).
* Le **noyau** est situé dans `/System/Library/Kernels/kernel`
* Les **extensions de noyau d'Apple** sont situées dans `/System/Library/Extensions`
* Les **extensions de noyau tierces** sont stockées dans `/Library/Extensions`

### Fichiers avec des informations sensibles

macOS stocke des informations telles que des mots de passe à plusieurs endroits :

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Installateurs pkg vulnérables

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Extensions spécifiques à OS X

* **`.dmg`** : Les fichiers d'image de disque Apple sont très fréquents pour les installateurs.
* **`.kext`** : Il doit suivre une structure spécifique et c'est la version OS X d'un pilote. (c'est un bundle)
* **`.plist`** : Également connu sous le nom de liste de propriétés, stocke des informations au format XML ou binaire.
  * Peut être XML ou binaire. Les binaires peuvent être lus avec :
    * `defaults read config.plist`
    * `/usr/libexec/PlistBuddy -c print config.plsit`
    * `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    * `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    * `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`** : Applications Apple qui suivent la structure de répertoire (c'est un bundle).
* **`.dylib`** : Bibliothèques dynamiques (comme les fichiers DLL Windows)
* **`.pkg`** : Sont identiques à xar (format d'archive extensible). La commande installer peut être utilisée pour installer le contenu de ces fichiers.
* **`.DS_Store`** : Ce fichier est présent dans chaque répertoire, il enregistre les attributs et les personnalisations du répertoire.
* **`.Spotlight-V100`** : Ce dossier apparaît sur le répertoire racine de chaque volume du système.
* **`.metadata_never_index`** : Si ce fichier se trouve à la racine d'un volume, Spotlight n'indexera pas ce volume.
* **`.noindex`** : Les fichiers et dossiers avec cette extension ne seront pas indexés par Spotlight.

### Bundles macOS

Fondamentalement, un bundle est une **structure de répertoire** dans le système de fichiers. Curieusement, par défaut, ce répertoire **ressemble à un seul objet dans Finder** (comme `.app`).&#x20;

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Autorisations de fichiers spéciales

### Autorisations de dossier

Dans un **dossier**, **la lecture** permet de **lister** celui-ci, **l'écriture** permet de **supprimer** et **écrire** des fichiers dessus, et **l'exécution** permet de **traverser** le répertoire. Ainsi, par exemple, un utilisateur avec **l'autorisation de lecture sur un fichier** à l'intérieur d'un répertoire où il **n'a pas l'autorisation d'exécution** **ne pourra pas lire** le fichier.

### Modificateurs de drapeaux

Il existe des drapeaux qui peuvent être dé
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Vous pouvez **lire les ACLs** du fichier avec:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```
Vous pouvez trouver **tous les fichiers avec des ACL** avec (c'est trèèès lent):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Fourches de ressources | ADS macOS

Il s'agit d'un moyen d'obtenir des **flux de données alternatifs dans les machines MacOS**. Vous pouvez enregistrer du contenu à l'intérieur d'un attribut étendu appelé **com.apple.ResourceFork** à l'intérieur d'un fichier en l'enregistrant dans **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Vous pouvez **trouver tous les fichiers contenant cet attribut étendu** avec :

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
## **Binaires universels et** format Mach-o

Les binaires Mac OS sont généralement compilés en tant que **binaires universels**. Un **binaire universel** peut **prendre en charge plusieurs architectures dans le même fichier**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Dumping de mémoire macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Fichiers de catégorie de risque Mac OS

Les fichiers `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` contiennent le risque associé aux fichiers en fonction de l'extension de fichier.

Les catégories possibles comprennent les suivantes :

* **LSRiskCategorySafe** : **Totalement** **sûr** ; Safari s'ouvrira automatiquement après le téléchargement
* **LSRiskCategoryNeutral** : Pas d'avertissement, mais **non ouvert automatiquement**
* **LSRiskCategoryUnsafeExecutable** : **Déclenche** un **avertissement** "Ce fichier est une application..."
* **LSRiskCategoryMayContainUnsafeExecutable** : Cela concerne des choses comme les archives qui contiennent un exécutable. Il **déclenche un avertissement à moins que Safari puisse déterminer que tous les contenus sont sûrs ou neutres**.

## Fichiers journaux

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** : Contient des informations sur les fichiers téléchargés, comme l'URL à partir de laquelle ils ont été téléchargés.
* **`/var/log/system.log`** : Journal principal des systèmes OSX. com.apple.syslogd.plist est responsable de l'exécution de la journalisation système (vous pouvez vérifier s'il est désactivé en cherchant "com.apple.syslogd" dans `launchctl list`.
* **`/private/var/log/asl/*.asl`** : Ce sont les journaux système Apple qui peuvent contenir des informations intéressantes.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`** : Stocke les fichiers et applications récemment consultés via "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`** : Stocke les éléments à lancer au démarrage du système
* **`$HOME/Library/Logs/DiskUtility.log`** : Fichier journal pour l'application DiskUtility (informations sur les lecteurs, y compris les clés USB)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`** : Données sur les points d'accès sans fil.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`** : Liste des démons désactivés.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
