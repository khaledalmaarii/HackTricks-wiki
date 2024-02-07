# Fichiers, Dossiers, Binaires et Mémoire macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Structure de la hiérarchie des fichiers

* **/Applications**: Les applications installées devraient être ici. Tous les utilisateurs pourront y accéder.
* **/bin**: Binaires de ligne de commande
* **/cores**: S'il existe, il est utilisé pour stocker les vidages de cœur
* **/dev**: Tout est traité comme un fichier, vous pouvez donc voir des périphériques matériels stockés ici.
* **/etc**: Fichiers de configuration
* **/Library**: De nombreux sous-répertoires et fichiers liés aux préférences, caches et journaux peuvent être trouvés ici. Un dossier Library existe à la racine et dans le répertoire de chaque utilisateur.
* **/private**: Non documenté mais beaucoup des dossiers mentionnés sont des liens symboliques vers le répertoire privé.
* **/sbin**: Binaires système essentiels (liés à l'administration)
* **/System**: Fichier pour faire fonctionner OS X. Vous devriez trouver principalement des fichiers spécifiques à Apple ici (pas de tiers).
* **/tmp**: Les fichiers sont supprimés après 3 jours (c'est un lien symbolique vers /private/tmp)
* **/Users**: Répertoire personnel des utilisateurs.
* **/usr**: Binaires de configuration et système
* **/var**: Fichiers journaux
* **/Volumes**: Les lecteurs montés apparaîtront ici.
* **/.vol**: En exécutant `stat a.txt`, vous obtenez quelque chose comme `16777223 7545753 -rw-r--r-- 1 nom_utilisateur wheel ...` où le premier nombre est l'identifiant du volume où se trouve le fichier et le deuxième est le numéro d'inode. Vous pouvez accéder au contenu de ce fichier via /.vol/ avec ces informations en exécutant `cat /.vol/16777223/7545753`

### Dossiers des Applications

* Les **applications système** sont situées sous `/System/Applications`
* Les applications **installées** sont généralement installées dans `/Applications` ou dans `~/Applications`
* Les **données de l'application** peuvent être trouvées dans `/Library/Application Support` pour les applications s'exécutant en tant que root et `~/Library/Application Support` pour les applications s'exécutant en tant qu'utilisateur.
* Les **daemons** d'applications tierces qui **doivent s'exécuter en tant que root** sont généralement situés dans `/Library/PrivilegedHelperTools/`
* Les applications **sandboxed** sont mappées dans le dossier `~/Library/Containers`. Chaque application a un dossier nommé selon l'ID de bundle de l'application (`com.apple.Safari`).
* Le **noyau** est situé dans `/System/Library/Kernels/kernel`
* Les **extensions de noyau d'Apple** sont situées dans `/System/Library/Extensions`
* Les **extensions de noyau tierces** sont stockées dans `/Library/Extensions`

### Fichiers avec des Informations Sensibles

macOS stocke des informations telles que des mots de passe à plusieurs endroits:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Installateurs pkg Vulnérables

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Extensions Spécifiques à OS X

* **`.dmg`**: Les fichiers d'image disque Apple sont très fréquents pour les installateurs.
* **`.kext`**: Il doit suivre une structure spécifique et c'est la version OS X d'un pilote. (c'est un bundle)
* **`.plist`**: Aussi connu sous le nom de liste de propriétés, stocke des informations au format XML ou binaire.
* Peut être XML ou binaire. Les binaires peuvent être lus avec:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Applications Apple qui suivent une structure de répertoire (c'est un bundle).
* **`.dylib`**: Bibliothèques dynamiques (comme les fichiers DLL Windows)
* **`.pkg`**: Sont identiques à xar (format d'archive extensible). La commande installer peut être utilisée pour installer le contenu de ces fichiers.
* **`.DS_Store`**: Ce fichier est présent dans chaque répertoire, il enregistre les attributs et personnalisations du répertoire.
* **`.Spotlight-V100`**: Ce dossier apparaît à la racine de chaque volume du système.
* **`.metadata_never_index`**: Si ce fichier se trouve à la racine d'un volume, Spotlight n'indexera pas ce volume.
* **`.noindex`**: Les fichiers et dossiers avec cette extension ne seront pas indexés par Spotlight.

### Bundles macOS

Un bundle est un **répertoire** qui **ressemble à un objet dans Finder** (un exemple de Bundle sont les fichiers `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Cache Partagé Dyld

Sur macOS (et iOS), toutes les bibliothèques système partagées, comme les frameworks et les dylibs, sont **combinées dans un seul fichier**, appelé le **cache partagé dyld**. Cela améliore les performances, car le code peut être chargé plus rapidement.

Tout comme le cache partagé dyld, le noyau et les extensions de noyau sont également compilés dans un cache de noyau, qui est chargé au démarrage.

Pour extraire les bibliothèques du fichier unique du cache partagé dylib, il était possible d'utiliser le binaire [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) qui pourrait ne pas fonctionner de nos jours, mais vous pouvez également utiliser [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

Dans les anciennes versions, vous pourriez trouver le **cache partagé** dans **`/System/Library/dyld/`**.

Sur iOS, vous pouvez les trouver dans **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Notez que même si l'outil `dyld_shared_cache_util` ne fonctionne pas, vous pouvez passer le **binaire dyld partagé à Hopper** et Hopper pourra identifier toutes les bibliothèques et vous permettre de **sélectionner celle que vous souhaitez** investiguer :
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Autorisations de fichiers spéciales

### Autorisations de dossier

Dans un **dossier**, **lire** permet de **lister son contenu**, **écrire** permet de **supprimer** et **écrire** des fichiers dessus, et **exécuter** permet de **traverser** le répertoire. Ainsi, par exemple, un utilisateur avec **l'autorisation de lecture sur un fichier** à l'intérieur d'un répertoire où il **n'a pas l'autorisation d'exécution** **ne pourra pas lire** le fichier.

### Modificateurs de drapeaux

Il existe des drapeaux qui peuvent être définis dans les fichiers et qui feront que le fichier se comportera différemment. Vous pouvez **vérifier les drapeaux** des fichiers à l'intérieur d'un répertoire avec `ls -lO /chemin/répertoire`

* **`uchg`** : Connu sous le nom de drapeau **uchange** empêchera toute action de **modification ou de suppression** du **fichier**. Pour le définir : `chflags uchg fichier.txt`
* L'utilisateur root pourrait **supprimer le drapeau** et modifier le fichier
* **`restricted`** : Ce drapeau fait en sorte que le fichier soit **protégé par SIP** (vous ne pouvez pas ajouter ce drapeau à un fichier).
* **`Bit collant`** : Si un répertoire a un bit collant, **seul** le **propriétaire du répertoire ou root peut renommer ou supprimer** des fichiers. Typiquement, cela est défini sur le répertoire /tmp pour empêcher les utilisateurs ordinaires de supprimer ou déplacer les fichiers d'autres utilisateurs.

### **Listes de contrôle d'accès aux fichiers (ACL)**

Les **ACL** des fichiers contiennent des **ACE** (entrées de contrôle d'accès) où des **autorisations plus granulaires** peuvent être attribuées à différents utilisateurs.

Il est possible d'accorder à un **dossier** ces autorisations : `liste`, `recherche`, `ajout_fichier`, `ajout_sous-dossier`, `supprimer_enfant`, `supprimer_enfant`.\
Et à un **fichier** : `lire`, `écrire`, `ajouter`, `exécuter`.

Lorsque le fichier contient des ACL, vous verrez un "+" lors de l'énumération des autorisations comme dans :
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Vous pouvez **lire les ACL** du fichier avec :
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Vous pouvez trouver **tous les fichiers avec des ACL** avec (c'est trèèès lent) :
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Fourches de ressources | ADS macOS

C'est une façon d'obtenir des **flux de données alternatifs sur les machines macOS**. Vous pouvez enregistrer du contenu à l'intérieur d'un attribut étendu appelé **com.apple.ResourceFork** à l'intérieur d'un fichier en l'enregistrant dans **file/..namedfork/rsrc**.
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
{% endcode %}

## **Binaires universels &** Format Mach-o

Les binaires Mac OS sont généralement compilés en tant que **binaires universels**. Un **binaire universel** peut **prendre en charge plusieurs architectures dans le même fichier**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Dumping de mémoire macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Fichiers de catégorie de risque Mac OS

Le répertoire `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` est l'endroit où sont stockées les informations sur le **risque associé aux différentes extensions de fichiers**. Ce répertoire catégorise les fichiers en différents niveaux de risque, influençant la manière dont Safari gère ces fichiers lors du téléchargement. Les catégories sont les suivantes :

- **LSRiskCategorySafe** : Les fichiers de cette catégorie sont considérés comme **complètement sûrs**. Safari ouvrira automatiquement ces fichiers après leur téléchargement.
- **LSRiskCategoryNeutral** : Ces fichiers ne comportent aucun avertissement et ne sont **pas ouverts automatiquement** par Safari.
- **LSRiskCategoryUnsafeExecutable** : Les fichiers de cette catégorie **déclenchent un avertissement** indiquant que le fichier est une application. Il s'agit d'une mesure de sécurité pour alerter l'utilisateur.
- **LSRiskCategoryMayContainUnsafeExecutable** : Cette catégorie est destinée aux fichiers, tels que les archives, qui pourraient contenir un exécutable. Safari **déclenchera un avertissement** à moins qu'il puisse vérifier que tous les contenus sont sûrs ou neutres.

## Fichiers journaux

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** : Contient des informations sur les fichiers téléchargés, comme l'URL à partir de laquelle ils ont été téléchargés.
* **`/var/log/system.log`** : Journal principal des systèmes OSX. com.apple.syslogd.plist est responsable de l'exécution de la journalisation système (vous pouvez vérifier s'il est désactivé en recherchant "com.apple.syslogd" dans `launchctl list`).
* **`/private/var/log/asl/*.asl`** : Ce sont les journaux système Apple qui peuvent contenir des informations intéressantes.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`** : Stocke les fichiers et applications récemment consultés via "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`** : Stocke les éléments à lancer au démarrage du système.
* **`$HOME/Library/Logs/DiskUtility.log`** : Fichier journal de l'application DiskUtility (informations sur les lecteurs, y compris les clés USB).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`** : Données sur les points d'accès sans fil.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`** : Liste des démons désactivés.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
