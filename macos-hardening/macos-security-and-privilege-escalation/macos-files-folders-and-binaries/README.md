# macOS Fichiers, Dossiers, Binaires & Mémoire

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Structure de la hiérarchie des fichiers

* **/Applications** : Les applications installées devraient être ici. Tous les utilisateurs pourront y accéder.
* **/bin** : Binaires de ligne de commande
* **/cores** : S'il existe, il est utilisé pour stocker les vidages de cœur.
* **/dev** : Tout est traité comme un fichier, vous pouvez donc voir des périphériques matériels stockés ici.
* **/etc** : Fichiers de configuration
* **/Library** : De nombreux sous-répertoires et fichiers liés aux préférences, caches et journaux peuvent être trouvés ici. Un dossier Library existe à la racine et dans le répertoire de chaque utilisateur.
* **/private** : Non documenté mais beaucoup des dossiers mentionnés sont des liens symboliques vers le répertoire private.
* **/sbin** : Binaires système essentiels (liés à l'administration)
* **/System** : Fichier pour faire fonctionner OS X. Vous devriez trouver principalement des fichiers spécifiques à Apple ici (pas de tiers).
* **/tmp** : Les fichiers sont supprimés après 3 jours (c'est un lien symbolique vers /private/tmp)
* **/Users** : Répertoire personnel des utilisateurs.
* **/usr** : Configuration et binaires système
* **/var** : Fichiers journaux
* **/Volumes** : Les lecteurs montés apparaîtront ici.
* **/.vol** : En exécutant `stat a.txt`, vous obtenez quelque chose comme `16777223 7545753 -rw-r--r-- 1 nom_utilisateur wheel ...` où le premier nombre est l'identifiant du volume où se trouve le fichier et le deuxième est le numéro d'inode. Vous pouvez accéder au contenu de ce fichier via /.vol/ avec ces informations en exécutant `cat /.vol/16777223/7545753`

### Dossiers des Applications

* Les **applications système** sont situées sous `/System/Applications`
* Les **applications installées** sont généralement installées dans `/Applications` ou dans `~/Applications`
* Les **données de l'application** peuvent être trouvées dans `/Library/Application Support` pour les applications s'exécutant en tant que root et `~/Library/Application Support` pour les applications s'exécutant en tant qu'utilisateur.
* Les **daemons** d'applications tierces qui **doivent s'exécuter en tant que root** sont généralement situés dans `/Library/PrivilegedHelperTools/`
* Les applications **sandboxed** sont mappées dans le dossier `~/Library/Containers`. Chaque application a un dossier nommé selon l'ID de bundle de l'application (`com.apple.Safari`).
* Le **noyau** est situé dans `/System/Library/Kernels/kernel`
* Les **extensions de noyau d'Apple** sont situées dans `/System/Library/Extensions`
* Les **extensions de noyau tierces** sont stockées dans `/Library/Extensions`

### Fichiers avec des Informations Sensibles

macOS stocke des informations telles que des mots de passe à plusieurs endroits :

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Installateurs pkg Vulnérables

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Extensions Spécifiques à OS X

* **`.dmg`** : Les fichiers d'image disque Apple sont très fréquents pour les installateurs.
* **`.kext`** : Il doit suivre une structure spécifique et c'est la version OS X d'un pilote. (c'est un bundle)
* **`.plist`** : Aussi connu sous le nom de liste de propriétés, stocke des informations au format XML ou binaire.
* Peut être XML ou binaire. Les binaires peuvent être lus avec :
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`** : Applications Apple qui suivent une structure de répertoire (c'est un bundle).
* **`.dylib`** : Bibliothèques dynamiques (comme les fichiers DLL Windows)
* **`.pkg`** : Sont identiques à xar (format d'archive extensible). La commande installer peut être utilisée pour installer le contenu de ces fichiers.
* **`.DS_Store`** : Ce fichier est présent dans chaque répertoire, il enregistre les attributs et personnalisations du répertoire.
* **`.Spotlight-V100`** : Ce dossier apparaît à la racine de chaque volume du système.
* **`.metadata_never_index`** : Si ce fichier se trouve à la racine d'un volume, Spotlight n'indexera pas ce volume.
* **`.noindex`** : Les fichiers et dossiers avec cette extension ne seront pas indexés par Spotlight.
* **`.sdef`** : Fichiers à l'intérieur des bundles spécifiant comment il est possible d'interagir avec l'application depuis un AppleScript.

### Bundles macOS

Un bundle est un **répertoire** qui **ressemble à un objet dans Finder** (un exemple de Bundle sont les fichiers `*.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Cache de Bibliothèques Partagées Dyld (SLC)

Sur macOS (et iOS), toutes les bibliothèques système partagées, comme les frameworks et les dylibs, sont **combinées en un seul fichier**, appelé le **cache de bibliothèques partagées dyld**. Cela améliore les performances, car le code peut être chargé plus rapidement.

Cela se trouve dans macOS dans `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` et dans les anciennes versions, vous pourriez trouver le **cache partagé** dans **`/System/Library/dyld/`**.\
Sur iOS, vous pouvez les trouver dans **`/System/Library/Caches/com.apple.dyld/`**.

Tout comme le cache de bibliothèques partagées dyld, le noyau et les extensions de noyau sont également compilés dans un cache de noyau, qui est chargé au démarrage.

Pour extraire les bibliothèques du fichier unique de cache partagé dylib, il était possible d'utiliser le binaire [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) qui pourrait ne pas fonctionner de nos jours, mais vous pouvez également utiliser [**dyldextractor**](https://github.com/arandomdev/dyldextractor):

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

{% hint style="success" %}
Notez que même si l'outil `dyld_shared_cache_util` ne fonctionne pas, vous pouvez passer le **binaire dyld partagé à Hopper** et Hopper pourra identifier toutes les bibliothèques et vous permettre de **sélectionner celle que** vous souhaitez étudier :
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Certains extracteurs ne fonctionneront pas car les dylibs sont préliées avec des adresses codées en dur, ils pourraient donc sauter à des adresses inconnues.

{% hint style="success" %}
Il est également possible de télécharger le Cache de Bibliothèques Partagées d'autres appareils \*OS sur macOS en utilisant un émulateur dans Xcode. Ils seront téléchargés à l'intérieur de : ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, comme : `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`
{% endhint %}

### Cartographie du SLC

**`dyld`** utilise l'appel système **`shared_region_check_np`** pour savoir si le SLC a été cartographié (ce qui renvoie l'adresse) et **`shared_region_map_and_slide_np`** pour cartographier le SLC.

Notez que même si le SLC est glissé à la première utilisation, tous les **processus** utilisent la **même copie**, ce qui **élimine la protection ASLR** si l'attaquant parvient à exécuter des processus dans le système. Cela a en fait été exploité dans le passé et corrigé avec le pager de région partagée.

Les pools de branches sont de petites dylibs Mach-O qui créent de petits espaces entre les mappages d'images, rendant impossible l'interposition des fonctions.

### Remplacer les SLC

En utilisant les variables d'environnement :

* **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Cela permettra de charger un nouveau cache de bibliothèques partagées
* **`DYLD_SHARED_CACHE_DIR=avoid`** et remplacer manuellement les bibliothèques par des liens symboliques vers le cache partagé avec les vraies (vous devrez les extraire)

## Autorisations de Fichiers Spéciaux

### Autorisations de Dossier

Dans un **dossier**, **lire** permet de **lister**, **écrire** permet de **supprimer** et **écrire** des fichiers dessus, et **exécuter** permet de **traverser** le répertoire. Par exemple, un utilisateur avec **l'autorisation de lecture sur un fichier** à l'intérieur d'un répertoire où il **n'a pas l'autorisation d'exécution** **ne pourra pas lire** le fichier.

### Modificateurs de drapeaux

Il existe des drapeaux qui peuvent être définis dans les fichiers et qui feront que le fichier se comportera différemment. Vous pouvez **vérifier les drapeaux** des fichiers à l'intérieur d'un répertoire avec `ls -lO /chemin/répertoire`

* **`uchg`** : Connu sous le nom de drapeau **uchange** empêchera toute action de changer ou de supprimer le **fichier**. Pour le définir : `chflags uchg fichier.txt`
* L'utilisateur root pourrait **supprimer le drapeau** et modifier le fichier
* **`restricted`** : Ce drapeau fait en sorte que le fichier soit **protégé par SIP** (vous ne pouvez pas ajouter ce drapeau à un fichier).
* **`Bit collant`** : Si un répertoire a un bit collant, **seul** le **propriétaire des répertoires ou root peut renommer ou supprimer** des fichiers. Typiquement, cela est défini sur le répertoire /tmp pour empêcher les utilisateurs ordinaires de supprimer ou déplacer les fichiers d'autres utilisateurs.

Tous les drapeaux se trouvent dans le fichier `sys/stat.h` (trouvez-le en utilisant `mdfind stat.h | grep stat.h`) et sont :

* `UF_SETTABLE` 0x0000ffff : Masque des drapeaux modifiables par le propriétaire.
* `UF_NODUMP` 0x00000001 : Ne pas sauvegarder le fichier.
* `UF_IMMUTABLE` 0x00000002 : Le fichier ne peut pas être modifié.
* `UF_APPEND` 0x00000004 : Les écritures dans le fichier ne peuvent être qu'ajoutées.
* `UF_OPAQUE` 0x00000008 : Le répertoire est opaque par rapport à l'union.
* `UF_COMPRESSED` 0x00000020 : Le fichier est compressé (certains systèmes de fichiers).
* `UF_TRACKED` 0x00000040 : Pas de notifications pour les suppressions/renommages pour les fichiers avec cela défini.
* `UF_DATAVAULT` 0x00000080 : Autorisation requise pour la lecture et l'écriture.
* `UF_HIDDEN` 0x00008000 : Indique que cet élément ne doit pas être affiché dans une interface graphique.
* `SF_SUPPORTED` 0x009f0000 : Masque des drapeaux pris en charge par le superutilisateur.
* `SF_SETTABLE` 0x3fff0000 : Masque des drapeaux modifiables par le superutilisateur.
* `SF_SYNTHETIC` 0xc0000000 : Masque des drapeaux synthétiques en lecture seule du système.
* `SF_ARCHIVED` 0x00010000 : Le fichier est archivé.
* `SF_IMMUTABLE` 0x00020000 : Le fichier ne peut pas être modifié.
* `SF_APPEND` 0x00040000 : Les écritures dans le fichier ne peuvent être qu'ajoutées.
* `SF_RESTRICTED` 0x00080000 : Autorisation requise pour l'écriture.
* `SF_NOUNLINK` 0x00100000 : L'élément ne peut pas être supprimé, renommé ou monté.
* `SF_FIRMLINK` 0x00800000 : Le fichier est un lien ferme.
* `SF_DATALESS` 0x40000000 : Le fichier est un objet sans données.

### **ACL des Fichiers**

Les **ACL des fichiers** contiennent des **ACE** (entrées de contrôle d'accès) où des **autorisations plus granulaires** peuvent être attribuées à différents utilisateurs.

Il est possible d'accorder à un **répertoire** ces autorisations : `liste`, `recherche`, `ajouter_fichier`, `ajouter_sous-répertoire`, `supprimer_enfant`, `supprimer_enfant`.\
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
Vous pouvez trouver **tous les fichiers avec des ACLs** avec (c'est trèèès lent) :
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Attributs étendus

Les attributs étendus ont un nom et une valeur souhaitée, et peuvent être visualisés en utilisant `ls -@` et manipulés en utilisant la commande `xattr`. Certains attributs étendus courants sont :

- `com.apple.resourceFork` : Compatibilité de la fourche de ressources. Visible également sous la forme `filename/..namedfork/rsrc`
- `com.apple.quarantine` : MacOS : Mécanisme de quarantaine de Gatekeeper (III/6)
- `metadata:*` : MacOS : diverses métadonnées, telles que `_backup_excludeItem`, ou `kMD*`
- `com.apple.lastuseddate` (#PS) : Date d'utilisation du fichier
- `com.apple.FinderInfo` : MacOS : Informations du Finder (par ex., étiquettes de couleur)
- `com.apple.TextEncoding` : Spécifie l'encodage de texte des fichiers texte ASCII
- `com.apple.logd.metadata` : Utilisé par logd sur les fichiers dans `/var/db/diagnostics`
- `com.apple.genstore.*` : Stockage générationnel (`/.DocumentRevisions-V100` à la racine du système de fichiers)
- `com.apple.rootless` : MacOS : Utilisé par la Protection de l'intégrité du système pour étiqueter les fichiers (III/10)
- `com.apple.uuidb.boot-uuid` : Marquages de logd des époques de démarrage avec UUID unique
- `com.apple.decmpfs` : MacOS : Compression de fichiers transparente (II/7)
- `com.apple.cprotect` : \*OS : Données de chiffrement par fichier (III/11)
- `com.apple.installd.*` : \*OS : Métadonnées utilisées par installd, par ex., `installType`, `uniqueInstallID`

### Fourches de ressources | ADS macOS

Il s'agit d'une manière d'obtenir des **flux de données alternatifs sur les machines MacOS**. Vous pouvez enregistrer du contenu à l'intérieur d'un attribut étendu appelé **com.apple.ResourceFork** à l'intérieur d'un fichier en l'enregistrant dans **file/..namedfork/rsrc**.
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

### decmpfs

L'attribut étendu `com.apple.decmpfs` indique que le fichier est stocké crypté, `ls -l` rapportera une **taille de 0** et les données compressées sont à l'intérieur de cet attribut. Chaque fois que le fichier est accédé, il sera déchiffré en mémoire.

Cet attribut peut être vu avec `ls -lO` indiqué comme compressé car les fichiers compressés sont également marqués avec le drapeau `UF_COMPRESSED`. Si un fichier compressé est supprimé, ce drapeau avec `chflags nocompressed </chemin/vers/fichier>`, le système ne saura pas que le fichier était compressé et donc il ne pourra pas le décompresser et accéder aux données (il pensera qu'il est en fait vide).

L'outil afscexpand peut être utilisé pour forcer la décompression d'un fichier.

## **Binaires universels &** Format Mach-o

Les binaires Mac OS sont généralement compilés en tant que **binaires universels**. Un **binaire universel** peut **prendre en charge plusieurs architectures dans le même fichier**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Mémoire des processus macOS

## Extraction de mémoire macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Fichiers de catégorie de risque Mac OS

Le répertoire `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` est l'endroit où sont stockées les informations sur le **risque associé à différentes extensions de fichier**. Ce répertoire catégorise les fichiers en différents niveaux de risque, influençant la manière dont Safari gère ces fichiers lors du téléchargement. Les catégories sont les suivantes :

* **LSRiskCategorySafe** : Les fichiers de cette catégorie sont considérés comme **complètement sûrs**. Safari ouvrira automatiquement ces fichiers après leur téléchargement.
* **LSRiskCategoryNeutral** : Ces fichiers ne sont accompagnés d'aucun avertissement et ne sont **pas ouverts automatiquement** par Safari.
* **LSRiskCategoryUnsafeExecutable** : Les fichiers de cette catégorie **déclenchent un avertissement** indiquant que le fichier est une application. Cela sert de mesure de sécurité pour alerter l'utilisateur.
* **LSRiskCategoryMayContainUnsafeExecutable** : Cette catégorie est pour les fichiers, tels que les archives, qui pourraient contenir un exécutable. Safari **déclenchera un avertissement** à moins qu'il puisse vérifier que tous les contenus sont sûrs ou neutres.

## Fichiers journaux

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** : Contient des informations sur les fichiers téléchargés, comme l'URL à partir de laquelle ils ont été téléchargés.
* **`/var/log/system.log`** : Principal journal des systèmes OSX. com.apple.syslogd.plist est responsable de l'exécution du journalisation système (vous pouvez vérifier s'il est désactivé en cherchant "com.apple.syslogd" dans `launchctl list`.
* **`/private/var/log/asl/*.asl`** : Ce sont les journaux système Apple qui peuvent contenir des informations intéressantes.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`** : Stocke les fichiers et applications récemment consultés via "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`** : Stocke les éléments à lancer au démarrage du système.
* **`$HOME/Library/Logs/DiskUtility.log`** : Fichier journal pour l'application DiskUtility (informations sur les lecteurs, y compris les clés USB).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`** : Données sur les points d'accès sans fil.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`** : Liste des démons désactivés.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous voulez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
