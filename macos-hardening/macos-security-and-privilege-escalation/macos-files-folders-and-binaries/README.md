# Fichiers, Dossiers, Binaires et Mémoire de macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Structure hiérarchique des fichiers

* **/Applications** : Les applications installées doivent se trouver ici. Tous les utilisateurs pourront y accéder.
* **/bin** : Binaires de ligne de commande
* **/cores** : S'il existe, il est utilisé pour stocker les vidages de mémoire
* **/dev** : Tout est traité comme un fichier, vous pouvez donc voir des périphériques matériels stockés ici.
* **/etc** : Fichiers de configuration
* **/Library** : Beaucoup de sous-dossiers et de fichiers liés aux préférences, caches et journaux peuvent être trouvés ici. Un dossier Library existe dans le répertoire racine et dans le répertoire de chaque utilisateur.
* **/private** : Non documenté, mais beaucoup des dossiers mentionnés sont des liens symboliques vers le répertoire privé.
* **/sbin** : Binaires système essentiels (liés à l'administration)
* **/System** : Fichier pour faire fonctionner OS X. Vous devriez trouver principalement des fichiers spécifiques à Apple ici (pas de tiers).
* **/tmp** : Les fichiers sont supprimés après 3 jours (c'est un lien symbolique vers /private/tmp)
* **/Users** : Répertoire personnel des utilisateurs.
* **/usr** : Config et binaires système
* **/var** : Fichiers journaux
* **/Volumes** : Les lecteurs montés apparaîtront ici.
* **/.vol** : En exécutant `stat a.txt`, vous obtenez quelque chose comme `16777223 7545753 -rw-r--r-- 1 nom_utilisateur wheel ...` où le premier nombre est le numéro d'identification du volume où le fichier existe et le second est le numéro d'inode. Vous pouvez accéder au contenu de ce fichier via /.vol/ avec ces informations en exécutant `cat /.vol/16777223/7545753`

### Dossiers d'applications

* **Les applications système** se trouvent sous `/System/Applications`
* **Les applications installées** sont généralement installées dans `/Applications` ou dans `~/Applications`
* **Les données d'application** peuvent être trouvées dans `/Library/Application Support` pour les applications fonctionnant en tant que root et `~/Library/Application Support` pour les applications fonctionnant en tant qu'utilisateur.
* Les **daemons** d'applications tierces qui **doivent s'exécuter en tant que root** sont généralement situés dans `/Library/PrivilegedHelperTools/`
* Les applications **sandboxées** sont mappées dans le dossier `~/Library/Containers`. Chaque application a un dossier nommé selon l'ID de bundle de l'application (`com.apple.Safari`).
* Le **noyau** est situé dans `/System/Library/Kernels/kernel`
* **Les extensions de noyau d'Apple** sont situées dans `/System/Library/Extensions`
* **Les extensions de noyau tierces** sont stockées dans `/Library/Extensions`

### Fichiers contenant des informations sensibles

MacOS stocke des informations telles que les mots de passe dans plusieurs endroits :

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Installateurs pkg vulnérables

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## Extensions spécifiques à OS X

* **`.dmg`** : Les fichiers d'image disque Apple sont très fréquents pour les installateurs.
* **`.kext`** : Il doit suivre une structure spécifique et c'est la version OS X d'un pilote. (c'est un bundle)
* **`.plist`** : Également connu sous le nom de liste de propriétés, stocke des informations au format XML ou binaire.
* Peut être XML ou binaire. Les binaires peuvent être lus avec :
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`** : Applications Apple qui suivent une structure de répertoire (C'est un bundle).
* **`.dylib`** : Bibliothèques dynamiques (comme les fichiers DLL de Windows)
* **`.pkg`** : Sont les mêmes que xar (format d'archive extensible). La commande d'installation peut être utilisée pour installer le contenu de ces fichiers.
* **`.DS_Store`** : Ce fichier se trouve dans chaque répertoire, il sauvegarde les attributs et les personnalisations du répertoire.
* **`.Spotlight-V100`** : Ce dossier apparaît dans le répertoire racine de chaque volume du système.
* **`.metadata_never_index`** : Si ce fichier se trouve à la racine d'un volume, Spotlight n'indexera pas ce volume.
* **`.noindex`** : Les fichiers et dossiers avec cette extension ne seront pas indexés par Spotlight.

### Bundles macOS

Essentiellement, un bundle est une **structure de répertoire** au sein du système de fichiers. Intéressant, par défaut ce répertoire **apparaît comme un objet unique dans Finder** (comme `.app`).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Cache partagé Dyld

Sur macOS (et iOS), toutes les bibliothèques partagées du système, comme les frameworks et les dylibs, sont **combinées en un seul fichier**, appelé le **cache partagé dyld**. Cela améliore les performances, car le code peut être chargé plus rapidement.

Semblable au cache partagé dyld, le noyau et les extensions de noyau sont également compilés dans un cache de noyau, qui est chargé au démarrage.

Pour extraire les bibliothèques du fichier unique dylib shared cache, il était possible d'utiliser le binaire [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) qui pourrait ne pas fonctionner de nos jours, mais vous pouvez également utiliser [**dyldextractor**](https://github.com/arandomdev/dyldextractor) :

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
```markdown
Dans les versions antérieures, vous pourriez être en mesure de trouver le **cache partagé** dans **`/System/Library/dyld/`**.

Dans iOS, vous pouvez les trouver dans **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Notez que même si l'outil `dyld_shared_cache_util` ne fonctionne pas, vous pouvez passer le **binaire dyld partagé à Hopper** et Hopper sera capable d'identifier toutes les bibliothèques et de vous permettre de **sélectionner celle** que vous souhaitez étudier :
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Permissions de fichiers spéciales

### Permissions de dossier

Dans un **dossier**, **lire** permet de **le lister**, **écrire** permet de **supprimer** et **écrire** des fichiers dedans, et **exécuter** permet de **traverser** le répertoire. Ainsi, par exemple, un utilisateur avec **la permission de lire un fichier** à l'intérieur d'un répertoire où il **n'a pas la permission d'exécuter** **ne pourra pas lire** le fichier.

### Modificateurs de drapeaux

Il existe certains drapeaux qui peuvent être définis dans les fichiers qui feront se comporter le fichier différemment. Vous pouvez **vérifier les drapeaux** des fichiers à l'intérieur d'un répertoire avec `ls -lO /chemin/répertoire`

* **`uchg`** : Connu sous le nom de drapeau **uchange**, il **empêchera toute action** de changer ou de supprimer le **fichier**. Pour le définir, faites : `chflags uchg fichier.txt`
* L'utilisateur root pourrait **retirer le drapeau** et modifier le fichier
* **`restricted`** : Ce drapeau rend le fichier **protégé par SIP** (vous ne pouvez pas ajouter ce drapeau à un fichier).
* **`Sticky bit`** : Si un répertoire avec sticky bit, **seul** le **propriétaire du répertoire ou root peut renommer ou supprimer** des fichiers. Typiquement, cela est défini sur le répertoire /tmp pour empêcher les utilisateurs ordinaires de supprimer ou de déplacer les fichiers d'autres utilisateurs.

### **ACLs de fichiers**

Les **ACLs** de fichiers contiennent des **ACE** (Entrées de Contrôle d'Accès) où des **permissions plus granulaires** peuvent être attribuées à différents utilisateurs.

Il est possible d'accorder à un **répertoire** ces permissions : `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Et à un **fichier** : `read`, `write`, `append`, `execute`.

Lorsque le fichier contient des ACLs, vous **trouverez un "+" lors de l'affichage des permissions comme dans** :
```
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Vous pouvez **lire les ACLs** du fichier avec :
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Vous pouvez trouver **tous les fichiers avec des ACLs** avec (cela est trèèès lent) :
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Fourches de ressources | macOS ADS

C'est une méthode pour obtenir des **Alternate Data Streams dans MacOS**. Vous pouvez enregistrer du contenu dans un attribut étendu appelé **com.apple.ResourceFork** à l'intérieur d'un fichier en le sauvegardant dans **file/..namedfork/rsrc**.
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
```markdown
{% endcode %}

## **Binaires universels &** Format Mach-o

Les binaires de Mac OS sont généralement compilés en tant que **binaires universels**. Un **binaire universel** peut **prendre en charge plusieurs architectures dans le même fichier**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Vidage de mémoire macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Fichiers de catégorie de risque Mac OS

Le fichier `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` contient le risque associé aux fichiers en fonction de l'extension de fichier.

Les catégories possibles incluent :

* **LSRiskCategorySafe**: **Totalement** **sûr** ; Safari ouvrira automatiquement après téléchargement
* **LSRiskCategoryNeutral**: Pas d'avertissement, mais **n'est pas ouvert automatiquement**
* **LSRiskCategoryUnsafeExecutable**: **Déclenche** un **avertissement** « Ce fichier est une application... »
* **LSRiskCategoryMayContainUnsafeExecutable**: Pour des éléments comme les archives contenant un exécutable. Il **déclenche un avertissement à moins que Safari ne puisse déterminer que tout le contenu est sûr ou neutre**.

## Fichiers journaux

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contient des informations sur les fichiers téléchargés, comme l'URL d'où ils ont été téléchargés.
* **`/var/log/system.log`**: Journal principal des systèmes OSX. com.apple.syslogd.plist est responsable de l'exécution de la journalisation système (vous pouvez vérifier s'il est désactivé en cherchant "com.apple.syslogd" dans `launchctl list`).
* **`/private/var/log/asl/*.asl`**: Ce sont les journaux système Apple qui peuvent contenir des informations intéressantes.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Stocke les fichiers et applications récemment accédés via "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Stocke les éléments à lancer au démarrage du système
* **`$HOME/Library/Logs/DiskUtility.log`**: Fichier journal pour l'application DiskUtility (informations sur les lecteurs, y compris les clés USB)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Données sur les points d'accès sans fil.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Liste des démons désactivés.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
