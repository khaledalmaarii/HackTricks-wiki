# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Informations de base**

**System Integrity Protection (SIP)** est une technologie de sécurité dans macOS qui protège certains répertoires système contre les accès non autorisés, même pour l'utilisateur root. Elle empêche les modifications de ces répertoires, y compris la création, la modification ou la suppression de fichiers. Les principaux répertoires que SIP protège sont :

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Les règles de protection pour ces répertoires et leurs sous-répertoires sont spécifiées dans le fichier **`/System/Library/Sandbox/rootless.conf`**. Dans ce fichier, les chemins commençant par une étoile (\*) représentent des exceptions aux restrictions de SIP.

Par exemple, la configuration suivante :
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
indique que le répertoire **`/usr`** est généralement protégé par SIP. Cependant, des modifications sont autorisées dans les trois sous-répertoires spécifiés (`/usr/libexec/cups`, `/usr/local` et `/usr/share/man`), car ils sont listés avec un astérisque initial (\*).

Pour vérifier si un répertoire ou un fichier est protégé par SIP, vous pouvez utiliser la commande **`ls -lOd`** pour vérifier la présence du drapeau **`restricted`** ou **`sunlnk`**. Par exemple :
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Dans ce cas, le drapeau **`sunlnk`** signifie que le répertoire `/usr/libexec/cups` lui-même **ne peut pas être supprimé**, bien que les fichiers à l'intérieur puissent être créés, modifiés ou supprimés.

D'autre part :
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Ici, le drapeau **`restricted`** indique que le répertoire `/usr/libexec` est protégé par SIP. Dans un répertoire protégé par SIP, les fichiers ne peuvent pas être créés, modifiés ou supprimés.

De plus, si un fichier contient l'attribut étendu **`com.apple.rootless`**, ce fichier sera également **protégé par SIP**.

**SIP limite également d'autres actions du root** telles que :

* Charger des extensions de noyau non fiables
* Obtenir des task-ports pour les processus signés par Apple
* Modifier les variables NVRAM
* Autoriser le débogage du noyau

Les options sont maintenues dans la variable nvram comme un bitflag (`csr-active-config` sur Intel et `lp-sip0` est lu à partir de l'arbre de périphériques démarré pour ARM). Vous pouvez trouver les drapeaux dans le code source XNU dans `csr.sh` :

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### Statut de SIP

Vous pouvez vérifier si SIP est activé sur votre système avec la commande suivante :
```bash
csrutil status
```
Si vous devez désactiver SIP, vous devez redémarrer votre ordinateur en mode de récupération (en appuyant sur Commande+R pendant le démarrage), puis exécuter la commande suivante :
```bash
csrutil disable
```
Si vous souhaitez conserver SIP activé mais supprimer les protections de débogage, vous pouvez le faire avec :
```bash
csrutil enable --without debug
```
### Autres Restrictions

SIP impose également plusieurs autres restrictions. Par exemple, il interdit le **chargement d'extensions de noyau non signées** (kexts) et empêche le **débogage** des processus système de macOS. Il inhibe également des outils comme dtrace d'inspecter les processus système.

[Plus d'infos sur SIP dans cette présentation](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).

## Contournements de SIP

Si un attaquant parvient à contourner SIP, voici ce qu'il pourra faire :

* Lire les mails, messages, l'historique Safari... de tous les utilisateurs
* Accorder des permissions pour la webcam, le microphone ou tout autre chose (en écrivant directement sur la base de données TCC protégée par SIP) - contournement de TCC
* Persistance : Il pourrait sauvegarder un malware dans un emplacement protégé par SIP et même root ne pourra pas le supprimer. Il pourrait également altérer MRT.
* Facilité pour charger des extensions de noyau (même si d'autres protections hardcore sont en place pour cela).

### Paquets d'installation

**Les paquets d'installation signés avec le certificat d'Apple** peuvent contourner ses protections. Cela signifie que même les paquets signés par des développeurs standards seront bloqués s'ils tentent de modifier des répertoires protégés par SIP.

### Fichier SIP inexistant

Une faille potentielle est que si un fichier est spécifié dans **`rootless.conf` mais n'existe pas actuellement**, il peut être créé. Un malware pourrait exploiter cela pour **établir une persistance** sur le système. Par exemple, un programme malveillant pourrait créer un fichier .plist dans `/System/Library/LaunchDaemons` s'il est listé dans `rootless.conf` mais absent.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Le droit **`com.apple.rootless.install.heritable`** permet de contourner SIP
{% endhint %}

#### Shrootless

[**Des chercheurs de ce billet de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) ont découvert une vulnérabilité dans le mécanisme de Protection de l'Intégrité du Système (SIP) de macOS, surnommée la vulnérabilité 'Shrootless'. Cette vulnérabilité concerne le daemon **`system_installd`**, qui possède un droit, **`com.apple.rootless.install.heritable`**, permettant à tous ses processus enfants de contourner les restrictions du système de fichiers de SIP.

Le daemon **`system_installd`** installera des paquets qui ont été signés par **Apple**.

Les chercheurs ont découvert que lors de l'installation d'un paquet signé par Apple (.pkg), **`system_installd`** **exécute** tous les scripts **post-installation** inclus dans le paquet. Ces scripts sont exécutés par le shell par défaut, **`zsh`**, qui exécute automatiquement les commandes du fichier **`/etc/zshenv`**, s'il existe, même en mode non interactif. Ce comportement pourrait être exploité par des attaquants : en créant un fichier `/etc/zshenv` malveillant et en attendant que **`system_installd` invoque `zsh`**, ils pourraient effectuer des opérations arbitraires sur l'appareil.

De plus, il a été découvert que **`/etc/zshenv` pourrait être utilisé comme technique d'attaque générale**, pas seulement pour un contournement de SIP. Chaque profil utilisateur a un fichier `~/.zshenv`, qui se comporte de la même manière que `/etc/zshenv` mais ne nécessite pas de permissions root. Ce fichier pourrait être utilisé comme mécanisme de persistance, se déclenchant chaque fois que `zsh` démarre, ou comme mécanisme d'élévation de privilège. Si un utilisateur admin s'élève en root en utilisant `sudo -s` ou `sudo <command>`, le fichier `~/.zshenv` serait déclenché, élevant effectivement en root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Dans [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/), il a été découvert que le même processus **`system_installd`** pouvait encore être abusé car il plaçait le script **post-installation dans un dossier nommé aléatoirement protégé par SIP dans `/tmp`**. Le fait est que **`/tmp` lui-même n'est pas protégé par SIP**, il était donc possible de **monter** une **image virtuelle dessus**, puis l'**installateur** y mettrait le script **post-installation**, **démonterait** l'image virtuelle, **recréerait** tous les **dossiers** et **ajouterait** le script **post-installation** avec le **payload** à exécuter.

#### [utilitaire fsck\_cs](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Le contournement a exploité le fait que **`fsck_cs`** suivrait les **liens symboliques** et tenterait de réparer le système de fichiers qui lui est présenté.

Ainsi, un attaquant pourrait créer un lien symbolique pointant de _`/dev/diskX`_ vers `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` et invoquer **`fsck_cs`** sur le premier. Comme le fichier `Info.plist` devient corrompu, le système d'exploitation ne pourrait **plus contrôler les exclusions d'extensions de noyau**, contournant ainsi SIP.

{% code overflow="wrap" %}
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
{% endcode %}

Le fichier Info.plist mentionné précédemment, maintenant détruit, est utilisé par **SIP pour mettre sur liste blanche certaines extensions de noyau** et spécifiquement **bloquer** **d'autres** pour empêcher leur chargement. Normalement, il met sur liste noire l'extension de noyau propre à Apple **`AppleHWAccess.kext`**, mais avec le fichier de configuration détruit, nous pouvons maintenant la charger et l'utiliser pour lire et écrire à notre guise dans et depuis la RAM du système.

#### [Monter sur des dossiers protégés par SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Il était possible de monter un nouveau système de fichiers sur **des dossiers protégés par SIP pour contourner la protection**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Contournement de la mise à niveau (2016)](https://objective-see.org/blog/blog\_0x14.html)

Lorsqu'exécutée, l'application de mise à niveau/installation (par exemple `Install macOS Sierra.app`) prépare le système pour démarrer à partir d'une image disque d'installation (qui est intégrée dans l'application téléchargée). Cette image disque d'installation contient la logique pour mettre à niveau le système d'exploitation, par exemple de OS X El Capitan à macOS Sierra.

Afin de démarrer le système à partir de l'image de mise à niveau/installation (`InstallESD.dmg`), l'application `Install macOS Sierra.app` utilise l'utilitaire **`bless`** (qui hérite de l'entitlement `com.apple.rootless.install.heritable`):

{% code overflow="wrap" %}
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
{% endcode %}

Par conséquent, si un attaquant peut modifier l'image de mise à niveau (`InstallESD.dmg`) avant que le système ne démarre à partir de celle-ci, il peut contourner SIP.

La méthode pour modifier l'image afin de l'infecter consistait à remplacer un chargeur dynamique (dyld) qui chargerait et exécuterait naïvement la bibliothèque dynamique malveillante dans le contexte de l'application. Comme la bibliothèque dynamique **`libBaseIA`**. Ainsi, chaque fois que l'application d'installation est lancée par l'utilisateur (c'est-à-dire pour mettre à jour le système), notre bibliothèque dynamique malveillante (nommée libBaseIA.dylib) sera également chargée et exécutée dans l'installateur.

Maintenant 'à l'intérieur' de l'application d'installation, nous pouvons contrôler cette phase du processus de mise à niveau. Puisque l'installateur va 'bénir' l'image, tout ce que nous avons à faire est de subvertir l'image, **`InstallESD.dmg`**, avant qu'elle ne soit utilisée. Il était possible de faire cela en accrochant la méthode **`extractBootBits`** avec un swizzling de méthode.\
Ayant le code malveillant exécuté juste avant que l'image disque soit utilisée, il est temps de l'infecter.

À l'intérieur de `InstallESD.dmg`, il y a une autre image disque intégrée `BaseSystem.dmg` qui est le 'système de fichiers racine' du code de mise à niveau. Il était possible d'injecter une bibliothèque dynamique dans le `BaseSystem.dmg` pour que le code malveillant soit exécuté dans le contexte d'un processus capable de modifier des fichiers au niveau du système d'exploitation.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Dans cette présentation de [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), il est montré comment **`systemmigrationd`** (qui peut contourner SIP) exécute un script **bash** et un script **perl**, qui peuvent être abusés via les variables d'environnement **`BASH_ENV`** et **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Le droit **`com.apple.rootless.install`** permet de contourner SIP
{% endhint %}

D'après [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) Le service XPC système `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possède le droit **`com.apple.rootless.install`**, qui accorde au processus la permission de contourner les restrictions SIP. Il **expose également une méthode pour déplacer des fichiers sans aucun contrôle de sécurité.**

## Instantanés de Système Scellés

Les Instantanés de Système Scellés sont une fonctionnalité introduite par Apple dans **macOS Big Sur (macOS 11)** dans le cadre de son mécanisme de **Protection de l'Intégrité du Système (SIP)** pour fournir une couche supplémentaire de sécurité et de stabilité du système. Ce sont essentiellement des versions en lecture seule du volume système.

Voici un regard plus détaillé :

1. **Système Immutable** : Les Instantanés de Système Scellés rendent le volume système de macOS "immutable", ce qui signifie qu'il ne peut pas être modifié. Cela empêche tout changement non autorisé ou accidentel du système qui pourrait compromettre la sécurité ou la stabilité du système.
2. **Mises à Jour du Logiciel Système** : Lorsque vous installez des mises à jour ou des mises à niveau de macOS, macOS crée un nouvel instantané système. Le volume de démarrage de macOS utilise ensuite **APFS (Apple File System)** pour passer à ce nouvel instantané. Le processus entier d'application des mises à jour devient plus sûr et plus fiable car le système peut toujours revenir à l'instantané précédent si quelque chose se passe mal pendant la mise à jour.
3. **Séparation des Données** : En conjonction avec le concept de séparation des volumes de Données et Système introduit dans macOS Catalina, la fonctionnalité d'Instantanés de Système Scellés assure que toutes vos données et paramètres sont stockés sur un volume "**Données**" séparé. Cette séparation rend vos données indépendantes du système, ce qui simplifie le processus de mises à jour du système et améliore la sécurité du système.

Rappelez-vous que ces instantanés sont automatiquement gérés par macOS et ne prennent pas d'espace supplémentaire sur votre disque, grâce aux capacités de partage d'espace d'APFS. Il est également important de noter que ces instantanés sont différents des **instantanés Time Machine**, qui sont des sauvegardes accessibles par l'utilisateur de l'ensemble du système.

### Vérifier les Instantanés

La commande **`diskutil apfs list`** liste les **détails des volumes APFS** et leur disposition :

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

Dans la sortie précédente, il est possible de voir que les **emplacements accessibles par l'utilisateur** sont montés sous `/System/Volumes/Data`.

De plus, **l'instantané du volume système macOS** est monté dans `/` et il est **scellé** (cryptographiquement signé par le système d'exploitation). Ainsi, si SIP est contourné et le modifie, le **système d'exploitation ne démarrera plus**.

Il est également possible de **vérifier que le scellé est activé** en exécutant :
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
En outre, le disque instantané est également monté en **lecture seule** :
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
