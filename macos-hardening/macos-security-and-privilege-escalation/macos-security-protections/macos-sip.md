# macOS SIP

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## **Informations de base**

**La Protection de l'Intégrité du Système (SIP)** dans macOS est un mécanisme conçu pour empêcher même les utilisateurs les plus privilégiés de faire des modifications non autorisées dans les dossiers système clés. Cette fonctionnalité joue un rôle crucial dans le maintien de l'intégrité du système en restreignant des actions telles que l'ajout, la modification ou la suppression de fichiers dans des zones protégées. Les principaux dossiers protégés par SIP incluent :

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Les règles qui régissent le comportement de SIP sont définies dans le fichier de configuration situé à **`/System/Library/Sandbox/rootless.conf`**. Dans ce fichier, les chemins préfixés par un astérisque (\*) sont désignés comme des exceptions aux restrictions strictes de SIP.

Considérez l'exemple ci-dessous:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Cet extrait implique que bien que SIP sécurise généralement le répertoire **`/usr`**, il existe des sous-répertoires spécifiques (`/usr/libexec/cups`, `/usr/local` et `/usr/share/man`) où des modifications sont permises, comme indiqué par l'astérisque (\*) précédant leurs chemins.

Pour vérifier si un répertoire ou un fichier est protégé par SIP, vous pouvez utiliser la commande **`ls -lOd`** pour vérifier la présence du drapeau **`restricted`** ou **`sunlnk`**. Par exemple:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Dans ce cas, le drapeau **`sunlnk`** signifie que le répertoire `/usr/libexec/cups` lui-même **ne peut pas être supprimé**, bien que des fichiers à l'intérieur puissent être créés, modifiés ou supprimés.

D'autre part:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Ici, le drapeau **`restricted`** indique que le répertoire `/usr/libexec` est protégé par SIP. Dans un répertoire protégé par SIP, les fichiers ne peuvent pas être créés, modifiés ou supprimés.

De plus, si un fichier contient l'attribut étendu **`com.apple.rootless`**, ce fichier sera également **protégé par SIP**.

**SIP limite également d'autres actions root** telles que :

* Chargement d'extensions de noyau non fiables
* Obtention de ports de tâche pour les processus signés par Apple
* Modification des variables NVRAM
* Autorisation du débogage du noyau

Les options sont maintenues dans la variable nvram sous forme de bitflag (`csr-active-config` sur Intel et `lp-sip0` est lu à partir de l'arborescence de périphérique démarrée pour ARM). Vous pouvez trouver les drapeaux dans le code source XNU dans `csr.sh` :

<figure><img src="../../../.gitbook/assets/image (1189).png" alt=""><figcaption></figcaption></figure>

### État de SIP

Vous pouvez vérifier si SIP est activé sur votre système avec la commande suivante :
```bash
csrutil status
```
Si vous devez désactiver SIP, vous devez redémarrer votre ordinateur en mode de récupération (en appuyant sur Commande+R au démarrage), puis exécuter la commande suivante :
```bash
csrutil disable
```
Si vous souhaitez conserver SIP activé mais supprimer les protections de débogage, vous pouvez le faire avec :
```bash
csrutil enable --without debug
```
### Autres Restrictions

* **Interdit le chargement d'extensions de noyau non signées** (kexts), garantissant que seules les extensions vérifiées interagissent avec le noyau du système.
* **Empêche le débogage** des processus système macOS, protégeant les composants principaux du système contre tout accès et modification non autorisés.
* **Inhibe les outils** comme dtrace d'inspecter les processus système, renforçant ainsi la protection de l'intégrité du fonctionnement du système.

[**En savoir plus sur les informations SIP dans cette présentation**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

## Contournements de SIP

Contourner SIP permet à un attaquant de :

* **Accéder aux données utilisateur** : Lire des données sensibles des utilisateurs telles que les e-mails, les messages et l'historique de Safari de tous les comptes utilisateurs.
* **Contournement de TCC** : Manipuler directement la base de données TCC (Transparency, Consent, and Control) pour accorder un accès non autorisé à la webcam, au microphone et à d'autres ressources.
* **Établir une persistance** : Placer des logiciels malveillants dans des emplacements protégés par SIP, les rendant résistants à la suppression, même avec des privilèges root. Cela inclut également la possibilité de manipuler l'outil de suppression de logiciels malveillants (MRT).
* **Charger des extensions de noyau** : Bien qu'il existe des protections supplémentaires, contourner SIP simplifie le processus de chargement d'extensions de noyau non signées.

### Packages d'installation

**Les packages d'installation signés avec le certificat d'Apple** peuvent contourner ses protections. Cela signifie que même les packages signés par des développeurs standard seront bloqués s'ils tentent de modifier des répertoires protégés par SIP.

### Fichier SIP inexistant

Une faille potentielle est que si un fichier est spécifié dans **`rootless.conf` mais n'existe pas actuellement**, il peut être créé. Les logiciels malveillants pourraient exploiter cela pour **établir une persistance** sur le système. Par exemple, un programme malveillant pourrait créer un fichier .plist dans `/System/Library/LaunchDaemons` s'il est répertorié dans `rootless.conf` mais n'est pas présent.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
L'entitlement **`com.apple.rootless.install.heritable`** permet de contourner SIP
{% endhint %}

#### Shrootless

[**Des chercheurs de ce billet de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) ont découvert une vulnérabilité dans le mécanisme de Protection de l'Intégrité du Système (SIP) de macOS, appelée la vulnérabilité 'Shrootless'. Cette vulnérabilité tourne autour du démon **`system_installd`**, qui a un entitlement, **`com.apple.rootless.install.heritable`**, permettant à l'un de ses processus enfants de contourner les restrictions du système de fichiers de SIP.

Le démon **`system_installd`** installera des packages signés par **Apple**.

Les chercheurs ont découvert que lors de l'installation d'un package signé par Apple (.pkg), **`system_installd`** **exécute** tous les scripts **post-installation** inclus dans le package. Ces scripts sont exécutés par le shell par défaut, **`zsh`**, qui **exécute automatiquement** les commandes du fichier **`/etc/zshenv`**, s'il existe, même en mode non interactif. Ce comportement pourrait être exploité par des attaquants : en créant un fichier `/etc/zshenv` malveillant et en attendant que **`system_installd` invoque `zsh`**, ils pourraient effectuer des opérations arbitraires sur l'appareil.

De plus, il a été découvert que **`/etc/zshenv` pourrait être utilisé comme une technique d'attaque générale**, pas seulement pour contourner SIP. Chaque profil utilisateur a un fichier `~/.zshenv`, qui se comporte de la même manière que `/etc/zshenv` mais ne nécessite pas de permissions root. Ce fichier pourrait être utilisé comme mécanisme de persistance, se déclenchant à chaque démarrage de `zsh`, ou comme mécanisme d'élévation de privilèges. Si un utilisateur admin élève ses privilèges à root en utilisant `sudo -s` ou `sudo <commande>`, le fichier `~/.zshenv` serait déclenché, élevant effectivement à root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Dans [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/), il a été découvert que le même processus **`system_installd`** pouvait toujours être abusé car il plaçait le **script post-installation dans un dossier nommé aléatoirement protégé par SIP à l'intérieur de `/tmp`**. Le fait est que **`/tmp` n'est pas protégé par SIP**, il était donc possible de **monter** une **image virtuelle dessus**, puis l'**installateur** placerait dans ce dossier le **script post-installation**, **démonterait** l'image virtuelle, **re-créerait** tous les **dossiers** et **ajouterait** le **script de post-installation** avec la **charge utile** à exécuter.

#### [Utilitaire fsck\_cs](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Une vulnérabilité a été identifiée où **`fsck_cs`** a été induit en erreur pour corrompre un fichier crucial, en raison de sa capacité à suivre les **liens symboliques**. Plus précisément, les attaquants ont créé un lien de _`/dev/diskX`_ vers le fichier `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. L'exécution de **`fsck_cs`** sur _`/dev/diskX`_ a conduit à la corruption de `Info.plist`. L'intégrité de ce fichier est vitale pour la Protection de l'Intégrité du Système (SIP) du système d'exploitation, qui contrôle le chargement des extensions de noyau. Une fois corrompu, la capacité de SIP à gérer les exclusions du noyau est compromise.

Les commandes pour exploiter cette vulnérabilité sont :
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
L'exploitation de cette vulnérabilité a des implications graves. Le fichier `Info.plist`, normalement responsable de la gestion des autorisations pour les extensions du noyau, devient inefficace. Cela inclut l'incapacité de mettre sur liste noire certaines extensions, telles que `AppleHWAccess.kext`. Par conséquent, avec le mécanisme de contrôle du SIP hors service, cette extension peut être chargée, accordant un accès en lecture et en écriture non autorisé à la RAM du système.

#### [Monter sur des dossiers protégés par SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Il était possible de monter un nouveau système de fichiers sur **des dossiers protégés par SIP pour contourner la protection**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Contournement de la mise à niveau (2016)](https://objective-see.org/blog/blog\_0x14.html)

Le système est configuré pour démarrer à partir d'une image disque d'installateur intégrée dans `Install macOS Sierra.app` pour mettre à niveau le système d'exploitation, en utilisant l'utilitaire `bless`. La commande utilisée est la suivante :
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
La sécurité de ce processus peut être compromise si un attaquant modifie l'image de mise à niveau (`InstallESD.dmg`) avant le démarrage. La stratégie consiste à substituer un chargeur dynamique (dyld) par une version malveillante (`libBaseIA.dylib`). Ce remplacement entraîne l'exécution du code de l'attaquant lorsque l'installateur est lancé.

Le code de l'attaquant prend le contrôle pendant le processus de mise à niveau, exploitant la confiance du système envers l'installateur. L'attaque se poursuit en modifiant l'image `InstallESD.dmg` via le swizzling de méthode, ciblant en particulier la méthode `extractBootBits`. Cela permet l'injection de code malveillant avant l'utilisation de l'image disque.

De plus, dans `InstallESD.dmg`, il y a un `BaseSystem.dmg`, qui sert de système de fichiers racine du code de mise à niveau. L'injection d'une bibliothèque dynamique dans cela permet au code malveillant de fonctionner dans un processus capable de modifier des fichiers au niveau du système d'exploitation, augmentant considérablement le potentiel de compromission du système.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Dans cette présentation de [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), il est montré comment **`systemmigrationd`** (qui peut contourner SIP) exécute un script **bash** et un script **perl**, qui peuvent être exploités via les variables d'environnement **`BASH_ENV`** et **`PERL5OPT`**.

### **com.apple.rootless.install**

{% hint style="danger" %}
L'entitlement **`com.apple.rootless.install`** permet de contourner SIP
{% endhint %}

L'entitlement `com.apple.rootless.install` est connu pour contourner la Protection de l'Intégrité du Système (SIP) sur macOS. Cela a été notamment mentionné en relation avec [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

Dans ce cas spécifique, le service XPC système situé à `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possède cet entitlement. Cela permet au processus associé de contourner les contraintes de SIP. De plus, ce service présente notamment une méthode qui permet le déplacement de fichiers sans appliquer de mesures de sécurité.

## Instantanés Système Scellés

Les Instantanés Système Scellés sont une fonctionnalité introduite par Apple dans **macOS Big Sur (macOS 11)** dans le cadre de son mécanisme de **Protection de l'Intégrité du Système (SIP)** pour fournir une couche supplémentaire de sécurité et de stabilité du système. Ce sont essentiellement des versions en lecture seule du volume système.

Voici un aperçu plus détaillé :

1. **Système Immuable** : Les Instantanés Système Scellés rendent le volume système macOS "immuable", ce qui signifie qu'il ne peut pas être modifié. Cela empêche toute modification non autorisée ou accidentelle du système qui pourrait compromettre la sécurité ou la stabilité du système.
2. **Mises à Jour du Logiciel Système** : Lorsque vous installez des mises à jour ou des mises à niveau macOS, macOS crée un nouveau instantané système. Le volume de démarrage macOS utilise ensuite **APFS (Apple File System)** pour basculer vers ce nouvel instantané. Tout le processus d'application des mises à jour devient plus sûr et fiable car le système peut toujours revenir à l'instantané précédent en cas de problème lors de la mise à jour.
3. **Séparation des Données** : En conjonction avec le concept de séparation des volumes de Données et du Système introduit dans macOS Catalina, la fonctionnalité d'Instantanés Système Scellés garantit que toutes vos données et paramètres sont stockés sur un volume "**Données**" séparé. Cette séparation rend vos données indépendantes du système, ce qui simplifie le processus de mise à jour du système et améliore la sécurité du système.

Rappelez-vous que ces instantanés sont automatiquement gérés par macOS et n'occupent pas d'espace supplémentaire sur votre disque, grâce aux capacités de partage d'espace d'APFS. Il est également important de noter que ces instantanés sont différents des **instantanés Time Machine**, qui sont des sauvegardes accessibles par l'utilisateur de l'ensemble du système.

### Vérifier les Instantanés

La commande **`diskutil apfs list`** affiche les **détails des volumes APFS** et leur disposition :

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   Référence du Conteneur APFS :     disk3
|   Taille (Capacité Maximale) :      494384795648 B (494,4 Go)
|   Capacité Utilisée par les Volumes :   219214536704 B (219,2 Go) (44,3% utilisé)
|   Capacité Non Allouée :       275170258944 B (275,2 Go) (55,7% libre)
|   |
|   +-&#x3C; Stockage Physique disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   Disque de Stockage Physique APFS :   disk0s2
|   |   Taille :                       494384795648 B (494,4 Go)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   Disque de Volume APFS (Rôle) :   disk3s1 (Système)
</strong>|   |   Nom :                      Macintosh HD (insensible à la casse)
<strong>|   |   Point de Montage :               /System/Volumes/Update/mnt1
</strong>|   |   Capacité Consommée :         12819210240 B (12,8 Go)
|   |   Scellé :                    Cassé
|   |   FileVault :                 Oui (Déverrouillé)
|   |   Chiffré :                 Non
|   |   |
|   |   Instantané :                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Disque de l'Instantané :             disk3s1s1
<strong>|   |   Point de Montage de l'Instantané :      /
</strong><strong>|   |   Instantané Scellé :           Oui
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Disque de Volume APFS (Rôle) :   disk3s5 (Données)
|   Nom :                      Macintosh HD - Données (insensible à la casse)
<strong>    |   Point de Montage :               /System/Volumes/Data
</strong><strong>    |   Capacité Consommée :         412071784448 B (412,1 Go)
</strong>    |   Scellé :                    Non
|   FileVault :                 Oui (Déverrouillé)
</code></pre>

Dans la sortie précédente, il est possible de voir que les **emplacements accessibles par l'utilisateur** sont montés sous `/System/Volumes/Data`.

De plus, l'**instantané du volume système macOS** est monté dans `/` et il est **scellé** (signé cryptographiquement par le système d'exploitation). Ainsi, si SIP est contourné et le modifie, le **système d'exploitation ne démarrera plus**.

Il est également possible de **vérifier que le scellement est activé** en exécutant :
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
De plus, le disque de snapshot est également monté en **lecture seule**:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

D'autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
