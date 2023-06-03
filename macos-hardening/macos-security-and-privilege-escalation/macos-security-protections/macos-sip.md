## **Informations de base**

**System Integrity Protection (SIP)** est une technologie de sécurité dans macOS qui protège certains répertoires système contre l'accès non autorisé, même pour l'utilisateur root. Il empêche les modifications de ces répertoires, y compris la création, la modification ou la suppression de fichiers. Les principaux répertoires que SIP protège sont :

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Les règles de protection pour ces répertoires et leurs sous-répertoires sont spécifiées dans le fichier **`/System/Library/Sandbox/rootless.conf`**. Dans ce fichier, les chemins commençant par un astérisque (\*) représentent des exceptions aux restrictions de SIP.

Par exemple, la configuration suivante :
```javascript
javascriptCopy code/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Indique que le répertoire **`/usr`** est généralement protégé par SIP. Cependant, des modifications sont autorisées dans les trois sous-répertoires spécifiés (`/usr/libexec/cups`, `/usr/local` et `/usr/share/man`), car ils sont répertoriés avec un astérisque en tête (\*).

Pour vérifier si un répertoire ou un fichier est protégé par SIP, vous pouvez utiliser la commande **`ls -lOd`** pour vérifier la présence du drapeau **`restricted`** ou **`sunlnk`**. Par exemple:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Dans ce cas, le drapeau **`sunlnk`** signifie que le répertoire `/usr/libexec/cups` lui-même ne peut pas être supprimé, bien que des fichiers à l'intérieur puissent être créés, modifiés ou supprimés.

D'autre part:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Ici, le drapeau **`restricted`** indique que le répertoire `/usr/libexec` est protégé par SIP. Dans un répertoire protégé par SIP, les fichiers ne peuvent pas être créés, modifiés ou supprimés.

### État de SIP

Vous pouvez vérifier si SIP est activé sur votre système avec la commande suivante :
```bash
csrutil status
```
Si vous devez désactiver SIP, vous devez redémarrer votre ordinateur en mode de récupération (en appuyant sur Commande+R au démarrage), puis exécuter la commande suivante:
```bash
csrutil disable
```
Si vous souhaitez conserver SIP activé mais supprimer les protections de débogage, vous pouvez le faire avec:
```bash
csrutil enable --without debug
```
### Autres restrictions

SIP impose également plusieurs autres restrictions. Par exemple, il interdit le **chargement d'extensions de noyau non signées** (kexts) et empêche le **débogage** des processus système de macOS. Il empêche également des outils tels que dtrace d'inspecter les processus système.

## Contournements de SIP

### Packages d'installation

Les **packages d'installation signés avec le certificat d'Apple** peuvent contourner ses protections. Cela signifie que même les packages signés par des développeurs standard seront bloqués s'ils tentent de modifier les répertoires protégés par SIP.

### Fichier SIP inexistant

Une faille potentielle est que si un fichier est spécifié dans **`rootless.conf` mais n'existe pas actuellement**, il peut être créé. Les logiciels malveillants pourraient exploiter cela pour **établir une persistance** sur le système. Par exemple, un programme malveillant pourrait créer un fichier .plist dans `/System/Library/LaunchDaemons` s'il est répertorié dans `rootless.conf` mais n'est pas présent.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
L'entitlement **`com.apple.rootless.install.heritable`** permet de contourner SIP
{% endhint %}

[**Des chercheurs de ce billet de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) ont découvert une vulnérabilité dans le mécanisme de protection de l'intégrité du système (SIP) de macOS, appelée vulnérabilité 'Shrootless'. Cette vulnérabilité concerne le démon `system_installd`, qui possède un entitlement, **`com.apple.rootless.install.heritable`**, qui permet à l'un de ses processus enfants de contourner les restrictions du système de fichiers de SIP.

Les chercheurs ont découvert que lors de l'installation d'un package signé par Apple (.pkg), **`system_installd`** **exécute** tous les scripts **post-installation** inclus dans le package. Ces scripts sont exécutés par le shell par défaut, **`zsh`**, qui exécute automatiquement les commandes du fichier **`/etc/zshenv`**, s'il existe, même en mode non interactif. Cette fonctionnalité pourrait être exploitée par des attaquants : en créant un fichier malveillant `/etc/zshenv` et en attendant que `system_installd` invoque `zsh`, ils pourraient effectuer des opérations arbitraires sur l'appareil.

De plus, il a été découvert que **`/etc/zshenv` pourrait être utilisé comme technique d'attaque générale**, pas seulement pour contourner SIP. Chaque profil utilisateur possède un fichier `~/.zshenv`, qui se comporte de la même manière que `/etc/zshenv` mais ne nécessite pas de permissions root. Ce fichier pourrait être utilisé comme mécanisme de persistance, se déclenchant à chaque démarrage de `zsh`, ou comme mécanisme d'élévation de privilèges. Si un utilisateur admin élève ses privilèges en utilisant `sudo -s` ou `sudo <commande>`, le fichier `~/.zshenv` serait déclenché, permettant ainsi une élévation de privilèges effective.

### **com.apple.rootless.install**

{% hint style="danger" %}
L'entitlement **`com.apple.rootless.install`** permet de contourner SIP
{% endhint %}

À partir de [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/), le service XPC système `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possède l'entitlement **`com.apple.rootless.install`**, qui accorde au processus l'autorisation de contourner les restrictions de SIP. Il **expose également une méthode pour déplacer des fichiers sans aucune vérification de sécurité.**

## Instantanés de système scellés

Les instantanés de système scellés sont une fonctionnalité introduite par Apple dans **macOS Big Sur (macOS 11)** dans le cadre de son mécanisme de protection de l'intégrité du système (SIP) pour fournir une couche de sécurité et de stabilité supplémentaire au système. Ce sont essentiellement des versions en lecture seule du volume système.

Voici un aperçu plus détaillé :

1. **Système immuable** : les instantanés de système scellés rendent le volume système de macOS "immuable", ce qui signifie qu'il ne peut pas être modifié. Cela empêche toute modification non autorisée ou accidentelle du système qui pourrait compromettre la sécurité ou la stabilité du système.
2. **Mises à jour du logiciel système** : lorsque vous installez des mises à jour ou des mises à niveau de macOS, macOS crée un nouvel instantané système. Le volume de démarrage de macOS utilise ensuite **APFS (Apple File System)** pour passer à ce nouvel instantané. Tout le processus de mise à jour devient plus sûr et plus fiable, car le système peut toujours revenir à l'instantané précédent en cas de problème pendant la mise à jour.
3. **Séparation des données** : en conjonction avec le concept de séparation des volumes de données et de système introduit dans macOS Catalina, la fonctionnalité d'instantanés de système scellés garantit que toutes vos données et paramètres sont stockés sur un volume "**Données**" séparé. Cette séparation rend vos données indépendantes du système, ce qui simplifie le processus de mise à jour du système et améliore la sécurité du système.

N'oubliez pas que ces instantanés sont gérés automatiquement par macOS et ne prennent pas d'espace supplémentaire sur votre disque, grâce aux capacités de partage d'espace d'APFS. Il est également important de noter que ces instantanés sont différents des **instantanés Time Machine**, qui sont des sauvegardes accessibles par l'utilisateur de l'ensemble du système.

### Vérifier les instantanés

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
|   |   APFS Volume Disk (Role):   disk3s1 (System)
|   |   Name:                      Macintosh HD (Case-insensitive)
|   |   Mount Point:               /System/Volumes/Update/mnt1
|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
|   |   Snapshot Mount Point:      /
<strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
</code></pre>

Dans la sortie précédente, il est possible de voir que **l'instantané du volume système de macOS est scellé** (signé cryptographiquement par le système d'exploitation). Ainsi, si SIP est contourné et modifié, le **système d'exploitation ne démarrera plus**.

Il est également possible de vérifier que le scellement est activé en exécutant :
```
csrutil authenticated-root status
Authenticated Root status: enabled
```
De plus, il est monté en **lecture seule**:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
