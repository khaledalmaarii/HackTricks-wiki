# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
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
### Autres restrictions

SIP impose également plusieurs autres restrictions. Par exemple, il interdit le **chargement d'extensions de noyau non signées** (kexts) et empêche le **débogage** des processus système de macOS. Il inhibe également des outils comme dtrace de l'inspection des processus système.

## Contournements de SIP

Si un attaquant parvient à contourner SIP, voici ce qu'il pourra faire :

* Lire les mails, messages, l'historique Safari... de tous les utilisateurs
* Accorder des permissions pour la webcam, le microphone ou tout autre chose (en écrivant directement sur la base de données TCC protégée par SIP)
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

[**Des chercheurs de ce billet de blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) ont découvert une vulnérabilité dans le mécanisme de Protection de l'Intégrité du Système (SIP) de macOS, surnommée la vulnérabilité 'Shrootless'. Cette vulnérabilité concerne le daemon **`system_installd`**, qui possède un droit, **`com.apple.rootless.install.heritable`**, permettant à tous ses processus enfants de contourner les restrictions du système de fichiers de SIP.

Le daemon **`system_installd`** installera des paquets qui ont été signés par **Apple**.

Les chercheurs ont découvert que lors de l'installation d'un paquet signé par Apple (.pkg), **`system_installd`** **exécute** tous les scripts **post-installation** inclus dans le paquet. Ces scripts sont exécutés par le shell par défaut, **`zsh`**, qui exécute automatiquement les commandes du fichier **`/etc/zshenv`**, s'il existe, même en mode non interactif. Ce comportement pourrait être exploité par des attaquants : en créant un fichier `/etc/zshenv` malveillant et en attendant que **`system_installd` invoque `zsh`**, ils pourraient effectuer des opérations arbitraires sur l'appareil.

De plus, il a été découvert que **`/etc/zshenv` pourrait être utilisé comme technique d'attaque générale**, pas seulement pour un contournement de SIP. Chaque profil utilisateur a un fichier `~/.zshenv`, qui se comporte de la même manière que `/etc/zshenv` mais ne nécessite pas de permissions root. Ce fichier pourrait être utilisé comme mécanisme de persistance, se déclenchant chaque fois que `zsh` démarre, ou comme mécanisme d'élévation de privilège. Si un utilisateur admin s'élève en root en utilisant `sudo -s` ou `sudo <command>`, le fichier `~/.zshenv` serait déclenché, élevant effectivement en root.

Dans [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) il a été découvert que le même processus **`system_installd`** pouvait encore être abusé car il plaçait le script **post-installation dans un dossier nommé aléatoirement protégé par SIP dans `/tmp`**. Le fait est que **`/tmp` lui-même n'est pas protégé par SIP**, il était donc possible de **monter** une **image virtuelle dessus**, puis l'**installateur** y mettrait le script **post-installation**, **démonterait** l'image virtuelle, **recréerait** tous les **dossiers** et **ajouterait** le script **post-installation** avec le **payload** à exécuter.

### **com.apple.rootless.install**

{% hint style="danger" %}
Le droit **`com.apple.rootless.install`** permet de contourner SIP
{% endhint %}

À partir de [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) Le service XPC système `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possède le droit **`com.apple.rootless.install`**, qui donne au processus la permission de contourner les restrictions de SIP. Il **expose également une méthode pour déplacer des fichiers sans aucune vérification de sécurité.**

## Instantanés de système scellés

Les Instantanés de système scellés sont une fonctionnalité introduite par Apple dans **macOS Big Sur (macOS 11)** dans le cadre de son mécanisme de Protection de l'Intégrité du Système (SIP) pour fournir une couche supplémentaire de sécurité et de stabilité du système. Ce sont essentiellement des versions en lecture seule du volume système.

Voici un regard plus détaillé :

1. **Système immuable** : Les Instantanés de système scellés rendent le volume système de macOS "immuable", ce qui signifie qu'il ne peut pas être modifié. Cela empêche tout changement non autorisé ou accidentel du système qui pourrait compromettre la sécurité ou la stabilité du système.
2. **Mises à jour logicielles du système** : Lorsque vous installez des mises à jour ou des mises à niveau de macOS, macOS crée un nouvel instantané du système. Le volume de démarrage de macOS utilise ensuite **APFS (Apple File System)** pour passer à ce nouvel instantané. Tout le processus d'application des mises à jour devient plus sûr et plus fiable car le système peut toujours revenir à l'instantané précédent si quelque chose se passe mal pendant la mise à jour.
3. **Séparation des données** : En conjonction avec le concept de séparation des volumes de données et système introduit dans macOS Catalina, la fonctionnalité d'Instantanés de système scellés assure que toutes vos données et paramètres sont stockés sur un volume "**Data**" séparé. Cette séparation rend vos données indépendantes du système, ce qui simplifie le processus de mises à jour du système et améliore la sécurité du système.

Rappelez-vous que ces instantanés sont automatiquement gérés par macOS et ne prennent pas d'espace supplémentaire sur votre disque, grâce aux capacités de partage d'espace d'APFS. Il est également important de noter que ces instantanés sont différents des **instantanés Time Machine**, qui sont des sauvegardes accessibles par l'utilisateur de l'ensemble du système.

### Vérifier les instantanés

La commande **`diskutil apfs list`** liste les **détails des volumes APFS** et leur disposition :

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   Référence du conteneur APFS :     disk3
|   Taille (Plafond de capacité) :      494384795648 B (494.4 GB)
|   Capacité utilisée par les volumes :   219214536704 B (219.2 GB) (44.3% utilisé)
|   Capacité non allouée :       275170258944 B (275.2 GB) (55.7% libre)
|   |
|   +-&#x3C; Magasin physique disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   Disque de magasin physique APFS :   disk0s2
|   |   Taille :                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   Disque de volume APFS (Rôle) :   disk3s1 (Système)
</strong>|   |   Nom :                      Macintosh HD (Sensible à la casse)
<strong>|   |   Point de montage :               /System/Volumes/Update/mnt1
</strong>|   |   Capacité consommée :         12819210240 B (12.8 GB)
|   |   Scellé :                    Brisé
|   |   FileVault :                 Oui (Déverrouillé)
|   |   Chiffré :                   Non
|   |   |
|   |   Instantané :                FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Disque de l'instantané :    disk3s1s1
<strong>|   |   Point de montage de l'instantané : /
</strong><strong>|   |   Instantané scellé :            Oui
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   Disque de volume APFS (Rôle) : disk3s5 (Données)
|   Nom :                         Macintosh HD - Données (Sans distinction de casse)
<strong>    |   Point de montage :              /System/Volumes/Data
</strong><strong>    |   Capacité consommée :          412071784448 B (412.1 Go)
</strong>    |   Scellé :                       Non
|   FileVault :                    Oui (Déverrouillé)
</code></pre>

Dans la sortie précédente, il est possible de voir que les **emplacements accessibles par l'utilisateur** sont montés sous `/System/Volumes/Data`.

De plus, **l'instantané du volume système macOS** est monté dans `/` et il est **scellé** (cryptographiquement signé par le système d'exploitation). Ainsi, si SIP est contourné et le modifie, **le système d'exploitation ne démarrera plus**.

Il est également possible de **vérifier que le scellement est activé** en exécutant :
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

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
