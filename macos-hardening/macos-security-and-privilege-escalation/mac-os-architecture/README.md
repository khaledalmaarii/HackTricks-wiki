# Architecture du noyau et des extensions système macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Noyau XNU

Le **cœur de macOS est XNU**, ce qui signifie "X is Not Unix". Ce noyau est fondamentalement composé du **micro-noyau Mach** (dont nous parlerons plus tard) et d'éléments de la distribution Berkeley Software Distribution (**BSD**). XNU fournit également une plateforme pour les **pilotes de noyau via un système appelé I/O Kit**. Le noyau XNU fait partie du projet open source Darwin, ce qui signifie que **son code source est librement accessible**.

Du point de vue d'un chercheur en sécurité ou d'un développeur Unix, **macOS** peut sembler assez **similaire** à un système **FreeBSD** avec une interface graphique élégante et une multitude d'applications personnalisées. La plupart des applications développées pour BSD se compileront et s'exécuteront sur macOS sans nécessiter de modifications, car les outils en ligne de commande familiers aux utilisateurs Unix sont tous présents dans macOS. Cependant, étant donné que le noyau XNU intègre Mach, il existe des différences significatives entre un système de type Unix traditionnel et macOS, et ces différences peuvent poser des problèmes potentiels ou offrir des avantages uniques.

Version open source de XNU : [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach est un **micro-noyau** conçu pour être **compatible avec UNIX**. Un de ses principes de conception clés était de **minimiser** la quantité de **code** s'exécutant dans l'espace du **noyau** et de permettre plutôt à de nombreuses fonctions de noyau typiques, telles que le système de fichiers, le réseau et l'E/S, de **s'exécuter en tant que tâches de niveau utilisateur**.

Dans XNU, Mach est **responsable de nombreuses opérations de bas niveau critiques** qu'un noyau gère généralement, telles que la planification du processeur, le multitâche et la gestion de la mémoire virtuelle.

### BSD

Le noyau XNU **intègre également** une quantité importante de code dérivé du projet **FreeBSD**. Ce code **s'exécute en tant que partie du noyau avec Mach**, dans le même espace d'adressage. Cependant, le code FreeBSD dans XNU peut différer considérablement du code FreeBSD original car des modifications ont été nécessaires pour assurer sa compatibilité avec Mach. FreeBSD contribue à de nombreuses opérations du noyau, notamment :

* Gestion des processus
* Gestion des signaux
* Mécanismes de sécurité de base, y compris la gestion des utilisateurs et des groupes
* Infrastructure des appels système
* Pile TCP/IP et sockets
* Pare-feu et filtrage des paquets

Comprendre l'interaction entre BSD et Mach peut être complexe en raison de leurs cadres conceptuels différents. Par exemple, BSD utilise des processus comme unité d'exécution fondamentale, tandis que Mach fonctionne sur la base de threads. Cette disparité est conciliée dans XNU en **associant chaque processus BSD à une tâche Mach** qui contient exactement un thread Mach. Lorsque l'appel système fork() de BSD est utilisé, le code BSD dans le noyau utilise les fonctions Mach pour créer une tâche et une structure de thread.

De plus, **Mach et BSD maintiennent chacun des modèles de sécurité différents** : le modèle de sécurité de Mach est basé sur les **droits de port**, tandis que le modèle de sécurité de BSD fonctionne sur la base de la **propriété du processus**. Les disparités entre ces deux modèles ont parfois entraîné des vulnérabilités d'escalade de privilèges locales. Outre les appels système classiques, il existe également des **trappes Mach qui permettent aux programmes de l'espace utilisateur d'interagir avec le noyau**. Ces différents éléments forment ensemble l'architecture hybride et multifacette du noyau macOS.

### I/O Kit - Pilotes

I/O Kit est le framework open source orienté objet de **gestion des pilotes de périphériques** dans le noyau XNU et est responsable de l'ajout et de la gestion des **pilotes de périphériques chargés dynamiquement**. Ces pilotes permettent d'ajouter du code modulaire au noyau de manière dynamique pour une utilisation avec différents matériels, par exemple.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Communication inter-processus

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

Le **kernelcache** est une version **précompilée et pré-liée du noyau XNU**, ainsi que des **pilotes de périphériques essentiels** et des **extensions de noyau**. Il est stocké dans un format **compressé** et est décompressé en mémoire lors du processus de démarrage. Le kernelcache facilite un **démarrage plus rapide** en ayant une version prête à l'emploi du noyau et des pilotes essentiels disponibles, ce qui réduit le temps et les ressources qui seraient sinon consacrés au chargement et à la liaison dynamique de ces composants au démarrage.

Dans iOS, il se trouve dans **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** et dans macOS, vous pouvez le trouver avec **`find / -name kernelcache 2>/dev/null`**.
#### IMG4

Le format de fichier IMG4 est un format de conteneur utilisé par Apple dans ses appareils iOS et macOS pour stocker et vérifier de manière sécurisée les composants du micrologiciel (comme le **kernelcache**). Le format IMG4 comprend un en-tête et plusieurs balises qui encapsulent différentes parties de données, y compris la charge utile réelle (comme un noyau ou un chargeur de démarrage), une signature et un ensemble de propriétés de manifeste. Le format prend en charge la vérification cryptographique, permettant à l'appareil de confirmer l'authenticité et l'intégrité du composant du micrologiciel avant de l'exécuter.

Il est généralement composé des éléments suivants :

* **Charge utile (IM4P)** :
* Souvent compressée (LZFSE4, LZSS, ...)
* Optionnellement chiffrée
* **Manifeste (IM4M)** :
* Contient une signature
* Dictionnaire clé/valeur supplémentaire
* **Informations de restauration (IM4R)** :
* Également connu sous le nom de APNonce
* Empêche la relecture de certaines mises à jour
* FACULTATIF : Habituellement, cela n'est pas trouvé

Décompressez le Kernelcache :
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Symboles du Kernelcache

Parfois, Apple publie des **kernelcache** avec des **symboles**. Vous pouvez télécharger certains firmwares avec des symboles en suivant les liens sur [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Ce sont des **firmwares** Apple que vous pouvez télécharger depuis [**https://ipsw.me/**](https://ipsw.me/). Parmi les autres fichiers, il contient le **kernelcache**.\
Pour **extraire** les fichiers, vous pouvez simplement les **décompresser**.

Après avoir extrait le firmware, vous obtiendrez un fichier tel que : **`kernelcache.release.iphone14`**. Il est au format **IMG4**, vous pouvez extraire les informations intéressantes avec :

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
Vous pouvez vérifier les symboles extraits du kernelcache avec: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Avec cela, nous pouvons maintenant extraire toutes les extensions ou celle qui vous intéresse:
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Extensions du noyau macOS

macOS est **très restrictif pour charger les extensions du noyau** (.kext) en raison des privilèges élevés avec lesquels le code s'exécute. En fait, par défaut, il est pratiquement impossible de le faire (à moins de trouver une faille).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Extensions système macOS

Au lieu d'utiliser des extensions du noyau, macOS a créé les extensions système, qui offrent des API de niveau utilisateur pour interagir avec le noyau. De cette manière, les développeurs peuvent éviter d'utiliser des extensions du noyau.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Références

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
