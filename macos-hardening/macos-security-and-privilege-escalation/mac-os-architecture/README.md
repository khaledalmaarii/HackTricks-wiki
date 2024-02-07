# Noyau macOS & Extensions Système

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Noyau XNU

Le **cœur de macOS est XNU**, qui signifie "X is Not Unix". Ce noyau est fondamentalement composé du **micro-noyau Mach** (à discuter plus tard), **et** d'éléments de la distribution logicielle de Berkeley (**BSD**). XNU fournit également une plateforme pour les **pilotes de noyau via un système appelé l'I/O Kit**. Le noyau XNU fait partie du projet open source Darwin, ce qui signifie que **son code source est librement accessible**.

Du point de vue d'un chercheur en sécurité ou d'un développeur Unix, **macOS** peut sembler assez **similaire** à un système **FreeBSD** avec une interface graphique élégante et une multitude d'applications personnalisées. La plupart des applications développées pour BSD se compileront et s'exécuteront sur macOS sans nécessiter de modifications, car les outils en ligne de commande familiers aux utilisateurs Unix sont tous présents dans macOS. Cependant, étant donné que le noyau XNU intègre Mach, il existe des différences significatives entre un système de type Unix traditionnel et macOS, et ces différences pourraient entraîner des problèmes potentiels ou offrir des avantages uniques.

Version open source de XNU : [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach est un **micro-noyau** conçu pour être **compatible avec UNIX**. Un de ses principes de conception clés était de **minimiser** la quantité de **code** s'exécutant dans l'espace du **noyau** et de permettre à de nombreuses fonctions de noyau typiques, telles que le système de fichiers, le réseau et l'E/S, de **s'exécuter en tant que tâches de niveau utilisateur**.

Dans XNU, Mach est **responsable de nombreuses opérations de bas niveau critiques** qu'un noyau gère généralement, telles que la planification du processeur, le multitâche et la gestion de la mémoire virtuelle.

### BSD

Le noyau XNU **intègre également** une quantité significative de code dérivé du projet **FreeBSD**. Ce code **s'exécute en tant que partie du noyau avec Mach**, dans le même espace d'adressage. Cependant, le code FreeBSD au sein de XNU peut différer considérablement du code FreeBSD original car des modifications ont été nécessaires pour assurer sa compatibilité avec Mach. FreeBSD contribue à de nombreuses opérations de noyau, notamment :

* Gestion des processus
* Gestion des signaux
* Mécanismes de sécurité de base, y compris la gestion des utilisateurs et des groupes
* Infrastructure des appels système
* Pile TCP/IP et sockets
* Pare-feu et filtrage de paquets

Comprendre l'interaction entre BSD et Mach peut être complexe en raison de leurs cadres conceptuels différents. Par exemple, BSD utilise les processus comme unité d'exécution fondamentale, tandis que Mach fonctionne sur la base des threads. Cette divergence est conciliée dans XNU en **associant chaque processus BSD à une tâche Mach** contenant exactement un thread Mach. Lorsque l'appel système fork() de BSD est utilisé, le code BSD au sein du noyau utilise des fonctions Mach pour créer une structure de tâche et de thread.

De plus, **Mach et BSD maintiennent chacun des modèles de sécurité différents** : le modèle de sécurité de **Mach** est basé sur les **droits de port**, tandis que le modèle de sécurité de BSD fonctionne sur la base de la **propriété des processus**. Les disparités entre ces deux modèles ont parfois entraîné des vulnérabilités d'escalade de privilèges locales. Outre les appels système classiques, il existe également des **trappes Mach qui permettent aux programmes de l'espace utilisateur d'interagir avec le noyau**. Ces différents éléments forment ensemble l'architecture hybride et multifacette du noyau macOS.

### I/O Kit - Pilotes

L'I/O Kit est un **cadre de pilote de périphérique orienté objet open source** dans le noyau XNU, qui gère les **pilotes de périphériques chargés dynamiquement**. Il permet d'ajouter du code modulaire au noyau à la volée, prenant en charge une variété de matériels.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Communication Inter Processus

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

Le **kernelcache** est une version **pré-compilée et pré-liée du noyau XNU**, avec des **pilotes de périphériques essentiels** et des **extensions de noyau**. Il est stocké dans un **format compressé** et est décompressé en mémoire lors du processus de démarrage. Le kernelcache facilite un **démarrage plus rapide** en ayant une version prête à l'emploi du noyau et des pilotes essentiels disponibles, réduisant ainsi le temps et les ressources qui seraient autrement dépensés pour charger et lier dynamiquement ces composants au démarrage.

Dans iOS, il se trouve dans **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** ; dans macOS, vous pouvez le trouver avec **`find / -name kernelcache 2>/dev/null`**

#### IMG4

Le format de fichier IMG4 est un format de conteneur utilisé par Apple dans ses appareils iOS et macOS pour **stocker et vérifier de manière sécurisée** les composants du micrologiciel (comme le **kernelcache**). Le format IMG4 comprend un en-tête et plusieurs balises qui encapsulent différentes parties de données, y compris la charge utile réelle (comme un noyau ou un chargeur de démarrage), une signature et un ensemble de propriétés de manifeste. Le format prend en charge la vérification cryptographique, permettant au périphérique de confirmer l'authenticité et l'intégrité du composant du micrologiciel avant de l'exécuter.

Il est généralement composé des composants suivants :

* **Charge utile (IM4P)** :
* Souvent compressé (LZFSE4, LZSS, ...)
* Optionnellement chiffré
* **Manifeste (IM4M)** :
* Contient une signature
* Dictionnaire clé/valeur supplémentaire
* **Informations de restauration (IM4R)** :
* Aussi connu sous le nom de APNonce
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

Parfois, Apple publie le **kernelcache** avec des **symboles**. Vous pouvez télécharger certains firmwares avec des symboles en suivant les liens sur [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Ce sont des **firmwares** Apple que vous pouvez télécharger depuis [**https://ipsw.me/**](https://ipsw.me/). Parmi les autres fichiers, il contiendra le **kernelcache**.\
Pour **extraire** les fichiers, vous pouvez simplement les **dézipper**.

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

Avec cela, nous pouvons maintenant **extraire toutes les extensions** ou **celle qui vous intéresse :**
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

macOS est **très restrictif pour charger les extensions du noyau** (.kext) en raison des privilèges élevés avec lesquels le code s'exécutera. En fait, par défaut, il est pratiquement impossible (à moins de trouver une faille).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Extensions système macOS

Au lieu d'utiliser des extensions du noyau, macOS a créé les extensions système, qui offrent des API au niveau utilisateur pour interagir avec le noyau. De cette manière, les développeurs peuvent éviter d'utiliser des extensions du noyau.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Références

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
