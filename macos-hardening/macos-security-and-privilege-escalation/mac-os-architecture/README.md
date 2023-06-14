# Noyau macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Noyau XNU

Le **cœur de macOS est XNU**, qui signifie "X is Not Unix". Ce noyau est fondamentalement composé du **micro-noyau Mach** (à discuter plus tard), **et** d'éléments de la distribution de logiciels Berkeley (**BSD**). XNU fournit également une plate-forme pour les **pilotes de noyau via un système appelé I/O Kit**. Le noyau XNU fait partie du projet open source Darwin, ce qui signifie que **son code source est librement accessible**.

Du point de vue d'un chercheur en sécurité ou d'un développeur Unix, **macOS** peut sembler assez **similaire** à un système **FreeBSD** avec une interface graphique élégante et une multitude d'applications personnalisées. La plupart des applications développées pour BSD se compileront et s'exécuteront sur macOS sans avoir besoin de modifications, car les outils en ligne de commande familiers aux utilisateurs Unix sont tous présents dans macOS. Cependant, parce que le noyau XNU intègre Mach, il existe des différences significatives entre un système de type Unix traditionnel et macOS, et ces différences peuvent causer des problèmes potentiels ou offrir des avantages uniques.

### Mach

Mach est un **micro-noyau** conçu pour être **compatible avec UNIX**. L'un de ses principes clés de conception était de **minimiser** la quantité de **code** s'exécutant dans l'espace du **noyau** et de permettre plutôt à de nombreuses fonctions de noyau typiques, telles que le système de fichiers, le réseau et l'E/S, de **s'exécuter en tant que tâches de niveau utilisateur**.

Dans XNU, Mach est **responsable de nombreuses opérations de bas niveau critiques** qu'un noyau gère généralement, telles que la planification du processeur, le multitâche et la gestion de la mémoire virtuelle.

### BSD

Le noyau XNU **intègre également** une quantité importante de code dérivé du projet **FreeBSD**. Ce code **s'exécute en tant que partie du noyau avec Mach**, dans le même espace d'adressage. Cependant, le code FreeBSD dans XNU peut différer considérablement du code FreeBSD original car des modifications ont été nécessaires pour assurer sa compatibilité avec Mach. FreeBSD contribue à de nombreuses opérations de noyau, notamment :

* Gestion des processus
* Gestion des signaux
* Mécanismes de sécurité de base, y compris la gestion des utilisateurs et des groupes
* Infrastructure d'appel système
* Pile TCP/IP et sockets
* Pare-feu et filtrage de paquets

Comprendre l'interaction entre BSD et Mach peut être complexe, en raison de leurs cadres conceptuels différents. Par exemple, BSD utilise des processus comme unité d'exécution fondamentale, tandis que Mach fonctionne sur la base de threads. Cette divergence est conciliée dans XNU en **associant chaque processus BSD à une tâche Mach** qui contient exactement un thread Mach. Lorsque l'appel système fork() de BSD est utilisé, le code BSD dans le noyau utilise des fonctions Mach pour créer une tâche et une structure de thread.

De plus, **Mach et BSD maintiennent chacun des modèles de sécurité différents** : le modèle de sécurité de **Mach** est basé sur les **droits de port**, tandis que le modèle de sécurité de BSD fonctionne sur la base de la **propriété de processus**. Les disparités entre ces deux modèles ont parfois entraîné des vulnérabilités d'escalade de privilèges locales. Outre les appels système typiques, il existe également des **trappes Mach qui permettent aux programmes de l'espace utilisateur d'interagir avec le noyau**. Ces différents éléments forment ensemble l'architecture hybride et multifacette du noyau macOS.

### I/O Kit - Pilotes

I/O Kit est le framework open source, orienté objet, de **pilotes de périphériques** dans le noyau XNU et est responsable de l'ajout et de la gestion des **pilotes de périphériques chargés dynamiquement**. Ces pilotes permettent l'ajout de code modulaire au noyau de manière dynamique pour une utilisation avec différents matériels, par exemple. Ils se trouvent dans :

* `/System/Library/Extensions`
  * Fichiers KEXT intégrés au système d'exploitation OS X.
* `/Library/Extensions`
  * Fichiers KEXT installés par des logiciels tiers.
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
    1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
   10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Jusqu'au numéro 9, les pilotes répertoriés sont **chargés à l'adresse 0**. Cela signifie qu'il ne s'agit pas de vrais pilotes mais **d'une partie du noyau et qu'ils ne peuvent pas être déchargés**.

Pour trouver des extensions spécifiques, vous pouvez utiliser:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Pour charger et décharger des extensions de noyau, faites :
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
### IPC - Communication Inter-Processus

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

## Extensions du noyau macOS

macOS est **très restrictif pour charger les extensions du noyau** (.kext) en raison des privilèges élevés avec lesquels le code s'exécutera. En fait, par défaut, c'est pratiquement impossible (à moins qu'une faille ne soit trouvée).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Extensions système macOS

Au lieu d'utiliser des extensions du noyau, macOS a créé les extensions système, qui offrent des API de niveau utilisateur pour interagir avec le noyau. De cette façon, les développeurs peuvent éviter d'utiliser des extensions du noyau.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Références

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
