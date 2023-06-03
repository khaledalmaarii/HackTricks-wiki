# Artéfacts Windows

## Artéfacts Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Artéfacts Windows génériques

### Notifications Windows 10

Dans le chemin `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`, vous pouvez trouver la base de données `appdb.dat` (avant l'anniversaire de Windows) ou `wpndatabase.db` (après l'anniversaire de Windows).

Dans cette base de données SQLite, vous pouvez trouver la table `Notification` avec toutes les notifications (au format XML) qui peuvent contenir des données intéressantes.

### Chronologie

La chronologie est une caractéristique de Windows qui fournit un historique **chronologique** des pages Web visitées, des documents édités et des applications exécutées.

La base de données réside dans le chemin `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Cette base de données peut être ouverte avec un outil SQLite ou avec l'outil [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **qui génère 2 fichiers qui peuvent être ouverts avec l'outil** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (flux de données alternatifs)

Les fichiers téléchargés peuvent contenir la **zone ADS.Identifier** indiquant **comment** il a été **téléchargé** depuis l'intranet, l'internet, etc. Certains logiciels (comme les navigateurs) mettent généralement encore **plus** **d'informations** comme l'**URL** à partir de laquelle le fichier a été téléchargé.

## **Sauvegardes de fichiers**

### Corbeille

Dans Vista/Win7/Win8/Win10, la **Corbeille** peut être trouvée dans le dossier **`$Recycle.bin`** à la racine du lecteur (`C:\$Recycle.bin`).\
Lorsqu'un fichier est supprimé dans ce dossier, 2 fichiers spécifiques sont créés :

* `$I{id}` : Informations sur le fichier (date de suppression)
* `$R{id}` : Contenu du fichier

![](<../../../.gitbook/assets/image (486).png>)

En ayant ces fichiers, vous pouvez utiliser l'outil [**Rifiuti**](https://github.com/abelcheung/rifiuti2) pour obtenir l'adresse originale des fichiers supprimés et la date à laquelle ils ont été supprimés (utilisez `rifiuti-vista.exe` pour Vista - Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Copies d'ombre de volume

Shadow Copy est une technologie incluse dans Microsoft Windows qui peut créer des **copies de sauvegarde** ou des instantanés de fichiers ou de volumes informatiques, même lorsqu'ils sont en cours d'utilisation.

Ces sauvegardes sont généralement situées dans le dossier `\System Volume Information` à partir de la racine du système de fichiers et le nom est composé d'**UID** comme indiqué dans l'image suivante :

![](<../../../.gitbook/assets/image (520).png>)

En montant l'image de la forensique avec **ArsenalImageMounter**, l'outil [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) peut être utilisé pour inspecter une copie d'ombre et même **extraire les fichiers** des sauvegardes de copie d'ombre.

![](<../../../.gitbook/assets/image (521).png>)

L'entrée de registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contient les fichiers et les clés **à ne pas sauvegarder** :

![](<../../../.gitbook/assets/image (522).png>)

Le registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contient également des informations de configuration sur les `copies d'ombre de volume`.

### Fichiers Office AutoSaved

Vous pouvez trouver les fichiers Office autosauvegardés dans : `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Éléments de Shell

Un élément de shell est un élément qui contient des informations sur la façon d'accéder à un autre fichier.

### Documents récents (LNK)

Windows **crée automatiquement** ces **raccourcis** lorsque l'utilisateur **ouvre, utilise ou crée un fichier** dans :

* Win7-Win10 : `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office : `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Lorsqu'un dossier est créé, un lien vers le dossier, le dossier parent et le dossier grand-parent est également créé.

Ces fichiers de lien créés automatiquement **contiennent des informations sur l'origine** comme s'il s'agit d'un **fichier** **ou** d'un **dossier**, des **horodatages MAC** de ce fichier, des **informations de volume** de l'emplacement où le fichier est stocké et du **dossier du fichier cible**. Ces informations peuvent être utiles pour récupérer ces fichiers en cas de suppression.

De plus, la **date de création du lien** est la première **fois** où le fichier d'origine a été **utilisé** et la **date de modification du lien** est la **dernière fois** où le fichier d'origine a été utilisé.

Pour inspecter ces fichiers, vous pouvez utiliser [**LinkParser**](http://4discovery.com/our-tools/).

Dans cet outil, vous trouverez **2 ensembles** de horodatages :

* **Premier ensemble :**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
* **Deuxième ensemble :**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

Le premier ensemble d'horodatages fait référence aux **horodatages du fichier lui-même**. Le deuxième ensemble fait référence aux **horodatages du fichier lié**.

Vous pouvez obtenir les mêmes informations en exécutant l'outil de ligne de commande Windows : [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Dans ce cas, les informations vont être enregistrées dans un fichier CSV.

### Jumplists

Ce sont les fichiers récents indiqués par application. C'est la liste des **fichiers récents utilisés par une application** auxquels vous pouvez accéder sur chaque application. Ils peuvent être créés **automatiquement ou personnalisés**.

Les **jumplists** créés automatiquement sont stockés dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Les jumplists sont nommés selon le format `{id}.autmaticDestinations-ms` où l'ID initial est l'ID de l'application.

Les jumplists personnalisés sont stockés dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` et sont créés par l'application généralement parce que quelque chose **d'important** s'est produit avec le fichier (peut-être marqué comme favori).

L'heure de création de n'importe quelle jumplist indique la **première fois que le fichier a été accédé** et l'heure de modification la dernière fois.

Vous pouvez inspecter les jumplists en utilisant [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Notez que les horodatages fournis par JumplistExplorer sont liés au fichier jumplist lui-même_)

### Shellbags

[**Suivez ce lien pour savoir ce que sont les shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Utilisation des clés USB Windows

Il est possible d'identifier qu'un périphérique USB a été utilisé grâce à la création de :

* Dossier récent Windows
* Dossier récent Microsoft Office
* Jumplists

Notez que certains fichiers LNK, au lieu de pointer vers le chemin d'origine, pointent vers le dossier WPDNSE :

![](<../../../.gitbook/assets/image (476).png>)

Les fichiers du dossier WPDNSE sont une copie de ceux d'origine, ils ne survivront donc pas à un redémarrage du PC et le GUID est pris à partir d'un shellbag.

### Informations du registre

[Vérifiez cette page pour savoir](interesting-windows-registry-keys.md#usb-information) quels clés de registre contiennent des informations intéressantes sur les périphériques USB connectés.

### setupapi

Vérifiez le fichier `C:\Windows\inf\setupapi.dev.log` pour obtenir les horodatages sur quand la connexion USB a été produite (recherchez `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (6).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) peut être utilisé pour obtenir des informations sur les périphériques USB qui ont été connectés à une image.

![](<../../../.gitbook/assets/image (483).png>)

### Nettoyage Plug and Play

La tâche planifiée "Nettoyage Plug and Play" est responsable de **supprimer** les versions obsolètes des pilotes. Il semblerait (selon des rapports en ligne) qu'elle supprime également les **pilotes qui n'ont pas été utilisés depuis 30 jours**, bien que sa description indique que "la version la plus récente de chaque package de pilotes sera conservée". En tant que tel, **les périphériques amovibles qui n'ont pas été connectés depuis 30 jours peuvent avoir leurs pilotes supprimés**.

La tâche planifiée elle-même est située à 'C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup', et son contenu est affiché ci-dessous :

![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

La tâche fait référence à 'pnpclean.dll' qui est responsable de l'activité de nettoyage, en outre, nous voyons que le champ ‘UseUnifiedSchedulingEngine’ est défini sur ‘TRUE’ ce qui spécifie que le
### BAM (Background Activity Moderator)

Vous pouvez ouvrir le fichier `SYSTEM` avec un éditeur de registre et à l'intérieur du chemin `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, vous pouvez trouver les informations sur les **applications exécutées par chaque utilisateur** (notez le `{SID}` dans le chemin) et à **quelle heure** elles ont été exécutées (l'heure est à l'intérieur de la valeur de données du registre).

### Windows Prefetch

Le prefetching est une technique qui permet à un ordinateur de **récupérer silencieusement les ressources nécessaires pour afficher le contenu** qu'un utilisateur **pourrait accéder dans un proche avenir** afin que les ressources puissent être accédées plus rapidement.

Le prefetching de Windows consiste à créer des **caches des programmes exécutés** pour pouvoir les charger plus rapidement. Ces caches sont créés sous forme de fichiers `.pf` dans le chemin : `C:\Windows\Prefetch`. Il y a une limite de 128 fichiers dans XP/VISTA/WIN7 et 1024 fichiers dans Win8/Win10.

Le nom de fichier est créé comme `{nom_du_programme}-{hash}.pf` (le hash est basé sur le chemin et les arguments de l'exécutable). Dans W10, ces fichiers sont compressés. Notez que la simple présence du fichier indique que **le programme a été exécuté** à un moment donné.

Le fichier `C:\Windows\Prefetch\Layout.ini` contient les **noms des dossiers des fichiers qui sont prefetchés**. Ce fichier contient des **informations sur le nombre d'exécutions**, les **dates** d'exécution et les **fichiers** **ouverts** par le programme.

Pour inspecter ces fichiers, vous pouvez utiliser l'outil [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) :
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** a le même objectif que prefetch, **charger les programmes plus rapidement** en prédisant ce qui va être chargé ensuite. Cependant, il ne remplace pas le service prefetch.\
Ce service générera des fichiers de base de données dans `C:\Windows\Prefetch\Ag*.db`.

Dans ces bases de données, vous pouvez trouver le **nom** du **programme**, le **nombre** d'**exécutions**, les **fichiers** **ouverts**, le **volume** **accédé**, le **chemin** **complet**, les **plages** **temporelles** et les **horodatages**.

Vous pouvez accéder à ces informations en utilisant l'outil [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **surveille** les **ressources** **consommées** **par un processus**. Il est apparu dans W8 et stocke les données dans une base de données ESE située dans `C:\Windows\System32\sru\SRUDB.dat`.

Il fournit les informations suivantes :

* ID de l'application et chemin d'accès
* Utilisateur ayant exécuté le processus
* Octets envoyés
* Octets reçus
* Interface réseau
* Durée de la connexion
* Durée du processus

Ces informations sont mises à jour toutes les 60 minutes.

Vous pouvez obtenir les données de ce fichier en utilisant l'outil [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Le **Shimcache**, également connu sous le nom de **AppCompatCache**, est un composant de la **base de données de compatibilité des applications**, créée par **Microsoft** et utilisée par le système d'exploitation pour identifier les problèmes de compatibilité des applications.

Le cache stocke diverses métadonnées de fichiers en fonction du système d'exploitation, telles que:

* Chemin complet du fichier
* Taille du fichier
* **$Standard\_Information** (SI) Heure de dernière modification
* Heure de dernière mise à jour du ShimCache
* Indicateur d'exécution de processus

Ces informations peuvent être trouvées dans le registre à:

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
  * XP (96 entrées)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
  * Server 2003 (512 entrées)
  * 2008/2012/2016 Win7/Win8/Win10 (1024 entrées)

Vous pouvez utiliser l'outil [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) pour analyser ces informations.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Le fichier **Amcache.hve** est un fichier de registre qui stocke les informations des applications exécutées. Il est situé dans `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** enregistre les processus récents qui ont été exécutés et liste le chemin des fichiers qui sont exécutés, ce qui peut ensuite être utilisé pour trouver le programme exécuté. Il enregistre également le SHA1 du programme.

Vous pouvez analyser ces informations avec l'outil [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser)
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
Le fichier CVS le plus intéressant généré est le fichier `Amcache_Unassociated file entries`.

### RecentFileCache

Cet artefact ne peut être trouvé que dans W7 dans `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` et il contient des informations sur l'exécution récente de certains binaires.

Vous pouvez utiliser l'outil [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) pour analyser le fichier.

### Tâches planifiées

Vous pouvez les extraire de `C:\Windows\Tasks` ou `C:\Windows\System32\Tasks` et les lire en tant que XML.

### Services

Vous pouvez les trouver dans le registre sous `SYSTEM\ControlSet001\Services`. Vous pouvez voir ce qui va être exécuté et quand.

### **Windows Store**

Les applications installées peuvent être trouvées dans `\ProgramData\Microsoft\Windows\AppRepository\`\
Ce référentiel a un **journal** avec **chaque application installée** dans le système à l'intérieur de la base de données **`StateRepository-Machine.srd`**.

Dans la table Application de cette base de données, il est possible de trouver les colonnes : "Application ID", "PackageNumber" et "Display Name". Ces colonnes contiennent des informations sur les applications préinstallées et installées et il est possible de savoir si certaines applications ont été désinstallées car les ID des applications installées doivent être séquentiels.

Il est également possible de **trouver des applications installées** dans le chemin du registre : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Et des **applications désinstallées** dans : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Événements Windows

Les informations qui apparaissent dans les événements Windows sont :

* Ce qui s'est passé
* Horodatage (UTC + 0)
* Utilisateurs impliqués
* Hôtes impliqués (nom d'hôte, IP)
* Actifs accessibles (fichiers, dossiers, imprimantes, services)

Les journaux sont situés dans `C:\Windows\System32\config` avant Windows Vista et dans `C:\Windows\System32\winevt\Logs` après Windows Vista. Avant Windows Vista, les journaux d'événements étaient au format binaire et après, ils sont au format **XML** et utilisent l'extension **.evtx**.

L'emplacement des fichiers d'événements peut être trouvé dans le registre SYSTEM dans **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Ils peuvent être visualisés à partir de l'Observateur d'événements Windows (**`eventvwr.msc`**) ou avec d'autres outils comme [**Event Log Explorer**](https://eventlogxp.com) **ou** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

### Sécurité

Cela enregistre les événements d'accès et donne des informations sur la configuration de sécurité qui peut être trouvée dans `C:\Windows\System32\winevt\Security.evtx`.

La **taille maximale** du fichier d'événements est configurable et il commencera à écraser les anciens événements lorsque la taille maximale est atteinte.

Les événements qui sont enregistrés comme :

* Connexion/Déconnexion
* Actions de l'utilisateur
* Accès aux fichiers, dossiers et actifs partagés
* Modification de la configuration de sécurité

Événements liés à l'authentification de l'utilisateur :

| EventID   | Description                  |
| --------- | ---------------------------- |
| 4624      | Authentification réussie     |
| 4625      | Erreur d'authentification    |
| 4634/4647 | Déconnexion                  |
| 4672      | Connexion avec des autorisations d'administrateur |

À l'intérieur de l'EventID 4634/4647, il y a des sous-types intéressants :

* **2 (interactif)** : La connexion était interactive en utilisant le clavier ou un logiciel comme VNC ou `PSexec -U-`
* **3 (réseau)** : Connexion à un dossier partagé
* **4 (lot)** : Processus exécuté
* **5 (service)** : Service démarré par le Gestionnaire de contrôle des services
* **6 (proxy)** : Connexion proxy
* **7 (déverrouillage)** : Écran déverrouillé en utilisant un mot de passe
* **8 (texte clair réseau)** : Utilisateur authentifié en envoyant des mots de passe en clair. Cet événement venait de l'IIS
* **9 (nouvelles informations d'identification)** : Il est généré lorsque la commande `RunAs` est utilisée ou que l'utilisateur accède à un service réseau avec des informations d'identification différentes.
* **10 (interactif à distance)** : Authentification via Terminal Services ou RDP
* **11 (cache interactif)** : Accès en utilisant les dernières informations d'identification mises en cache car il n'a pas été possible de contacter le contrôleur de domaine
* **12 (cache interactif à distance)** : Connexion à distance avec des informations d'identification mises en cache (une combinaison de 10 et 11).
* **13 (déverrouillage mis en cache)** : Déverrouiller une machine verrouillée avec des informations d'identification mises en cache.

Dans ce post, vous pouvez trouver comment imiter tous ces types de connexion et dans lesquels vous pourrez extraire les informations d'identification de la mémoire : [https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

Les informations d'état et de sous-état des événements peuvent indiquer plus de détails sur les causes de l'événement. Par exemple, jetez un coup d'œil aux codes d'état et de sous-état suivants de l'ID d'événement 4625 :

![](<../../../.gitbook/assets/image (455).png>)

### Récupération des événements Windows

Il est fortement recommandé d'éteindre l'ordinateur suspect en le **débranchant** pour maximiser la probabilité de récupération des événements Windows. Dans le cas où ils ont été supprimés, un outil qui peut être utile pour essayer de les récupérer est [**Bulk\_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor) en indiquant l'extension **evtx**.

## Identification des attaques courantes avec les événements Windows

### Attaque par force brute

Une attaque par force brute peut être facilement identifiable car **plusieurs EventIDs 4625 apparaîtront**. Si l'attaque a été **réussie**, après les EventIDs 4625, **un EventID 4624 apparaîtra**.

### Changement de temps

C'est terrible pour l'équipe de forensique car tous les horodatages seront modifiés. Cet événement est enregistré par l'EventID 4616 dans le journal d'événements de sécurité.

### Périphériques USB

Les EventIDs système suivants sont utiles :

* 20001 / 20003 / 10000 : Première fois qu'il a été utilisé
* 10100 : Mise à jour du pilote

L'EventID 112 de DeviceSetupManager contient l'horodatage de chaque périphérique USB inséré.

### Allumage / Extinction

L'ID 6005 du service "Journal des événements" indique que l'ordinateur a été allumé. L'ID 6006 indique qu'il a été éteint.

### Suppression des journaux

L'EventID de sécurité 1102 indique que les journaux ont été supprimés.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annon
