# Artefacts Windows

## Artefacts Windows

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Artefacts Windows Génériques

### Notifications Windows 10

Dans le chemin `\Users\<nom_utilisateur>\AppData\Local\Microsoft\Windows\Notifications`, vous pouvez trouver la base de données `appdb.dat` (avant l'anniversaire de Windows) ou `wpndatabase.db` (après l'anniversaire de Windows).

À l'intérieur de cette base de données SQLite, vous pouvez trouver la table `Notification` avec toutes les notifications (au format XML) qui peuvent contenir des données intéressantes.

### Chronologie

La chronologie est une caractéristique de Windows qui fournit un **historique chronologique** des pages Web visitées, des documents édités et des applications exécutées.

La base de données se trouve dans le chemin `\Users\<nom_utilisateur>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Cette base de données peut être ouverte avec un outil SQLite ou avec l'outil [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **qui génère 2 fichiers pouvant être ouverts avec l'outil** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### Flux de données alternatifs (ADS)

Les fichiers téléchargés peuvent contenir la **zone ADS (Alternate Data Streams)** indiquant **comment** il a été **téléchargé** depuis l'intranet, Internet, etc. Certains logiciels (comme les navigateurs) mettent généralement **encore plus** **d'informations** comme l'**URL** à partir de laquelle le fichier a été téléchargé.

## **Sauvegardes de fichiers**

### Corbeille

Dans Vista/Win7/Win8/Win10, la **Corbeille** se trouve dans le dossier **`$Recycle.bin`** à la racine du lecteur (`C:\$Recycle.bin`).\
Lorsqu'un fichier est supprimé dans ce dossier, 2 fichiers spécifiques sont créés :

* `$I{id}` : Informations sur le fichier (date de suppression)
* `$R{id}` : Contenu du fichier

![](<../../../.gitbook/assets/image (486).png>)

En ayant ces fichiers, vous pouvez utiliser l'outil [**Rifiuti**](https://github.com/abelcheung/rifiuti2) pour obtenir l'adresse d'origine des fichiers supprimés et la date de suppression (utilisez `rifiuti-vista.exe` pour Vista - Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Copies d'ombre du volume

Shadow Copy est une technologie incluse dans Microsoft Windows qui peut créer des **copies de sauvegarde** ou des instantanés de fichiers ou de volumes d'ordinateur, même lorsqu'ils sont en cours d'utilisation.

Ces sauvegardes sont généralement situées dans le dossier `\System Volume Information` à la racine du système de fichiers et le nom est composé d'**UID** comme indiqué dans l'image suivante :

![](<../../../.gitbook/assets/image (520).png>)

En montant l'image forensique avec l'outil **ArsenalImageMounter**, l'outil [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) peut être utilisé pour inspecter une copie d'ombre et même **extraire les fichiers** des sauvegardes de copie d'ombre.

![](<../../../.gitbook/assets/image (521).png>)

L'entrée de registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contient les fichiers et clés **à ne pas sauvegarder** :

![](<../../../.gitbook/assets/image (522).png>)

Le registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contient également des informations de configuration sur les `Copies d'ombre du volume`.

### Fichiers Office AutoSaved

Vous pouvez trouver les fichiers autosauvegardés d'Office dans : `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Éléments de Shell

Un élément de shell est un élément qui contient des informations sur la manière d'accéder à un autre fichier.

### Documents récents (LNK)

Windows **crée automatiquement** ces **raccourcis** lorsque l'utilisateur **ouvre, utilise ou crée un fichier** dans :

* Win7-Win10 : `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office : `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Lorsqu'un dossier est créé, un lien vers le dossier, vers le dossier parent et le dossier grand-parent est également créé.

Ces fichiers de lien créés automatiquement **contiennent des informations sur l'origine** comme s'il s'agit d'un **fichier** ou d'un **dossier**, les **horodatages MAC** de ce fichier, les **informations de volume** où le fichier est stocké et le **dossier du fichier cible**. Ces informations peuvent être utiles pour récupérer ces fichiers en cas de suppression.

De plus, la **date de création du fichier de lien** est la première **fois** où le fichier d'origine a été **utilisé** et la **date de modification** du fichier de lien est la **dernière** **fois** où le fichier d'origine a été utilisé.

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

Le premier ensemble de horodatages fait référence aux **horodatages du fichier lui-même**. Le deuxième ensemble fait référence aux **horodatages du fichier lié**.

Vous pouvez obtenir les mêmes informations en exécutant l'outil en ligne de commande Windows : [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### Jumplists

Ce sont les fichiers récents indiqués par application. C'est la liste des **fichiers récemment utilisés par une application** auxquels vous pouvez accéder sur chaque application. Ils peuvent être créés **automatiquement ou personnalisés**.

Les **jumplists** créés automatiquement sont stockés dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Les jumplists sont nommés selon le format `{id}.autmaticDestinations-ms` où l'ID initial est l'ID de l'application.

Les jumplists personnalisés sont stockés dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` et sont créés par l'application généralement parce que quelque chose d'**important** s'est produit avec le fichier (peut-être marqué comme favori).

Le **temps de création** de toute jumplist indique **la première fois que le fichier a été consulté** et le **temps de modification la dernière fois**.

Vous pouvez inspecter les jumplists en utilisant [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Notez que les horodatages fournis par JumplistExplorer sont liés au fichier jumplist lui-même_)

### Shellbags

[**Suivez ce lien pour en savoir plus sur les shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Utilisation des clés USB Windows

Il est possible d'identifier l'utilisation d'un périphérique USB grâce à la création de :

* Dossier récent de Windows
* Dossier récent de Microsoft Office
* Jumplists

Notez que certains fichiers LNK, au lieu de pointer vers le chemin d'origine, pointent vers le dossier WPDNSE :

![](<../../../.gitbook/assets/image (476).png>)

Les fichiers dans le dossier WPDNSE sont une copie des fichiers originaux, ils ne survivront donc pas à un redémarrage du PC et le GUID est extrait d'un shellbag.

### Informations du Registre

[Consultez cette page pour en savoir plus](interesting-windows-registry-keys.md#usb-information) sur les clés de registre contenant des informations intéressantes sur les périphériques USB connectés.

### setupapi

Consultez le fichier `C:\Windows\inf\setupapi.dev.log` pour obtenir les horodatages sur quand la connexion USB a été établie (recherchez `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) peut être utilisé pour obtenir des informations sur les périphériques USB qui ont été connectés à une image.

![](<../../../.gitbook/assets/image (483).png>)

### Nettoyage Plug and Play

La tâche planifiée connue sous le nom de 'Nettoyage Plug and Play' est principalement conçue pour supprimer les versions obsolètes des pilotes. Contrairement à son objectif spécifié de conserver la dernière version du package de pilotes, des sources en ligne suggèrent qu'elle cible également les pilotes inactifs depuis 30 jours. Par conséquent, les pilotes des périphériques amovibles non connectés au cours des 30 derniers jours peuvent être supprimés.

La tâche est située dans le chemin suivant :
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Une capture d'écran du contenu de la tâche est fournie :
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Composants clés et paramètres de la tâche :**
- **pnpclean.dll** : Cette DLL est responsable du processus de nettoyage réel.
- **UseUnifiedSchedulingEngine** : Défini sur `TRUE`, indiquant l'utilisation du moteur de planification de tâches générique.
- **MaintenanceSettings** :
- **Période ('P1M')** : Indique au Planificateur de tâches de lancer la tâche de nettoyage mensuellement pendant la maintenance automatique régulière.
- **Date limite ('P2M')** : Instruit le Planificateur de tâches, si la tâche échoue pendant deux mois consécutifs, d'exécuter la tâche pendant la maintenance automatique d'urgence.

Cette configuration garantit une maintenance régulière et un nettoyage des pilotes, avec des dispositions pour réessayer la tâche en cas d'échecs consécutifs.

**Pour plus d'informations, consultez :** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Les emails contiennent **2 parties intéressantes : Les en-têtes et le contenu** de l'email. Dans les **en-têtes**, vous pouvez trouver des informations telles que :

* **Qui** a envoyé les emails (adresse e-mail, IP, serveurs de messagerie ayant redirigé l'e-mail)
* **Quand** l'e-mail a été envoyé

De plus, dans les en-têtes `References` et `In-Reply-To`, vous pouvez trouver l'ID des messages :

![](<../../../.gitbook/assets/image (484).png>)

### Application Courrier Windows

Cette application enregistre les emails en HTML ou en texte. Vous pouvez trouver les emails dans des sous-dossiers à l'intérieur de `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Les emails sont enregistrés avec l'extension `.dat`.

Les **métadonnées** des emails et les **contacts** peuvent être trouvés à l'intérieur de la base de données **EDB** : `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Changez l'extension** du fichier de `.vol` à `.edb` et vous pouvez utiliser l'outil [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) pour l'ouvrir. À l'intérieur de la table `Message`, vous pouvez voir les emails.

### Microsoft Outlook

Lorsque des serveurs Exchange ou des clients Outlook sont utilisés, il y aura quelques en-têtes MAPI :

* `Mapi-Client-Submit-Time` : Heure du système lorsque l'e-mail a été envoyé
* `Mapi-Conversation-Index` : Nombre de messages enfants du fil et horodatage de chaque message du fil
* `Mapi-Entry-ID` : Identifiant du message.
* `Mappi-Message-Flags` et `Pr_last_Verb-Executed` : Informations sur le client MAPI (message lu ? non lu ? répondu ? redirigé ? absent du bureau ?)

Dans le client Microsoft Outlook, tous les messages envoyés/reçus, les données de contacts et les données de calendrier sont stockés dans un fichier PST dans :

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Le chemin du registre `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indique le fichier qui est utilisé.

Vous pouvez ouvrir le fichier PST en utilisant l'outil [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (485).png>)

### Fichiers OST de Microsoft Outlook

Un fichier **OST** est généré par Microsoft Outlook lorsqu'il est configuré avec un serveur **IMAP** ou **Exchange**, stockant des informations similaires à un fichier PST. Ce fichier est synchronisé avec le serveur, conservant les données des **12 derniers mois** jusqu'à une **taille maximale de 50 Go**, et est situé dans le même répertoire que le fichier PST. Pour visualiser un fichier OST, le [**Visionneur OST Kernel**](https://www.nucleustechnologies.com/ost-viewer.html) peut être utilisé.

### Récupération des Pièces Jointes

Les pièces jointes perdues peuvent être récupérées à partir de :

- Pour **IE10** : `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Pour **IE11 et versions ultérieures** : `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Fichiers MBOX de Thunderbird

**Thunderbird** utilise des fichiers **MBOX** pour stocker des données, situés dans `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniatures d'Images

- **Windows XP et 8-8.1** : L'accès à un dossier avec des miniatures génère un fichier `thumbs.db` stockant des aperçus d'images, même après suppression.
- **Windows 7/10** : `thumbs.db` est créé lors de l'accès via un réseau via un chemin UNC.
- **Windows Vista et versions ultérieures** : Les aperçus des miniatures sont centralisés dans `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` avec des fichiers nommés **thumbcache\_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) et [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sont des outils pour visualiser ces fichiers.

### Informations du Registre Windows

Le Registre Windows, stockant des données étendues sur l'activité du système et de l'utilisateur, est contenu dans des fichiers dans :

- `%windir%\System32\Config` pour diverses sous-clés `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` pour `HKEY_CURRENT_USER`.
- Windows Vista et les versions ultérieures sauvegardent les fichiers de registre `HKEY_LOCAL_MACHINE` dans `%Windir%\System32\Config\RegBack\`.
- De plus, les informations sur l'exécution des programmes sont stockées dans `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` à partir de Windows Vista et de Windows 2008 Server.

### Outils

Certains outils sont utiles pour analyser les fichiers de registre :

* **Éditeur de Registre** : Il est installé dans Windows. C'est une interface graphique pour naviguer dans le registre Windows de la session en cours.
* [**Explorateur de Registre**](https://ericzimmerman.github.io/#!index.md) : Il vous permet de charger le fichier de registre et de naviguer à travers eux avec une interface graphique. Il contient également des signets mettant en évidence les clés contenant des informations intéressantes.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0) : Encore une fois, il possède une interface graphique qui permet de naviguer dans le registre chargé et contient également des plugins mettant en évidence des informations intéressantes à l'intérieur du registre chargé.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html) : Une autre application GUI capable d'extraire les informations importantes du registre chargé.

### Récupération d'un Élément Supprimé

Lorsqu'une clé est supprimée, elle est marquée comme telle, mais tant que l'espace qu'elle occupe n'est pas nécessaire, elle ne sera pas supprimée. Par conséquent, en utilisant des outils comme **Registry Explorer**, il est possible de récupérer ces clés supprimées.

### Dernière Heure d'Écriture

Chaque clé-valeur contient un **horodatage** indiquant la dernière fois qu'elle a été modifiée.

### SAM

Le fichier/base de registre **SAM** contient les **utilisateurs, groupes et mots de passe des utilisateurs** du système.

Dans `SAM\Domains\Account\Users`, vous pouvez obtenir le nom d'utilisateur, le RID, la dernière connexion, la dernière tentative de connexion échouée, le compteur de connexion, la politique de mot de passe et la date de création du compte. Pour obtenir les **hashes**, vous avez également **besoin** du fichier/base de registre **SYSTEM**.

### Entrées Intéressantes dans le Registre Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programmes Exécutés

### Processus de Base de Windows

Dans [cet article](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d), vous pouvez en apprendre davantage sur les processus Windows courants pour détecter les comportements suspects.

### Applications Récentes Windows

Dans le registre `NTUSER.DAT` dans le chemin `Software\Microsoft\Current Version\Search\RecentApps`, vous pouvez trouver des sous-clés avec des informations sur l'**application exécutée**, la **dernière fois** qu'elle a été exécutée et le **nombre de fois** qu'elle a été lancée.

### BAM (Modérateur d'Activité en Arrière-Plan)

Vous pouvez ouvrir le fichier `SYSTEM` avec un éditeur de registre et à l'intérieur du chemin `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, vous pouvez trouver des informations sur les **applications exécutées par chaque utilisateur** (notez le `{SID}` dans le chemin) et à **quelle heure** elles ont été exécutées (l'heure est à l'intérieur de la valeur de données du registre).

### Préchargement Windows

Le préchargement est une technique qui permet à un ordinateur de **récupérer silencieusement les ressources nécessaires pour afficher le contenu** auquel un utilisateur **pourrait accéder dans un avenir proche** afin que les ressources puissent être accédées plus rapidement.

Le préchargement Windows consiste à créer des **caches des programmes exécutés** pour pouvoir les charger plus rapidement. Ces caches sont créés sous forme de fichiers `.pf` dans le chemin : `C:\Windows\Prefetch`. Il y a une limite de 128 fichiers dans XP/VISTA/WIN7 et 1024 fichiers dans Win8/Win10.

Le nom du fichier est créé sous la forme `{nom_du_programme}-{hash}.pf` (le hash est basé sur le chemin et les arguments de l'exécutable). Dans W10, ces fichiers sont compressés. Notez que la seule présence du fichier indique que **le programme a été exécuté** à un moment donné.

Le fichier `C:\Windows\Prefetch\Layout.ini` contient les **noms des dossiers des fichiers préchargés**. Ce fichier contient des informations sur le **nombre d'exécutions**, les **dates** de l'exécution et les **fichiers** **ouverts** par le programme.

Pour inspecter ces fichiers, vous pouvez utiliser l'outil [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** a le même objectif que prefetch, **charger les programmes plus rapidement** en prédisant ce qui va être chargé ensuite. Cependant, il ne remplace pas le service prefetch.\
Ce service générera des fichiers de base de données dans `C:\Windows\Prefetch\Ag*.db`.

Dans ces bases de données, vous pouvez trouver le **nom** du **programme**, le **nombre** d'**exécutions**, les **fichiers** **ouverts**, le **volume** **accédé**, le **chemin** **complet**, les **plages** **horaires** et les **horodatages**.

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

Le **AppCompatCache**, également connu sous le nom de **ShimCache**, fait partie de la **Base de données de compatibilité des applications** développée par **Microsoft** pour résoudre les problèmes de compatibilité des applications. Ce composant système enregistre divers éléments de métadonnées de fichiers, qui incluent :

- Chemin complet du fichier
- Taille du fichier
- Dernière heure de modification sous **$Standard\_Information** (SI)
- Dernière heure de mise à jour du ShimCache
- Indicateur d'exécution du processus

Ces données sont stockées dans le registre à des emplacements spécifiques en fonction de la version du système d'exploitation :

- Pour XP, les données sont stockées sous `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` avec une capacité de 96 entrées.
- Pour Server 2003, ainsi que pour les versions de Windows 2008, 2012, 2016, 7, 8 et 10, le chemin de stockage est `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, avec une capacité de 512 et 1024 entrées, respectivement.

Pour analyser les informations stockées, l'outil [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) est recommandé.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Le fichier **Amcache.hve** est essentiellement une ruche de registre qui enregistre des détails sur les applications qui ont été exécutées sur un système. Il se trouve généralement à `C:\Windows\AppCompat\Programas\Amcache.hve`.

Ce fichier est remarquable pour stocker des enregistrements de processus récemment exécutés, y compris les chemins vers les fichiers exécutables et leurs hachages SHA1. Ces informations sont inestimables pour suivre l'activité des applications sur un système.

Pour extraire et analyser les données de **Amcache.hve**, l'outil [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) peut être utilisé. La commande suivante est un exemple de la façon d'utiliser AmcacheParser pour analyser le contenu du fichier **Amcache.hve** et afficher les résultats au format CSV :
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Parmi les fichiers CSV générés, le fichier `Amcache_Unassociated file entries` est particulièrement remarquable en raison des informations détaillées qu'il fournit sur les entrées de fichiers non associées.

Le fichier CSV le plus intéressant généré est le `Amcache_Unassociated file entries`.

### RecentFileCache

Cet artefact ne peut être trouvé que dans W7 dans `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` et il contient des informations sur l'exécution récente de certains binaires.

Vous pouvez utiliser l'outil [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) pour analyser le fichier.

### Tâches planifiées

Vous pouvez les extraire de `C:\Windows\Tasks` ou `C:\Windows\System32\Tasks` et les lire au format XML.

### Services

Vous pouvez les trouver dans le registre sous `SYSTEM\ControlSet001\Services`. Vous pouvez voir ce qui va être exécuté et quand.

### **Windows Store**

Les applications installées peuvent être trouvées dans `\ProgramData\Microsoft\Windows\AppRepository\`\
Ce référentiel contient un **journal** avec **chaque application installée** dans le système à l'intérieur de la base de données **`StateRepository-Machine.srd`**.

À l'intérieur de la table Application de cette base de données, il est possible de trouver les colonnes : "ID de l'application", "Numéro de package" et "Nom d'affichage". Ces colonnes contiennent des informations sur les applications préinstallées et installées et il est possible de savoir si certaines applications ont été désinstallées car les ID des applications installées devraient être séquentiels.

Il est également possible de **trouver des applications installées** dans le chemin du registre : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Et des **applications désinstallées** dans : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Événements Windows

Les informations qui apparaissent dans les événements Windows sont :

* Ce qui s'est passé
* Horodatage (UTC + 0)
* Utilisateurs impliqués
* Hôtes impliqués (nom d'hôte, IP)
* Actifs consultés (fichiers, dossiers, imprimantes, services)

Les journaux se trouvent dans `C:\Windows\System32\config` avant Windows Vista et dans `C:\Windows\System32\winevt\Logs` après Windows Vista. Avant Windows Vista, les journaux d'événements étaient au format binaire et après, ils sont au format **XML** et utilisent l'extension **.evtx**.

L'emplacement des fichiers d'événements peut être trouvé dans le registre SYSTEM dans **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Ils peuvent être visualisés à partir de l'Observateur d'événements Windows (**`eventvwr.msc`**) ou avec d'autres outils comme [**Event Log Explorer**](https://eventlogxp.com) **ou** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Compréhension de la journalisation des événements de sécurité Windows

Les événements d'accès sont enregistrés dans le fichier de configuration de sécurité situé à `C:\Windows\System32\winevt\Security.evtx`. La taille de ce fichier est ajustable et lorsque sa capacité est atteinte, les événements plus anciens sont écrasés. Les événements enregistrés incluent les connexions et déconnexions d'utilisateurs, les actions des utilisateurs, les modifications des paramètres de sécurité, ainsi que l'accès aux fichiers, dossiers et ressources partagées.

### Principaux ID d'événements pour l'authentification des utilisateurs :

- **ID d'événement 4624** : Indique qu'un utilisateur s'est authentifié avec succès.
- **ID d'événement 4625** : Signale un échec d'authentification.
- **ID d'événements 4634/4647** : Représentent les événements de déconnexion d'utilisateurs.
- **ID d'événement 4672** : Indique une connexion avec des privilèges administratifs.

#### Sous-types dans l'ID d'événement 4634/4647 :

- **Interactif (2)** : Connexion directe de l'utilisateur.
- **Réseau (3)** : Accès aux dossiers partagés.
- **Lot (4)** : Exécution de processus en lot.
- **Service (5)** : Lancement de services.
- **Proxy (6)** : Authentification de proxy.
- **Déverrouillage (7)** : Écran déverrouillé avec un mot de passe.
- **Réseau en clair (8)** : Transmission de mot de passe en clair, souvent depuis IIS.
- **Nouvelles informations d'identification (9)** : Utilisation de différentes informations d'identification pour l'accès.
- **Interactif à distance (10)** : Connexion à distance via le bureau à distance ou les services de terminal.
- **Interactif mis en cache (11)** : Connexion avec des informations d'identification mises en cache sans contact avec le contrôleur de domaine.
- **Interactif à distance mis en cache (12)** : Connexion à distance avec des informations d'identification mises en cache.
- **Déverrouillage mis en cache (13)** : Déverrouillage avec des informations d'identification mises en cache.

#### Codes d'état et de sous-état pour l'ID d'événement 4625 :

- **0xC0000064** : Le nom d'utilisateur n'existe pas - pourrait indiquer une attaque d'énumération de noms d'utilisateur.
- **0xC000006A** : Nom d'utilisateur correct mais mauvais mot de passe - Tentative de deviner ou de forcer le mot de passe.
- **0xC0000234** : Compte utilisateur verrouillé - Peut suivre une attaque par force brute entraînant plusieurs échecs de connexion.
- **0xC0000072** : Compte désactivé - Tentatives non autorisées d'accéder à des comptes désactivés.
- **0xC000006F** : Connexion en dehors des heures autorisées - Indique des tentatives d'accès en dehors des heures de connexion définies, un signe possible d'accès non autorisé.
- **0xC0000070** : Violation des restrictions de poste de travail - Pourrait être une tentative de connexion depuis un emplacement non autorisé.
- **0xC0000193** : Expiration du compte - Tentatives d'accès avec des comptes utilisateur expirés.
- **0xC0000071** : Mot de passe expiré - Tentatives de connexion avec des mots de passe obsolètes.
- **0xC0000133** : Problèmes de synchronisation de l'heure - De grands écarts de temps entre le client et le serveur peuvent indiquer des attaques plus sophistiquées comme le pass-the-ticket.
- **0xC0000224** : Changement de mot de passe obligatoire - Des changements obligatoires fréquents pourraient suggérer une tentative de déstabilisation de la sécurité du compte.
- **0xC0000225** : Indique un bug système plutôt qu'un problème de sécurité.
- **0xC000015b** : Type de connexion refusé - Tentative d'accès avec un type de connexion non autorisé, comme un utilisateur essayant d'exécuter une connexion de service.

#### ID d'événement 4616 :
- **Changement d'heure** : Modification de l'heure du système, pourrait obscurcir la chronologie des événements.

#### ID d'événements 6005 et 6006 :
- **Démarrage et arrêt du système** : L'ID d'événement 6005 indique le démarrage du système, tandis que l'ID d'événement 6006 marque son arrêt.

#### ID d'événement 1102 :
- **Suppression de journal** : Les journaux de sécurité sont effacés, ce qui est souvent un indicateur pour dissimuler des activités illicites.

#### ID d'événements pour le suivi des périphériques USB :
- **20001 / 20003 / 10000** : Première connexion du périphérique USB.
- **10100** : Mise à jour du pilote USB.
- **ID d'événement 112** : Heure d'insertion du périphérique USB.

Pour des exemples pratiques sur la simulation de ces types de connexion et les opportunités de récupération d'informations d'identification, consultez le guide détaillé d'Altered Security.

Les détails des événements, y compris les codes d'état et de sous-état, fournissent des informations supplémentaires sur les causes des événements, particulièrement remarquables dans l'ID d'événement 4625.

### Récupération des événements Windows

Pour augmenter les chances de récupérer des événements Windows supprimés, il est conseillé d'éteindre l'ordinateur suspect en le débranchant directement. **Bulk_extractor**, un outil de récupération spécifiant l'extension `.evtx`, est recommandé pour tenter de récupérer de tels événements.

### Identification des attaques courantes via les événements Windows

Pour un guide complet sur l'utilisation des ID d'événements Windows pour identifier les attaques cybernétiques courantes, consultez Red Team Recipe.

#### Attaques par force brute

Identifiables par de multiples enregistrements d'ID d'événement 4625, suivis d'un ID d'événement 4624 si l'attaque réussit.

#### Changement d'heure

Enregistré par l'ID d'événement 4616, les changements d'heure système peuvent compliquer l'analyse forensique.

#### Suivi des périphériques USB

Les ID d'événements système utiles pour le suivi des périphériques USB incluent 20001/20003/10000 pour une utilisation initiale, 10100 pour les mises à jour des pilotes, et l'ID d'événement 112 de DeviceSetupManager pour les horodatages d'insertion.

#### Événements d'alimentation du système

L'ID d'événement 6005 indique le démarrage du système, tandis que l'ID d'événement 6006 marque l'arrêt.

#### Suppression de journal

L'ID d'événement de sécurité 1102 signale la suppression des journaux, un événement critique pour l'analyse forensique.
