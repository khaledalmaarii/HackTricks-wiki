# Artefacts Windows

## Artefacts Windows

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

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

La chronologie est une caractéristique de Windows qui fournit un **historique chronologique** des pages web visitées, des documents édités et des applications exécutées.

La base de données se trouve dans le chemin `\Users\<nom_utilisateur>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Cette base de données peut être ouverte avec un outil SQLite ou avec l'outil [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **qui génère 2 fichiers pouvant être ouverts avec l'outil** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Flux de données alternatifs)

Les fichiers téléchargés peuvent contenir la **Zone.Identifier des ADS** indiquant **comment** il a été **téléchargé** depuis l'intranet, internet, etc. Certains logiciels (comme les navigateurs) mettent généralement **encore plus** **d'informations** comme l'**URL** à partir de laquelle le fichier a été téléchargé.

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

Ces sauvegardes sont généralement situées dans le dossier `\System Volume Information` à la racine du système de fichiers et le nom est composé d'**UIDs** comme indiqué dans l'image suivante :

![](<../../../.gitbook/assets/image (520).png>)

En montant l'image forensique avec l'outil **ArsenalImageMounter**, l'outil [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) peut être utilisé pour inspecter une copie d'ombre et même **extraire les fichiers** des sauvegardes de copie d'ombre.

![](<../../../.gitbook/assets/image (521).png>)

L'entrée de registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contient les fichiers et clés **à ne pas sauvegarder** :

![](<../../../.gitbook/assets/image (522).png>)

Le registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contient également des informations de configuration sur les `Copies d'ombre du volume`.

### Fichiers Office AutoSaved

Vous pouvez trouver les fichiers autosauvegardés de bureau dans : `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Éléments de Shell

Un élément de shell est un élément qui contient des informations sur la façon d'accéder à un autre fichier.

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

Les **jumplists** créés automatiquement sont stockés dans `C:\Users\{nom_utilisateur}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Les jumplists sont nommés selon le format `{id}.autmaticDestinations-ms` où l'ID initial est l'ID de l'application.

Les jumplists personnalisés sont stockés dans `C:\Users\{nom_utilisateur}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` et sont généralement créés par l'application car quelque chose d'**important** s'est produit avec le fichier (peut-être marqué comme favori).

L'**heure de création** de toute jumplist indique la **première fois que le fichier a été consulté** et l'**heure de modification la dernière fois**.

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

### Détective USB

[**USBDetective**](https://usbdetective.com) peut être utilisé pour obtenir des informations sur les périphériques USB qui ont été connectés à une image.

![](<../../../.gitbook/assets/image (483).png>)

### Nettoyage Plug and Play

La tâche planifiée connue sous le nom de 'Nettoyage Plug and Play' est principalement conçue pour supprimer les versions obsolètes des pilotes. Contrairement à son objectif spécifié de conserver la dernière version du package de pilotes, des sources en ligne suggèrent qu'elle cible également les pilotes inactifs depuis 30 jours. Par conséquent, les pilotes des périphériques amovibles non connectés au cours des 30 derniers jours peuvent être supprimés.

La tâche est située dans le chemin suivant :
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Une capture d'écran illustrant le contenu de la tâche est fournie :
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Composants clés et paramètres de la tâche :**
- **pnpclean.dll** : Cette DLL est responsable du processus de nettoyage réel.
- **UseUnifiedSchedulingEngine** : Défini sur `TRUE`, indiquant l'utilisation du moteur de planification de tâches générique.
- **MaintenanceSettings** :
- **Période ('P1M')** : Indique au Planificateur de tâches d'initier la tâche de nettoyage mensuellement pendant la maintenance automatique régulière.
- **Date limite ('P2M')** : Instruit le Planificateur de tâches, si la tâche échoue pendant deux mois consécutifs, d'exécuter la tâche pendant la maintenance automatique d'urgence.

Cette configuration garantit une maintenance régulière et un nettoyage des pilotes, avec des dispositions pour réessayer la tâche en cas d'échecs consécutifs.

**Pour plus d'informations, consultez :** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Les emails contiennent **2 parties intéressantes : les en-têtes et le contenu** de l'email. Dans les **en-têtes**, vous pouvez trouver des informations telles que :

* **Qui** a envoyé les emails (adresse e-mail, IP, serveurs de messagerie ayant redirigé l'e-mail)
* **Quand** l'e-mail a été envoyé

De plus, dans les en-têtes `References` et `In-Reply-To`, vous pouvez trouver l'ID des messages :

![](<../../../.gitbook/assets/image (484).png>)

### Application Courrier Windows

Cette application enregistre les emails en HTML ou en texte. Vous pouvez trouver les emails dans des sous-dossiers à l'intérieur de `\Users\<nom_utilisateur>\AppData\Local\Comms\Unistore\data\3\`. Les emails sont enregistrés avec l'extension `.dat`.

Les **métadonnées** des emails et les **contacts** peuvent être trouvés dans la base de données **EDB** : `\Users\<nom_utilisateur>\AppData\Local\Comms\UnistoreDB\store.vol`

**Changez l'extension** du fichier de `.vol` à `.edb` et vous pouvez utiliser l'outil [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) pour l'ouvrir. Dans la table `Message`, vous pouvez voir les emails.

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

### Outlook OST

Lorsque Microsoft Outlook est configuré **en utilisant** **IMAP** ou en utilisant un serveur **Exchange**, il génère un fichier **OST** qui stocke presque les mêmes informations que le fichier PST. Il garde le fichier synchronisé avec le serveur pour les **12 derniers mois**, avec une **taille maximale de fichier de 50 Go** et dans le **même dossier que le fichier PST** est enregistré. Vous pouvez inspecter ce fichier en utilisant [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Récupération des pièces jointes

Vous pouvez les trouver dans le dossier :

* `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook` -> IE10
* `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook` -> IE11+

### Thunderbird MBOX

**Thunderbird** stocke les informations dans des **fichiers MBOX** dans le dossier `\Users\%NOM_UTILISATEUR%\AppData\Roaming\Thunderbird\Profiles`

## Miniatures

Lorsqu'un utilisateur accède à un dossier et l'organise en utilisant des miniatures, un fichier `thumbs.db` est créé. Cette base de données **stocke les miniatures des images** du dossier même si elles sont supprimées. Dans WinXP et Win 8-8.1, ce fichier est créé automatiquement. Dans Win7/Win10, il est créé automatiquement s'il est accédé via un chemin UNC (\IP\dossier...).

Il est possible de lire ce fichier avec l'outil [**Thumbsviewer**](https://thumbsviewer.github.io).

### Thumbcache

À partir de Windows Vista, **les aperçus des miniatures sont stockés dans un emplacement centralisé sur le système**. Cela permet au système d'accéder aux images indépendamment de leur emplacement et résout les problèmes de localisation des fichiers Thumbs.db. Le cache est stocké à **`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`** sous la forme de plusieurs fichiers portant l'étiquette **thumbcache\_xxx.db** (numérotés par taille) ; ainsi qu'un index utilisé pour trouver les miniatures dans chaque base de données de taille.

* Thumbcache\_32.db -> petit
* Thumbcache\_96.db -> moyen
* Thumbcache\_256.db -> grand
* Thumbcache\_1024.db -> très grand

Vous pouvez lire ce fichier en utilisant [**ThumbCache Viewer**](https://thumbcacheviewer.github.io).

## Registre Windows

Le Registre Windows contient beaucoup d'**informations** sur le **système et les actions des utilisateurs**.

Les fichiers contenant le registre sont situés dans :

* %windir%\System32\Config\*_SAM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SECURITY\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SYSTEM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SOFTWARE\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_DEFAULT\*_: `HKEY_LOCAL_MACHINE`
* %UserProfile%{Utilisateur}\*_NTUSER.DAT\*_: `HKEY_CURRENT_USER`

À partir de Windows Vista et de Windows 2008 Server, il existe des sauvegardes des fichiers de registre `HKEY_LOCAL_MACHINE` dans **`%Windir%\System32\Config\RegBack\`**.

Également à partir de ces versions, le fichier de registre **`%UserProfile%\{Utilisateur}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`** est créé pour sauvegarder des informations sur les exécutions de programmes.

### Outils

Certains outils sont utiles pour analyser les fichiers de registre :

* **Éditeur de Registre** : Il est installé dans Windows. C'est une interface graphique pour naviguer dans le registre Windows de la session en cours.
* [**Explorateur de Registre**](https://ericzimmerman.github.io/#!index.md) : Il vous permet de charger le fichier de registre et de naviguer à travers eux avec une interface graphique. Il contient également des signets mettant en évidence les clés contenant des informations intéressantes.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0) : Encore une fois, il possède une interface graphique qui permet de naviguer dans le registre chargé et contient également des plugins mettant en évidence des informations intéressantes dans le registre chargé.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html) : Une autre application graphique capable d'extraire les informations importantes du registre chargé.

### Récupération d'éléments supprimés

Lorsqu'une clé est supprimée, elle est marquée comme telle, mais tant que l'espace qu'elle occupe n'est pas nécessaire, elle ne sera pas supprimée. Par conséquent, en utilisant des outils comme **Registry Explorer**, il est possible de récupérer ces clés supprimées.

### Heure de dernière écriture

Chaque clé-valeur contient une **horodatage** indiquant la dernière fois qu'elle a été modifiée.

### SAM

Le fichier/hive **SAM** contient les **utilisateurs, groupes et mots de passe des utilisateurs** du système.

Dans `SAM\Domains\Account\Users`, vous pouvez obtenir le nom d'utilisateur, le RID, la dernière connexion, la dernière tentative de connexion échouée, le compteur de connexion, la politique de mot de passe et la date de création du compte. Pour obtenir les **hashes**, vous avez également besoin du fichier/hive **SYSTEM**.

### Entrées intéressantes dans le Registre Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programmes Exécutés

### Processus Windows de base

Sur la page suivante, vous pouvez en apprendre davantage sur les processus Windows de base pour détecter les comportements suspects :

{% content-ref url="windows-processes.md" %}
[windows-processes.md](windows-processes.md)
{% endcontent-ref %}

### Applications récentes Windows

Dans le registre `NTUSER.DAT` dans le chemin `Software\Microsoft\Current Version\Search\RecentApps`, vous pouvez trouver des sous-clés avec des informations sur l'**application exécutée**, la **dernière fois** qu'elle a été exécutée et le **nombre de fois** qu'elle a été lancée.

### BAM (Modérateur d'activité en arrière-plan)

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

Dans ces bases de données, vous pouvez trouver le **nom** du **programme**, le **nombre** d'**exécutions**, les **fichiers** **ouverts**, le **volume** **accédé**, le **chemin complet**, les **plages horaires** et les **horodatages**.

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

**Shimcache**, également connu sous le nom de **AppCompatCache**, est un composant de la **Base de données de compatibilité des applications**, créée par **Microsoft** et utilisée par le système d'exploitation pour identifier les problèmes de compatibilité des applications.

Le cache stocke diverses métadonnées de fichiers en fonction du système d'exploitation, telles que :

* Chemin complet du fichier
* Taille du fichier
* Dernière heure de modification de **$Standard\_Information** (SI)
* Dernière heure de mise à jour de ShimCache
* Indicateur d'exécution du processus

Ces informations peuvent être trouvées dans le registre à :

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
* XP (96 entrées)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
* Server 2003 (512 entrées)
* 2008/2012/2016 Win7/Win8/Win10 (1024 entrées)

Vous pouvez utiliser l'outil [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) pour analyser ces informations.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Le fichier **Amcache.hve** est un fichier de registre qui stocke les informations des applications exécutées. Il est situé dans `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** enregistre les processus récents qui ont été exécutés et répertorie le chemin des fichiers qui sont exécutés, ce qui peut ensuite être utilisé pour trouver le programme exécuté. Il enregistre également le SHA1 du programme.

Vous pouvez analyser ces informations avec l'outil [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser)
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
Le fichier CVS le plus intéressant généré est les `entrées de fichiers non associées Amcache`.

### RecentFileCache

Cet artefact ne peut être trouvé que dans W7 dans `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` et il contient des informations sur l'exécution récente de certains binaires.

Vous pouvez utiliser l'outil [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) pour analyser le fichier.

### Tâches planifiées

Vous pouvez les extraire de `C:\Windows\Tasks` ou `C:\Windows\System32\Tasks` et les lire en tant que XML.

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

### Sécurité

Cela enregistre les événements d'accès et fournit des informations sur la configuration de sécurité qui peuvent être trouvées dans `C:\Windows\System32\winevt\Security.evtx`.

La **taille maximale** du fichier d'événements est configurable, et il commencera à écraser les anciens événements lorsque la taille maximale est atteinte.

Les événements enregistrés sont :

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
| 4672      | Connexion avec permissions administratives |

À l'intérieur de l'EventID 4634/4647, il y a des sous-types intéressants :

* **2 (interactif)** : La connexion était interactive en utilisant le clavier ou un logiciel comme VNC ou `PSexec -U-`
* **3 (réseau)** : Connexion à un dossier partagé
* **4 (lot)** : Processus exécuté
* **5 (service)** : Service démarré par le Gestionnaire de services
* **6 (proxy)** : Connexion proxy
* **7 (déverrouillage)** : Écran déverrouillé en utilisant un mot de passe
* **8 (texte en clair réseau)** : Utilisateur authentifié en envoyant des mots de passe en clair. Cet événement provenait de l'IIS
* **9 (nouvelles informations d'identification)** : Il est généré lorsque la commande `RunAs` est utilisée ou lorsque l'utilisateur accède à un service réseau avec des informations d'identification différentes.
* **10 (interactif à distance)** : Authentification via les Services Terminal ou RDP
* **11 (interactif mis en cache)** : Accès en utilisant les dernières informations d'identification mises en cache car il n'était pas possible de contacter le contrôleur de domaine
* **12 (interactif à distance mis en cache)** : Connexion à distance avec des informations d'identification mises en cache (une combinaison de 10 et 11).
* **13 (déverrouillage mis en cache)** : Déverrouiller une machine verrouillée avec des informations d'identification mises en cache.

Dans ce post, vous pouvez trouver comment imiter tous ces types de connexion et dans lesquels vous pourrez extraire des informations d'identification de la mémoire : [https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

Les informations d'état et de sous-état des événements peuvent indiquer plus de détails sur les causes de l'événement. Par exemple, jetez un œil aux codes d'état et de sous-état suivants de l'ID d'événement 4625 :

![](<../../../.gitbook/assets/image (455).png>)

### Récupération des événements Windows

Il est fortement recommandé d'éteindre l'ordinateur suspect en le **débranchant** pour maximiser la probabilité de récupérer les événements Windows. En cas de suppression, un outil qui peut être utile pour essayer de les récupérer est [**Bulk\_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor) en indiquant l'extension **evtx**.

## Identification des attaques courantes avec les événements Windows

* [https://redteamrecipe.com/event-codes/](https://redteamrecipe.com/event-codes/)

### Attaque par force brute

Une attaque par force brute peut être facilement identifiable car **plusieurs EventIDs 4625 apparaîtront**. Si l'attaque a été **réussie**, après les EventIDs 4625, **un EventID 4624 apparaîtra**.

### Changement d'heure

C'est terrible pour l'équipe de la police scientifique car tous les horodatages seront modifiés. Cet événement est enregistré par l'EventID 4616 à l'intérieur du journal d'événements de sécurité.

### Périphériques USB

Les EventIDs système suivants sont utiles :

* 20001 / 20003 / 10000 : Première utilisation
* 10100 : Mise à jour du pilote

L'EventID 112 de DeviceSetupManager contient l'horodatage de chaque périphérique USB inséré.

### Allumer / Éteindre

L'ID 6005 du service "Journal d'événements" indique que l'ordinateur a été allumé. L'ID 6006 indique qu'il a été éteint.

### Suppression des journaux

L'EventID 1102 de sécurité indique que les journaux ont été supprimés.
