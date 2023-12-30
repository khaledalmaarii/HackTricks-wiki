# Artéfacts Windows

## Artéfacts Windows

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Artéfacts Windows Génériques

### Notifications Windows 10

Dans le chemin `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`, vous pouvez trouver la base de données `appdb.dat` (avant l'anniversaire de Windows) ou `wpndatabase.db` (après l'anniversaire de Windows).

À l'intérieur de cette base de données SQLite, vous pouvez trouver la table `Notification` avec toutes les notifications (au format XML) qui peuvent contenir des données intéressantes.

### Timeline

Timeline est une caractéristique de Windows qui fournit un **historique chronologique** des pages web visitées, des documents édités et des applications exécutées.

La base de données se trouve dans le chemin `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Cette base de données peut être ouverte avec un outil SQLite ou avec l'outil [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **qui génère 2 fichiers pouvant être ouverts avec l'outil** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Les fichiers téléchargés peuvent contenir **ADS Zone.Identifier** indiquant **comment** il a été **téléchargé** depuis l'intranet, internet, etc. Certains logiciels (comme les navigateurs) mettent généralement **encore plus** d'**informations** comme l'**URL** d'où le fichier a été téléchargé.

## **Sauvegardes de Fichiers**

### Corbeille

Dans Vista/Win7/Win8/Win10, la **Corbeille** peut être trouvée dans le dossier **`$Recycle.bin`** à la racine du disque (`C:\$Recycle.bin`).\
Lorsqu'un fichier est supprimé dans ce dossier, 2 fichiers spécifiques sont créés :

* `$I{id}` : Informations sur le fichier (date de suppression)
* `$R{id}` : Contenu du fichier

![](<../../../.gitbook/assets/image (486).png>)

Avec ces fichiers, vous pouvez utiliser l'outil [**Rifiuti**](https://github.com/abelcheung/rifiuti2) pour obtenir l'adresse originale des fichiers supprimés et la date de suppression (utilisez `rifiuti-vista.exe` pour Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
### Copies de l'ombre de volume

La Copie de l'ombre est une technologie incluse dans Microsoft Windows qui peut créer des **copies de sauvegarde** ou des instantanés de fichiers informatiques ou de volumes, même lorsqu'ils sont utilisés.

Ces sauvegardes sont généralement situées dans le `\System Volume Information` à la racine du système de fichiers et le nom est composé de **UIDs** montrés dans l'image suivante :

![](<../../../.gitbook/assets/image (520).png>)

En montant l'image forensique avec **ArsenalImageMounter**, l'outil [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) peut être utilisé pour inspecter une copie de l'ombre et même **extraire les fichiers** des sauvegardes de copie de l'ombre.

![](<../../../.gitbook/assets/image (521).png>)

L'entrée de registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contient les fichiers et clés **à ne pas sauvegarder** :

![](<../../../.gitbook/assets/image (522).png>)

Le registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contient également des informations de configuration sur les `Copies de l'ombre de volume`.

### Fichiers AutoSauvegardés Office

Vous pouvez trouver les fichiers autosauvegardés d'Office dans : `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Éléments Shell

Un élément shell est un élément qui contient des informations sur comment accéder à un autre fichier.

### Documents Récents (LNK)

Windows **crée automatiquement** ces **raccourcis** lorsque l'utilisateur **ouvre, utilise ou crée un fichier** dans :

* Win7-Win10 : `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office : `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Lorsqu'un dossier est créé, un lien vers le dossier, le dossier parent et le grand-parent est également créé.

Ces fichiers de lien créés automatiquement **contiennent des informations sur l'origine** comme s'il s'agit d'un **fichier** ou d'un **dossier**, les **temps MAC** de ce fichier, les **informations de volume** de l'endroit où le fichier est stocké et le **dossier du fichier cible**. Ces informations peuvent être utiles pour récupérer ces fichiers dans le cas où ils auraient été supprimés.

De plus, la **date de création du fichier de lien** est la première **fois** que le fichier original a été **utilisé** et la **date de modification** du fichier de lien est la **dernière fois** que le fichier d'origine a été utilisé.

Pour inspecter ces fichiers, vous pouvez utiliser [**LinkParser**](http://4discovery.com/our-tools/).

Dans cet outil, vous trouverez **2 ensembles** de dates et heures :

* **Premier Ensemble :**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **Deuxième Ensemble :**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Le premier ensemble de dates et heures fait référence aux **dates et heures du fichier lui-même**. Le deuxième ensemble fait référence aux **dates et heures du fichier lié**.

Vous pouvez obtenir les mêmes informations en exécutant l'outil CLI Windows : [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Dans ce cas, les informations seront enregistrées dans un fichier CSV.

### Jumplists

Ce sont les fichiers récents indiqués par application. C'est la liste des **fichiers récents utilisés par une application** auxquels vous pouvez accéder pour chaque application. Ils peuvent être créés **automatiquement ou personnalisés**.

Les **jumplists** créées automatiquement sont stockées dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Les jumplists sont nommées selon le format `{id}.autmaticDestinations-ms` où l'ID initial est celui de l'application.

Les jumplists personnalisées sont stockées dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` et sont créées par l'application généralement parce que quelque chose d'**important** s'est produit avec le fichier (peut-être marqué comme favori).

Le **temps de création** d'une jumplist indique **la première fois que le fichier a été accédé** et le **temps modifié la dernière fois**.

Vous pouvez inspecter les jumplists en utilisant [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Notez que les horodatages fournis par JumplistExplorer sont liés au fichier jumplist lui-même_)

### Shellbags

[**Suivez ce lien pour apprendre ce que sont les shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Utilisation des USB Windows

Il est possible d'identifier qu'un périphérique USB a été utilisé grâce à la création de :

* Dossier Windows Recent
* Dossier Microsoft Office Recent
* Jumplists

Notez que certains fichiers LNK au lieu de pointer vers le chemin d'origine, pointent vers le dossier WPDNSE :

![](<../../../.gitbook/assets/image (476).png>)

Les fichiers dans le dossier WPDNSE sont une copie des originaux, ils ne survivront donc pas à un redémarrage du PC et le GUID est pris d'un shellbag.

### Informations du Registre

[Consultez cette page pour apprendre](interesting-windows-registry-keys.md#usb-information) quels clés de registre contiennent des informations intéressantes sur les périphériques USB connectés.

### setupapi

Vérifiez le fichier `C:\Windows\inf\setupapi.dev.log` pour obtenir les horodatages de quand la connexion USB a été produite (recherchez `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) peut être utilisé pour obtenir des informations sur les périphériques USB qui ont été connectés à une image.

![](<../../../.gitbook/assets/image (483).png>)

### Nettoyage Plug and Play

La tâche planifiée 'Nettoyage Plug and Play' est responsable de **nettoyer** les versions obsolètes des pilotes. Il semble (d'après les rapports en ligne) qu'elle récupère également **les pilotes qui n'ont pas été utilisés pendant 30 jours**, malgré sa description indiquant que "la version la plus récente de chaque package de pilotes sera conservée". Ainsi, **les périphériques amovibles qui n'ont pas été connectés pendant 30 jours peuvent voir leurs pilotes supprimés**.

La tâche planifiée elle-même est située à ‘C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup’, et son contenu est affiché ci-dessous :

![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

La tâche fait référence à 'pnpclean.dll' qui est responsable de l'activité de nettoyage et nous voyons également que le champ ‘UseUnifiedSchedulingEngine’ est défini sur ‘TRUE’, ce qui spécifie que le moteur de planification de tâches générique est utilisé pour gérer la tâche. Les valeurs ‘Period’ et ‘Deadline’ de 'P1M' et 'P2M' dans ‘MaintenanceSettings’ instruisent le Planificateur de tâches d'exécuter la tâche une fois par mois pendant la maintenance automatique régulière et si elle échoue pendant 2 mois consécutifs, de commencer à tenter la tâche pendant la maintenance automatique d'urgence. **Cette section a été copiée de** [**ici**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)**.**

## Emails

Les emails contiennent **2 parties intéressantes : Les en-têtes et le contenu** de l'email. Dans les **en-têtes**, vous pouvez trouver des informations telles que :

* **Qui** a envoyé les emails (adresse email, IP, serveurs de messagerie qui ont redirigé l'email)
* **Quand** l'email a été envoyé

Aussi, à l'intérieur des en-têtes `References` et `In-Reply-To`, vous pouvez trouver l'ID des messages :

![](<../../../.gitbook/assets/image (484).png>)

### Application de Courrier Windows

Cette application enregistre les emails en HTML ou en texte. Vous pouvez trouver les emails dans des sous-dossiers à l'intérieur de `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Les emails sont enregistrés avec l'extension `.dat`.

Les **métadonnées** des emails et les **contacts** peuvent être trouvés à l'intérieur de la **base de données EDB** : `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Changez l'extension** du fichier de `.vol` à `.edb` et vous pouvez utiliser l'outil [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) pour l'ouvrir. À l'intérieur de la table `Message`, vous pouvez voir les emails.

### Microsoft Outlook

Lorsque des serveurs Exchange ou des clients Outlook sont utilisés, il y aura des en-têtes MAPI :

* `Mapi-Client-Submit-Time` : Heure du système lorsque l'email a été envoyé
* `Mapi-Conversation-Index` : Nombre de messages enfants du fil et horodatage de chaque message du fil
* `Mapi-Entry-ID` : Identifiant du message.
* `Mappi-Message-Flags` et `Pr_last_Verb-Executed` : Informations sur le client MAPI (message lu ? non lu ? répondu ? redirigé ? hors du bureau ?)

Dans le client Microsoft Outlook, tous les messages envoyés/reçus, les données des contacts et les données du calendrier sont stockés dans un fichier PST dans :

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Le chemin de registre `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indique le fichier qui est utilisé.

Vous pouvez ouvrir le fichier PST en utilisant l'outil [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (485).png>)

### Outlook OST

Lorsque Microsoft Outlook est configuré **en utilisant** **IMAP** ou en utilisant un serveur **Exchange**, il génère un fichier **OST** qui stocke presque les mêmes informations que le fichier PST. Il maintient le fichier synchronisé avec le serveur pour les **12 derniers mois**, avec une **taille maximale de fichier de 50 Go** et dans le **même dossier que le fichier PST** est enregistré. Vous pouvez inspecter ce fichier en utilisant [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Récupération des Pièces Jointes

Vous pourriez les trouver dans le dossier :

* `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook` -> IE10
* `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook` -> IE11+

### Thunderbird MBOX

**Thunderbird** stocke les informations dans des **fichiers MBOX** dans le dossier `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`

## Miniatures

Lorsqu'un utilisateur accède à un dossier et l'organise en utilisant des miniatures, alors un fichier `thumbs.db` est créé. Cette base de données **stocke les miniatures des images** du dossier même si elles sont supprimées. Dans WinXP et Win 8-8.1, ce fichier est créé automatiquement. Dans Win7/Win10, il est créé automatiquement s'il est accédé via un chemin UNC (\IP\dossier...).

Il est possible de lire ce fichier avec l'outil [**Thumbsviewer**](https://thumbsviewer.github.io).

### Thumbcache

À partir de Windows Vista, **les aperçus des miniatures sont stockés dans un emplacement centralisé sur le système**. Cela permet au système d'accéder aux images indépendamment de leur emplacement et résout les problèmes de localité des fichiers Thumbs.db. Le cache est stocké à **`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`** sous plusieurs fichiers avec l'étiquette **thumbcache\_xxx.db** (numérotés par taille) ; ainsi qu'un index utilisé pour trouver des miniatures dans chaque base de données de taille.

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
* %UserProfile%{User}\*_NTUSER.DAT\*_: `HKEY_CURRENT_USER`

À partir de Windows Vista et Windows 2008 Server, il y a des sauvegardes des fichiers de registre `HKEY_LOCAL_MACHINE` dans **`%Windir%\System32\Config\RegBack\`**.

Également à partir de ces versions, le fichier de registre **`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`** est créé en enregistrant des informations sur les exécutions de programmes.

### Outils

Certains outils sont utiles pour analyser les fichiers de registre :

* **Éditeur du Registre** : Il est installé dans Windows. C'est une interface graphique pour naviguer à travers le registre Windows de la session actuelle.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md) : Il vous permet de charger le fichier de registre et de naviguer à travers eux avec une interface graphique. Il contient également des signets mettant en évidence les clés avec des informations intéressantes.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0) : Encore une fois, il a une interface graphique qui permet de naviguer à travers le registre chargé et contient également des plugins qui mettent en évidence des informations intéressantes à l'intérieur du registre chargé.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html) : Une autre application graphique capable d'extraire les informations importantes du registre chargé.

### Récupération d'Éléments Supprimés

Lorsqu'une clé est supprimée, elle est marquée comme telle, mais tant que l'espace qu'elle occupe n'est pas nécessaire, elle ne sera pas supprimée. Par conséquent, en utilisant des outils comme **Registry Explorer**, il est possible de récupérer ces clés supprimées.

### Dernier Temps d'Écriture

Chaque Clé-Valeur contient un **horodatage** indiquant la dernière fois qu'elle a été modifiée.

### SAM

Le fichier/ruche **SAM** contient les **utilisateurs, groupes et les hachages des mots de passe des utilisateurs** du système.

Dans `SAM\Domains\Account\Users`, vous pouvez obtenir le nom d'utilisateur, le RID, la dernière connexion, le dernier échec de connexion, le compteur de connexion, la politique de mot de passe et quand le compte a été créé. Pour obtenir les **hachages**, vous avez également **besoin** du fichier/ruche **SYSTEM**.

### Entrées intéressantes dans le Registre Windows

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programmes Exécutés

### Processus Windows de Base

Sur la page suivante, vous pouvez en apprendre davantage sur les processus Windows de base pour détecter des comportements suspects :

{% content-ref url="windows-processes.md" %}
[windows-processes.md](windows-processes.md)
{% endcontent-ref %}

### Applications Récents Windows

Dans le registre `NTUSER.DAT` dans le chemin `Software\Microsoft\Current Version\Search\RecentApps`, vous pouvez trouver des sous-clés avec des informations sur l'**application exécutée**, **la dernière fois** qu'elle a été exécutée et le **nombre de fois** qu'elle a été lancée.

### BAM (Background Activity Moderator)

Vous pouvez ouvrir le fichier `SYSTEM` avec un éditeur de registre et à l'intérieur du chemin `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, vous pouvez trouver des informations sur les **applications exécutées par chaque utilisateur** (notez le `{SID}` dans le chemin) et à **quel moment** elles ont été exécutées (le temps est à l'intérieur de la valeur Data du registre).

### Windows Prefetch

Le préchargement est une technique qui permet à un ordinateur de **récupérer silencieusement les ressources nécessaires pour afficher le contenu** qu'un utilisateur **pourrait accéder dans un avenir proche** afin que les ressources puissent être accédées plus rapidement.

Le préchargement Windows consiste à créer des **caches des programmes exécutés** pour pouvoir les charger plus rapidement. Ces caches sont créés sous forme de fichiers `.pf` dans le chemin : `C:\Windows\Prefetch`. Il y a une limite de 128 fichiers dans XP/VISTA/WIN7 et 1024 fichiers dans Win8/Win10.

Le nom du fichier est créé comme `{program_name}-{hash}.pf` (le hachage est basé sur le chemin et les arguments de l'exécutable). Dans W10, ces fichiers sont compressés. Notez que la seule présence du fichier indique que **le programme a été exécuté** à un moment donné.

Le fichier `C:\Windows\Prefetch\Layout.ini` contient les **noms des dossiers des fichiers qui sont préchargés**. Ce fichier contient des **informations sur le nombre d'exécutions**, les **dates** d'exécution et les **fichiers ouverts** par le programme.

Pour inspecter ces fichiers, vous pouvez utiliser l'outil [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) :
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** a le même objectif que prefetch, **charger les programmes plus rapidement** en prédisant ce qui va être chargé ensuite. Cependant, il ne remplace pas le service prefetch.\
Ce service va générer des fichiers de base de données dans `C:\Windows\Prefetch\Ag*.db`.

Dans ces bases de données, vous pouvez trouver le **nom** du **programme**, le **nombre** d'**exécutions**, les **fichiers** **ouverts**, le **volume** **accédé**, le **chemin complet**, les **plages horaires** et les **horodatages**.

Vous pouvez accéder à cette information en utilisant l'outil [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **surveille** les **ressources** **consommées** **par un processus**. Il est apparu dans W8 et il stocke les données dans une base de données ESE située dans `C:\Windows\System32\sru\SRUDB.dat`.

Il fournit les informations suivantes :

* AppID et Chemin
* Utilisateur ayant exécuté le processus
* Octets envoyés
* Octets reçus
* Interface réseau
* Durée de connexion
* Durée du processus

Cette information est mise à jour toutes les 60 minutes.

Vous pouvez obtenir les données de ce fichier en utilisant l'outil [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**Shimcache**, également connu sous le nom de **AppCompatCache**, est un composant de la **Base de données de compatibilité des applications**, créée par **Microsoft** et utilisée par le système d'exploitation pour identifier les problèmes de compatibilité des applications.

Le cache stocke divers métadonnées de fichier en fonction du système d'exploitation, telles que :

* Chemin complet du fichier
* Taille du fichier
* Heure de dernière modification **$Standard\_Information** (SI)
* Heure de dernière mise à jour de ShimCache
* Indicateur d'exécution du processus

Ces informations se trouvent dans le registre à :

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
* XP (96 entrées)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
* Server 2003 (512 entrées)
* 2008/2012/2016 Win7/Win8/Win10 (1024 entrées)

Vous pouvez utiliser l'outil [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) pour analyser ces informations.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

Le fichier **Amcache.hve** est un fichier de registre qui stocke les informations des applications exécutées. Il se trouve dans `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** enregistre les processus récents qui ont été exécutés et liste le chemin des fichiers exécutés, ce qui peut ensuite être utilisé pour trouver le programme exécuté. Il enregistre également le SHA1 du programme.

Vous pouvez analyser ces informations avec l'outil [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser)
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
Le fichier CVS le plus intéressant généré est `Amcache_Unassociated file entries`.

### RecentFileCache

Cet artefact ne peut être trouvé que dans W7 dans `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` et il contient des informations sur l'exécution récente de certains binaires.

Vous pouvez utiliser l'outil [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) pour analyser le fichier.

### Tâches planifiées

Vous pouvez les extraire de `C:\Windows\Tasks` ou `C:\Windows\System32\Tasks` et les lire comme du XML.

### Services

Vous pouvez les trouver dans le registre sous `SYSTEM\ControlSet001\Services`. Vous pouvez voir ce qui va être exécuté et quand.

### **Windows Store**

Les applications installées peuvent être trouvées dans `\ProgramData\Microsoft\Windows\AppRepository\`\
Ce répertoire a un **log** avec **chaque application installée** dans le système à l'intérieur de la base de données **`StateRepository-Machine.srd`**.

À l'intérieur de la table des applications de cette base de données, il est possible de trouver les colonnes : "Application ID", "PackageNumber" et "Display Name". Ces colonnes contiennent des informations sur les applications préinstallées et installées et il est possible de savoir si certaines applications ont été désinstallées car les ID des applications installées devraient être séquentiels.

Il est également possible de **trouver des applications installées** dans le chemin du registre : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Et des **applications désinstallées** dans : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Événements Windows

Les informations qui apparaissent dans les événements Windows sont :

* Ce qui s'est passé
* Horodatage (UTC + 0)
* Utilisateurs impliqués
* Hôtes impliqués (nom d'hôte, IP)
* Actifs accédés (fichiers, dossiers, imprimantes, services)

Les journaux sont situés dans `C:\Windows\System32\config` avant Windows Vista et dans `C:\Windows\System32\winevt\Logs` après Windows Vista. Avant Windows Vista, les journaux d'événements étaient au format binaire et après, ils sont au **format XML** et utilisent l'extension **.evtx**.

L'emplacement des fichiers d'événements peut être trouvé dans le registre SYSTEM sous **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Ils peuvent être visualisés depuis la Visionneuse d'événements Windows (**`eventvwr.msc`**) ou avec d'autres outils comme [**Event Log Explorer**](https://eventlogxp.com) **ou** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

### Sécurité

Cela enregistre les événements d'accès et donne des informations sur la configuration de sécurité qui peuvent être trouvées dans `C:\Windows\System32\winevt\Security.evtx`.

La **taille maximale** du fichier d'événement est configurable, et il commencera à écraser les anciens événements lorsque la taille maximale est atteinte.

Les événements qui sont enregistrés comme :

* Connexion/Déconnexion
* Actions de l'utilisateur
* Accès aux fichiers, dossiers et actifs partagés
* Modification de la configuration de sécurité

Événements liés à l'authentification des utilisateurs :

| EventID   | Description                  |
| --------- | ---------------------------- |
| 4624      | Authentification réussie     |
| 4625      | Erreur d'authentification    |
| 4634/4647 | déconnexion                  |
| 4672      | Connexion avec des permissions d'admin |

À l'intérieur de l'EventID 4634/4647, il y a des sous-types intéressants :

* **2 (interactif)** : La connexion était interactive en utilisant le clavier ou des logiciels comme VNC ou `PSexec -U-`
* **3 (réseau)** : Connexion à un dossier partagé
* **4 (Batch)** : Processus exécuté
* **5 (service)** : Service démarré par le Gestionnaire de contrôle des services
* **6 (proxy)** : Connexion proxy
* **7 (déverrouillage)** : Écran déverrouillé en utilisant un mot de passe
* **8 (texte clair réseau)** : Utilisateur authentifié en envoyant des mots de passe en texte clair. Cet événement provient généralement de l'IIS
* **9 (nouvelles informations d'identification)** : Il est généré lorsque la commande `RunAs` est utilisée ou que l'utilisateur accède à un service réseau avec des informations d'identification différentes.
* **10 (interactif à distance)** : Authentification via les Services de Terminal ou RDP
* **11 (cache interactif)** : Accès en utilisant les dernières informations d'identification mises en cache car il n'était pas possible de contacter le contrôleur de domaine
* **12 (cache interactif à distance)** : Connexion à distance avec des informations d'identification mises en cache (une combinaison de 10 et 11).
* **13 (déverrouillage en cache)** : Déverrouillage d'une machine verrouillée avec des informations d'identification mises en cache.

Dans cet article, vous pouvez trouver comment imiter tous ces types de connexion et dans lesquels vous pourrez extraire des informations d'identification de la mémoire : [https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

Les informations de statut et de sous-statut des événements peuvent indiquer plus de détails sur les causes de l'événement. Par exemple, regardez les codes de statut et de sous-statut suivants de l'Event ID 4625 :

![](<../../../.gitbook/assets/image (455).png>)

### Récupération des événements Windows

Il est fortement recommandé d'éteindre le PC suspect en le **débranchant** pour maximiser la probabilité de récupérer les événements Windows. Dans le cas où ils auraient été supprimés, un outil qui peut être utile pour essayer de les récupérer est [**Bulk_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor) en indiquant l'extension **evtx**.

## Identification des attaques courantes avec les événements Windows

* [https://redteamrecipe.com/event-codes/](https://redteamrecipe.com/event-codes/)

### Attaque par force brute

Une attaque par force brute peut être facilement identifiable car **plusieurs EventIDs 4625 apparaîtront**. Si l'attaque était **réussie**, après les EventIDs 4625, **un EventID 4624 apparaîtra**.

### Changement d'heure

C'est terrible pour l'équipe de la police scientifique car tous les horodatages seront modifiés. Cet événement est enregistré par l'EventID 4616 dans le journal des événements de sécurité.

### Périphériques USB

Les EventIDs système suivants sont utiles :

* 20001 / 20003 / 10000 : Première fois qu'il a été utilisé
* 10100 : Mise à jour du pilote

L'EventID 112 de DeviceSetupManager contient l'horodatage de chaque périphérique USB inséré.

### Extinction / Allumage

L'ID 6005 du service "Event Log" indique que le PC a été allumé. L'ID 6006 indique qu'il a été éteint.

### Suppression des journaux

L'EventID 1102 de sécurité indique que les journaux ont été supprimés.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
