# NTFS

## NTFS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **NTFS**

**NTFS** (**New Technology File System**) est un système de fichiers journalisé propriétaire développé par Microsoft.

Le cluster est l'unité de taille la plus petite dans NTFS et la taille du cluster dépend de la taille d'une partition.

| Taille de la partition | Secteurs par cluster | Taille du cluster |
| ------------------------ | ------------------- | ------------ |
| 512 Mo ou moins            | 1                   | 512 octets    |
| 513 Mo-1024 Mo (1 Go)       | 2                   | 1 Ko          |
| 1025 Mo-2048 Mo (2 Go)      | 4                   | 2 Ko          |
| 2049 Mo-4096 Mo (4 Go)      | 8                   | 4 Ko          |
| 4097 Mo-8192 Mo (8 Go)      | 16                  | 8 Ko          |
| 8193 Mo-16 384 Mo (16 Go)   |
### Horodatage NTFS

![](<../../../.gitbook/assets/image (512).png>)

Un autre outil utile pour analyser le MFT est [**MFT2csv**](https://github.com/jschicht/Mft2Csv) (sélectionnez le fichier MFT ou l'image et appuyez sur "dump all and extract" pour extraire tous les objets).\
Ce programme extraira toutes les données MFT et les présentera au format CSV. Il peut également être utilisé pour extraire des fichiers.

![](<../../../.gitbook/assets/image (513).png>)

### $LOGFILE

Le fichier **`$LOGFILE`** contient des **journaux** sur les **actions** qui ont été **effectuées** **sur** **les fichiers**. Il **enregistre** également l'**action** qu'il devrait effectuer en cas de **refaire** et l'action nécessaire pour **revenir** à l'**état** **précédent**.\
Ces journaux sont utiles pour que le MFT puisse reconstruire le système de fichiers en cas d'erreur. La taille maximale de ce fichier est de **65536 Ko**.

Pour inspecter le fichier `$LOGFILE`, vous devez l'extraire et inspecter le fichier `$MFT` précédemment avec [**MFT2csv**](https://github.com/jschicht/Mft2Csv).\
Ensuite, exécutez [**LogFileParser**](https://github.com/jschicht/LogFileParser) sur ce fichier et sélectionnez le fichier `$LOGFILE` exporté et le CVS de l'inspection du `$MFT`. Vous obtiendrez un fichier CSV avec les journaux de l'activité du système de fichiers enregistrée par le journal `$LOGFILE`.

![](<../../../.gitbook/assets/image (515).png>)

En filtrant par noms de fichiers, vous pouvez voir **toutes les actions effectuées sur un fichier** :

![](<../../../.gitbook/assets/image (514).png>)

### $USNJnrl

Le fichier `$EXTEND/$USNJnrl/$J` est un flux de données alternatif du fichier `$EXTEND$USNJnrl`. Cet artefact contient un **registre des modifications produites à l'intérieur du volume NTFS avec plus de détails que `$LOGFILE`**.

Pour inspecter ce fichier, vous pouvez utiliser l'outil [**UsnJrnl2csv**](https://github.com/jschicht/UsnJrnl2Csv).

En filtrant par nom de fichier, il est possible de voir **toutes les actions effectuées sur un fichier**. De plus, vous pouvez trouver la `MFTReference` dans le dossier parent. Ensuite, en regardant cette `MFTReference`, vous pouvez trouver **des informations sur le dossier parent**.

![](<../../../.gitbook/assets/image (516).png>)

### $I30

Chaque **répertoire** dans le système de fichiers contient un **attribut `$I30`** qui doit être maintenu chaque fois qu'il y a des modifications dans le contenu du répertoire. Lorsque des fichiers ou des dossiers sont supprimés du répertoire, les enregistrements d'index `$I30` sont réorganisés en conséquence. Cependant, **la réorganisation des enregistrements d'index peut laisser des restes de l'entrée de fichier/dossier supprimée dans l'espace libre**. Cela peut être utile dans l'analyse de la criminalistique pour identifier les fichiers qui ont pu exister sur le disque.

Vous pouvez obtenir le fichier `$I30` d'un répertoire à partir de **FTK Imager** et l'inspecter avec l'outil [Indx2Csv](https://github.com/jschicht/Indx2Csv).

![](<../../../.gitbook/assets/image (519).png>)

Avec ces données, vous pouvez trouver **des informations sur les modifications de fichiers effectuées à l'intérieur du dossier**, mais notez que l'heure de suppression d'un fichier n'est pas enregistrée dans ce journal. Cependant, vous pouvez voir que la **dernière date de modification** du fichier **`$I30`**, et si la **dernière action effectuée** sur le répertoire est la **suppression** d'un fichier, les heures peuvent être les mêmes.

### $Bitmap

Le **`$BitMap`** est un fichier spécial dans le système de fichiers NTFS. Ce fichier garde **trace de tous les clusters utilisés et inutilisés** sur un volume NTFS. Lorsqu'un fichier prend de l'espace sur le volume NTFS, l'emplacement utilisé est marqué dans le `$BitMap`.

![](<../../../.gitbook/assets/image (523).png>)

### ADS (flux de données alternatif)

Les flux de données alternatifs permettent aux fichiers de contenir plus d'un flux de données. Chaque fichier a au moins un flux de données. Dans Windows, ce flux de données par défaut est appelé `:$DATA`.\
Dans cette [page, vous pouvez voir différentes façons de créer/accéder/découvrir des flux de données alternatifs](../../../windows-hardening/basic-cmd-for-pentesters.md#alternate-data-streams-cheatsheet-ads-alternate-data-stream) depuis la console. Dans le passé, cela a causé une vulnérabilité dans IIS car les gens pouvaient accéder au code source d'une page en accédant au flux `:$DATA` comme `http://www.alternate-data-streams.com/default.asp::$DATA`.

En utilisant l'outil [**AlternateStreamView**](https://www.nirsoft.net/utils/alternate\_data\_streams.html), vous pouvez rechercher et exporter tous les fichiers avec un ADS.

![](<../../../.gitbook/assets/image (518).png>)

En utilisant FTK Imager et en double-cliquant sur un fichier avec ADS, vous pouvez **accéder aux données ADS** :

![](<../../../.gitbook/assets/image (517).png>)

Si vous trouvez un ADS appelé **`Zone.Identifier`** (voir l'image ci-dessus), cela contient généralement **des informations sur la façon dont le fichier a été téléchargé**. Il y aurait un champ "ZoneId" avec les informations suivantes :

* Zone ID = 0 -> Mon ordinateur
* Zone ID = 1 -> Intranet
* Zone ID = 2 -> Fiable
* Zone ID = 3 -> Internet
* Zone ID = 4 -> Non fiable

De plus, différents logiciels peuvent stocker des informations supplémentaires :

| Logiciel                                                            | Info                                                                         |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Google Chrome, Opera, Vivaldi,                                      | ZoneId=3, ReferrerUrl, HostUrl                                               |
| Microsoft Edge                                                      | ZoneId=3, LastWriterPackageFamilyName=Microsoft.MicrosoftEdge\_8wekyb3d8bbwe |
| Firefox, Tor browser, Outlook2016, Thunderbird, Windows Mail, Skype | ZoneId=3                                                                     |
| μTorrent                                                            | ZoneId=3, HostUrl=about:internet                                             |

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [
