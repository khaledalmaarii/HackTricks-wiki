<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


# Horodatage

Un attaquant peut être intéressé par **la modification des horodatages des fichiers** pour éviter d'être détecté.\
Il est possible de trouver les horodatages à l'intérieur du MFT dans les attributs `$STANDARD_INFORMATION` __ et __ `$FILE_NAME`.

Les deux attributs ont 4 horodatages : **modification**, **accès**, **création** et **modification du registre MFT** (MACE ou MACB).

**L'explorateur Windows** et d'autres outils affichent les informations de **`$STANDARD_INFORMATION`**.

## TimeStomp - Outil anti-forensique

Cet outil **modifie** les informations d'horodatage à l'intérieur de **`$STANDARD_INFORMATION`** **mais** **pas** les informations à l'intérieur de **`$FILE_NAME`**. Par conséquent, il est possible d'**identifier** une **activité suspecte**.

## Usnjrnl

Le **journal USN** (Journal de numéro de séquence de mise à jour) est une fonctionnalité du NTFS (système de fichiers Windows NT) qui garde une trace des modifications du volume. L'outil [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permet d'examiner ces changements.

![](<../../.gitbook/assets/image (449).png>)

L'image précédente est la **sortie** affichée par l'**outil** où l'on peut observer que des **changements ont été effectués** sur le fichier.

## $LogFile

**Toutes les modifications de métadonnées sur un système de fichiers sont enregistrées** dans un processus appelé [journalisation en avance](https://en.wikipedia.org/wiki/Write-ahead_logging). Les métadonnées enregistrées sont conservées dans un fichier nommé `**$LogFile**`, situé dans le répertoire racine d'un système de fichiers NTFS. Des outils tels que [LogFileParser](https://github.com/jschicht/LogFileParser) peuvent être utilisés pour analyser ce fichier et identifier les changements.

![](<../../.gitbook/assets/image (450).png>)

Encore une fois, dans la sortie de l'outil, il est possible de voir que **des changements ont été effectués**.

En utilisant le même outil, il est possible d'identifier à **quel moment les horodatages ont été modifiés** :

![](<../../.gitbook/assets/image (451).png>)

* CTIME : Heure de création du fichier
* ATIME : Heure de modification du fichier
* MTIME : Heure de modification du registre MFT du fichier
* RTIME : Heure d'accès au fichier

## Comparaison de `$STANDARD_INFORMATION` et `$FILE_NAME`

Une autre façon d'identifier des fichiers modifiés de manière suspecte serait de comparer l'heure dans les deux attributs à la recherche de **discordances**.

## Nanosecondes

Les horodatages **NTFS** ont une **précision** de **100 nanosecondes**. Ainsi, trouver des fichiers avec des horodatages comme 2010-10-10 10:10:**00.000:0000 est très suspect**.

## SetMace - Outil anti-forensique

Cet outil peut modifier les deux attributs `$STARNDAR_INFORMATION` et `$FILE_NAME`. Cependant, à partir de Windows Vista, il est nécessaire d'avoir un système d'exploitation en direct pour modifier ces informations.

# Dissimulation de données

NTFS utilise un cluster et la taille d'information minimale. Cela signifie que si un fichier occupe un cluster et demi, la **moitié restante ne sera jamais utilisée** tant que le fichier n'est pas supprimé. Ainsi, il est possible de **cacher des données dans cet espace inutilisé**.

Il existe des outils comme slacker qui permettent de cacher des données dans cet espace "caché". Cependant, une analyse du `$logfile` et du `$usnjrnl` peut montrer qu'une certaine donnée a été ajoutée :

![](<../../.gitbook/assets/image (452).png>)

Il est alors possible de récupérer l'espace inutilisé en utilisant des outils comme FTK Imager. Notez que ce type d'outil peut enregistrer le contenu de manière obfusquée ou même chiffrée.

# UsbKill

C'est un outil qui **éteindra l'ordinateur si un changement dans les ports USB** est détecté.\
Une façon de découvrir cela serait d'inspecter les processus en cours d'exécution et de **revoir chaque script Python en cours d'exécution**.

# Distributions Linux en direct

Ces distributions sont **exécutées dans la mémoire RAM**. La seule façon de les détecter est **si le système de fichiers NTFS est monté avec des autorisations d'écriture**. S'il est monté uniquement avec des autorisations de lecture, il ne sera pas possible de détecter l'intrusion.

# Suppression sécurisée

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Configuration Windows

Il est possible de désactiver plusieurs méthodes de journalisation de Windows pour rendre l'investigation forensique beaucoup plus difficile.

## Désactiver les horodatages - UserAssist

Il s'agit d'une clé de registre qui conserve les dates et heures auxquelles chaque exécutable a été lancé par l'utilisateur.

La désactivation de UserAssist nécessite deux étapes :

1. Définir deux clés de registre, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` et `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, toutes deux à zéro pour indiquer que nous voulons désactiver UserAssist.
2. Effacer vos sous-arbres de registre ressemblant à `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Désactiver les horodatages - Prefetch

Cela enregistrera des informations sur les applications exécutées dans le but d'améliorer les performances du système Windows. Cependant, cela peut également être utile pour les pratiques forensiques.

* Exécutez `regedit`
* Sélectionnez le chemin du fichier `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Cliquez avec le bouton droit sur `EnablePrefetcher` et `EnableSuperfetch`
* Sélectionnez Modifier sur chacun d'eux pour changer la valeur de 1 (ou 3) à 0
* Redémarrez

## Désactiver les horodatages - Heure de dernier accès

Chaque fois qu'un dossier est ouvert à partir d'un volume NTFS sur un serveur Windows NT, le système prend le temps de **mettre à jour un champ d'horodatage sur chaque dossier répertorié**, appelé l'heure de dernier accès. Sur un volume NTFS très utilisé, cela peut affecter les performances.

1. Ouvrez l'Éditeur du Registre (Regedit.exe).
2. Accédez à `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Recherchez `NtfsDisableLastAccessUpdate`. S'il n'existe pas, ajoutez ce DWORD et définissez sa valeur sur 1, ce qui désactivera le processus.
4. Fermez l'Éditeur du Registre et redémarrez le serveur.
## Supprimer l'historique USB

Toutes les **entrées de périphériques USB** sont stockées dans le Registre Windows sous la clé de registre **USBSTOR** qui contient des sous-clés créées chaque fois que vous branchez un périphérique USB sur votre PC ou ordinateur portable. Vous pouvez trouver cette clé ici `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. En **supprimant cela**, vous supprimerez l'historique USB.\
Vous pouvez également utiliser l'outil [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) pour vous assurer de les avoir supprimés (et pour les supprimer).

Un autre fichier qui enregistre des informations sur les clés USB est le fichier `setupapi.dev.log` à l'intérieur de `C:\Windows\INF`. Celui-ci devrait également être supprimé.

## Désactiver les copies d'ombre

**Listez** les copies d'ombre avec `vssadmin list shadowstorage`\
**Supprimez** les en exécutant `vssadmin delete shadow`

Vous pouvez également les supprimer via l'interface graphique en suivant les étapes proposées dans [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Pour désactiver les copies d'ombre [étapes à partir d'ici](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Ouvrez le programme Services en tapant "services" dans la zone de recherche de texte après avoir cliqué sur le bouton Démarrer de Windows.
2. Dans la liste, trouvez "Copie d'ombre de volume", sélectionnez-le, puis accédez aux Propriétés en cliquant avec le bouton droit.
3. Choisissez Désactivé dans le menu déroulant "Type de démarrage", puis confirmez le changement en cliquant sur Appliquer et OK.

Il est également possible de modifier la configuration des fichiers qui vont être copiés dans la copie d'ombre dans le registre `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Écraser les fichiers supprimés

* Vous pouvez utiliser un **outil Windows**: `cipher /w:C` Cela indiquera à cipher de supprimer toutes les données de l'espace disque inutilisé disponible dans le lecteur C.
* Vous pouvez également utiliser des outils comme [**Eraser**](https://eraser.heidi.ie)

## Supprimer les journaux d'événements Windows

* Windows + R --> eventvwr.msc --> Développez "Journaux Windows" --> Cliquez avec le bouton droit sur chaque catégorie et sélectionnez "Effacer le journal"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Désactiver les journaux d'événements Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* À l'intérieur de la section des services, désactivez le service "Journal des événements Windows"
* `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

## Désactiver $UsnJrnl

* `fsutil usn deletejournal /d c:`

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}
