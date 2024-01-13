```markdown
# Horodatages

Un attaquant peut être intéressé par **changer les horodatages des fichiers** pour éviter d'être détecté.\
Il est possible de trouver les horodatages dans le MFT dans les attributs `$STANDARD_INFORMATION` __ et __ `$FILE_NAME`.

Les deux attributs ont 4 horodatages : **Modification**, **accès**, **création**, et **modification du registre MFT** (MACE ou MACB).

**L'explorateur Windows** et d'autres outils affichent les informations de **`$STANDARD_INFORMATION`**.

## TimeStomp - Outil anti-forensique

Cet outil **modifie** les informations d'horodatage dans **`$STANDARD_INFORMATION`** **mais** **pas** les informations dans **`$FILE_NAME`**. Par conséquent, il est possible d'**identifier** une **activité suspecte**.

## Usnjrnl

Le **Journal USN** (Update Sequence Number Journal), ou Journal de Modification, est une fonctionnalité du système de fichiers Windows NT (NTFS) qui **maintient un enregistrement des modifications apportées au volume**.\
Il est possible d'utiliser l'outil [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) pour rechercher des modifications dans cet enregistrement.

![](<../../.gitbook/assets/image (449).png>)

L'image précédente est le **résultat** affiché par l'**outil** où l'on peut observer que des **changements ont été effectués** sur le fichier.

## $LogFile

Tous les changements de métadonnées d'un système de fichiers sont enregistrés pour assurer la récupération cohérente des structures critiques du système de fichiers après un crash système. Cela s'appelle [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging).\
Les métadonnées enregistrées sont stockées dans un fichier appelé “**$LogFile**”, qui se trouve dans un répertoire racine d'un système de fichiers NTFS.\
Il est possible d'utiliser des outils comme [LogFileParser](https://github.com/jschicht/LogFileParser) pour analyser ce fichier et trouver des changements.

![](<../../.gitbook/assets/image (450).png>)

Encore une fois, dans le résultat de l'outil, il est possible de voir que **des changements ont été effectués**.

En utilisant le même outil, il est possible d'identifier **à quel moment les horodatages ont été modifiés** :

![](<../../.gitbook/assets/image (451).png>)

* CTIME : Heure de création du fichier
* ATIME : Heure de modification du fichier
* MTIME : Heure de modification du registre MFT du fichier
* RTIME : Heure d'accès au fichier

## Comparaison `$STANDARD_INFORMATION` et `$FILE_NAME`

Une autre manière d'identifier des fichiers modifiés de manière suspecte serait de comparer les horodatages des deux attributs à la recherche de **divergences**.

## Nanosecondes

Les horodatages **NTFS** ont une **précision** de **100 nanosecondes**. Ainsi, trouver des fichiers avec des horodatages comme 2010-10-10 10:10:**00.000:0000 est très suspect**.

## SetMace - Outil anti-forensique

Cet outil peut modifier les deux attributs `$STARNDAR_INFORMATION` et `$FILE_NAME`. Cependant, à partir de Windows Vista, il est nécessaire d'avoir un OS actif pour modifier ces informations.

# Dissimulation de données

NTFS utilise un cluster et la taille minimale d'information. Cela signifie que si un fichier occupe un cluster et demi, la **moitié restante ne sera jamais utilisée** jusqu'à ce que le fichier soit supprimé. Il est alors possible de **cacher des données dans cet espace libre**.

Il existe des outils comme slacker qui permettent de cacher des données dans cet espace "caché". Cependant, une analyse des fichiers `$logfile` et `$usnjrnl` peut montrer que des données ont été ajoutées :

![](<../../.gitbook/assets/image (452).png>)

Il est alors possible de récupérer l'espace libre en utilisant des outils comme FTK Imager. Notez que ce type d'outil peut sauvegarder le contenu de manière obfusquée ou même chiffrée.

# UsbKill

C'est un outil qui **éteindra l'ordinateur si un changement dans les ports USB** est détecté.\
Une manière de découvrir cela serait d'inspecter les processus en cours et **d'examiner chaque script python en cours d'exécution**.

# Distributions Linux Live

Ces distributions sont **exécutées dans la mémoire RAM**. La seule manière de les détecter est **dans le cas où le système de fichiers NTFS est monté avec des permissions d'écriture**. Si c'est monté juste avec des permissions de lecture, il ne sera pas possible de détecter l'intrusion.

# Suppression Sécurisée

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Configuration Windows

Il est possible de désactiver plusieurs méthodes de journalisation de Windows pour rendre l'investigation forensique beaucoup plus difficile.

## Désactiver les Horodatages - UserAssist

Il s'agit d'une clé de registre qui conserve les dates et heures auxquelles chaque exécutable a été exécuté par l'utilisateur.

Pour désactiver UserAssist, deux étapes sont nécessaires :

1. Définir deux clés de registre, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` et `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, toutes deux à zéro pour indiquer que nous voulons désactiver UserAssist.
2. Effacer vos sous-arbres de registre qui ressemblent à `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Désactiver les Horodatages - Prefetch

Cela enregistrera des informations sur les applications exécutées dans le but d'améliorer la performance du système Windows. Cependant, cela peut aussi être utile pour les pratiques forensiques.

* Exécuter `regedit`
* Sélectionner le chemin de fichier `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Cliquer avec le bouton droit sur `EnablePrefetcher` et `EnableSuperfetch`
* Sélectionner Modifier sur chacun d'eux pour changer la valeur de 1 (ou 3) à 0
* Redémarrer

## Désactiver les Horodatages - Dernier Temps d'Accès

Chaque fois qu'un dossier est ouvert à partir d'un volume NTFS sur un serveur Windows NT, le système prend le temps de **mettre à jour un champ d'horodatage sur chaque dossier listé**, appelé le dernier temps d'accès. Sur un volume NTFS fortement utilisé, cela peut affecter les performances.

1. Ouvrir l'Éditeur de Registre (Regedit.exe).
2. Naviguer jusqu'à `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Chercher `NtfsDisableLastAccessUpdate`. S'il n'existe pas, ajouter ce DWORD et définir sa valeur à 1, ce qui désactivera le processus.
4. Fermer l'Éditeur de Registre et redémarrer le serveur.

## Supprimer l'Historique USB

Toutes les **entrées de périphériques USB** sont stockées dans le Registre Windows sous la clé **USBSTOR** qui contient des sous-clés créées chaque fois que vous branchez un périphérique USB sur votre PC ou ordinateur portable. Vous pouvez trouver cette clé ici `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **En supprimant cela**, vous supprimerez l'historique USB.\
Vous pouvez également utiliser l'outil [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) pour vous assurer de les avoir supprimés (et pour les supprimer).

Un autre fichier qui enregistre des informations sur les USB est le fichier `setupapi.dev.log` dans `C:\Windows\INF`. Celui-ci devrait également être supprimé.

## Désactiver les Copies d'Ombre

**Lister** les copies d'ombre avec `vssadmin list shadowstorage`\
**Supprimer** les en exécutant `vssadmin delete shadow`

Vous pouvez également les supprimer via l'interface graphique en suivant les étapes proposées dans [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Pour désactiver les copies d'ombre :

1. Aller au bouton de démarrage Windows et taper "services" dans la boîte de recherche de texte ; ouvrir le programme Services.
2. Localiser "Volume Shadow Copy" dans la liste, le mettre en surbrillance, puis cliquer avec le bouton droit > Propriétés.
3. Dans le menu déroulant "Type de démarrage", sélectionner Désactivé, puis cliquer sur Appliquer et OK.

![](<../../.gitbook/assets/image (453).png>)

Il est également possible de modifier la configuration des fichiers qui vont être copiés dans la copie d'ombre dans le registre `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Écraser les fichiers supprimés

* Vous pouvez utiliser un **outil Windows** : `cipher /w:C` Cela indiquera à cipher de supprimer toutes les données de l'espace disque disponible inutilisé dans le lecteur C.
* Vous pouvez également utiliser des outils comme [**Eraser**](https://eraser.heidi.ie)

## Supprimer les journaux d'événements Windows

* Windows + R --> eventvwr.msc --> Développer "Journaux Windows" --> Cliquer avec le bouton droit sur chaque catégorie et sélectionner "Effacer le journal"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Désactiver les journaux d'événements Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Dans la section des services, désactiver le service "Journal des événements Windows"
* `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

## Désactiver $UsnJrnl

* `fsutil usn deletejournal /d c:`
```
