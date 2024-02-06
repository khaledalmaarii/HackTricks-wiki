# Clés de registre Windows intéressantes

## Clés de registre Windows intéressantes

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## **Informations système Windows**

### Version

- **`Software\Microsoft\Windows NT\CurrentVersion`** : Version de Windows, Service Pack, heure d'installation et propriétaire enregistré

### Nom d'hôte

- **`System\ControlSet001\Control\ComputerName\ComputerName`** : Nom d'hôte

### Fuseau horaire

- **`System\ControlSet001\Control\TimeZoneInformation`** : Fuseau horaire

### Dernière heure d'accès

- **`System\ControlSet001\Control\Filesystem`** : Dernière heure d'accès (par défaut désactivée avec `NtfsDisableLastAccessUpdate=1`, si `0`, alors elle est activée).
- Pour l'activer : `fsutil behavior set disablelastaccess 0`

### Heure d'arrêt

- `System\ControlSet001\Control\Windows` : Heure d'arrêt
- `System\ControlSet001\Control\Watchdog\Display` : Nombre d'arrêts (uniquement XP)

### Informations réseau

- **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`** : Interfaces réseau
- **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`** : Première et dernière fois qu'une connexion réseau a été effectuée et connexions via VPN
- **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}`** (pour XP) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` : Type de réseau (0x47-sans fil, 0x06-câble, 0x17-3G) et catégorie (0-Public, 1-Privé/Domicile, 2-Domaine/Travail) et dernières connexions

### Dossiers partagés

- **`System\ControlSet001\Services\lanmanserver\Shares\`** : Dossiers partagés et leurs configurations. Si **la mise en cache côté client** (CSCFLAGS) est activée, une copie des fichiers partagés sera enregistrée dans les clients et le serveur dans `C:\Windows\CSC`
- CSCFlag=0 -> Par défaut, l'utilisateur doit indiquer les fichiers qu'il souhaite mettre en cache
- CSCFlag=16 -> Mise en cache automatique des documents. "Tous les fichiers et programmes ouverts à partir du dossier partagé sont automatiquement disponibles hors connexion" avec l'option "optimiser les performances" décochée.
- CSCFlag=32 -> Comme les options précédentes mais avec l'option "optimiser les performances" cochée
- CSCFlag=48 -> La mise en cache est désactivée.
- CSCFlag=2048 : Ce paramètre est uniquement sur Win 7 & 8 et est le paramètre par défaut jusqu'à ce que vous désactiviez le "Partage de fichiers simple" ou utilisiez l'option de partage "avancée". Il semble également être le paramètre par défaut pour le "Groupe résidentiel"
- CSCFlag=768 -> Ce paramètre n'a été vu que sur les périphériques d'impression partagés.

### Programmes de démarrage automatique

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `Software\Microsoft\Windows\CurrentVersion\Runonce`
- `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
- `Software\Microsoft\Windows\CurrentVersion\Run`

### Recherches dans l'Explorateur

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery` : Ce que l'utilisateur a recherché en utilisant l'explorateur/assistant. L'élément avec `MRU=0` est le dernier.

### Chemins saisis

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` : Chemins saisis dans l'explorateur (uniquement W10)

### Documents récents

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` : Documents récemment ouverts par l'utilisateur
- `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word}\FileMRU` : Documents Office récents. Versions :
  - 14.0 Office 2010
  - 12.0 Office 2007
  - 11.0 Office 2003
  - 10.0 Office X
- `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word} UserMRU\LiveID_###\FileMRU` : Documents Office récents. Versions :
  - 15.0 Office 2013
  - 16.0 Office 2016

### MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LasVisitedPidlMRU`

Indique le chemin à partir duquel l'exécutable a été lancé

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU` (XP)
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSavePidlMRU`

Indique les fichiers ouverts dans une fenêtre ouverte

### Dernières commandes exécutées

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMR`

### Clé User Assist

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

Le GUID est l'identifiant de l'application. Données enregistrées :

- Dernière heure d'exécution
- Nombre d'exécutions
- Nom de l'application GUI (contient le chemin absolu et plus d'informations)
- Temps de mise au premier plan et nom de mise au premier plan

## Shellbags

Lorsque vous ouvrez un répertoire, Windows enregistre des données sur la manière de visualiser le répertoire dans le registre. Ces entrées sont connues sous le nom de Shellbags.

Accès à l'Explorateur :

- `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
- `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

Accès au Bureau :

- `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

Pour analyser les Shellbags, vous pouvez utiliser [**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md) et vous pourrez trouver le **temps MAC du dossier** ainsi que la **date de création et de modification du shellbag** qui sont liées à la **première et à la dernière fois** où le dossier a été accédé.

Notez 2 choses à partir de l'image suivante :

1. Nous connaissons le **nom des dossiers de la clé USB** qui a été insérée dans **E:**
2. Nous savons quand le **shellbag a été créé et modifié** et quand le dossier a été créé et accédé

![](<../../../.gitbook/assets/image (475).png>)

## Informations sur les clés USB

### Informations sur le périphérique

Le registre `HKLM\SYSTEM\ControlSet001\Enum\USBSTOR` surveille chaque périphérique USB connecté au PC.\
Dans ce registre, il est possible de trouver :

- Le nom du fabricant
- Le nom et la version du produit
- L'ID de classe du périphérique
- Le nom du volume (dans les images suivantes, le nom du volume est la sous-clé surlignée)

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

De plus, en vérifiant le registre `HKLM\SYSTEM\ControlSet001\Enum\USB` et en comparant les valeurs des sous-clés, il est possible de trouver la valeur VID.

![](<../../../.gitbook/assets/image (478).png>)

Avec les informations précédentes, le registre `SOFTWARE\Microsoft\Windows Portable Devices\Devices` peut être utilisé pour obtenir le **`{GUID}`** :

![](<../../../.gitbook/assets/image (480).png>)

### Utilisateur ayant utilisé le périphérique

En ayant le **{GUID}** du périphérique, il est maintenant possible de **vérifier toutes les ruches NTUDER.DAT de tous les utilisateurs**, en recherchant le GUID jusqu'à ce que vous le trouviez dans l'un d'eux (`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`).

![](<../../../.gitbook/assets/image (481).png>)

### Dernier montage

En vérifiant le registre `System\MoutedDevices`, il est possible de découvrir **quel périphérique a été le dernier monté**. Dans l'image suivante, vérifiez comment le dernier périphérique monté en `E:` est celui de Toshiba (en utilisant l'outil Registry Explorer).

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### Numéro de série du volume

Dans `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, vous pouvez trouver le numéro de série du volume. **En connaissant le nom du volume et le numéro de série du volume, vous pouvez corréler les informations** des fichiers LNK qui utilisent ces informations.

Notez que lorsqu'un périphérique USB est formaté :

- Un nouveau nom de volume est créé
- Un nouveau numéro de série de volume est créé
- Le numéro de série physique est conservé

### Horodatages

Dans `System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\`, vous pouvez trouver la première et la dernière fois où le périphérique a été connecté :

- 0064 -- Première connexion
- 0066 -- Dernière connexion
- 0067 -- Déconnexion

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
