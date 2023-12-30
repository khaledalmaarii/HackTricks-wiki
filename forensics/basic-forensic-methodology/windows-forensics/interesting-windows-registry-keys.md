# Clés de registre Windows intéressantes

## Clés de registre Windows intéressantes

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Informations système Windows**

### Version

* **`Software\Microsoft\Windows NT\CurrentVersion`** : Version de Windows, Service Pack, heure d'installation et propriétaire enregistré

### Nom d'hôte

* **`System\ControlSet001\Control\ComputerName\ComputerName`** : Nom d'hôte

### Fuseau horaire

* **`System\ControlSet001\Control\TimeZoneInformation`** : Fuseau horaire

### Dernier accès

* **`System\ControlSet001\Control\Filesystem`** : Dernier accès (par défaut désactivé avec `NtfsDisableLastAccessUpdate=1`, si `0`, alors, c'est activé).
* Pour l'activer : `fsutil behavior set disablelastaccess 0`

### Heure d'arrêt

* `System\ControlSet001\Control\Windows` : Heure d'arrêt
* `System\ControlSet001\Control\Watchdog\Display` : Compteur d'arrêt (uniquement XP)

### Informations réseau

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`** : Interfaces réseau
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`** : Première et dernière fois qu'une connexion réseau a été effectuée et connexions via VPN
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}` (pour XP) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`** : Type de réseau (0x47-sans fil, 0x06-câble, 0x17-3G) et catégorie (0-Public, 1-Privé/Maison, 2-Domaine/Travail) et dernières connexions

### Dossiers partagés

* **`System\ControlSet001\Services\lanmanserver\Shares\`** : Dossiers partagés et leurs configurations. Si **Client Side Caching** (CSCFLAGS) est activé, alors, une copie des fichiers partagés sera sauvegardée chez les clients et le serveur dans `C:\Windows\CSC`
* CSCFlag=0 -> Par défaut, l'utilisateur doit indiquer les fichiers qu'il souhaite mettre en cache
* CSCFlag=16 -> Mise en cache automatique des documents. "Tous les fichiers et programmes que les utilisateurs ouvrent à partir du dossier partagé sont automatiquement disponibles hors ligne" avec l'option "optimiser pour la performance" décochée.
* CSCFlag=32 -> Comme les options précédentes mais "optimiser pour la performance" est cochée
* CSCFlag=48 -> Le cache est désactivé.
* CSCFlag=2048 : Ce paramètre est uniquement sur Win 7 & 8 et est le paramètre par défaut jusqu'à ce que vous désactiviez le "Partage de fichiers simple" ou utilisiez l'option de partage "avancée". Il semble également être le paramètre par défaut pour le "Groupe résidentiel"
* CSCFlag=768 -> Ce paramètre a été vu uniquement sur des périphériques d'impression partagés.

### Programmes de démarrage automatique

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### Recherches dans l'Explorateur

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery` : Ce que l'utilisateur a recherché en utilisant l'explorateur/l'assistant. L'élément avec `MRU=0` est le dernier.

### Chemins saisis

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` : Chemins saisis dans l'explorateur (uniquement W10)

### Documents récents

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` : Documents récents ouverts par l'utilisateur
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word}\FileMRU` : Documents Office récents. Versions :
  * 14.0 Office 2010
  * 12.0 Office 2007
  * 11.0 Office 2003
  * 10.0 Office X
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word} UserMRU\LiveID_###\FileMRU` : Documents Office récents. Versions :
  * 15.0 office 2013
  * 16.0 Office 2016

### MRUs

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LasVisitedPidlMRU`

Indique le chemin d'où l'exécutable a été lancé

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU` (XP)
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSavePidlMRU`

Indique les fichiers ouverts à l'intérieur d'une fenêtre ouverte

### Dernières commandes exécutées

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMR`

### Clé User Assist

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

Le GUID est l'identifiant de l'application. Données enregistrées :

* Dernière heure d'exécution
* Compteur d'exécution
* Nom de l'application GUI (cela contient le chemin absolu et plus d'informations)
* Temps de focus et nom du focus

## Shellbags

Lorsque vous ouvrez un répertoire, Windows enregistre des données sur la façon de visualiser le répertoire dans le registre. Ces entrées sont connues sous le nom de Shellbags.

Accès à l'Explorateur :

* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

Accès au Bureau :

* `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

Pour analyser les Shellbags, vous pouvez utiliser [**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md) et vous pourrez trouver le **temps MAC du dossier** ainsi que la **date de création et la date de modification du shellbag** qui sont liées à la **première et à la dernière fois** que le dossier a été accédé.

Notez deux choses de l'image suivante :

1. Nous connaissons le **nom des dossiers du USB** qui a été inséré dans **E:**
2. Nous savons quand le **shellbag a été créé et modifié** et quand le dossier a été créé et accédé

![](<../../../.gitbook/assets/image (475).png>)

## Informations USB

### Infos sur l'appareil

Le registre `HKLM\SYSTEM\ControlSet001\Enum\USBSTOR` surveille chaque appareil USB qui a été connecté au PC.\
Dans ce registre, il est possible de trouver :

* Le nom du fabricant
* Le nom et la version du produit
* L'ID de classe de l'appareil
* Le nom du volume (dans les images suivantes, le nom du volume est la sous-clé en surbrillance)

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

De plus, en vérifiant le registre `HKLM\SYSTEM\ControlSet001\Enum\USB` et en comparant les valeurs des sous-clés, il est possible de trouver la valeur VID.

![](<../../../.gitbook/assets/image (478).png>)

Avec les informations précédentes, le registre `SOFTWARE\Microsoft\Windows Portable Devices\Devices` peut être utilisé pour obtenir le **`{GUID}`** :

![](<../../../.gitbook/assets/image (480).png>)

### Utilisateur ayant utilisé l'appareil

Avec le **{GUID}** de l'appareil, il est maintenant possible de **vérifier toutes les ruches NTUDER.DAT de tous les utilisateurs**, en recherchant le GUID jusqu'à ce que vous le trouviez dans l'un d'eux (`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`).

![](<../../../.gitbook/assets/image (481).png>)

### Dernier montage

En vérifiant le registre `System\MoutedDevices`, il est possible de savoir **quel appareil a été le dernier monté**. Dans l'image suivante, vérifiez comment le dernier appareil monté dans `E:` est le Toshiba (en utilisant l'outil Registry Explorer).

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### Numéro de série du volume

Dans `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, vous pouvez trouver le numéro de série du volume. **En connaissant le nom du volume et le numéro de série du volume, vous pouvez corréler les informations** à partir des fichiers LNK qui utilisent ces informations.

Notez que lorsqu'un appareil USB est formaté :

* Un nouveau nom de volume est créé
* Un nouveau numéro de série du volume est créé
* Le numéro de série physique est conservé

### Horodatages

Dans `System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\`, vous pouvez trouver la première et la dernière fois que l'appareil a été connecté :

* 0064 -- Première connexion
* 0066 -- Dernière connexion
* 0067 -- Déconnexion

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
