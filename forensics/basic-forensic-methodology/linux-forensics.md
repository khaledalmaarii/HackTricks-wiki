# Analyse Forensique Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Collecte d'Informations Initiale

### Informations de Base

Tout d'abord, il est recommandé d'avoir une **clé USB** avec des **binaires et des bibliothèques bien connus** (vous pouvez simplement prendre Ubuntu et copier les dossiers _/bin_, _/sbin_, _/lib,_ et _/lib64_), puis monter la clé USB et modifier les variables d'environnement pour utiliser ces binaires :
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Une fois que vous avez configuré le système pour utiliser des binaires bons et connus, vous pouvez commencer **à extraire quelques informations de base** :
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Informations suspectes

Lors de l'obtention des informations de base, vous devriez vérifier des choses étranges comme :

- Les **processus root** ont généralement des PIDS bas, donc si vous trouvez un processus root avec un PID élevé, vous pouvez suspecter
- Vérifiez les **connexions enregistrées** des utilisateurs sans shell dans `/etc/passwd`
- Vérifiez les **hachages de mots de passe** dans `/etc/shadow` pour les utilisateurs sans shell

### Capture de mémoire

Pour obtenir la mémoire du système en cours d'exécution, il est recommandé d'utiliser [**LiME**](https://github.com/504ensicsLabs/LiME).\
Pour le **compiler**, vous devez utiliser le **même noyau** que celui utilisé par la machine victime.

{% hint style="info" %}
Rappelez-vous que vous **ne pouvez pas installer LiME ou quoi que ce soit d'autre** sur la machine victime car cela apportera plusieurs modifications à celle-ci
{% endhint %}

Ainsi, si vous avez une version identique d'Ubuntu, vous pouvez utiliser `apt-get install lime-forensics-dkms`\
Dans d'autres cas, vous devez télécharger [**LiME**](https://github.com/504ensicsLabs/LiME) depuis github et le compiler avec les en-têtes de noyau corrects. Pour **obtenir les en-têtes de noyau exacts** de la machine victime, vous pouvez simplement **copier le répertoire** `/lib/modules/<version du noyau>` sur votre machine, puis **compiler** LiME en les utilisant :
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME prend en charge 3 **formats**:

* Brut (chaque segment concaténé ensemble)
* Rembourré (identique au brut, mais avec des zéros dans les bits de droite)
* Lime (format recommandé avec des métadonnées)

LiME peut également être utilisé pour **envoyer le vidage via le réseau** au lieu de le stocker sur le système en utilisant quelque chose comme : `path=tcp:4444`

### Imagerie de disque

#### Arrêt

Tout d'abord, vous devrez **arrêter le système**. Ce n'est pas toujours une option car parfois le système sera un serveur de production que l'entreprise ne peut pas se permettre d'arrêter.\
Il existe **2 façons** d'arrêter le système, un **arrêt normal** et un **arrêt "débrancher la prise"**. Le premier permettra aux **processus de se terminer comme d'habitude** et au **système de fichiers** d'être **synchronisé**, mais il permettra également à un éventuel **logiciel malveillant** de **détruire des preuves**. L'approche "débrancher la prise" peut entraîner **une perte d'informations** (pas beaucoup d'informations seront perdues car nous avons déjà pris une image de la mémoire) et le **logiciel malveillant n'aura aucune opportunité** d'intervenir. Par conséquent, si vous **soupçonnez** la présence d'un **logiciel malveillant**, exécutez simplement la commande **`sync`** sur le système et débranchez la prise.

#### Prendre une image du disque

Il est important de noter que **avant de connecter votre ordinateur à quoi que ce soit lié à l'affaire**, vous devez vous assurer qu'il va être **monté en lecture seule** pour éviter de modifier des informations.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-analyse de l'image disque

Imager une image disque sans plus de données.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recherche de logiciels malveillants connus

### Fichiers système modifiés

Linux propose des outils pour garantir l'intégrité des composants système, essentiels pour repérer les fichiers potentiellement problématiques.

* **Systèmes basés sur RedHat** : Utilisez `rpm -Va` pour une vérification complète.
* **Systèmes basés sur Debian** : `dpkg --verify` pour une vérification initiale, suivi de `debsums | grep -v "OK$"` (après avoir installé `debsums` avec `apt-get install debsums`) pour identifier d'éventuels problèmes.

### Détecteurs de logiciels malveillants/rootkits

Consultez la page suivante pour découvrir des outils utiles pour trouver des logiciels malveillants :

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Recherche de programmes installés

Pour rechercher efficacement des programmes installés sur les systèmes Debian et RedHat, envisagez d'utiliser les journaux système et les bases de données en plus des vérifications manuelles dans les répertoires courants.

* Pour Debian, inspectez _**`/var/lib/dpkg/status`**_ et _**`/var/log/dpkg.log`**_ pour obtenir des détails sur les installations de packages, en utilisant `grep` pour filtrer des informations spécifiques.
* Les utilisateurs de RedHat peuvent interroger la base de données RPM avec `rpm -qa --root=/mntpath/var/lib/rpm` pour lister les packages installés.

Pour découvrir les logiciels installés manuellement ou en dehors de ces gestionnaires de packages, explorez des répertoires tels que _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, et _**`/sbin`**_. Combiner les listes de répertoires avec des commandes spécifiques au système pour identifier les exécutables non associés à des packages connus, améliorant ainsi votre recherche de tous les programmes installés.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Récupérer les binaires en cours d'exécution supprimés

Imaginez un processus qui a été exécuté à partir de /tmp/exec puis supprimé. Il est possible de l'extraire
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspectez les emplacements de démarrage automatique

### Tâches planifiées
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### Services

Chemins où un logiciel malveillant pourrait être installé en tant que service :

* **/etc/inittab** : Appelle des scripts d'initialisation comme rc.sysinit, redirigeant ensuite vers des scripts de démarrage.
* **/etc/rc.d/** et **/etc/rc.boot/** : Contiennent des scripts pour le démarrage des services, ce dernier étant trouvé dans les anciennes versions de Linux.
* **/etc/init.d/** : Utilisé dans certaines versions de Linux comme Debian pour stocker des scripts de démarrage.
* Les services peuvent également être activés via **/etc/inetd.conf** ou **/etc/xinetd/**, selon la variante de Linux.
* **/etc/systemd/system** : Un répertoire pour les scripts du système et du gestionnaire de services.
* **/etc/systemd/system/multi-user.target.wants/** : Contient des liens vers des services qui doivent être démarrés dans un niveau d'exécution multi-utilisateurs.
* **/usr/local/etc/rc.d/** : Pour les services personnalisés ou tiers.
* **\~/.config/autostart/** : Pour les applications de démarrage automatique spécifiques à l'utilisateur, qui peuvent être un endroit de dissimulation pour les logiciels malveillants ciblant les utilisateurs.
* **/lib/systemd/system/** : Fichiers d'unités par défaut à l'échelle du système fournis par les packages installés.

### Modules du Noyau

Les modules du noyau Linux, souvent utilisés par les logiciels malveillants comme composants de rootkit, sont chargés au démarrage du système. Les répertoires et fichiers critiques pour ces modules incluent :

* **/lib/modules/$(uname -r)** : Contient les modules pour la version du noyau en cours d'exécution.
* **/etc/modprobe.d** : Contient des fichiers de configuration pour contrôler le chargement des modules.
* **/etc/modprobe** et **/etc/modprobe.conf** : Fichiers pour les paramètres globaux des modules.

### Autres Emplacements de Démarrage Automatique

Linux utilise divers fichiers pour exécuter automatiquement des programmes lors de la connexion de l'utilisateur, pouvant potentiellement héberger des logiciels malveillants :

* **/etc/profile.d/**\*, **/etc/profile**, et **/etc/bash.bashrc** : Exécuté pour toute connexion d'utilisateur.
* **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, et **\~/.config/autostart** : Fichiers spécifiques à l'utilisateur qui s'exécutent lors de leur connexion.
* **/etc/rc.local** : S'exécute après le démarrage de tous les services système, marquant la fin de la transition vers un environnement multi-utilisateurs.

## Examiner les Journaux

Les systèmes Linux suivent les activités des utilisateurs et les événements système à travers divers fichiers journaux. Ces journaux sont essentiels pour identifier les accès non autorisés, les infections par des logiciels malveillants et d'autres incidents de sécurité. Les principaux fichiers journaux incluent :

* **/var/log/syslog** (Debian) ou **/var/log/messages** (RedHat) : Capture les messages et activités système à l'échelle du système.
* **/var/log/auth.log** (Debian) ou **/var/log/secure** (RedHat) : Enregistre les tentatives d'authentification, les connexions réussies et échouées.
* Utilisez `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` pour filtrer les événements d'authentification pertinents.
* **/var/log/boot.log** : Contient les messages de démarrage du système.
* **/var/log/maillog** ou **/var/log/mail.log** : Enregistre les activités du serveur de messagerie, utile pour suivre les services liés aux e-mails.
* **/var/log/kern.log** : Stocke les messages du noyau, y compris les erreurs et les avertissements.
* **/var/log/dmesg** : Contient les messages des pilotes de périphériques.
* **/var/log/faillog** : Enregistre les tentatives de connexion échouées, aidant dans les enquêtes sur les violations de sécurité.
* **/var/log/cron** : Enregistre les exécutions des tâches cron.
* **/var/log/daemon.log** : Trace les activités des services en arrière-plan.
* **/var/log/btmp** : Documente les tentatives de connexion échouées.
* **/var/log/httpd/** : Contient les journaux d'erreurs et d'accès d'Apache HTTPD.
* **/var/log/mysqld.log** ou **/var/log/mysql.log** : Enregistre les activités de la base de données MySQL.
* **/var/log/xferlog** : Enregistre les transferts de fichiers FTP.
* **/var/log/** : Vérifiez toujours les journaux inattendus ici.

{% hint style="info" %}
Les journaux système Linux et les sous-systèmes d'audit peuvent être désactivés ou supprimés lors d'une intrusion ou d'un incident de logiciel malveillant. Parce que les journaux sur les systèmes Linux contiennent généralement certaines des informations les plus utiles sur les activités malveillantes, les intrus les suppriment régulièrement. Par conséquent, lors de l'examen des fichiers journaux disponibles, il est important de rechercher des lacunes ou des entrées désordonnées qui pourraient indiquer une suppression ou une altération.
{% endhint %}

**Linux conserve un historique des commandes pour chaque utilisateur**, stocké dans :

* \~/.bash\_history
* \~/.zsh\_history
* \~/.zsh\_sessions/\*
* \~/.python\_history
* \~/.\*\_history

De plus, la commande `last -Faiwx` fournit une liste des connexions des utilisateurs. Vérifiez-la pour des connexions inconnues ou inattendues.

Vérifiez les fichiers qui peuvent accorder des privilèges supplémentaires :

* Examinez `/etc/sudoers` pour des privilèges d'utilisateur inattendus qui ont pu être accordés.
* Examinez `/etc/sudoers.d/` pour des privilèges d'utilisateur inattendus qui ont pu être accordés.
* Examinez `/etc/groups` pour identifier des adhésions ou des autorisations de groupe inhabituelles.
* Examinez `/etc/passwd` pour identifier des adhésions ou des autorisations de groupe inhabituelles.

Certaines applications génèrent également leurs propres journaux :

* **SSH** : Examinez _\~/.ssh/authorized\_keys_ et _\~/.ssh/known\_hosts_ pour des connexions distantes non autorisées.
* **Bureau Gnome** : Consultez _\~/.recently-used.xbel_ pour les fichiers récemment consultés via les applications Gnome.
* **Firefox/Chrome** : Vérifiez l'historique du navigateur et les téléchargements dans _\~/.mozilla/firefox_ ou _\~/.config/google-chrome_ pour des activités suspectes.
* **VIM** : Consultez _\~/.viminfo_ pour des détails d'utilisation, tels que les chemins d'accès aux fichiers consultés et l'historique des recherches.
* **Open Office** : Vérifiez les accès récents aux documents qui peuvent indiquer des fichiers compromis.
* **FTP/SFTP** : Consultez les journaux dans _\~/.ftp\_history_ ou _\~/.sftp\_history_ pour les transferts de fichiers qui pourraient être non autorisés.
* **MySQL** : Enquêtez sur _\~/.mysql\_history_ pour les requêtes MySQL exécutées, révélant potentiellement des activités de base de données non autorisées.
* **Less** : Analysez _\~/.lesshst_ pour l'historique d'utilisation, y compris les fichiers consultés et les commandes exécutées.
* **Git** : Examinez _\~/.gitconfig_ et le projet _.git/logs_ pour les modifications apportées aux dépôts.

### Journaux USB

[**usbrip**](https://github.com/snovvcrash/usbrip) est un petit logiciel écrit en Python 3 pur qui analyse les fichiers journaux Linux (`/var/log/syslog*` ou `/var/log/messages*` selon la distribution) pour construire des tables d'historique des événements USB.

Il est intéressant de **connaître tous les périphériques USB qui ont été utilisés** et cela sera plus utile si vous avez une liste autorisée de périphériques USB pour trouver des "événements de violation" (l'utilisation de périphériques USB qui ne sont pas dans cette liste).

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Exemples
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Plus d'exemples et d'informations sur le github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Examiner les comptes d'utilisateurs et les activités de connexion

Examinez les fichiers _**/etc/passwd**_, _**/etc/shadow**_ et les **logs de sécurité** à la recherche de noms ou de comptes inhabituels créés et/ou utilisés à proximité d'événements non autorisés connus. Vérifiez également les possibles attaques de force brute sudo.\
De plus, vérifiez des fichiers comme _**/etc/sudoers**_ et _**/etc/groups**_ pour des privilèges inattendus accordés aux utilisateurs.\
Enfin, recherchez des comptes sans **mot de passe** ou avec des mots de passe **facilement devinables**.

## Examiner le système de fichiers

### Analyse des structures du système de fichiers dans les enquêtes sur les logiciels malveillants

Lors d'enquêtes sur des incidents de logiciels malveillants, la structure du système de fichiers est une source d'information cruciale, révélant à la fois la séquence des événements et le contenu du logiciel malveillant. Cependant, les auteurs de logiciels malveillants développent des techniques pour entraver cette analyse, telles que la modification des horodatages des fichiers ou l'évitement du système de fichiers pour le stockage des données.

Pour contrer ces méthodes anti-forensiques, il est essentiel de:

* **Effectuer une analyse minutieuse de la chronologie** en utilisant des outils comme **Autopsy** pour visualiser les chronologies d'événements ou `mactime` de **Sleuth Kit** pour des données chronologiques détaillées.
* **Enquêter sur des scripts inattendus** dans le $PATH du système, qui pourraient inclure des scripts shell ou PHP utilisés par des attaquants.
* **Examiner `/dev` pour des fichiers atypiques**, car il contient traditionnellement des fichiers spéciaux, mais peut contenir des fichiers liés aux logiciels malveillants.
* **Rechercher des fichiers ou répertoires cachés** avec des noms comme ".. " (point point espace) ou "..^G" (point point contrôle-G), qui pourraient dissimuler un contenu malveillant.
* **Identifier les fichiers setuid root** en utilisant la commande: `find / -user root -perm -04000 -print` Cela permet de trouver des fichiers avec des permissions élevées, qui pourraient être exploités par des attaquants.
* **Vérifier les horodatages de suppression** dans les tables d'inodes pour repérer des suppressions massives de fichiers, indiquant éventuellement la présence de rootkits ou de chevaux de Troie.
* **Inspecter les inodes consécutifs** pour repérer des fichiers malveillants à proximité après en avoir identifié un, car ils peuvent avoir été placés ensemble.
* **Vérifier les répertoires binaires courants** (_/bin_, _/sbin_) pour des fichiers récemment modifiés, car ils pourraient avoir été altérés par des logiciels malveillants.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Notez qu'un **attaquant** peut **modifier** l'**heure** pour faire **apparaître** les **fichiers comme légitimes**, mais il **ne peut pas** modifier l'**inode**. Si vous constatez qu'un **fichier** indique qu'il a été créé et modifié en même temps que le reste des fichiers du même dossier, mais que l'**inode** est **plus grand que prévu**, alors les **horodatages de ce fichier ont été modifiés**.
{% endhint %}

## Comparer des fichiers de différentes versions de systèmes de fichiers

### Résumé de la comparaison des versions du système de fichiers

Pour comparer les versions du système de fichiers et repérer les changements, nous utilisons des commandes `git diff` simplifiées :

* **Pour trouver de nouveaux fichiers**, comparez deux répertoires :
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Pour le contenu modifié**, répertoriez les modifications en ignorant les lignes spécifiques :
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Pour détecter les fichiers supprimés**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Options de filtre** (`--diff-filter`) aident à restreindre les changements spécifiques tels que les fichiers ajoutés (`A`), supprimés (`D`), ou modifiés (`M`).
* `A`: Fichiers ajoutés
* `C`: Fichiers copiés
* `D`: Fichiers supprimés
* `M`: Fichiers modifiés
* `R`: Fichiers renommés
* `T`: Changements de type (par exemple, fichier vers lien symbolique)
* `U`: Fichiers non fusionnés
* `X`: Fichiers inconnus
* `B`: Fichiers cassés

## Références

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Livre: Guide de terrain de la cybercriminalité pour les systèmes Linux: Guides de terrain de la cybercriminalité**

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!

* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord**](https://discord.gg/hRep4RUj7f) ou le **groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
