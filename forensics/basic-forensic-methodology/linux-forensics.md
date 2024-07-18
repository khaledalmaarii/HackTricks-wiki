# Linux Forensics

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser des flux de travail** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## Collecte d'informations initiales

### Informations de base

Tout d'abord, il est recommandé d'avoir une **clé USB** avec des **binaires et bibliothèques bien connus** dessus (vous pouvez simplement obtenir ubuntu et copier les dossiers _/bin_, _/sbin_, _/lib,_ et _/lib64_), puis monter la clé USB et modifier les variables d'environnement pour utiliser ces binaires :
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Une fois que vous avez configuré le système pour utiliser de bons binaires connus, vous pouvez commencer à **extraire quelques informations de base** :
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

Lors de l'obtention des informations de base, vous devez vérifier des éléments étranges tels que :

* **Les processus root** s'exécutent généralement avec de faibles PIDS, donc si vous trouvez un processus root avec un grand PID, vous pouvez suspecter
* Vérifiez les **connexions enregistrées** des utilisateurs sans shell dans `/etc/passwd`
* Vérifiez les **hashs de mot de passe** dans `/etc/shadow` pour les utilisateurs sans shell

### Dump de mémoire

Pour obtenir la mémoire du système en cours d'exécution, il est recommandé d'utiliser [**LiME**](https://github.com/504ensicsLabs/LiME).\
Pour **compiler** cela, vous devez utiliser le **même noyau** que celui utilisé par la machine victime.

{% hint style="info" %}
N'oubliez pas que vous **ne pouvez pas installer LiME ou quoi que ce soit d'autre** sur la machine victime car cela apportera plusieurs modifications.
{% endhint %}

Donc, si vous avez une version identique d'Ubuntu, vous pouvez utiliser `apt-get install lime-forensics-dkms`\
Dans d'autres cas, vous devez télécharger [**LiME**](https://github.com/504ensicsLabs/LiME) depuis github et le compiler avec les bons en-têtes de noyau. Pour **obtenir les en-têtes de noyau exacts** de la machine victime, vous pouvez simplement **copier le répertoire** `/lib/modules/<version du noyau>` sur votre machine, puis **compiler** LiME en les utilisant :
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME prend en charge 3 **formats** :

* Brut (chaque segment concaténé ensemble)
* Padded (même que brut, mais avec des zéros dans les bits de droite)
* Lime (format recommandé avec des métadonnées)

LiME peut également être utilisé pour **envoyer le dump via le réseau** au lieu de le stocker sur le système en utilisant quelque chose comme : `path=tcp:4444`

### Imagerie de disque

#### Arrêt

Tout d'abord, vous devrez **éteindre le système**. Ce n'est pas toujours une option car parfois le système sera un serveur de production que l'entreprise ne peut pas se permettre d'éteindre.\
Il existe **2 façons** d'éteindre le système, un **arrêt normal** et un **arrêt "débrancher le câble"**. Le premier permettra aux **processus de se terminer comme d'habitude** et au **système de fichiers** d'être **synchronisé**, mais il permettra également au **malware** de **détruire des preuves**. L'approche "débrancher le câble" peut entraîner **une certaine perte d'informations** (pas beaucoup d'infos ne vont être perdues car nous avons déjà pris une image de la mémoire) et le **malware n'aura aucune opportunité** d'agir. Par conséquent, si vous **soupçonnez** qu'il pourrait y avoir un **malware**, exécutez simplement la **commande** **`sync`** sur le système et débranchez le câble.

#### Prendre une image du disque

Il est important de noter que **avant de connecter votre ordinateur à quoi que ce soit lié à l'affaire**, vous devez vous assurer qu'il sera **monté en lecture seule** pour éviter de modifier des informations.
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
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser des flux de travail** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recherche de Malware connu

### Fichiers système modifiés

Linux offre des outils pour garantir l'intégrité des composants système, ce qui est crucial pour repérer les fichiers potentiellement problématiques.

* **Systèmes basés sur RedHat** : Utilisez `rpm -Va` pour un contrôle complet.
* **Systèmes basés sur Debian** : `dpkg --verify` pour une vérification initiale, suivi de `debsums | grep -v "OK$"` (après avoir installé `debsums` avec `apt-get install debsums`) pour identifier d'éventuels problèmes.

### Détecteurs de Malware/Rootkit

Lisez la page suivante pour en savoir plus sur les outils qui peuvent être utiles pour trouver des malwares :

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Recherche de programmes installés

Pour rechercher efficacement des programmes installés sur les systèmes Debian et RedHat, envisagez d'exploiter les journaux système et les bases de données en plus des vérifications manuelles dans les répertoires courants.

* Pour Debian, inspectez _**`/var/lib/dpkg/status`**_ et _**`/var/log/dpkg.log`**_ pour obtenir des détails sur les installations de paquets, en utilisant `grep` pour filtrer des informations spécifiques.
* Les utilisateurs de RedHat peuvent interroger la base de données RPM avec `rpm -qa --root=/mntpath/var/lib/rpm` pour lister les paquets installés.

Pour découvrir les logiciels installés manuellement ou en dehors de ces gestionnaires de paquets, explorez des répertoires comme _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, et _**`/sbin`**_. Combinez les listes de répertoires avec des commandes spécifiques au système pour identifier les exécutables non associés à des paquets connus, améliorant ainsi votre recherche de tous les programmes installés.
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
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser des flux de travail** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Récupérer des binaires en cours d'exécution supprimés

Imaginez un processus qui a été exécuté depuis /tmp/exec et qui a ensuite été supprimé. Il est possible de l'extraire.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspecter les emplacements de démarrage automatique

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

Chemins où un malware pourrait être installé en tant que service :

* **/etc/inittab** : Appelle des scripts d'initialisation comme rc.sysinit, dirigeant ensuite vers des scripts de démarrage.
* **/etc/rc.d/** et **/etc/rc.boot/** : Contiennent des scripts pour le démarrage des services, ce dernier étant trouvé dans les anciennes versions de Linux.
* **/etc/init.d/** : Utilisé dans certaines versions de Linux comme Debian pour stocker des scripts de démarrage.
* Les services peuvent également être activés via **/etc/inetd.conf** ou **/etc/xinetd/**, selon la variante de Linux.
* **/etc/systemd/system** : Un répertoire pour les scripts du gestionnaire de système et de service.
* **/etc/systemd/system/multi-user.target.wants/** : Contient des liens vers des services qui doivent être démarrés dans un niveau d'exécution multi-utilisateur.
* **/usr/local/etc/rc.d/** : Pour des services personnalisés ou tiers.
* **\~/.config/autostart/** : Pour les applications de démarrage automatique spécifiques à l'utilisateur, qui peuvent être un endroit caché pour des malwares ciblant l'utilisateur.
* **/lib/systemd/system/** : Fichiers d'unité par défaut à l'échelle du système fournis par les paquets installés.

### Kernel Modules

Les modules du noyau Linux, souvent utilisés par les malwares comme composants de rootkit, sont chargés au démarrage du système. Les répertoires et fichiers critiques pour ces modules incluent :

* **/lib/modules/$(uname -r)** : Contient des modules pour la version du noyau en cours d'exécution.
* **/etc/modprobe.d** : Contient des fichiers de configuration pour contrôler le chargement des modules.
* **/etc/modprobe** et **/etc/modprobe.conf** : Fichiers pour les paramètres globaux des modules.

### Other Autostart Locations

Linux utilise divers fichiers pour exécuter automatiquement des programmes lors de la connexion de l'utilisateur, pouvant potentiellement abriter des malwares :

* **/etc/profile.d/**\*, **/etc/profile**, et **/etc/bash.bashrc** : Exécutés pour toute connexion utilisateur.
* **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, et **\~/.config/autostart** : Fichiers spécifiques à l'utilisateur qui s'exécutent lors de leur connexion.
* **/etc/rc.local** : S'exécute après que tous les services système ont démarré, marquant la fin de la transition vers un environnement multi-utilisateur.

## Examine Logs

Les systèmes Linux suivent les activités des utilisateurs et les événements système à travers divers fichiers journaux. Ces journaux sont essentiels pour identifier les accès non autorisés, les infections par malware et d'autres incidents de sécurité. Les fichiers journaux clés incluent :

* **/var/log/syslog** (Debian) ou **/var/log/messages** (RedHat) : Capturent les messages et activités à l'échelle du système.
* **/var/log/auth.log** (Debian) ou **/var/log/secure** (RedHat) : Enregistrent les tentatives d'authentification, les connexions réussies et échouées.
* Utilisez `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` pour filtrer les événements d'authentification pertinents.
* **/var/log/boot.log** : Contient des messages de démarrage du système.
* **/var/log/maillog** ou **/var/log/mail.log** : Journalise les activités du serveur de messagerie, utile pour suivre les services liés aux e-mails.
* **/var/log/kern.log** : Stocke les messages du noyau, y compris les erreurs et les avertissements.
* **/var/log/dmesg** : Contient des messages de pilotes de périphériques.
* **/var/log/faillog** : Enregistre les tentatives de connexion échouées, aidant dans les enquêtes sur les violations de sécurité.
* **/var/log/cron** : Journalise les exécutions de tâches cron.
* **/var/log/daemon.log** : Suit les activités des services en arrière-plan.
* **/var/log/btmp** : Documente les tentatives de connexion échouées.
* **/var/log/httpd/** : Contient les journaux d'erreurs et d'accès d'Apache HTTPD.
* **/var/log/mysqld.log** ou **/var/log/mysql.log** : Journalise les activités de la base de données MySQL.
* **/var/log/xferlog** : Enregistre les transferts de fichiers FTP.
* **/var/log/** : Vérifiez toujours les journaux inattendus ici.

{% hint style="info" %}
Les journaux système Linux et les sous-systèmes d'audit peuvent être désactivés ou supprimés lors d'une intrusion ou d'un incident de malware. Étant donné que les journaux sur les systèmes Linux contiennent généralement certaines des informations les plus utiles sur les activités malveillantes, les intrus les suppriment régulièrement. Par conséquent, lors de l'examen des fichiers journaux disponibles, il est important de rechercher des lacunes ou des entrées hors d'ordre qui pourraient indiquer une suppression ou une falsification.
{% endhint %}

**Linux maintient un historique des commandes pour chaque utilisateur**, stocké dans :

* \~/.bash\_history
* \~/.zsh\_history
* \~/.zsh\_sessions/\*
* \~/.python\_history
* \~/.\*\_history

De plus, la commande `last -Faiwx` fournit une liste des connexions des utilisateurs. Vérifiez-la pour des connexions inconnues ou inattendues.

Vérifiez les fichiers qui peuvent accorder des privilèges supplémentaires :

* Examinez `/etc/sudoers` pour des privilèges d'utilisateur inattendus qui pourraient avoir été accordés.
* Examinez `/etc/sudoers.d/` pour des privilèges d'utilisateur inattendus qui pourraient avoir été accordés.
* Examinez `/etc/groups` pour identifier des adhésions ou des permissions de groupe inhabituelles.
* Examinez `/etc/passwd` pour identifier des adhésions ou des permissions de groupe inhabituelles.

Certaines applications génèrent également leurs propres journaux :

* **SSH** : Examinez _\~/.ssh/authorized\_keys_ et _\~/.ssh/known\_hosts_ pour des connexions distantes non autorisées.
* **Gnome Desktop** : Consultez _\~/.recently-used.xbel_ pour des fichiers récemment accédés via des applications Gnome.
* **Firefox/Chrome** : Vérifiez l'historique du navigateur et les téléchargements dans _\~/.mozilla/firefox_ ou _\~/.config/google-chrome_ pour des activités suspectes.
* **VIM** : Examinez _\~/.viminfo_ pour des détails d'utilisation, tels que les chemins de fichiers accédés et l'historique des recherches.
* **Open Office** : Vérifiez l'accès récent aux documents qui pourrait indiquer des fichiers compromis.
* **FTP/SFTP** : Consultez les journaux dans _\~/.ftp\_history_ ou _\~/.sftp\_history_ pour des transferts de fichiers qui pourraient être non autorisés.
* **MySQL** : Examinez _\~/.mysql\_history_ pour des requêtes MySQL exécutées, révélant potentiellement des activités de base de données non autorisées.
* **Less** : Analysez _\~/.lesshst_ pour l'historique d'utilisation, y compris les fichiers vus et les commandes exécutées.
* **Git** : Examinez _\~/.gitconfig_ et le projet _.git/logs_ pour des modifications des dépôts.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) est un petit logiciel écrit en pur Python 3 qui analyse les fichiers journaux Linux (`/var/log/syslog*` ou `/var/log/messages*` selon la distribution) pour construire des tableaux d'historique des événements USB.

Il est intéressant de **savoir tous les USB qui ont été utilisés** et cela sera plus utile si vous avez une liste autorisée d'USB pour trouver des "événements de violation" (l'utilisation d'USB qui ne figurent pas dans cette liste).

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
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser des flux de travail** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Examiner les comptes utilisateurs et les activités de connexion

Examinez le _**/etc/passwd**_, _**/etc/shadow**_ et les **journaux de sécurité** pour des noms ou des comptes inhabituels créés et ou utilisés à proximité d'événements non autorisés connus. Vérifiez également les attaques par force brute sudo possibles.\
De plus, vérifiez des fichiers comme _**/etc/sudoers**_ et _**/etc/groups**_ pour des privilèges inattendus accordés aux utilisateurs.\
Enfin, recherchez des comptes avec **aucun mot de passe** ou des mots de passe **facilement devinables**.

## Examiner le système de fichiers

### Analyser les structures de système de fichiers dans l'enquête sur les logiciels malveillants

Lors de l'enquête sur des incidents de logiciels malveillants, la structure du système de fichiers est une source d'information cruciale, révélant à la fois la séquence des événements et le contenu des logiciels malveillants. Cependant, les auteurs de logiciels malveillants développent des techniques pour entraver cette analyse, comme la modification des horodatages de fichiers ou l'évitement du système de fichiers pour le stockage de données.

Pour contrer ces méthodes anti-forensiques, il est essentiel de :

* **Effectuer une analyse chronologique approfondie** en utilisant des outils comme **Autopsy** pour visualiser les chronologies des événements ou **Sleuth Kit's** `mactime` pour des données chronologiques détaillées.
* **Enquêter sur des scripts inattendus** dans le $PATH du système, qui pourraient inclure des scripts shell ou PHP utilisés par des attaquants.
* **Examiner `/dev` pour des fichiers atypiques**, car il contient traditionnellement des fichiers spéciaux, mais peut abriter des fichiers liés aux logiciels malveillants.
* **Rechercher des fichiers ou des répertoires cachés** avec des noms comme ".. " (point point espace) ou "..^G" (point point contrôle-G), qui pourraient dissimuler un contenu malveillant.
* **Identifier les fichiers setuid root** en utilisant la commande : `find / -user root -perm -04000 -print` Cela trouve des fichiers avec des permissions élevées, qui pourraient être abusés par des attaquants.
* **Examiner les horodatages de suppression** dans les tables d'inodes pour repérer des suppressions massives de fichiers, ce qui pourrait indiquer la présence de rootkits ou de trojans.
* **Inspecter les inodes consécutifs** pour des fichiers malveillants à proximité après en avoir identifié un, car ils peuvent avoir été placés ensemble.
* **Vérifier les répertoires binaires courants** (_/bin_, _/sbin_) pour des fichiers récemment modifiés, car ceux-ci pourraient avoir été altérés par des logiciels malveillants.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Notez qu'un **attaquant** peut **modifier** le **temps** pour faire en sorte que des **fichiers apparaissent** **légitimes**, mais il **ne peut pas** modifier l'**inode**. Si vous constatez qu'un **fichier** indique qu'il a été créé et modifié en même temps que le reste des fichiers dans le même dossier, mais que l'**inode** est **inattendu plus grand**, alors les **horodatages de ce fichier ont été modifiés**.
{% endhint %}

## Comparer les fichiers de différentes versions de système de fichiers

### Résumé de la comparaison des versions de système de fichiers

Pour comparer les versions de système de fichiers et identifier les changements, nous utilisons des commandes `git diff` simplifiées :

* **Pour trouver de nouveaux fichiers**, comparez deux répertoires :
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Pour le contenu modifié**, listez les changements en ignorant des lignes spécifiques :
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Pour détecter les fichiers supprimés** :
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Les options de filtre** (`--diff-filter`) aident à se concentrer sur des changements spécifiques comme les fichiers ajoutés (`A`), supprimés (`D`) ou modifiés (`M`).
* `A`: Fichiers ajoutés
* `C`: Fichiers copiés
* `D`: Fichiers supprimés
* `M`: Fichiers modifiés
* `R`: Fichiers renommés
* `T`: Changements de type (par exemple, fichier vers symlink)
* `U`: Fichiers non fusionnés
* `X`: Fichiers inconnus
* `B`: Fichiers corrompus

## Références

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Livre : Guide de terrain sur la criminalistique des logiciels malveillants pour les systèmes Linux : Guides de terrain en criminalistique numérique**

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'**NFTs** exclusifs [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**merch officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Partagez vos astuces de hacking en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des flux de travail** alimentés par les **outils communautaires les plus avancés** au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
