# Analyse Forensique Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez-y aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
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

- Les **processus root** ont généralement des PIDs bas, donc si vous trouvez un processus root avec un PID élevé, vous pouvez suspecter
- Vérifiez les **connexions enregistrées** des utilisateurs sans shell dans `/etc/passwd`
- Vérifiez les **hachages de mots de passe** dans `/etc/shadow` pour les utilisateurs sans shell

### Capture de mémoire

Pour obtenir la mémoire du système en cours d'exécution, il est recommandé d'utiliser [**LiME**](https://github.com/504ensicsLabs/LiME).\
Pour le **compiler**, vous devez utiliser le **même noyau** que celui utilisé par la machine victime.

{% hint style="info" %}
Rappelez-vous que vous **ne pouvez pas installer LiME ou quoi que ce soit d'autre** sur la machine victime car cela apportera plusieurs modifications à celle-ci
{% endhint %}

Donc, si vous avez une version identique d'Ubuntu, vous pouvez utiliser `apt-get install lime-forensics-dkms`\
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
Il existe **2 façons** d'arrêter le système, un **arrêt normal** et un **arrêt "débrancher la prise"**. Le premier permettra aux **processus de se terminer comme d'habitude** et au **système de fichiers** d'être **synchronisé**, mais il permettra également à un éventuel **logiciel malveillant** de **détruire des preuves**. L'approche "débrancher la prise" peut entraîner **une perte d'informations** (pas beaucoup d'informations seront perdues car nous avons déjà pris une image de la mémoire) et le **logiciel malveillant n'aura aucune opportunité** d'y remédier. Par conséquent, si vous **soupçonnez** la présence d'un **logiciel malveillant**, exécutez simplement la commande **`sync`** sur le système et débranchez la prise.

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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recherche de logiciels malveillants connus

### Fichiers système modifiés

Certains systèmes Linux disposent d'une fonctionnalité pour **vérifier l'intégrité de nombreux composants installés**, offrant un moyen efficace d'identifier des fichiers inhabituels ou mal placés. Par exemple, `rpm -Va` sur Linux est conçu pour vérifier tous les packages installés à l'aide du gestionnaire de paquets RedHat.
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### Détecteurs de logiciels malveillants/Rootkit

Lisez la page suivante pour en savoir plus sur les outils qui peuvent être utiles pour trouver des logiciels malveillants :

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Recherche des programmes installés

### Gestionnaire de paquets

Sur les systèmes basés sur Debian, le fichier _**/var/lib/dpkg/status**_ contient des détails sur les paquets installés et le fichier _**/var/log/dpkg.log**_ enregistre des informations lorsqu'un paquet est installé.\
Sur RedHat et les distributions Linux connexes, la commande **`rpm -qa --root=/mntpath/var/lib/rpm`** listera le contenu d'une base de données RPM sur un système.
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### Autre

**Tous les programmes installés ne seront pas répertoriés par les commandes ci-dessus** car certaines applications ne sont pas disponibles en tant que packages pour certains systèmes et doivent être installées à partir de la source. Par conséquent, un examen des emplacements tels que _**/usr/local**_ et _**/opt**_ peut révéler d'autres applications qui ont été compilées et installées à partir du code source.
```bash
ls /opt /usr/local
```
Une autre bonne idée est de **vérifier** les **dossiers communs** à l'intérieur de **$PATH** pour les **binaires non liés** aux **paquets installés :**
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Récupérer les binaires en cours d'exécution supprimés

![](<../../.gitbook/assets/image (641).png>)

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

Il est extrêmement courant que les logiciels malveillants s'implantent en tant que nouveau service non autorisé. Linux dispose de plusieurs scripts utilisés pour démarrer des services lorsque l'ordinateur démarre. Le script d'initialisation de démarrage _**/etc/inittab**_ appelle d'autres scripts tels que rc.sysinit et divers scripts de démarrage dans le répertoire _**/etc/rc.d/**_, ou _**/etc/rc.boot/**_ dans certaines versions plus anciennes. Sur d'autres versions de Linux, comme Debian, les scripts de démarrage sont stockés dans le répertoire _**/etc/init.d/**_. De plus, certains services courants sont activés dans _**/etc/inetd.conf**_ ou _**/etc/xinetd/**_ en fonction de la version de Linux. Les enquêteurs numériques devraient inspecter chacun de ces scripts de démarrage pour des entrées anormales.

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### Modules du noyau

Sur les systèmes Linux, les modules du noyau sont couramment utilisés comme composants de rootkit pour les packages de logiciels malveillants. Les modules du noyau sont chargés lorsque le système démarre en fonction des informations de configuration dans les répertoires `/lib/modules/'uname -r'` et `/etc/modprobe.d`, et du fichier `/etc/modprobe` ou `/etc/modprobe.conf`. Ces zones doivent être inspectées pour les éléments liés aux logiciels malveillants.

### Autres emplacements de démarrage automatique

Il existe plusieurs fichiers de configuration que Linux utilise pour lancer automatiquement un exécutable lorsqu'un utilisateur se connecte au système, pouvant contenir des traces de logiciels malveillants.

* _**/etc/profile.d/\***_, _**/etc/profile**_, _**/etc/bash.bashrc**_ sont exécutés lorsque n'importe quel compte utilisateur se connecte.
* _**∼/.bashrc**_, _**∼/.bash\_profile**_, _**\~/.profile**_, _**∼/.config/autostart**_ sont exécutés lorsque l'utilisateur spécifique se connecte.
* _**/etc/rc.local**_ est traditionnellement exécuté après le démarrage de tous les services système normaux, à la fin du processus de passage à un niveau d'exécution multi-utilisateurs.

## Examiner les journaux

Recherchez dans tous les fichiers journaux disponibles sur le système compromis des traces d'exécution malveillante et d'activités associées telles que la création d'un nouveau service.

### Journaux purs

Les événements de **connexion** enregistrés dans les journaux système et de sécurité, y compris les connexions via le réseau, peuvent révéler qu'un **logiciel malveillant** ou un **intrus a accédé** à un système compromis via un compte donné à un moment spécifique. D'autres événements autour du moment d'une infection par un logiciel malveillant peuvent être capturés dans les journaux système, y compris la **création** d'un **nouveau** **service** ou de nouveaux comptes autour du moment d'un incident.\
Connexions système intéressantes :

* **/var/log/syslog** (debian) ou **/var/log/messages** (Redhat)
* Affiche des messages généraux et des informations concernant le système. C'est un journal de données de toute l'activité dans le système global.
* **/var/log/auth.log** (debian) ou **/var/log/secure** (Redhat)
* Conserve les journaux d'authentification pour les connexions réussies ou échouées, et les processus d'authentification. Le stockage dépend du type de système.
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log** : messages de démarrage et informations de démarrage.
* **/var/log/maillog** ou **var/log/mail.log** : est destiné aux journaux du serveur de messagerie, utile pour les informations sur postfix, smtpd, ou les services liés aux e-mails s'exécutant sur votre serveur.
* **/var/log/kern.log** : conserve les journaux du noyau et les informations d'avertissement. Les journaux d'activité du noyau (par ex., dmesg, kern.log, klog) peuvent montrer qu'un service particulier a planté à plusieurs reprises, indiquant potentiellement qu'une version trojanisée instable a été installée.
* **/var/log/dmesg** : un répertoire pour les messages des pilotes de périphériques. Utilisez **dmesg** pour voir les messages dans ce fichier.
* **/var/log/faillog** : enregistre des informations sur les échecs de connexion. Utile pour examiner les violations potentielles de sécurité telles que les piratages de mots de passe de connexion et les attaques par force brute.
* **/var/log/cron** : conserve un enregistrement des messages liés à Crond (tâches cron). Par exemple, lorsque le démon cron a lancé une tâche.
* **/var/log/daemon.log** : suit les services d'arrière-plan en cours d'exécution mais ne les représente pas graphiquement.
* **/var/log/btmp** : note toutes les tentatives de connexion échouées.
* **/var/log/httpd/** : un répertoire contenant les fichiers error\_log et access\_log du démon Apache httpd. Toute erreur rencontrée par httpd est conservée dans le fichier **error\_log**. Pensez aux problèmes de mémoire et autres erreurs liées au système. **access\_log** enregistre toutes les demandes reçues via HTTP.
* **/var/log/mysqld.log** ou **/var/log/mysql.log** : fichier journal MySQL qui enregistre chaque message de débogage, d'échec et de succès, y compris le démarrage, l'arrêt et le redémarrage du démon MySQL mysqld. Le système décide du répertoire. Les systèmes RedHat, CentOS, Fedora et autres systèmes basés sur RedHat utilisent /var/log/mariadb/mariadb.log. Cependant, Debian/Ubuntu utilisent le répertoire /var/log/mysql/error.log.
* **/var/log/xferlog** : conserve les sessions de transfert de fichiers FTP. Comprend des informations telles que les noms de fichiers et les transferts FTP initiés par l'utilisateur.
* **/var/log/\*** : Vous devriez toujours vérifier les journaux inattendus dans ce répertoire

{% hint style="info" %}
Les journaux système Linux et les sous-systèmes d'audit peuvent être désactivés ou supprimés lors d'une intrusion ou d'un incident de logiciel malveillant. Étant donné que les journaux sur les systèmes Linux contiennent généralement certaines des informations les plus utiles sur les activités malveillantes, les intrus les suppriment régulièrement. Par conséquent, lors de l'examen des fichiers journaux disponibles, il est important de rechercher des lacunes ou des entrées désordonnées qui pourraient indiquer une suppression ou une manipulation.
{% endhint %}

### Historique des commandes

De nombreux systèmes Linux sont configurés pour conserver un historique des commandes pour chaque compte utilisateur :

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### Connexions

En utilisant la commande `last -Faiwx`, il est possible d'obtenir la liste des utilisateurs qui se sont connectés.\
Il est recommandé de vérifier si ces connexions ont du sens :

* Un utilisateur inconnu ?
* Un utilisateur qui ne devrait pas avoir un shell connecté ?

Ceci est important car les **attaquants** peuvent parfois copier `/bin/bash` à l'intérieur de `/bin/false` afin que des utilisateurs comme **lightdm** puissent se **connecter**.

Notez que vous pouvez également **consulter ces informations en lisant les journaux**.

### Traces d'application

* **SSH** : Les connexions aux systèmes effectuées en utilisant SSH vers et depuis un système compromis entraînent l'enregistrement d'entrées dans des fichiers pour chaque compte utilisateur (_**∼/.ssh/authorized\_keys**_ et _**∼/.ssh/known\_keys**_). Ces entrées peuvent révéler le nom d'hôte ou l'adresse IP des hôtes distants.
* **Bureau Gnome** : Les comptes utilisateur peuvent avoir un fichier _**∼/.recently-used.xbel**_ contenant des informations sur les fichiers récemment consultés à l'aide d'applications s'exécutant sur le bureau Gnome.
* **VIM** : Les comptes utilisateur peuvent avoir un fichier _**∼/.viminfo**_ contenant des détails sur l'utilisation de VIM, y compris l'historique des chaînes de recherche et les chemins des fichiers ouverts avec vim.
* **Open Office** : Fichiers récents.
* **MySQL** : Les comptes utilisateur peuvent avoir un fichier _**∼/.mysql\_history**_ contenant des requêtes exécutées avec MySQL.
* **Less** : Les comptes utilisateur peuvent avoir un fichier _**∼/.lesshst**_ contenant des détails sur l'utilisation de less, y compris l'historique des chaînes de recherche et les commandes shell exécutées via less.

### Journaux USB

[**usbrip**](https://github.com/snovvcrash/usbrip) est un petit logiciel écrit en Python 3 pur qui analyse les fichiers journaux Linux (`/var/log/syslog*` ou `/var/log/messages*` selon la distribution) pour construire des tables d'historique des événements USB.

Il est intéressant de **connaître tous les USB qui ont été utilisés** et cela sera plus utile si vous avez une liste autorisée d'USB pour trouver des "événements de violation" (l'utilisation d'USB qui ne sont pas dans cette liste).

### Installation
```
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Exemples
```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Plus d'exemples et d'informations sur le github : [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Examiner les comptes d'utilisateurs et les activités de connexion

Examinez les fichiers _**/etc/passwd**_, _**/etc/shadow**_ et les **logs de sécurité** à la recherche de noms ou de comptes inhabituels créés et/ou utilisés à proximité d'événements non autorisés connus. Vérifiez également les possibles attaques de force brute sudo.\
De plus, vérifiez les fichiers tels que _**/etc/sudoers**_ et _**/etc/groups**_ pour des privilèges inattendus accordés aux utilisateurs.\
Enfin, recherchez des comptes sans **mot de passe** ou avec des mots de passe **facilement devinables**.

## Examiner le système de fichiers

Les structures de données du système de fichiers peuvent fournir des quantités substantielles d'**informations** liées à un incident de **logiciel malveillant**, y compris la **chronologie** des événements et le **contenu** réel du **logiciel malveillant**.\
Les **logiciels malveillants** sont de plus en plus conçus pour **contourner l'analyse du système de fichiers**. Certains logiciels malveillants modifient les horodatages des fichiers malveillants pour les rendre plus difficiles à trouver avec une analyse chronologique. D'autres codes malveillants sont conçus pour stocker uniquement certaines informations en mémoire afin de minimiser la quantité de données stockées dans le système de fichiers.\
Pour faire face à de telles techniques anti-forensiques, il est nécessaire de porter une **attention particulière à l'analyse chronologique** des horodatages du système de fichiers et aux fichiers stockés dans des emplacements courants où des logiciels malveillants pourraient être trouvés.

* En utilisant **autopsy**, vous pouvez voir la chronologie des événements qui peut être utile pour découvrir une activité suspecte. Vous pouvez également utiliser la fonction `mactime` de **Sleuth Kit** directement.
* Recherchez des **scripts inattendus** à l'intérieur de **$PATH** (peut-être des scripts sh ou php ?)
* Les fichiers dans `/dev` étaient des fichiers spéciaux, vous pouvez trouver des fichiers non spéciaux ici liés aux logiciels malveillants.
* Recherchez des fichiers et des répertoires inhabituels ou **cachés**, tels que ".. " (point point espace) ou "..^G " (point point contrôle-G)
* Copies setuid de /bin/bash sur le système `find / -user root -perm -04000 –print`
* Examinez les horodatages des **inodes supprimés pour un grand nombre de fichiers supprimés en même temps**, ce qui pourrait indiquer une activité malveillante telle que l'installation d'un rootkit ou d'un service trojanisé.
* Comme les inodes sont alloués sur une base du prochain disponible, **les fichiers malveillants placés sur le système à peu près au même moment peuvent se voir attribuer des inodes consécutifs**. Par conséquent, après avoir localisé un composant de logiciel malveillant, il peut être productif d'inspecter les inodes voisins.
* Vérifiez également les répertoires comme _/bin_ ou _/sbin_ car la **date de modification et/ou de changement** des nouveaux fichiers ou des fichiers modifiés peut être intéressante.
* Il est intéressant de voir les fichiers et les dossiers d'un répertoire **triés par date de création** au lieu de manière alphabétique pour voir quels fichiers ou dossiers sont plus récents (les derniers en général).

Vous pouvez vérifier les fichiers les plus récents d'un dossier en utilisant `ls -laR --sort=time /bin`\
Vous pouvez vérifier les inodes des fichiers à l'intérieur d'un dossier en utilisant `ls -lai /bin |sort -n`

{% hint style="info" %}
Notez qu'un **attaquant** peut **modifier** l'**heure** pour faire apparaître des **fichiers comme légitimes**, mais il ne peut pas modifier l'**inode**. Si vous constatez qu'un **fichier** indique qu'il a été créé et modifié en même temps que le reste des fichiers du même dossier, mais que l'**inode** est **anormalement plus grand**, alors les **horodatages de ce fichier ont été modifiés**.
{% endhint %}

## Comparer les fichiers de différentes versions du système de fichiers

#### Trouver les fichiers ajoutés
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### Trouver le contenu modifié
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### Trouver des fichiers supprimés
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### Autres filtres

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

Sélectionnez uniquement les fichiers qui ont été ajoutés (`A`), copiés (`C`), supprimés (`D`), modifiés (`M`), renommés (`R`), dont le type (c'est-à-dire fichier régulier, lien symbolique, sous-module, …​) a été modifié (`T`), sont non fusionnés (`U`), sont inconnus (`X`), ou dont la paire a été rompue (`B`). Toute combinaison des caractères de filtre (y compris aucun) peut être utilisée. Lorsque `*` (Tout ou rien) est ajouté à la combinaison, tous les chemins sont sélectionnés s'il y a un fichier qui correspond à d'autres critères dans la comparaison ; s'il n'y a aucun fichier qui correspond à d'autres critères, rien n'est sélectionné.

De plus, **ces lettres majuscules peuvent être en minuscules pour exclure**. Par exemple, `--diff-filter=ad` exclut les chemins ajoutés et supprimés.

Notez que tous les diffs ne peuvent pas comporter tous les types. Par exemple, les diffs de l'index vers l'arborescence de travail ne peuvent jamais comporter d'entrées ajoutées (car l'ensemble des chemins inclus dans le diff est limité par ce qui se trouve dans l'index). De même, les entrées copiées et renommées ne peuvent pas apparaître si la détection de ces types est désactivée.

## Références

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez** le [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
