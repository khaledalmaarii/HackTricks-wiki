# Forensique Linux

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Collecte d'informations initiale

### Informations de base

Tout d'abord, il est recommandé d'avoir une **clé USB** avec des **binaires et des bibliothèques bien connus** (vous pouvez simplement obtenir Ubuntu et copier les dossiers _/bin_, _/sbin_, _/lib_ et _/lib64_), puis monter la clé USB et modifier les variables d'environnement pour utiliser ces binaires :
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Une fois que vous avez configuré le système pour utiliser des binaires fiables et connus, vous pouvez commencer à **extraire quelques informations de base** :
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

* Les **processus root** s'exécutent généralement avec de petits PIDs, donc si vous trouvez un processus root avec un grand PID, vous pouvez suspecter.
* Vérifiez les **connexions enregistrées** des utilisateurs sans shell dans `/etc/passwd`.
* Vérifiez les **hachages de mots de passe** dans `/etc/shadow` pour les utilisateurs sans shell.

### Capture de mémoire

Pour obtenir la mémoire du système en cours d'exécution, il est recommandé d'utiliser [**LiME**](https://github.com/504ensicsLabs/LiME).\
Pour **compiler** LiME, vous devez utiliser le **même noyau** que celui de la machine victime.

{% hint style="info" %}
Rappelez-vous que vous **ne pouvez pas installer LiME ou autre chose** sur la machine victime car cela apporterait plusieurs modifications.
{% endhint %}

Donc, si vous avez une version identique d'Ubuntu, vous pouvez utiliser `apt-get install lime-forensics-dkms`\
Dans d'autres cas, vous devez télécharger [**LiME**](https://github.com/504ensicsLabs/LiME) depuis GitHub et le compiler avec les en-têtes de noyau corrects. Pour **obtenir les en-têtes de noyau exacts** de la machine victime, vous pouvez simplement **copier le répertoire** `/lib/modules/<version du noyau>` sur votre machine, puis **compiler** LiME en les utilisant :
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME prend en charge 3 **formats** :

* Brut (chaque segment concaténé ensemble)
* Rembourré (identique au brut, mais avec des zéros dans les bits de droite)
* Lime (format recommandé avec des métadonnées)

LiME peut également être utilisé pour **envoyer la capture via le réseau** au lieu de la stocker sur le système en utilisant quelque chose comme : `path=tcp:4444`

### Imagerie de disque

#### Arrêt du système

Tout d'abord, vous devrez **arrêter le système**. Ce n'est pas toujours une option car parfois le système sera un serveur de production que l'entreprise ne peut pas se permettre d'arrêter.\
Il existe **2 façons** d'arrêter le système, un **arrêt normal** et un **arrêt "débrancher la prise"**. Le premier permettra aux **processus de se terminer normalement** et au **système de fichiers** d'être **synchronisé**, mais il permettra également au **logiciel malveillant éventuel** de **détruire les preuves**. L'approche "débrancher la prise" peut entraîner **une perte d'informations** (peu d'informations seront perdues car nous avons déjà pris une image de la mémoire) et le **logiciel malveillant n'aura aucune opportunité** d'y remédier. Par conséquent, si vous **soupçonnez** la présence d'un **logiciel malveillant**, exécutez simplement la commande **`sync`** sur le système et débranchez la prise.

#### Prendre une image du disque

Il est important de noter que **avant de connecter votre ordinateur à quoi que ce soit lié à l'affaire**, vous devez vous assurer qu'il sera **monté en lecture seule** pour éviter de modifier les informations.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-analyse de l'image disque

Création d'une image disque sans perte de données.
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
<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recherche de logiciels malveillants connus

### Fichiers système modifiés

Certains systèmes Linux disposent d'une fonctionnalité permettant de vérifier l'intégrité de nombreux composants installés, offrant ainsi un moyen efficace d'identifier des fichiers inhabituels ou hors de leur emplacement habituel. Par exemple, `rpm -Va` sur Linux est conçu pour vérifier tous les packages qui ont été installés à l'aide du gestionnaire de paquets RedHat.
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### Détecteurs de logiciels malveillants/rootkits

Lisez la page suivante pour en savoir plus sur les outils qui peuvent être utiles pour trouver des logiciels malveillants :

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Recherche de programmes installés

### Gestionnaire de paquets

Sur les systèmes basés sur Debian, le fichier _**/var/lib/dpkg/status**_ contient des détails sur les paquets installés et le fichier _**/var/log/dpkg.log**_ enregistre des informations lorsqu'un paquet est installé.\
Sur RedHat et les distributions Linux connexes, la commande **`rpm -qa --root=/mntpath/var/lib/rpm`** répertorie le contenu d'une base de données RPM sur un système.
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### Autre

**Tous les programmes installés ne seront pas répertoriés par les commandes ci-dessus** car certaines applications ne sont pas disponibles sous forme de packages pour certains systèmes et doivent être installées à partir de la source. Par conséquent, une vérification des emplacements tels que _**/usr/local**_ et _**/opt**_ peut révéler d'autres applications qui ont été compilées et installées à partir du code source.
```bash
ls /opt /usr/local
```
Une autre bonne idée est de **vérifier** les **dossiers courants** à l'intérieur de **$PATH** pour les **binaires non liés** aux **paquets installés** :
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

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

Il est extrêmement courant que les logiciels malveillants s'implantent en tant que nouveaux services non autorisés. Linux dispose de plusieurs scripts utilisés pour démarrer les services au démarrage de l'ordinateur. Le script d'initialisation de démarrage _**/etc/inittab**_ appelle d'autres scripts tels que rc.sysinit et divers scripts de démarrage dans le répertoire _**/etc/rc.d/**_, ou _**/etc/rc.boot/**_ dans certaines anciennes versions. Dans d'autres versions de Linux, comme Debian, les scripts de démarrage sont stockés dans le répertoire _**/etc/init.d/**_. De plus, certains services courants sont activés dans _**/etc/inetd.conf**_ ou _**/etc/xinetd/**_ en fonction de la version de Linux. Les enquêteurs numériques doivent inspecter chacun de ces scripts de démarrage à la recherche d'entrées anormales.

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### Modules du noyau

Sur les systèmes Linux, les modules du noyau sont couramment utilisés comme composants de rootkit pour les packages de logiciels malveillants. Les modules du noyau sont chargés lorsque le système démarre en fonction des informations de configuration dans les répertoires `/lib/modules/'uname -r'` et `/etc/modprobe.d`, ainsi que du fichier `/etc/modprobe` ou `/etc/modprobe.conf`. Ces zones doivent être inspectées pour repérer les éléments liés aux logiciels malveillants.

### Autres emplacements de démarrage automatique

Il existe plusieurs fichiers de configuration que Linux utilise pour lancer automatiquement un exécutable lorsqu'un utilisateur se connecte au système et qui peuvent contenir des traces de logiciels malveillants.

* _**/etc/profile.d/\***_, _**/etc/profile**_, _**/etc/bash.bashrc**_ sont exécutés lorsque n'importe quel compte utilisateur se connecte.
* _**∼/.bashrc**_, _**∼/.bash\_profile**_, _**\~/.profile**_, _**∼/.config/autostart**_ sont exécutés lorsque l'utilisateur spécifique se connecte.
* _**/etc/rc.local**_ est traditionnellement exécuté après le démarrage de tous les services système normaux, à la fin du processus de passage à un niveau d'exécution multi-utilisateurs.

## Examiner les journaux

Consultez tous les fichiers journaux disponibles sur le système compromis à la recherche de traces d'exécution malveillante et d'activités associées telles que la création d'un nouveau service.

### Journaux purs

Les événements de **connexion** enregistrés dans les journaux système et de sécurité, y compris les connexions via le réseau, peuvent révéler que des **logiciels malveillants** ou un **intrus ont accédé** à un système compromis via un compte donné à un moment précis. D'autres événements autour du moment d'une infection par des logiciels malveillants peuvent être capturés dans les journaux système, y compris la **création** d'un **nouveau** **service** ou de nouveaux comptes autour de l'incident.\
Connexions système intéressantes :

* **/var/log/syslog** (debian) ou **/var/log/messages** (Redhat)
* Affiche des messages généraux et des informations concernant le système. Il s'agit d'un journal de données de toutes les activités dans l'ensemble du système global.
* **/var/log/auth.log** (debian) ou **/var/log/secure** (Redhat)
* Conserve les journaux d'authentification pour les connexions réussies ou échouées, ainsi que les processus d'authentification. Le stockage dépend du type de système.
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log** : messages de démarrage et informations de démarrage.
* **/var/log/maillog** ou **var/log/mail.log** : est destiné aux journaux du serveur de messagerie, pratique pour les informations sur postfix, smtpd ou les services liés aux e-mails exécutés sur votre serveur.
* **/var/log/kern.log** : conserve les journaux du noyau et les informations d'avertissement. Les journaux d'activité du noyau (par exemple, dmesg, kern.log, klog) peuvent montrer qu'un service particulier a planté à plusieurs reprises, ce qui peut indiquer l'installation d'une version trojanisée instable.
* **/var/log/dmesg** : un référentiel pour les messages du pilote de périphérique. Utilisez **dmesg** pour voir les messages dans ce fichier.
* **/var/log/faillog** : enregistre des informations sur les connexions échouées. Utile pour examiner les violations de sécurité potentielles telles que les piratages de mots de passe de connexion et les attaques par force brute.
* **/var/log/cron** : enregistre les messages liés à Crond (tâches cron). Par exemple, lorsque le démon cron a démarré une tâche.
* **/var/log/daemon.log** : suit les services d'arrière-plan en cours d'exécution, mais ne les représente pas graphiquement.
* **/var/log/btmp** : enregistre toutes les tentatives de connexion échouées.
* **/var/log/httpd/** : un répertoire contenant les fichiers error\_log et access\_log du démon Apache httpd. Toutes les erreurs rencontrées par httpd sont conservées dans le fichier **error\_log**. Pensez aux problèmes de mémoire et aux autres erreurs liées au système. **access\_log** enregistre toutes les demandes reçues via HTTP.
* **/var/log/mysqld.log** ou **/var/log/mysql.log** : fichier journal MySQL qui enregistre chaque message de débogage, d'échec et de réussite, y compris le démarrage, l'arrêt et le redémarrage du démon MySQL mysqld. Le système décide du répertoire. Les systèmes RedHat, CentOS, Fedora et autres systèmes basés sur RedHat utilisent /var/log/mariadb/mariadb.log. Cependant, Debian/Ubuntu utilise le répertoire /var/log/mysql/error.log.
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
* Un utilisateur qui ne devrait pas avoir de shell connecté ?

Cela est important car les **attaquants** peuvent parfois copier `/bin/bash` à l'intérieur de `/bin/false`, de sorte que des utilisateurs comme **lightdm** peuvent être **capables de se connecter**.

Notez que vous pouvez également **consulter ces informations en lisant les journaux**.
### Traces d'application

* **SSH**: Les connexions aux systèmes effectuées à l'aide de SSH depuis un système compromis entraînent la création d'entrées dans les fichiers de chaque compte utilisateur (_**∼/.ssh/authorized\_keys**_ et _**∼/.ssh/known\_keys**_). Ces entrées peuvent révéler le nom d'hôte ou l'adresse IP des hôtes distants.
* **Bureau Gnome**: Les comptes utilisateur peuvent avoir un fichier _**∼/.recently-used.xbel**_ qui contient des informations sur les fichiers récemment consultés à l'aide des applications exécutées sur le bureau Gnome.
* **VIM**: Les comptes utilisateur peuvent avoir un fichier _**∼/.viminfo**_ qui contient des détails sur l'utilisation de VIM, y compris l'historique des chaînes de recherche et les chemins des fichiers ouverts avec vim.
* **Open Office**: Fichiers récents.
* **MySQL**: Les comptes utilisateur peuvent avoir un fichier _**∼/.mysql\_history**_ qui contient les requêtes exécutées avec MySQL.
* **Less**: Les comptes utilisateur peuvent avoir un fichier _**∼/.lesshst**_ qui contient des détails sur l'utilisation de less, y compris l'historique des chaînes de recherche et les commandes shell exécutées via less.

### Journaux USB

[**usbrip**](https://github.com/snovvcrash/usbrip) est un petit logiciel écrit en Python 3 pur qui analyse les fichiers journaux Linux (`/var/log/syslog*` ou `/var/log/messages*` selon la distribution) pour construire des tables d'historique des événements USB.

Il est intéressant de **connaître tous les périphériques USB qui ont été utilisés** et cela sera encore plus utile si vous disposez d'une liste autorisée de périphériques USB pour détecter les "événements de violation" (l'utilisation de périphériques USB qui ne figurent pas dans cette liste).

### Installation
```
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Exemples

#### Example 1: Collecting Volatile Data

##### Description

In this example, we will demonstrate how to collect volatile data from a Linux system using basic forensic tools.

##### Steps

1. Connect to the target Linux system using SSH.
2. Run the following command to collect information about running processes:

   ```bash
   ps aux > processes.txt
   ```

3. Run the following command to collect network connections:

   ```bash
   netstat -antp > connections.txt
   ```

4. Run the following command to collect open files:

   ```bash
   lsof > files.txt
   ```

5. Run the following command to collect system logs:

   ```bash
   dmesg > logs.txt
   ```

6. Copy the collected data to your local machine for further analysis.

##### Analysis

By collecting volatile data from the target Linux system, we can gain insights into the running processes, network connections, open files, and system logs. This information can be useful for identifying any suspicious activities or potential security breaches.

#### Example 2: Analyzing File Metadata

##### Description

In this example, we will demonstrate how to analyze file metadata to gather information about a file on a Linux system.

##### Steps

1. Obtain the file you want to analyze.

2. Run the following command to view the file metadata:

   ```bash
   stat <filename>
   ```

3. Analyze the output to gather information such as file size, permissions, owner, and modification timestamps.

##### Analysis

Analyzing file metadata can provide valuable information about a file, including its size, permissions, owner, and timestamps. This information can help in understanding the file's purpose, its origin, and any potential modifications or tampering.

#### Example 3: Recovering Deleted Files

##### Description

In this example, we will demonstrate how to recover deleted files from a Linux system using basic forensic tools.

##### Steps

1. Connect to the target Linux system using SSH.

2. Run the following command to search for deleted files:

   ```bash
   sudo grep -a -C 100 "deleted" /dev/sda1 > recovered_files.txt
   ```

3. Analyze the output to identify any recovered files.

4. Copy the recovered files to your local machine for further analysis.

##### Analysis

By searching for deleted files on the target Linux system, we can potentially recover files that have been deleted but still exist on the disk. This can be useful for retrieving important data or investigating any suspicious activities.
```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Plus d'exemples et d'informations sont disponibles sur GitHub : [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer facilement et automatiser des flux de travail avec les outils communautaires les plus avancés au monde.\
Accédez-y dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Examiner les comptes d'utilisateurs et les activités de connexion

Examinez les fichiers _**/etc/passwd**_, _**/etc/shadow**_ et les journaux de sécurité pour repérer des noms ou des comptes inhabituels créés ou utilisés à proximité d'événements non autorisés connus. Vérifiez également les éventuelles attaques de force brute sudo.\
De plus, vérifiez les fichiers tels que _**/etc/sudoers**_ et _**/etc/groups**_ pour les privilèges inattendus accordés aux utilisateurs.\
Enfin, recherchez les comptes sans mot de passe ou avec des mots de passe faciles à deviner.

## Examiner le système de fichiers

Les structures de données du système de fichiers peuvent fournir des quantités importantes d'**informations** liées à un incident de **logiciel malveillant**, y compris le **moment** des événements et le **contenu** réel du **logiciel malveillant**.\
Les logiciels malveillants sont de plus en plus conçus pour **contourner l'analyse du système de fichiers**. Certains logiciels malveillants modifient les horodatages des fichiers malveillants pour les rendre plus difficiles à trouver avec une analyse chronologique. D'autres codes malveillants sont conçus pour stocker uniquement certaines informations en mémoire afin de réduire la quantité de données stockées dans le système de fichiers.\
Pour faire face à de telles techniques anti-forensiques, il est nécessaire de prêter une **attention particulière à l'analyse chronologique** des horodatages du système de fichiers et aux fichiers stockés dans des emplacements courants où des logiciels malveillants pourraient être trouvés.

* Avec **autopsy**, vous pouvez voir la chronologie des événements qui peut être utile pour découvrir une activité suspecte. Vous pouvez également utiliser la fonction `mactime` de **Sleuth Kit** directement.
* Vérifiez la présence de **scripts inattendus** dans **$PATH** (peut-être des scripts sh ou php ?)
* Les fichiers dans `/dev` étaient autrefois des fichiers spéciaux, vous pouvez y trouver des fichiers non spéciaux liés à des logiciels malveillants.
* Recherchez des fichiers et des répertoires inhabituels ou **cachés**, tels que ".. " (point point espace) ou "..^G " (point point contrôle-G)
* Copies setuid de /bin/bash sur le système `find / -user root -perm -04000 –print`
* Examinez les horodatages des **inodes supprimés pour un grand nombre de fichiers supprimés à la même heure**, ce qui pourrait indiquer une activité malveillante telle que l'installation d'un rootkit ou d'un service trojanisé.
* Étant donné que les inodes sont alloués sur la base du prochain disponible, **des fichiers malveillants placés sur le système à peu près au même moment peuvent se voir attribuer des inodes consécutifs**. Par conséquent, après avoir localisé un composant de logiciel malveillant, il peut être productif d'inspecter les inodes voisins.
* Vérifiez également les répertoires tels que _/bin_ ou _/sbin_ car l'heure de **modification et/ou de changement** des nouveaux fichiers ou des fichiers modifiés peut être intéressante.
* Il est intéressant de voir les fichiers et les dossiers d'un répertoire **triés par date de création** plutôt que par ordre alphabétique pour voir quels fichiers ou dossiers sont plus récents (les derniers en général).

Vous pouvez vérifier les fichiers les plus récents d'un dossier en utilisant `ls -laR --sort=time /bin`\
Vous pouvez vérifier les inodes des fichiers à l'intérieur d'un dossier en utilisant `ls -lai /bin |sort -n`

{% hint style="info" %}
Notez qu'un **attaquant** peut **modifier l'heure** pour faire **apparaître des fichiers** comme **légitimes**, mais il ne peut pas modifier l'**inode**. Si vous constatez qu'un **fichier** indique qu'il a été créé et modifié en même temps que le reste des fichiers du même dossier, mais que l'**inode** est **plus grand que prévu**, alors les **horodatages de ce fichier ont été modifiés**.
{% endhint %}

## Comparer les fichiers de différentes versions du système de fichiers

#### Trouver les fichiers ajoutés
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### Trouver le contenu modifié

Lors de l'analyse forensique d'un système Linux, il est important de rechercher tout contenu modifié qui pourrait être pertinent pour l'enquête. Voici une méthodologie de base pour trouver ce contenu :

1. **Recherche des fichiers modifiés récemment** : Utilisez la commande `find` pour rechercher les fichiers modifiés dans un certain intervalle de temps. Par exemple, pour rechercher les fichiers modifiés au cours des 24 dernières heures, utilisez la commande suivante :
```bash
find / -type f -mtime 0
```

2. **Vérification des journaux système** : Les journaux système, tels que `/var/log/syslog` et `/var/log/auth.log`, peuvent contenir des informations sur les activités suspectes. Utilisez la commande `cat` pour afficher le contenu des journaux système et recherchez des entrées anormales.

3. **Analyse des fichiers de configuration** : Les fichiers de configuration, tels que `/etc/passwd` et `/etc/shadow`, peuvent être modifiés pour compromettre le système. Utilisez la commande `cat` pour afficher le contenu de ces fichiers et recherchez des modifications suspectes.

4. **Vérification des fichiers de log d'application** : Les applications peuvent enregistrer des activités dans des fichiers de log spécifiques. Utilisez la commande `cat` pour afficher le contenu de ces fichiers et recherchez des entrées suspectes.

5. **Analyse des fichiers de sauvegarde** : Les fichiers de sauvegarde peuvent contenir des versions antérieures des fichiers modifiés. Utilisez la commande `ls` pour répertorier les fichiers de sauvegarde et utilisez la commande `diff` pour comparer les versions antérieures avec les versions actuelles.

6. **Recherche des fichiers cachés** : Les fichiers cachés peuvent être utilisés pour masquer des activités malveillantes. Utilisez la commande `ls -a` pour afficher les fichiers cachés et recherchez des fichiers suspects.

7. **Analyse des fichiers de swap** : Les fichiers de swap peuvent contenir des informations sensibles. Utilisez la commande `strings` pour extraire du texte à partir des fichiers de swap et recherchez des informations suspectes.

8. **Vérification des fichiers de configuration réseau** : Les fichiers de configuration réseau, tels que `/etc/network/interfaces`, peuvent être modifiés pour faciliter les attaques. Utilisez la commande `cat` pour afficher le contenu de ces fichiers et recherchez des modifications suspectes.

En suivant cette méthodologie de base, vous pouvez trouver du contenu modifié qui peut être utile pour votre enquête forensique sur un système Linux.
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### Trouver des fichiers supprimés

Lors de l'analyse d'un système Linux dans le cadre d'une enquête forensique, il est important de rechercher des fichiers supprimés qui pourraient contenir des informations cruciales. Voici une méthodologie de base pour trouver des fichiers supprimés :

1. **Analyser l'espace libre** : Utilisez des outils tels que `fls` pour examiner l'espace libre du système de fichiers et rechercher des inodes non alloués. Ces inodes peuvent indiquer l'emplacement de fichiers supprimés.

2. **Utiliser `icat`** : Une fois que vous avez identifié les inodes correspondant à des fichiers supprimés, utilisez l'outil `icat` pour extraire le contenu de ces fichiers. Par exemple, vous pouvez exécuter la commande `icat -r <device> <inode>` pour récupérer le contenu d'un fichier supprimé.

3. **Rechercher dans les journaux** : Les systèmes de fichiers journalisés, tels que ext3 et ext4, enregistrent les métadonnées des fichiers supprimés dans les journaux. Utilisez des outils tels que `grep` pour rechercher des entrées de journal correspondant à des fichiers supprimés.

4. **Analyser les fichiers temporaires** : Les fichiers temporaires peuvent contenir des informations sensibles. Recherchez des fichiers avec des extensions telles que `.tmp`, `.swp` ou `.bak` qui pourraient contenir des données supprimées.

5. **Utiliser des outils spécialisés** : Il existe de nombreux outils spécialisés pour la récupération de fichiers supprimés sur Linux, tels que `foremost` et `scalpel`. Ces outils peuvent vous aider à récupérer des fichiers supprimés à partir d'images disque ou de systèmes de fichiers.

En suivant cette méthodologie de base, vous pouvez augmenter vos chances de trouver des fichiers supprimés contenant des informations pertinentes pour votre enquête forensique.
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### Autres filtres

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

Sélectionnez uniquement les fichiers qui ont été ajoutés (`A`), copiés (`C`), supprimés (`D`), modifiés (`M`), renommés (`R`), dont le type (c'est-à-dire fichier régulier, lien symbolique, sous-module, etc.) a été modifié (`T`), sont non fusionnés (`U`), sont inconnus (`X`), ou dont la correspondance a été rompue (`B`). Toute combinaison des caractères de filtre (y compris aucun) peut être utilisée. Lorsque `*` (tout ou rien) est ajouté à la combinaison, tous les chemins sont sélectionnés s'il y a un fichier qui correspond à d'autres critères dans la comparaison ; s'il n'y a pas de fichier qui correspond à d'autres critères, rien n'est sélectionné.

De plus, **ces lettres majuscules peuvent être en minuscules pour exclure**. Par exemple, `--diff-filter=ad` exclut les chemins ajoutés et supprimés.

Notez que toutes les différences ne peuvent pas comporter tous les types. Par exemple, les différences de l'index vers l'arborescence de travail ne peuvent jamais comporter d'entrées ajoutées (car l'ensemble des chemins inclus dans la différence est limité à ce qui se trouve dans l'index). De même, les entrées copiées et renommées ne peuvent pas apparaître si la détection de ces types est désactivée.

## Références

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
