# Forensique Linux

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et automatiser facilement des workflows alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Collecte d'informations initiales

### Informations de base

Tout d'abord, il est recommandé d'avoir une **clé USB** avec des **binaires et des bibliothèques bien connus** (vous pouvez simplement prendre Ubuntu et copier les dossiers _/bin_, _/sbin_, _/lib,_ et _/lib64_), puis monter la clé USB et modifier les variables d'environnement pour utiliser ces binaires :
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Une fois que vous avez configuré le système pour utiliser des binaires bons et connus, vous pouvez commencer à **extraire des informations de base** :
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

Lors de l'obtention des informations de base, vous devez vérifier les éléments suspects tels que :

* Les **processus root** ont généralement des PIDS bas, donc si vous trouvez un processus root avec un PID élevé, vous pouvez suspecter
* Vérifiez les **connexions enregistrées** des utilisateurs sans shell dans `/etc/passwd`
* Vérifiez les **hachages de mots de passe** à l'intérieur de `/etc/shadow` pour les utilisateurs sans shell

### Dump de mémoire

Pour obtenir la mémoire du système en cours d'exécution, il est recommandé d'utiliser [**LiME**](https://github.com/504ensicsLabs/LiME).\
Pour **compiler** LiME, vous devez utiliser le **même noyau** que celui utilisé par la machine victime.

{% hint style="info" %}
Rappelez-vous que vous **ne pouvez pas installer LiME ou toute autre chose** sur la machine victime car cela apportera plusieurs modifications à celle-ci.
{% endhint %}

Donc, si vous avez une version identique d'Ubuntu, vous pouvez utiliser `apt-get install lime-forensics-dkms`\
Dans d'autres cas, vous devez télécharger [**LiME**](https://github.com/504ensicsLabs/LiME) depuis github et le compiler avec les en-têtes de noyau corrects. Pour **obtenir les en-têtes de noyau exacts** de la machine victime, vous pouvez simplement **copier le répertoire** `/lib/modules/<version du noyau>` sur votre machine, puis **compiler** LiME en les utilisant :
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME prend en charge 3 **formats** :

* Brut (chaque segment concaténé ensemble)
* Rembourré (identique au brut, mais avec des zéros dans les bits de droite)
* Lime (format recommandé avec des métadonnées)

LiME peut également être utilisé pour **envoyer le dump via le réseau** au lieu de le stocker sur le système en utilisant quelque chose comme : `path=tcp:4444`

### Imagerie de disque

#### Arrêt

Tout d'abord, vous devrez **arrêter le système**. Ce n'est pas toujours une option car parfois le système sera un serveur de production que l'entreprise ne peut pas se permettre d'arrêter.\
Il y a **2 façons** d'arrêter le système, un **arrêt normal** et un **arrêt "débrancher la prise"**. Le premier permettra aux **processus de se terminer normalement** et au **système de fichiers** d'être **synchronisé**, mais il permettra également au **logiciel malveillant** possible de **détruire des preuves**. L'approche "débrancher la prise" peut entraîner **une perte d'informations** (pas beaucoup d'informations vont être perdues car nous avons déjà pris une image de la mémoire) et le **logiciel malveillant n'aura aucune opportunité** d'y remédier. Par conséquent, si vous **soupçonnez** qu'il peut y avoir un **logiciel malveillant**, exécutez simplement la commande **`sync`** sur le système et débranchez la prise.

#### Prendre une image du disque

Il est important de noter que **avant de connecter votre ordinateur à quoi que ce soit lié à l'affaire**, vous devez être sûr qu'il va être **monté en lecture seule** pour éviter de modifier toute information.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-analyse de l'image disque

Création d'une image disque sans plus de données.
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
![](<../../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recherche de logiciels malveillants connus

### Fichiers système modifiés

Certains systèmes Linux ont une fonctionnalité pour **vérifier l'intégrité de nombreux composants installés**, offrant ainsi un moyen efficace d'identifier les fichiers inhabituels ou mal placés. Par exemple, `rpm -Va` sur Linux est conçu pour vérifier tous les packages qui ont été installés à l'aide du gestionnaire de packages RedHat.
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
Sur les distributions Linux RedHat et similaires, la commande **`rpm -qa --root=/chemin_montage/var/lib/rpm`** répertorie le contenu d'une base de données RPM sur un système.
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### Autre

**Tous les programmes installés ne seront pas répertoriés par les commandes ci-dessus** car certaines applications ne sont pas disponibles sous forme de packages pour certains systèmes et doivent être installées à partir de la source. Par conséquent, un examen des emplacements tels que _**/usr/local**_ et _**/opt**_ peut révéler d'autres applications qui ont été compilées et installées à partir du code source.
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
![](<../../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

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

Il est extrêmement courant que les logiciels malveillants s'implantent en tant que nouveau service non autorisé. Linux dispose de plusieurs scripts qui sont utilisés pour démarrer des services lorsque l'ordinateur démarre. Le script d'initialisation de démarrage _**/etc/inittab**_ appelle d'autres scripts tels que rc.sysinit et divers scripts de démarrage sous le répertoire _**/etc/rc.d/**_, ou _**/etc/rc.boot/**_ dans certaines versions plus anciennes. Dans d'autres versions de Linux, telles que Debian, les scripts de démarrage sont stockés dans le répertoire _**/etc/init.d/**_. De plus, certains services courants sont activés dans _**/etc/inetd.conf**_ ou _**/etc/xinetd/**_ en fonction de la version de Linux. Les enquêteurs numériques doivent inspecter chacun de ces scripts de démarrage pour détecter les entrées anormales.

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### Modules du noyau

Sur les systèmes Linux, les modules du noyau sont couramment utilisés comme composants rootkit pour les packages de logiciels malveillants. Les modules du noyau sont chargés lorsque le système démarre en fonction des informations de configuration dans les répertoires `/lib/modules/'uname -r'` et `/etc/modprobe.d`, et le fichier `/etc/modprobe` ou `/etc/modprobe.conf`. Ces zones doivent être inspectées pour les éléments liés aux logiciels malveillants.

### Autres emplacements de démarrage automatique

Il existe plusieurs fichiers de configuration que Linux utilise pour lancer automatiquement un exécutable lorsqu'un utilisateur se connecte au système et qui peuvent contenir des traces de logiciels malveillants.

* _**/etc/profile.d/\***_ , _**/etc/profile**_ , _**/etc/bash.bashrc**_ sont exécutés lorsqu'un compte utilisateur se connecte.
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**\~/.profile**_ , _**∼/.config/autostart**_ sont exécutés lorsque l'utilisateur spécifique se connecte.
* _**/etc/rc.local**_ Il est traditionnellement exécuté après que tous les services système normaux sont démarrés, à la fin du processus de passage à un niveau d'exécution multi-utilisateur.

## Examiner les journaux

Recherchez dans tous les fichiers journaux disponibles sur le système compromis des traces d'exécution malveillante et d'activités associées telles que la création d'un nouveau service.

### Journaux purs

Les événements de **connexion** enregistrés dans les journaux système et de sécurité, y compris les connexions via le réseau, peuvent révéler que des **logiciels malveillants** ou un **intrus ont accédé** à un système compromis via un compte donné à un moment spécifique. D'autres événements autour du moment d'une infection par un logiciel malveillant peuvent être capturés dans les journaux système, y compris la **création** d'un **nouveau** **service** ou de nouveaux comptes autour du moment d'un incident.\
Connexions système intéressantes :

* **/var/log/syslog** (debian) ou **/var/log/messages** (Redhat)
  * Affiche des messages et des informations générales concernant le système. C'est un journal de données de toutes les activités dans l'ensemble du système global.
* **/var/log/auth.log** (debian) ou **/var/log/secure** (Redhat)
  * Conserve les journaux d'authentification pour les connexions réussies ou échouées, et les processus d'authentification. Le stockage dépend du type de système.
  * `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**: messages de démarrage et informations de démarrage.
* **/var/log/maillog** ou **var/log/mail.log:** est destiné aux journaux du serveur de messagerie, pratique pour les informations sur postfix, smtpd ou les services liés aux e-mails exécutés sur votre serveur.
* **/var/log/kern.log**: conserve les journaux et les avertissements du noyau. Les journaux d'activité du noyau (par exemple, dmesg, kern.log, klog) peuvent montrer qu'un service particulier a planté à plusieurs reprises, indiquant potentiellement qu'une version trojanisée instable a été installée.
* **/var/log/dmesg**: un référentiel pour les messages du pilote de périphérique. Utilisez **dmesg** pour voir les messages dans ce fichier.
* **/var/log/faillog:** enregistre des informations sur les connexions échouées. Par conséquent, pratique pour examiner les violations de sécurité potentielles telles que les piratages de crédentials de connexion et les attaques de force brute.
* **/var/log/cron**: conserve un enregistrement des messages liés à Crond (tâches cron). Comme quand le démon cron a démarré une tâche.
* **/var/log/daemon.log:** suit les services d'arrière-plan en cours d'exécution mais ne les représente pas graphiquement.
* **/var/log/btmp**: conserve une note de toutes les tentatives de connexion échouées.
* **/var/log/httpd/**: un répertoire contenant les fichiers error\_log et access\_log du démon Apache httpd. Chaque erreur rencontrée par httpd est conservée dans le fichier **error\_log**. Pensez aux problèmes de mémoire et aux autres erreurs liées au système. **access\_log** enregistre toutes les demandes qui arrivent via HTTP.
* **/var/log/mysqld.log** ou **/var/log/mysql.log**: fichier journal MySQL qui enregistre chaque message de débogage, d'échec et de réussite, y compris le démarrage, l'arrêt et le redémarrage du démon MySQL mysqld. Le système décide du répertoire. Les systèmes RedHat, CentOS, Fedora et autres systèmes basés sur RedHat utilisent /var/log/mariadb/mariadb.log. Cependant, Debian/Ubuntu utilise le répertoire /var/log/mysql/error.log.
* **/var/log/xferlog**: conserve les sessions de transfert de fichiers FTP. Comprend des informations telles que les noms de fichiers et les transferts FTP initiés par l'utilisateur.
* **/var/log/\*** : Vous devez toujours vérifier les journaux inattendus dans ce répertoire.

{% hint style="info" %}
Les journaux et les sous-systèmes d'audit des systèmes Linux peuvent être désactivés ou supprimés lors d'une intrusion ou d'un incident de logiciel malveillant. Étant donné que les journaux sur les systèmes Linux contiennent généralement les informations les plus utiles sur les activités malveillantes, les intrus les suppriment régulièrement. Par conséquent, lors de l'examen des fichiers journaux disponibles, il est important de rechercher des lacunes ou des entrées hors ordre qui pourraient indiquer une suppression ou une manipulation.
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

* Tout utilisateur inconnu ?
* Tout utilisateur qui ne devrait pas avoir un shell connecté ?

Ceci est important car les **attaquants** peuvent parfois copier `/bin/bash` à l'intérieur de `/bin/false` de sorte que des utilisateurs tels que **lightdm** peuvent être **capables de se connecter**.

Notez que vous pouvez également **consulter ces informations en lisant les journaux**.

### Traces d'application

* **SSH**: Les connexions aux systèmes effectuées à l'aide de SSH vers et depuis un système compromis entraînent l'enregistrement d'entrées dans des fichiers pour chaque compte utilisateur (_**∼/.ssh/authorized\_keys**_ et _**∼/.ssh/known\_keys**_). Ces entrées peuvent révéler le nom d'hôte ou l'adresse IP des hôtes distants.
* **Gnome Desktop**: Les comptes d'utilisateurs peuvent avoir un fichier _**∼/.recently-used.xbel**_ qui contient des informations sur les fichiers qui ont été récemment accédés à l
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
Plus d'exemples et d'informations sont disponibles sur Github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.io/) pour créer et **automatiser des workflows** avec les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Examiner les comptes d'utilisateurs et les activités de connexion

Examinez les fichiers _**/etc/passwd**_, _**/etc/shadow**_ et les **logs de sécurité** pour trouver des noms inhabituels ou des comptes créés et/ou utilisés à proximité d'événements non autorisés connus. Vérifiez également les possibles attaques de force brute sudo.\
De plus, vérifiez les fichiers tels que _**/etc/sudoers**_ et _**/etc/groups**_ pour les privilèges inattendus accordés aux utilisateurs.\
Enfin, recherchez les comptes sans mot de passe ou avec des mots de passe **facilement devinables**.

## Examiner le système de fichiers

Les structures de données du système de fichiers peuvent fournir des quantités substantielles d'**informations** liées à un incident de **malware**, y compris le **moment** des événements et le **contenu** réel du **malware**.\
Les **malwares** sont de plus en plus conçus pour **contrecarrer l'analyse du système de fichiers**. Certains malwares modifient les horodatages des fichiers malveillants pour rendre plus difficile leur identification avec l'analyse de la chronologie. D'autres codes malveillants sont conçus pour ne stocker que certaines informations en mémoire pour minimiser la quantité de données stockées dans le système de fichiers.\
Pour faire face à de telles techniques anti-forensiques, il est nécessaire de prêter une **attention particulière à l'analyse de la chronologie** des horodatages du système de fichiers et aux fichiers stockés dans des emplacements courants où les malwares pourraient être trouvés.

* Avec **autopsy**, vous pouvez voir la chronologie des événements qui peuvent être utiles pour découvrir une activité suspecte. Vous pouvez également utiliser la fonction `mactime` de **Sleuth Kit** directement.
* Vérifiez les **scripts inattendus** dans **$PATH** (peut-être des scripts sh ou php?)
* Les fichiers dans `/dev` étaient autrefois des fichiers spéciaux, vous pouvez trouver ici des fichiers non spéciaux liés aux malwares.
* Recherchez des fichiers et des répertoires inhabituels ou **cachés**, tels que ".. " (point point espace) ou "..^G " (point point contrôle-G)
* Copies setuid de /bin/bash sur le système `find / -user root -perm -04000 –print`
* Examinez les horodatages des inodes supprimés pour un grand nombre de fichiers supprimés autour du même moment, ce qui pourrait indiquer une activité malveillante telle que l'installation d'un rootkit ou d'un service trojanisé.
* Étant donné que les inodes sont alloués sur une base de disponibilité suivante, **les fichiers malveillants placés sur le système à peu près au même moment peuvent se voir attribuer des inodes consécutifs**. Par conséquent, après la localisation d'un composant de malware, il peut être productif d'inspecter les inodes voisins.
* Vérifiez également les répertoires tels que _/bin_ ou _/sbin_ car la **date de modification et/ou de changement** des nouveaux fichiers ou des fichiers modifiés peut être intéressante.
* Il est intéressant de voir les fichiers et les dossiers d'un répertoire **triés par date de création** plutôt qu'alphabétiquement pour voir quels fichiers ou dossiers sont plus récents (les derniers étant généralement).

Vous pouvez vérifier les fichiers les plus récents d'un dossier en utilisant `ls -laR --sort=time /bin`\
Vous pouvez vérifier les inodes des fichiers à l'intérieur d'un dossier en utilisant `ls -lai /bin |sort -n`

{% hint style="info" %}
Notez qu'un **attaquant** peut **modifier** l'**heure** pour faire **apparaître des fichiers légitimes**, mais il ne peut pas modifier l'**inode**. Si vous constatez qu'un **fichier** indique qu'il a été créé et modifié en même temps que le reste des fichiers dans le même dossier, mais que l'**inode** est **inhabituellement plus grand**, alors les **horodatages de ce fichier ont été modifiés**.
{% endhint %}

## Comparer les fichiers de différentes versions du système de fichiers

#### Trouver les fichiers ajoutés
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### Trouver le contenu modifié

---

To find modified content in a Linux system, we can use the `find` command with the `-mtime` option. This option allows us to search for files that were modified within a certain time frame.

For example, to find files that were modified in the last 24 hours, we can use the following command:

```
find / -mtime 0
```

This will search the entire file system (`/`) for files that were modified within the last 24 hours (`-mtime 0`).

We can also use the `-type` option to search for specific types of files. For example, to search for only modified text files, we can use the following command:

```
find / -type f -name "*.txt" -mtime 0
```

This will search for only text files (`-type f` and `-name "*.txt"`) that were modified within the last 24 hours (`-mtime 0`).

Once we have found the modified files, we can analyze them further using other forensic tools and techniques.
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### Trouver des fichiers supprimés
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### Autres filtres

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

Sélectionne uniquement les fichiers qui ont été ajoutés (`A`), copiés (`C`), supprimés (`D`), modifiés (`M`), renommés (`R`), et dont le type (c'est-à-dire fichier régulier, lien symbolique, sous-module, ...) a été modifié (`T`), sont non fusionnés (`U`), sont inconnus (`X`), ou ont eu leur association rompue (`B`). Toute combinaison de caractères de filtre (y compris aucun) peut être utilisée. Lorsque `*` (tout ou rien) est ajouté à la combinaison, tous les chemins sont sélectionnés s'il y a un fichier qui correspond à d'autres critères de comparaison ; s'il n'y a pas de fichier qui correspond à d'autres critères, rien n'est sélectionné.

De plus, **ces lettres majuscules peuvent être en minuscules pour exclure**. Par exemple, `--diff-filter=ad` exclut les chemins ajoutés et supprimés.

Notez que tous les diffs ne peuvent pas comporter tous les types. Par exemple, les diffs de l'index vers l'arborescence de travail ne peuvent jamais comporter d'entrées ajoutées (parce que l'ensemble des chemins inclus dans le diff est limité par ce qui se trouve dans l'index). De même, les entrées copiées et renommées ne peuvent pas apparaître si la détection de ces types est désactivée.

## Références

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

**Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
