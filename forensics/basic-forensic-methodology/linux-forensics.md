# Linux Forensics

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des workflows** alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Collecte d'Informations Initiales

### Informations de Base

Tout d'abord, il est recommandé d'avoir une **clé USB** avec des **binaires et bibliothèques bien connus dessus** (vous pouvez simplement obtenir ubuntu et copier les dossiers _/bin_, _/sbin_, _/lib,_ et _/lib64_), puis monter la clé USB, et modifier les variables d'environnement pour utiliser ces binaires :
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Une fois que vous avez configuré le système pour utiliser de bons binaires connus, vous pouvez commencer à **extraire des informations de base** :
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

Lors de l'obtention des informations de base, vous devriez vérifier des anomalies telles que :

* Les **processus root** s'exécutent généralement avec des PIDS bas, donc si vous trouvez un processus root avec un grand PID, vous pourriez être suspicieux
* Vérifiez les **connexions enregistrées** des utilisateurs sans shell dans `/etc/passwd`
* Recherchez les **hashes de mot de passe** dans `/etc/shadow` pour les utilisateurs sans shell

### Dump de mémoire

Pour obtenir la mémoire du système en cours d'exécution, il est recommandé d'utiliser [**LiME**](https://github.com/504ensicsLabs/LiME).\
Pour le **compiler**, vous devez utiliser le **même noyau** que celui de la machine victime.

{% hint style="info" %}
Rappelez-vous que vous **ne pouvez pas installer LiME ou toute autre chose** sur la machine victime car cela entraînerait plusieurs modifications
{% endhint %}

Donc, si vous avez une version identique d'Ubuntu, vous pouvez utiliser `apt-get install lime-forensics-dkms`\
Dans d'autres cas, vous devez télécharger [**LiME**](https://github.com/504ensicsLabs/LiME) depuis github et le compiler avec les en-têtes de noyau corrects. Pour **obtenir les en-têtes de noyau exacts** de la machine victime, vous pouvez simplement **copier le répertoire** `/lib/modules/<version du noyau>` sur votre machine, puis **compiler** LiME en les utilisant :
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME prend en charge 3 **formats** :

* Raw (chaque segment concaténé ensemble)
* Padded (identique au raw, mais avec des zéros dans les bits de droite)
* Lime (format recommandé avec métadonnées)

LiME peut également être utilisé pour **envoyer le dump via le réseau** au lieu de le stocker sur le système en utilisant quelque chose comme : `path=tcp:4444`

### Imagerie de disque

#### Arrêt du système

Tout d'abord, vous devrez **arrêter le système**. Ce n'est pas toujours une option car parfois le système sera un serveur de production que l'entreprise ne peut pas se permettre d'arrêter.\
Il y a **2 manières** d'arrêter le système, un **arrêt normal** et un **arrêt "débrancher la prise"**. Le premier permettra aux **processus de se terminer comme d'habitude** et au **système de fichiers** d'être **synchronisé**, mais il permettra également au **malware éventuel** de **détruire des preuves**. L'approche "débrancher la prise" peut entraîner **une perte d'informations** (peu d'infos seront perdues car nous avons déjà pris une image de la mémoire) et le **malware n'aura aucune opportunité** d'agir. Par conséquent, si vous **soupçonnez** la présence d'un **malware**, exécutez simplement la **commande `sync`** sur le système et débranchez la prise.

#### Prendre une image du disque

Il est important de noter que **avant de connecter votre ordinateur à quoi que ce soit lié à l'affaire**, vous devez vous assurer qu'il va être **monté en lecture seule** pour éviter de modifier des informations.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-analyse d'image disque

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
```markdown
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recherche de Malware connu

### Fichiers Système Modifiés

Certains systèmes Linux disposent d'une fonctionnalité pour **vérifier l'intégrité de nombreux composants installés**, offrant un moyen efficace d'identifier les fichiers inhabituels ou déplacés. Par exemple, `rpm -Va` sur Linux est conçu pour vérifier tous les paquets qui ont été installés en utilisant le RedHat Package Manager.
```
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### Détecteurs de Malware/Rootkit

Lisez la page suivante pour en savoir plus sur les outils qui peuvent être utiles pour trouver des malwares :

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Recherche de programmes installés

### Gestionnaire de paquets

Sur les systèmes basés sur Debian, le fichier _**/var/lib/dpkg/status**_ contient des détails sur les paquets installés et le fichier _**/var/log/dpkg.log**_ enregistre des informations lorsqu'un paquet est installé.\
Sur les distributions Linux liées à RedHat, la commande **`rpm -qa --root=/mntpath/var/lib/rpm`** listera le contenu d'une base de données RPM sur un système.
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### Autres

**Tous les programmes installés ne seront pas listés par les commandes ci-dessus** car certaines applications ne sont pas disponibles en tant que paquets pour certains systèmes et doivent être installées à partir du code source. Par conséquent, un examen des emplacements tels que _**/usr/local**_ et _**/opt**_ peut révéler d'autres applications qui ont été compilées et installées à partir du code source.
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
```markdown
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Récupérer les Binaires Supprimés en Cours d'Exécution

![](<../../.gitbook/assets/image (641).png>)

## Inspecter les Emplacements de Démarrage Automatique

### Tâches Planifiées
```
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

Il est extrêmement courant que les malwares s'incrustent en tant que nouveau service non autorisé. Linux utilise plusieurs scripts pour démarrer des services lors du démarrage de l'ordinateur. Le script de démarrage d'initialisation _**/etc/inittab**_ appelle d'autres scripts tels que rc.sysinit et divers scripts de démarrage sous le répertoire _**/etc/rc.d/**_, ou _**/etc/rc.boot/**_ dans certaines anciennes versions. Sur d'autres versions de Linux, comme Debian, les scripts de démarrage sont stockés dans le répertoire _**/etc/init.d/**_. De plus, certains services courants sont activés dans _**/etc/inetd.conf**_ ou _**/etc/xinetd/**_ selon la version de Linux. Les enquêteurs numériques doivent inspecter chacun de ces scripts de démarrage pour y détecter des entrées anormales.

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### Modules du Noyau

Sur les systèmes Linux, les modules du noyau sont couramment utilisés comme composants de rootkit pour les paquets de malwares. Les modules du noyau sont chargés lors du démarrage du système en fonction des informations de configuration dans les répertoires `/lib/modules/'uname -r'` et `/etc/modprobe.d`, et le fichier `/etc/modprobe` ou `/etc/modprobe.conf`. Ces zones doivent être inspectées pour détecter des éléments liés aux malwares.

### Autres Emplacements de Démarrage Automatique

Il existe plusieurs fichiers de configuration que Linux utilise pour lancer automatiquement un exécutable lorsqu'un utilisateur se connecte au système et qui peuvent contenir des traces de malware.

* _**/etc/profile.d/\***_ , _**/etc/profile**_ , _**/etc/bash.bashrc**_ sont exécutés lors de la connexion de n'importe quel compte utilisateur.
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**\~/.profile**_ , _**∼/.config/autostart**_ sont exécutés lors de la connexion de l'utilisateur spécifique.
* _**/etc/rc.local**_ Il est traditionnellement exécuté après le démarrage de tous les services système normaux, à la fin du processus de passage à un niveau d'exécution multi-utilisateur.

## Examiner les Journaux

Recherchez dans tous les fichiers journaux disponibles sur le système compromis des traces d'exécution malveillante et d'activités associées telles que la création d'un nouveau service.

### Journaux Purs

Les événements de **connexion** enregistrés dans les journaux système et de sécurité, y compris les connexions via le réseau, peuvent révéler que le **malware** ou un **intrus a accédé** à un système compromis via un compte donné à un moment précis. D'autres événements autour du moment d'une infection par un malware peuvent être capturés dans les journaux système, y compris la **création** d'un **nouveau** **service** ou de nouveaux comptes autour du moment d'un incident.\
Connexions système intéressantes :

* **/var/log/syslog** (debian) ou **/var/log/messages** (Redhat)
* Affiche des messages généraux et des informations concernant le système. C'est un journal de données de toute l'activité à travers le système global.
* **/var/log/auth.log** (debian) ou **/var/log/secure** (Redhat)
* Conserve les journaux d'authentification pour les connexions réussies ou échouées, et les processus d'authentification. Le stockage dépend du type de système.
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log** : messages de démarrage et informations de boot.
* **/var/log/maillog** ou **var/log/mail.log:** pour les journaux du serveur de messagerie, utile pour postfix, smtpd ou les informations de services liés aux e-mails fonctionnant sur votre serveur.
* **/var/log/kern.log**: conserve les journaux et les informations d'avertissement du noyau. Les journaux d'activité du noyau (par exemple, dmesg, kern.log, klog) peuvent montrer qu'un service particulier s'est écrasé à plusieurs reprises, indiquant potentiellement qu'une version trojanisée instable a été installée.
* **/var/log/dmesg**: un dépôt pour les messages des pilotes de périphériques. Utilisez **dmesg** pour voir les messages dans ce fichier.
* **/var/log/faillog:** enregistre les informations sur les échecs de connexion. Donc, pratique pour examiner les violations de sécurité potentielles comme les piratages de données d'identification de connexion et les attaques par force brute.
* **/var/log/cron**: conserve un enregistrement des messages liés à Crond (tâches cron). Comme lorsque le démon cron a démarré une tâche.
* **/var/log/daemon.log:** suit les services d'arrière-plan en cours d'exécution mais ne les représente pas graphiquement.
* **/var/log/btmp**: prend note de toutes les tentatives de connexion échouées.
* **/var/log/httpd/**: un répertoire contenant les fichiers error\_log et access\_log du démon Apache httpd. Chaque erreur rencontrée par httpd est conservée dans le fichier **error\_log**. Pensez aux problèmes de mémoire et autres erreurs liées au système. **access\_log** enregistre toutes les demandes qui arrivent via HTTP.
* **/var/log/mysqld.log** ou **/var/log/mysql.log**: fichier journal MySQL qui enregistre chaque message de débogage, d'échec et de succès, y compris le démarrage, l'arrêt et le redémarrage du démon MySQL mysqld. Le système décide du répertoire. RedHat, CentOS, Fedora et autres systèmes basés sur RedHat utilisent /var/log/mariadb/mariadb.log. Cependant, Debian/Ubuntu utilisent le répertoire /var/log/mysql/error.log.
* **/var/log/xferlog**: conserve les sessions de transfert de fichiers FTP. Comprend des informations telles que les noms de fichiers et les transferts FTP initiés par l'utilisateur.
* **/var/log/\*** : Vous devriez toujours vérifier la présence de journaux inattendus dans ce répertoire

{% hint style="info" %}
Les journaux système Linux et les sous-systèmes d'audit peuvent être désactivés ou supprimés lors d'une intrusion ou d'un incident de malware. Étant donné que les journaux sur les systèmes Linux contiennent généralement certaines des informations les plus utiles sur les activités malveillantes, les intrus les suppriment régulièrement. Par conséquent, lors de l'examen des fichiers journaux disponibles, il est important de rechercher des lacunes ou des entrées désordonnées qui pourraient indiquer une suppression ou une manipulation.
{% endhint %}

### Historique des Commandes

De nombreux systèmes Linux sont configurés pour conserver un historique des commandes pour chaque compte utilisateur :

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### Connexions

En utilisant la commande `last -Faiwx`, il est possible d'obtenir la liste des utilisateurs qui se sont connectés.\
Il est recommandé de vérifier si ces connexions sont logiques :

* Un utilisateur inconnu ?
* Un utilisateur qui ne devrait pas avoir de shell connecté ?

Ceci est important car les **attaquants** copient parfois `/bin/bash` dans `/bin/false` pour que des utilisateurs comme **lightdm** puissent **se connecter**.

Notez que vous pouvez également **examiner ces informations en lisant les journaux**.

### Traces d'Applications

* **SSH** : Les connexions aux systèmes effectuées en utilisant SSH vers et depuis un système compromis entraînent des entrées dans les fichiers pour chaque compte utilisateur (_**∼/.ssh/authorized\_keys**_ et _**∼/.ssh/known\_keys**_). Ces entrées peuvent révéler le nom d'hôte ou l'adresse IP des hôtes distants.
* **Bureau Gnome** : Les comptes utilisateurs peuvent avoir un fichier _**∼/.recently-used.xbel**_ qui contient des informations sur les fichiers qui ont été récemment accédés à l'aide d'applications fonctionnant sur le bureau Gnome.
* **VIM** : Les comptes utilisateurs peuvent avoir un fichier _**∼/.viminfo**_ qui contient des détails sur l'utilisation de VIM, y compris l'historique des chaînes de recherche et les chemins vers les fichiers qui ont été ouverts en utilisant vim.
* **Open Office** : Fichiers récents.
* **MySQL** : Les comptes utilisateurs peuvent avoir un fichier _**∼/.mysql\_history**_ qui contient les requêtes exécutées en utilisant MySQL.
* **Less** : Les comptes utilisateurs peuvent avoir un fichier _**∼/.lesshst**_ qui contient des détails sur l'utilisation de less, y compris l'historique des chaînes de recherche et les commandes shell exécutées via less.

### Journaux USB

[**usbrip**](https://github.com/snovvcrash/usbrip) est un petit logiciel écrit en Python 3 pur qui analyse les fichiers journaux Linux (`/var/log/syslog*` ou `/var/log/messages*` selon la distribution) pour construire des tables d'historique d'événements USB.

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
Plus d'exemples et d'informations à l'intérieur du github : [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Examiner les comptes utilisateurs et les activités de connexion

Examinez les fichiers _**/etc/passwd**_, _**/etc/shadow**_ et les **journaux de sécurité** pour détecter des noms inhabituels ou des comptes créés et/ou utilisés à proximité d'événements non autorisés connus. Vérifiez également les possibles attaques par force brute avec sudo.\
De plus, vérifiez des fichiers comme _**/etc/sudoers**_ et _**/etc/groups**_ pour des privilèges inattendus accordés aux utilisateurs.\
Enfin, recherchez des comptes sans **mot de passe** ou avec des mots de passe **facilement devinables**.

## Examiner le système de fichiers

Les structures de données du système de fichiers peuvent fournir des quantités substantielles d'**informations** liées à un incident de **malware**, y compris le **moment** des événements et le **contenu** réel du **malware**.\
Les **malwares** sont de plus en plus conçus pour **contrecarrer l'analyse du système de fichiers**. Certains malwares modifient les horodatages des fichiers malveillants pour rendre leur découverte plus difficile avec l'analyse de la chronologie. D'autres codes malveillants sont conçus pour stocker certaines informations uniquement en mémoire afin de minimiser la quantité de données stockées dans le système de fichiers.\
Pour faire face à de telles techniques anti-forensiques, il est nécessaire de prêter une **attention particulière à l'analyse de la chronologie** des horodatages du système de fichiers et aux fichiers stockés dans des emplacements communs où le malware pourrait être trouvé.

* En utilisant **autopsy**, vous pouvez voir la chronologie des événements qui peuvent être utiles pour découvrir une activité suspecte. Vous pouvez également utiliser la fonctionnalité `mactime` de **Sleuth Kit** directement.
* Vérifiez la présence de **scripts inattendus** dans **$PATH** (peut-être des scripts sh ou php ?)
* Les fichiers dans `/dev` étaient des fichiers spéciaux, vous pourriez trouver ici des fichiers non spéciaux liés au malware.
* Recherchez des fichiers et des **répertoires cachés** ou inhabituels, tels que “.. ” (point point espace) ou “..^G ” (point point contrôle-G)
* Des copies de /bin/bash avec setuid sur le système `find / -user root -perm -04000 –print`
* Examinez les horodatages des **inodes supprimés pour un grand nombre de fichiers supprimés en même temps**, ce qui pourrait indiquer une activité malveillante telle que l'installation d'un rootkit ou d'un service trojanisé.
* Étant donné que les inodes sont alloués sur une base du premier disponible, les **fichiers malveillants placés sur le système en même temps peuvent se voir attribuer des inodes consécutifs**. Par conséquent, après avoir localisé un composant du malware, il peut être productif d'inspecter les inodes voisins.
* Vérifiez également des répertoires comme _/bin_ ou _/sbin_ car l'**heure de modification ou de changement** de nouveaux fichiers ou de fichiers modifiés peut être intéressante.
* Il est intéressant de voir les fichiers et dossiers d'un répertoire **triés par date de création** plutôt que par ordre alphabétique pour voir quels fichiers ou dossiers sont les plus récents (généralement les derniers).

Vous pouvez vérifier les fichiers les plus récents d'un dossier en utilisant `ls -laR --sort=time /bin`\
Vous pouvez vérifier les inodes des fichiers à l'intérieur d'un dossier en utilisant `ls -lai /bin |sort -n`

{% hint style="info" %}
Notez qu'un **attaquant** peut **modifier** l'**heure** pour faire **apparaître les fichiers comme légitimes**, mais il **ne peut pas** modifier l'**inode**. Si vous trouvez qu'un **fichier** indique qu'il a été créé et modifié en même temps que le reste des fichiers du même dossier, mais que l'**inode** est **anormalement grand**, alors les **horodatages de ce fichier ont été modifiés**.
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

Sélectionnez uniquement les fichiers qui sont Ajoutés (`A`), Copiés (`C`), Supprimés (`D`), Modifiés (`M`), Renommés (`R`), et dont le type (c.-à-d. fichier régulier, lien symbolique, sous-module, …​) a changé (`T`), sont Non fusionnés (`U`), sont Inconnus (`X`), ou ont eu leur appariement Brisé (`B`). Toute combinaison des caractères de filtre (y compris aucune) peut être utilisée. Lorsque `*` (Tout-ou-rien) est ajouté à la combinaison, tous les chemins sont sélectionnés s'il y a un fichier qui correspond à d'autres critères dans la comparaison ; s'il n'y a pas de fichier qui correspond à d'autres critères, rien n'est sélectionné.

De plus, **ces lettres majuscules peuvent être minuscules pour exclure**. Par exemple, `--diff-filter=ad` exclut les chemins ajoutés et supprimés.

Notez que tous les diffs ne peuvent pas présenter tous les types. Par exemple, les diffs de l'index à l'arbre de travail ne peuvent jamais avoir d'entrées Ajoutées (car l'ensemble des chemins inclus dans le diff est limité par ce qui est dans l'index). De même, les entrées copiées et renommées ne peuvent apparaître si la détection pour ces types est désactivée.

## Références

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Partagez vos astuces de hacking en soumettant des PRs au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires les **plus avancés**.\
Accédez-y dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
