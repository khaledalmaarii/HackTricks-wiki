## CGroups

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Les **groupes de contrôle Linux**, également connus sous le nom de cgroups, sont une fonctionnalité du noyau Linux qui vous permet de **limiter**, de contrôler et de prioriser les **ressources système** pour une collection de processus. Les cgroups fournissent un moyen de **gérer et d'isoler l'utilisation des ressources** (CPU, mémoire, E/S de disque, réseau, etc.) de groupes de processus dans un système. Cela peut être utile pour de nombreuses fins, telles que la limitation des ressources disponibles pour un groupe particulier de processus, l'isolation de certains types de charges de travail des autres, ou la priorisation de l'utilisation des ressources système entre différents groupes de processus.

Il existe **deux versions de cgroups**, 1 et 2, et les deux sont actuellement utilisées et peuvent être configurées simultanément sur un système. La **différence la plus significative** entre la version 1 et la **version 2** des cgroups est que cette dernière a introduit une nouvelle organisation hiérarchique pour les cgroups, où les groupes peuvent être disposés dans une structure **arborescente** avec des relations parent-enfant. Cela permet un contrôle plus flexible et plus fin de l'allocation des ressources entre différents groupes de processus.

En plus de la nouvelle organisation hiérarchique, la version 2 des cgroups a également introduit **plusieurs autres changements et améliorations**, tels que le support de **nouveaux contrôleurs de ressources**, un meilleur support pour les applications héritées et des performances améliorées.

Dans l'ensemble, la version 2 des cgroups **offre plus de fonctionnalités et de meilleures performances** que la version 1, mais cette dernière peut encore être utilisée dans certains scénarios où la compatibilité avec les anciens systèmes est une préoccupation.

Vous pouvez lister les cgroups v1 et v2 pour n'importe quel processus en regardant son fichier cgroup dans /proc/\<pid>. Vous pouvez commencer par regarder les cgroups de votre shell avec cette commande :
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
Ne soyez pas alarmé si la **sortie est considérablement plus courte** sur votre système; cela signifie simplement que vous avez probablement **seulement des cgroups v2**. Chaque ligne de sortie commence par un numéro et représente un cgroup différent. Voici quelques points à prendre en compte pour la lecture :

* Les numéros 2 à 12 sont pour les cgroups v1. Les **contrôleurs** pour ceux-ci sont listés à côté du numéro.
* Le numéro 1 est également pour la **version 1**, mais il n'a pas de contrôleur. Ce cgroup est uniquement destiné à des **fins de gestion** (dans ce cas, systemd l'a configuré).
* La dernière ligne, le **numéro 0**, est pour les **cgroups v2**. Aucun contrôleur n'est visible ici. Sur un système qui n'a pas de cgroups v1, ce sera la seule ligne de sortie.
* Les **noms sont hiérarchiques et ressemblent à des parties de chemins de fichiers**. Vous pouvez voir dans cet exemple que certains des cgroups sont nommés /user.slice et d'autres /user.slice/user-1000.slice/session-2.scope.
* Le nom /testcgroup a été créé pour montrer que dans les cgroups v1, les cgroups pour un processus peuvent être complètement indépendants.
* Les noms sous user.slice qui incluent session sont des sessions de connexion, attribuées par systemd. Vous les verrez lorsque vous regarderez les cgroups d'un shell. Les cgroups pour vos services système seront sous system.slice.

### Visualisation des cgroups

Les cgroups sont généralement **accessibles via le système de fichiers**. Cela contraste avec l'interface d'appel système Unix traditionnelle pour interagir avec le noyau.\
Pour explorer la configuration des cgroups d'un shell, vous pouvez regarder dans le fichier `/proc/self/cgroup` pour trouver le cgroup du shell, puis naviguer vers le répertoire `/sys/fs/cgroup` (ou `/sys/fs/cgroup/unified`) et chercher un **répertoire portant le même nom que le cgroup**. En changeant de répertoire et en regardant autour, vous pourrez voir les différents **paramètres et informations d'utilisation des ressources pour le cgroup**.

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

Parmi les nombreux fichiers qui peuvent être ici, **les fichiers d'interface de cgroup principaux commencent par `cgroup`**. Commencez par regarder `cgroup.procs` (utiliser cat est bien), qui liste les processus dans le cgroup. Un fichier similaire, `cgroup.threads`, inclut également les threads.

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

La plupart des cgroups utilisés pour les shells ont ces deux contrôleurs, qui peuvent contrôler la **quantité de mémoire** utilisée et le **nombre total de processus dans le cgroup**. Pour interagir avec un contrôleur, cherchez les **fichiers qui correspondent au préfixe du contrôleur**. Par exemple, si vous voulez voir le nombre de threads en cours d'exécution dans le cgroup, consultez pids.current :

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

Une valeur de **max signifie que ce cgroup n'a pas de limite spécifique**, mais parce que les cgroups sont hiérarchiques, un cgroup en aval de la chaîne de sous-répertoires pourrait le limiter.

### Manipulation et création de cgroups

Pour mettre un processus dans un cgroup, **écrivez son PID dans son fichier `cgroup.procs` en tant que root :**
```shell-session
# echo pid > cgroup.procs
```
Voici comment fonctionnent les modifications apportées aux cgroups. Par exemple, si vous souhaitez **limiter le nombre maximal de PIDs d'un cgroup** (à, disons, 3 000 PIDs), procédez comme suit :
```shell-session
# echo 3000 > pids.max
```
**La création de cgroups est plus délicate**. Techniquement, c'est aussi simple que de créer un sous-répertoire quelque part dans l'arborescence des cgroups ; lorsque vous le faites, le noyau crée automatiquement les fichiers d'interface. Si un cgroup n'a pas de processus, vous pouvez supprimer le cgroup avec rmdir même si les fichiers d'interface sont présents. Ce qui peut vous tromper, ce sont les règles régissant les cgroups, notamment :

* Vous ne pouvez mettre des **processus que dans des cgroups de niveau supérieur ("feuille")**. Par exemple, si vous avez des cgroups nommés /my-cgroup et /my-cgroup/my-subgroup, vous ne pouvez pas mettre de processus dans /my-cgroup, mais /my-cgroup/my-subgroup est correct. (Une exception est si les cgroups n'ont pas de contrôleurs, mais ne creusons pas plus loin.)
* Un cgroup **ne peut pas avoir de contrôleur qui n'est pas dans son cgroup parent**.
* Vous devez **spécifier explicitement les contrôleurs pour les cgroups enfants**. Vous le faites via le fichier `cgroup.subtree_control`; par exemple, si vous voulez qu'un cgroup enfant ait les contrôleurs cpu et pids, écrivez +cpu +pids dans ce fichier.

Une exception à ces règles est le **cgroup racine** situé en bas de la hiérarchie. Vous pouvez **placer des processus dans ce cgroup**. Une raison pour laquelle vous pourriez vouloir le faire est de détacher un processus du contrôle de systemd.

Même sans contrôleurs activés, vous pouvez voir l'utilisation du CPU d'un cgroup en regardant son fichier cpu.stat :

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

Étant donné que c'est l'utilisation accumulée du CPU sur toute la durée de vie du cgroup, vous pouvez voir comment un service consomme du temps processeur même s'il génère de nombreux sous-processus qui finissent par se terminer.
