# CGroups

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Les **groupes de contrôle Linux**, également connus sous le nom de cgroups, sont une fonctionnalité du noyau Linux qui vous permet de **limiter**, réguler et prioriser les **ressources système** pour un ensemble de processus. Les cgroups offrent un moyen de **gérer et isoler l'utilisation des ressources** (CPU, mémoire, entrées/sorties disque, réseau, etc.) de groupes de processus dans un système. Cela peut être utile à de nombreuses fins, telles que limiter les ressources disponibles pour un groupe particulier de processus, isoler certains types de charges de travail des autres, ou prioriser l'utilisation des ressources système entre différents groupes de processus.

Il existe **deux versions de cgroups**, 1 et 2, et les deux sont actuellement utilisées et peuvent être configurées simultanément sur un système. La **différence la plus significative** entre la version 1 des cgroups et la **version 2** est que cette dernière a introduit une nouvelle organisation hiérarchique pour les cgroups, où les groupes peuvent être arrangés dans une **structure arborescente** avec des relations parent-enfant. Cela permet un contrôle plus flexible et plus précis de l'allocation des ressources entre différents groupes de processus.

En plus de la nouvelle organisation hiérarchique, la version 2 des cgroups a également introduit **plusieurs autres changements et améliorations**, tels que le support pour **de nouveaux contrôleurs de ressources**, une meilleure prise en charge des applications héritées et des performances améliorées.

Dans l'ensemble, la **version 2 des cgroups offre plus de fonctionnalités et de meilleures performances** que la version 1, mais cette dernière peut encore être utilisée dans certains scénarios où la compatibilité avec les anciens systèmes est une préoccupation.

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
Ne soyez pas alarmé si le **résultat est considérablement plus court** sur votre système ; cela signifie simplement que vous avez probablement **seulement les cgroups v2**. Chaque ligne de sortie commence par un numéro et correspond à un cgroup différent. Voici quelques indications pour savoir comment les lire :

* **Les numéros 2–12 sont pour les cgroups v1**. Les **contrôleurs** pour ceux-ci sont listés à côté du numéro.
* **Le numéro 1** est également pour la **version 1**, mais il n'a pas de contrôleur. Ce cgroup est uniquement pour des **fins de gestion** (dans ce cas, configuré par systemd).
* La dernière ligne, **le numéro 0**, est pour les **cgroups v2**. Aucun contrôleur n'est visible ici. Sur un système qui n'a pas de cgroups v1, ce sera la seule ligne de sortie.
* **Les noms sont hiérarchiques et ressemblent à des parties de chemins de fichiers**. Vous pouvez voir dans cet exemple que certains des cgroups sont nommés /user.slice et d'autres /user.slice/user-1000.slice/session-2.scope.
* Le nom /testcgroup a été créé pour montrer que dans les cgroups v1, les cgroups pour un processus peuvent être complètement indépendants.
* **Les noms sous user.slice** qui incluent session sont des sessions de connexion, assignées par systemd. Vous les verrez lorsque vous examinerez les cgroups d'un shell. Les **cgroups** pour vos **services système** seront **sous system.slice**.

### Visualisation des cgroups

Les cgroups sont typiquement **accessibles via le système de fichiers**. Cela contraste avec l'interface d'appel système Unix traditionnelle pour interagir avec le noyau.\
Pour explorer la configuration des cgroups d'un shell, vous pouvez regarder dans le fichier `/proc/self/cgroup` pour trouver le cgroup du shell, puis naviguer vers le répertoire `/sys/fs/cgroup` (ou `/sys/fs/cgroup/unified`) et chercher un **répertoire portant le même nom que le cgroup**. Changer pour ce répertoire et regarder autour vous permettra de voir les différents **paramètres et informations sur l'utilisation des ressources pour le cgroup**.

<figure><img src="../../../.gitbook/assets/image (10) (2) (2).png" alt=""><figcaption></figcaption></figure>

Parmi les nombreux fichiers qui peuvent être ici, **les principaux fichiers d'interface cgroup commencent par `cgroup`**. Commencez par regarder `cgroup.procs` (utiliser cat est correct), qui liste les processus dans le cgroup. Un fichier similaire, `cgroup.threads`, inclut également les threads.

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

La plupart des cgroups utilisés pour les shells ont ces deux contrôleurs, qui peuvent contrôler la **quantité de mémoire** utilisée et le **nombre total de processus dans le cgroup**. Pour interagir avec un contrôleur, cherchez les **fichiers qui correspondent au préfixe du contrôleur**. Par exemple, si vous voulez voir le nombre de threads exécutés dans le cgroup, consultez pids.current :

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

Une valeur de **max signifie que ce cgroup n'a pas de limite spécifique**, mais comme les cgroups sont hiérarchiques, un cgroup plus bas dans la chaîne de sous-répertoires pourrait le limiter.

### Manipulation et Création de cgroups

Pour mettre un processus dans un cgroup, **écrivez son PID dans son fichier `cgroup.procs` en tant que root :**
```shell-session
# echo pid > cgroup.procs
```
Voici comment fonctionnent de nombreux changements aux cgroups. Par exemple, si vous souhaitez **limiter le nombre maximum de PIDs d'un cgroup** (à, disons, 3 000 PIDs), procédez comme suit :
```shell-session
# echo 3000 > pids.max
```
**Créer des cgroups est plus délicat**. Techniquement, c'est aussi simple que de créer un sous-répertoire quelque part dans l'arbre des cgroups ; lorsque vous faites cela, le noyau crée automatiquement les fichiers d'interface. Si un cgroup n'a pas de processus, vous pouvez supprimer le cgroup avec rmdir même si les fichiers d'interface sont présents. Ce qui peut vous piéger, ce sont les règles régissant les cgroups, y compris :

* Vous ne pouvez mettre des **processus que dans des cgroups de niveau extérieur ("feuille")**. Par exemple, si vous avez des cgroups nommés /mon-cgroup et /mon-cgroup/mon-sous-groupe, vous ne pouvez pas mettre de processus dans /mon-cgroup, mais /mon-cgroup/mon-sous-groupe est acceptable. (Une exception est si les cgroups n'ont pas de contrôleurs, mais ne creusons pas davantage.)
* Un cgroup **ne peut pas avoir un contrôleur qui n'est pas dans son cgroup parent**.
* Vous devez explicitement **spécifier les contrôleurs pour les cgroups enfants**. Vous faites cela via le fichier `cgroup.subtree_control`; par exemple, si vous voulez qu'un cgroup enfant ait les contrôleurs cpu et pids, écrivez +cpu +pids dans ce fichier.

Une exception à ces règles est le **cgroup racine** situé au bas de la hiérarchie. Vous pouvez **placer des processus dans ce cgroup**. Une raison pour laquelle vous pourriez vouloir faire cela est de détacher un processus du contrôle de systemd.

Même sans contrôleurs activés, vous pouvez voir l'utilisation du CPU d'un cgroup en regardant son fichier cpu.stat :

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

Comme il s'agit de l'utilisation cumulée du CPU sur toute la durée de vie du cgroup, vous pouvez voir comment un service consomme du temps processeur même s'il génère de nombreux sous-processus qui finissent par se terminer.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous voulez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux repos github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
