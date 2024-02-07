# CGroups

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informations de base

Les **groupes de contrôle Linux**, ou **cgroups**, sont une fonctionnalité du noyau Linux qui permet l'allocation, la limitation et la priorisation des ressources système telles que le CPU, la mémoire et les E/S disque parmi les groupes de processus. Ils offrent un mécanisme de **gestion et d'isolation de l'utilisation des ressources** des collections de processus, bénéfique pour des objectifs tels que la limitation des ressources, l'isolation des charges de travail et la priorisation des ressources parmi différents groupes de processus.

Il existe **deux versions de cgroups** : la version 1 et la version 2. Les deux peuvent être utilisées simultanément sur un système. La distinction principale est que **la version 2 de cgroups** introduit une **structure hiérarchique en forme d'arbre**, permettant une distribution des ressources plus nuancée et détaillée entre les groupes de processus. De plus, la version 2 apporte diverses améliorations, notamment :

En plus de la nouvelle organisation hiérarchique, la version 2 de cgroups a également introduit **plusieurs autres changements et améliorations**, tels que le support de **nouveaux contrôleurs de ressources**, un meilleur support pour les applications héritées et des performances améliorées.

Dans l'ensemble, cgroups **version 2 offre plus de fonctionnalités et de meilleures performances** que la version 1, mais cette dernière peut encore être utilisée dans certains scénarios où la compatibilité avec les anciens systèmes est une préoccupation.

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
La structure de sortie est la suivante :

- **Nombres 2 à 12** : cgroups v1, chaque ligne représentant un cgroup différent. Les contrôleurs pour ceux-ci sont spécifiés à côté du nombre.
- **Nombre 1** : Également cgroups v1, mais uniquement à des fins de gestion (défini par, par exemple, systemd), et ne comporte pas de contrôleur.
- **Nombre 0** : Représente les cgroups v2. Aucun contrôleur n'est répertorié, et cette ligne est exclusive aux systèmes exécutant uniquement des cgroups v2.
- Les **noms sont hiérarchiques**, ressemblant à des chemins de fichiers, indiquant la structure et la relation entre différents cgroups.
- Des noms comme /user.slice ou /system.slice spécifient la catégorisation des cgroups, avec user.slice généralement pour les sessions de connexion gérées par systemd et system.slice pour les services système.

### Visualisation des cgroups

Le système de fichiers est généralement utilisé pour accéder aux **cgroups**, s'éloignant de l'interface d'appel système Unix traditionnellement utilisée pour les interactions avec le noyau. Pour examiner la configuration cgroup d'un shell, il convient d'examiner le fichier **/proc/self/cgroup**, qui révèle le cgroup du shell. Ensuite, en naviguant vers le répertoire **/sys/fs/cgroup** (ou **`/sys/fs/cgroup/unified`**) et en localisant un répertoire portant le nom du cgroup, on peut observer divers paramètres et informations d'utilisation des ressources pertinentes au cgroup.

![Système de fichiers Cgroup](../../../.gitbook/assets/image%20(10)%20(2)%20(2).png)

Les fichiers d'interface clés pour les cgroups sont préfixés par **cgroup**. Le fichier **cgroup.procs**, qui peut être consulté avec des commandes standard comme cat, répertorie les processus dans le cgroup. Un autre fichier, **cgroup.threads**, inclut des informations sur les threads.

![Cgroup Procs](../../../.gitbook/assets/image%20(1)%20(1)%20(5).png)

Les cgroups gérant les shells englobent généralement deux contrôleurs qui régulent l'utilisation de la mémoire et le nombre de processus. Pour interagir avec un contrôleur, il convient de consulter les fichiers portant le préfixe du contrôleur. Par exemple, **pids.current** serait consulté pour déterminer le nombre de threads dans le cgroup.

![Mémoire Cgroup](../../../.gitbook/assets/image%20(3)%20(5).png)

L'indication de **max** dans une valeur suggère l'absence d'une limite spécifique pour le cgroup. Cependant, en raison de la nature hiérarchique des cgroups, des limites pourraient être imposées par un cgroup à un niveau inférieur dans la hiérarchie des répertoires.


### Manipulation et création de cgroups

Les processus sont assignés à des cgroups en **écrivant leur ID de processus (PID) dans le fichier `cgroup.procs`**. Cela nécessite des privilèges root. Par exemple, pour ajouter un processus :
```bash
echo [pid] > cgroup.procs
```
De même, **modifier les attributs du cgroup, comme définir une limite de PID**, se fait en écrivant la valeur souhaitée dans le fichier correspondant. Pour définir un maximum de 3 000 PID pour un cgroup :
```bash
echo 3000 > pids.max
```
**Créer de nouveaux cgroups** implique de créer un nouveau sous-répertoire dans la hiérarchie cgroup, ce qui incite le noyau à générer automatiquement les fichiers d'interface nécessaires. Bien que les cgroups sans processus actifs puissent être supprimés avec `rmdir`, soyez conscient de certaines contraintes :

- **Les processus ne peuvent être placés que dans des cgroups feuilles** (c'est-à-dire les plus imbriqués dans une hiérarchie).
- **Un cgroup ne peut pas posséder un contrôleur absent dans son parent**.
- **Les contrôleurs pour les cgroups enfants doivent être explicitement déclarés** dans le fichier `cgroup.subtree_control`. Par exemple, pour activer les contrôleurs CPU et PID dans un cgroup enfant :
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
Le **cgroup racine** est une exception à ces règles, permettant un placement direct des processus. Cela peut être utilisé pour retirer des processus de la gestion de systemd.

**La surveillance de l'utilisation du CPU** au sein d'un cgroup est possible grâce au fichier `cpu.stat`, affichant le temps total du CPU consommé, utile pour suivre l'utilisation à travers les sous-processus d'un service :

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption>Statistiques d'utilisation du CPU telles qu'indiquées dans le fichier cpu.stat</figcaption></figure>

## Références
* **Livre : How Linux Works, 3rd Edition: What Every Superuser Should Know Par Brian Ward**
