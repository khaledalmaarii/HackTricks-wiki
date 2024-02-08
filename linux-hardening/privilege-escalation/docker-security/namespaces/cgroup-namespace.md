# Espace de noms CGroup

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Informations de base

Un espace de noms CGroup est une fonctionnalité du noyau Linux qui fournit **l'isolation des hiérarchies de cgroup pour les processus s'exécutant dans un espace de noms**. Les cgroups, abréviation de **groupes de contrôle**, sont une fonctionnalité du noyau qui permet d'organiser les processus en groupes hiérarchiques pour gérer et imposer des **limites sur les ressources système** telles que le CPU, la mémoire et l'E/S.

Bien que les espaces de noms cgroup ne soient pas un type d'espace de noms distinct comme ceux que nous avons discutés précédemment (PID, montage, réseau, etc.), ils sont liés au concept d'isolation des espaces de noms. **Les espaces de noms cgroup virtualisent la vue de la hiérarchie cgroup**, de sorte que les processus s'exécutant dans un espace de noms cgroup ont une vue différente de la hiérarchie par rapport aux processus s'exécutant dans l'hôte ou d'autres espaces de noms.

### Comment cela fonctionne :

1. Lorsqu'un nouvel espace de noms cgroup est créé, **il démarre avec une vue de la hiérarchie cgroup basée sur le cgroup du processus créateur**. Cela signifie que les processus s'exécutant dans le nouvel espace de noms cgroup ne verront qu'un sous-ensemble de toute la hiérarchie cgroup, limité à la sous-arborescence cgroup enracinée dans le cgroup du processus créateur.
2. Les processus au sein d'un espace de noms cgroup **voient leur propre cgroup comme la racine de la hiérarchie**. Cela signifie que, du point de vue des processus à l'intérieur de l'espace de noms, leur propre cgroup apparaît comme la racine, et ils ne peuvent pas voir ou accéder aux cgroups en dehors de leur propre sous-arborescence.
3. Les espaces de noms cgroup ne fournissent pas directement l'isolation des ressources ; **ils fournissent uniquement l'isolation de la vue de la hiérarchie cgroup**. **Le contrôle et l'isolation des ressources sont toujours appliqués par les sous-systèmes cgroup** (par exemple, cpu, mémoire, etc.) eux-mêmes.

Pour plus d'informations sur les CGroups, consultez :

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
En montant une nouvelle instance du système de fichiers `/proc` en utilisant le paramètre `--mount-proc`, vous vous assurez que le nouveau namespace de montage a une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

<details>

<summary>Erreur : bash: fork: Impossible d'allouer de la mémoire</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur est rencontrée en raison de la manière dont Linux gère les nouveaux espaces de noms PID (Process ID). Les détails clés et la solution sont décrits ci-dessous :

1. **Explication du Problème** :
- Le noyau Linux permet à un processus de créer de nouveaux espaces de noms en utilisant l'appel système `unshare`. Cependant, le processus qui initie la création d'un nouveau namespace PID (appelé processus "unshare") n'entre pas dans le nouveau namespace ; seuls ses processus enfants le font.
- L'exécution de `%unshare -p /bin/bash%` lance `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants se trouvent dans le namespace PID d'origine.
- Le premier processus enfant de `/bin/bash` dans le nouveau namespace devient le PID 1. Lorsque ce processus se termine, il déclenche le nettoyage du namespace s'il n'y a pas d'autres processus, car le PID 1 a le rôle spécial d'adopter les processus orphelins. Le noyau Linux désactive alors l'allocation de PID dans ce namespace.

2. **Conséquence** :
- La sortie du PID 1 dans un nouveau namespace entraîne le nettoyage du drapeau `PIDNS_HASH_ADDING`. Cela entraîne l'échec de la fonction `alloc_pid` pour allouer un nouveau PID lors de la création d'un nouveau processus, produisant l'erreur "Impossible d'allouer de la mémoire".

3. **Solution** :
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option fait en sorte que `unshare` fork un nouveau processus après la création du nouveau namespace PID.
- L'exécution de `%unshare -fp /bin/bash%` garantit que la commande `unshare` elle-même devient le PID 1 dans le nouveau namespace. `/bin/bash` et ses processus enfants sont alors en toute sécurité contenus dans ce nouveau namespace, empêchant la sortie prématurée du PID 1 et permettant une allocation normale des PID.

En veillant à ce que `unshare` s'exécute avec le drapeau `-f`, le nouveau namespace PID est correctement maintenu, permettant à `/bin/bash` et à ses sous-processus de fonctionner sans rencontrer l'erreur d'allocation de mémoire.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Vérifier dans quel espace de nom se trouve votre processus
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Trouver tous les espaces de noms CGroup

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrer dans un espace de noms CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
De plus, vous ne pouvez **entrer dans un autre espace de noms de processus que si vous êtes root**. Et vous ne pouvez **pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/cgroup`).

## Références
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
