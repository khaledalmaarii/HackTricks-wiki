# Espace de noms CGroup

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Un espace de noms cgroup est une fonctionnalité du noyau Linux qui fournit **l'isolation des hiérarchies de cgroup pour les processus s'exécutant dans un espace de noms**. Les cgroups, abréviation de **control groups**, sont une fonctionnalité du noyau qui permet d'organiser les processus en groupes hiérarchiques pour gérer et appliquer des **limites sur les ressources système** comme le CPU, la mémoire et les E/S.

Bien que les espaces de noms cgroup ne soient pas un type d'espace de noms séparé comme les autres dont nous avons discuté précédemment (PID, montage, réseau, etc.), ils sont liés au concept d'isolation d'espace de noms. **Les espaces de noms cgroup virtualisent la vue de la hiérarchie de cgroup**, de sorte que les processus s'exécutant dans un espace de noms cgroup ont une vue différente de la hiérarchie par rapport aux processus s'exécutant sur l'hôte ou dans d'autres espaces de noms.

### Comment ça fonctionne :

1. Lorsqu'un nouvel espace de noms cgroup est créé, **il commence avec une vue de la hiérarchie de cgroup basée sur le cgroup du processus créateur**. Cela signifie que les processus s'exécutant dans le nouvel espace de noms cgroup ne verront qu'un sous-ensemble de la hiérarchie de cgroup entière, limité à la sous-arborescence de cgroup à la racine du cgroup du processus créateur.
2. Les processus au sein d'un espace de noms cgroup **verront leur propre cgroup comme la racine de la hiérarchie**. Cela signifie que, du point de vue des processus à l'intérieur de l'espace de noms, leur propre cgroup apparaît comme la racine, et ils ne peuvent ni voir ni accéder aux cgroups en dehors de leur propre sous-arborescence.
3. Les espaces de noms cgroup ne fournissent pas directement l'isolation des ressources ; **ils fournissent uniquement l'isolation de la vue de la hiérarchie de cgroup**. **Le contrôle et l'isolation des ressources sont toujours appliqués par les sous-systèmes de cgroup** (par exemple, cpu, mémoire, etc.) eux-mêmes.

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
En montant une nouvelle instance du système de fichiers `/proc` en utilisant le paramètre `--mount-proc`, vous garantissez que le nouveau namespace de montage dispose d'une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

<details>

<summary>Erreur : bash: fork: Impossible d'allouer de la mémoire</summary>

Si vous exécutez la ligne précédente sans `-f`, vous obtiendrez cette erreur.\
L'erreur est causée par le fait que le processus PID 1 se termine dans le nouveau namespace.

Après le démarrage de bash, bash va créer plusieurs nouveaux sous-processus pour faire certaines choses. Si vous exécutez unshare sans -f, bash aura le même pid que le processus "unshare" actuel. Le processus "unshare" actuel appelle l'appel système unshare, crée un nouveau namespace pid, mais le processus "unshare" actuel n'est pas dans le nouveau namespace pid. C'est le comportement souhaité du noyau Linux : le processus A crée un nouveau namespace, le processus A lui-même ne sera pas placé dans le nouveau namespace, seuls les sous-processus du processus A seront placés dans le nouveau namespace. Donc, lorsque vous exécutez :
```
unshare -p /bin/bash
```
```markdown
Le processus unshare exécutera /bin/bash, et /bin/bash engendrera plusieurs sous-processus. Le premier sous-processus de bash deviendra le PID 1 du nouveau namespace, et le sous-processus se terminera après avoir accompli sa tâche. Ainsi, le PID 1 du nouveau namespace se termine.

Le processus PID 1 a une fonction spéciale : il doit devenir le processus parent de tous les processus orphelins. Si le processus PID 1 dans le namespace racine se termine, le noyau paniquera. Si le processus PID 1 dans un sous-namespace se termine, le noyau Linux appellera la fonction disable\_pid\_allocation, qui nettoiera le drapeau PIDNS\_HASH\_ADDING dans ce namespace. Lorsque le noyau Linux crée un nouveau processus, il appelle la fonction alloc\_pid pour allouer un PID dans un namespace, et si le drapeau PIDNS\_HASH\_ADDING n'est pas défini, la fonction alloc\_pid retournera une erreur -ENOMEM. C'est pourquoi vous avez obtenu l'erreur "Cannot allocate memory".

Vous pouvez résoudre ce problème en utilisant l'option '-f' :
```
```
unshare -fp /bin/bash
```
```markdown
Si vous exécutez unshare avec l'option '-f', unshare va forker un nouveau processus après avoir créé le nouveau namespace pid. Et exécuter /bin/bash dans le nouveau processus. Le nouveau processus sera le pid 1 du nouveau namespace pid. Ensuite, bash va également forker plusieurs sous-processus pour effectuer certaines tâches. Comme bash lui-même est le pid 1 du nouveau namespace pid, ses sous-processus peuvent se terminer sans aucun problème.

Copié depuis [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Vérifiez dans quel espace de noms se trouve votre processus
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
### Entrer dans un espace de noms CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Vous pouvez uniquement **entrer dans l'espace de noms d'un autre processus si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/cgroup`).

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
