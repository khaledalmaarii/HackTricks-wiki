# Espace de noms CGroup

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Un espace de noms CGroup est une fonctionnalité du noyau Linux qui fournit **l'isolation des hiérarchies de cgroup pour les processus s'exécutant dans un espace de noms**. Les cgroups, abréviation de **groupes de contrôle**, sont une fonctionnalité du noyau qui permet d'organiser les processus en groupes hiérarchiques pour gérer et appliquer des **limites sur les ressources système** telles que le CPU, la mémoire et l'E/S.

Bien que les espaces de noms CGroup ne soient pas un type d'espace de noms distinct comme les autres que nous avons discutés précédemment (PID, montage, réseau, etc.), ils sont liés au concept d'isolation d'espace de noms. **Les espaces de noms CGroup virtualisent la vue de la hiérarchie de cgroup**, de sorte que les processus s'exécutant dans un espace de noms CGroup ont une vue différente de la hiérarchie par rapport aux processus s'exécutant dans l'hôte ou d'autres espaces de noms.

### Comment ça marche :

1. Lorsqu'un nouvel espace de noms CGroup est créé, **il démarre avec une vue de la hiérarchie de cgroup basée sur le cgroup du processus créateur**. Cela signifie que les processus s'exécutant dans le nouvel espace de noms CGroup ne verront qu'un sous-ensemble de l'ensemble de la hiérarchie de cgroup, limité au sous-arbre de cgroup enraciné dans le cgroup du processus créateur.
2. Les processus dans un espace de noms CGroup **voient leur propre cgroup comme la racine de la hiérarchie**. Cela signifie que, du point de vue des processus à l'intérieur de l'espace de noms, leur propre cgroup apparaît comme la racine, et ils ne peuvent pas voir ou accéder aux cgroups en dehors de leur propre sous-arbre.
3. Les espaces de noms CGroup ne fournissent pas directement l'isolation des ressources ; **ils ne fournissent que l'isolation de la vue de la hiérarchie de cgroup**. **Le contrôle et l'isolation des ressources sont toujours appliqués par les sous-systèmes de cgroup (par exemple, cpu, mémoire, etc.) eux-mêmes**.

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

<summary>Erreur : bash: fork: Cannot allocate memory</summary>

Si vous exécutez la ligne précédente sans `-f`, vous obtiendrez cette erreur.\
L'erreur est causée par la sortie du processus PID 1 dans le nouveau namespace.

Après le démarrage de bash, celui-ci va créer plusieurs nouveaux sous-processus pour effectuer des actions. Si vous exécutez unshare sans -f, bash aura le même PID que le processus "unshare" actuel. Le processus "unshare" actuel appelle l'appel système unshare, crée un nouveau namespace PID, mais le processus "unshare" actuel n'est pas dans le nouveau namespace PID. C'est le comportement souhaité du noyau Linux : le processus A crée un nouveau namespace, le processus A lui-même ne sera pas mis dans le nouveau namespace, seuls les sous-processus du processus A seront mis dans le nouveau namespace. Ainsi, lorsque vous exécutez :
```
unshare -p /bin/bash
```
Le processus unshare exécutera /bin/bash, et /bin/bash créera plusieurs sous-processus. Le premier sous-processus de bash deviendra le PID 1 du nouveau namespace, et le sous-processus se terminera après avoir terminé son travail. Ainsi, le PID 1 du nouveau namespace se termine.

Le processus PID 1 a une fonction spéciale : il doit devenir le processus parent de tous les processus orphelins. Si le processus PID 1 dans le namespace racine se termine, le noyau panique. Si le processus PID 1 dans un sous-namespace se termine, le noyau Linux appellera la fonction disable\_pid\_allocation, qui nettoiera le drapeau PIDNS\_HASH\_ADDING dans ce namespace. Lorsque le noyau Linux crée un nouveau processus, il appelle la fonction alloc\_pid pour allouer un PID dans un namespace, et si le drapeau PIDNS\_HASH\_ADDING n'est pas défini, la fonction alloc\_pid renverra une erreur -ENOMEM. C'est pourquoi vous obtenez l'erreur "Cannot allocate memory".

Vous pouvez résoudre ce problème en utilisant l'option '-f':
```
unshare -fp /bin/bash
```
Si vous exécutez unshare avec l'option '-f', unshare va créer un nouveau processus après avoir créé le nouveau namespace pid. Et exécuter /bin/bash dans le nouveau processus. Le nouveau processus sera le pid 1 du nouveau namespace pid. Ensuite, bash va également créer plusieurs sous-processus pour effectuer certaines tâches. Comme bash lui-même est le pid 1 du nouveau namespace pid, ses sous-processus peuvent se terminer sans aucun problème.

Traduit de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Vérifier dans quel namespace se trouve votre processus
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

### Entrer dans un namespace CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
De plus, vous ne pouvez **entrer dans un autre espace de noms de processus que si vous êtes root**. Et vous ne pouvez **pas entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/cgroup`).
