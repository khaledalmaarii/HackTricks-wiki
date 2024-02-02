# Espace de noms de montage

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Un espace de noms de montage est une fonctionnalité du noyau Linux qui fournit l'isolation des points de montage du système de fichiers vus par un groupe de processus. Chaque espace de noms de montage a son propre ensemble de points de montage du système de fichiers, et **les modifications apportées aux points de montage dans un espace de noms n'affectent pas les autres espaces de noms**. Cela signifie que les processus s'exécutant dans différents espaces de noms de montage peuvent avoir des vues différentes de la hiérarchie du système de fichiers.

Les espaces de noms de montage sont particulièrement utiles dans la conteneurisation, où chaque conteneur doit avoir son propre système de fichiers et configuration, isolé des autres conteneurs et du système hôte.

### Comment ça fonctionne :

1. Lorsqu'un nouvel espace de noms de montage est créé, il est initialisé avec une **copie des points de montage de son espace de noms parent**. Cela signifie qu'au moment de la création, le nouvel espace de noms partage la même vue du système de fichiers que son parent. Cependant, tout changement ultérieur des points de montage à l'intérieur de l'espace de noms n'affectera pas le parent ou d'autres espaces de noms.
2. Lorsqu'un processus modifie un point de montage à l'intérieur de son espace de noms, comme monter ou démonter un système de fichiers, le **changement est local à cet espace de noms** et n'affecte pas les autres espaces de noms. Cela permet à chaque espace de noms d'avoir sa propre hiérarchie de système de fichiers indépendante.
3. Les processus peuvent se déplacer entre les espaces de noms en utilisant l'appel système `setns()`, ou créer de nouveaux espaces de noms en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWNS`. Lorsqu'un processus se déplace vers un nouvel espace de noms ou en crée un, il commencera à utiliser les points de montage associés à cet espace de noms.
4. **Les descripteurs de fichiers et les inodes sont partagés à travers les espaces de noms**, ce qui signifie que si un processus dans un espace de noms a un descripteur de fichier ouvert pointant vers un fichier, il peut **passer ce descripteur de fichier** à un processus dans un autre espace de noms, et **les deux processus accéderont au même fichier**. Cependant, le chemin du fichier peut ne pas être le même dans les deux espaces de noms en raison de différences dans les points de montage.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
En montant une nouvelle instance du système de fichiers `/proc` en utilisant le paramètre `--mount-proc`, vous garantissez que le nouveau namespace de montage dispose d'une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

<details>

<summary>Erreur : bash: fork: Impossible d'allouer de la mémoire</summary>

Si vous exécutez la ligne précédente sans `-f`, vous obtiendrez cette erreur.\
L'erreur est causée par le fait que le processus PID 1 se termine dans le nouveau namespace.

Après le démarrage de bash, bash va créer plusieurs nouveaux sous-processus pour faire certaines choses. Si vous exécutez unshare sans -f, bash aura le même pid que le processus "unshare" actuel. Le processus "unshare" actuel appelle l'appel système unshare, crée un nouveau namespace pid, mais le processus "unshare" actuel n'est pas dans le nouveau namespace pid. C'est le comportement souhaité du noyau linux : le processus A crée un nouveau namespace, le processus A lui-même ne sera pas placé dans le nouveau namespace, seuls les sous-processus du processus A seront placés dans le nouveau namespace. Donc, lorsque vous exécutez :
```
unshare -p /bin/bash
```
Le processus unshare exécutera /bin/bash, et /bin/bash engendrera plusieurs sous-processus, le premier sous-processus de bash deviendra le PID 1 du nouveau namespace, et le sous-processus se terminera après avoir accompli sa tâche. Ainsi, le PID 1 du nouveau namespace se termine.

Le processus PID 1 a une fonction spéciale : il doit devenir le processus parent de tous les processus orphelins. Si le processus PID 1 dans le namespace racine se termine, le noyau paniquera. Si le processus PID 1 dans un sous-namespace se termine, le noyau Linux appellera la fonction disable\_pid\_allocation, qui nettoiera le drapeau PIDNS\_HASH\_ADDING dans ce namespace. Lorsque le noyau Linux crée un nouveau processus, il appelle la fonction alloc\_pid pour allouer un PID dans un namespace, et si le drapeau PIDNS\_HASH\_ADDING n'est pas défini, la fonction alloc\_pid retournera une erreur -ENOMEM. C'est pourquoi vous avez obtenu l'erreur "Cannot allocate memory".

Vous pouvez résoudre ce problème en utilisant l'option '-f' :
```
unshare -fp /bin/bash
```
Si vous exécutez unshare avec l'option '-f', unshare va forker un nouveau processus après avoir créé le nouveau namespace pid. Et exécuter /bin/bash dans le nouveau processus. Le nouveau processus sera le pid 1 du nouveau namespace pid. Ensuite, bash va également forker plusieurs sous-processus pour effectuer certaines tâches. Comme bash lui-même est le pid 1 du nouveau namespace pid, ses sous-processus peuvent se terminer sans aucun problème.

Copié depuis [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Vérifiez dans quel espace de noms se trouve votre processus
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Trouver tous les espaces de noms de montage

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrer dans un espace de noms de montage
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Aussi, vous pouvez seulement **entrer dans l'espace de noms d'un autre processus si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/mnt`).

Étant donné que les nouveaux montages ne sont accessibles que dans l'espace de noms, il est possible qu'un espace de noms contienne des informations sensibles qui ne peuvent être accessibles que depuis celui-ci.

### Monter quelque chose
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```
<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
