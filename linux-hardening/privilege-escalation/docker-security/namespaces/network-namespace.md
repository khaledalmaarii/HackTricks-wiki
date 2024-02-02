# Espace de noms réseau

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

Un espace de noms réseau est une fonctionnalité du noyau Linux qui fournit l'isolation de la pile réseau, permettant **à chaque espace de noms réseau d'avoir sa propre configuration réseau indépendante**, interfaces, adresses IP, tables de routage et règles de pare-feu. Cette isolation est utile dans divers scénarios, tels que la conteneurisation, où chaque conteneur doit avoir sa propre configuration réseau, indépendante des autres conteneurs et du système hôte.

### Fonctionnement :

1. Lorsqu'un nouvel espace de noms réseau est créé, il commence avec une **pile réseau complètement isolée**, avec **aucune interface réseau** à l'exception de l'interface de bouclage (lo). Cela signifie que les processus s'exécutant dans le nouvel espace de noms réseau ne peuvent pas communiquer par défaut avec les processus dans d'autres espaces de noms ou le système hôte.
2. Des **interfaces réseau virtuelles**, telles que des paires veth, peuvent être créées et déplacées entre les espaces de noms réseau. Cela permet d'établir une connectivité réseau entre les espaces de noms ou entre un espace de noms et le système hôte. Par exemple, une extrémité d'une paire veth peut être placée dans l'espace de noms réseau d'un conteneur, et l'autre extrémité peut être connectée à un **pont** ou à une autre interface réseau dans l'espace de noms hôte, fournissant une connectivité réseau au conteneur.
3. Les interfaces réseau au sein d'un espace de noms peuvent avoir leurs **propres adresses IP, tables de routage et règles de pare-feu**, indépendamment des autres espaces de noms. Cela permet aux processus dans différents espaces de noms réseau d'avoir différentes configurations réseau et d'opérer comme s'ils étaient sur des systèmes en réseau séparés.
4. Les processus peuvent se déplacer entre les espaces de noms en utilisant l'appel système `setns()`, ou créer de nouveaux espaces de noms en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWNET`. Lorsqu'un processus se déplace vers un nouvel espace de noms ou en crée un, il commencera à utiliser la configuration réseau et les interfaces associées à cet espace de noms.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
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
```markdown
Le processus unshare exécutera /bin/bash, et /bin/bash engendrera plusieurs sous-processus, le premier sous-processus de bash deviendra le PID 1 du nouveau namespace, et le sous-processus se terminera après avoir accompli sa tâche. Ainsi, le PID 1 du nouveau namespace se termine.

Le processus PID 1 a une fonction spéciale : il doit devenir le processus parent de tous les processus orphelins. Si le processus PID 1 dans le namespace racine se termine, le noyau paniquera. Si le processus PID 1 dans un sous-namespace se termine, le noyau Linux appellera la fonction disable\_pid\_allocation, qui nettoiera le drapeau PIDNS\_HASH\_ADDING dans ce namespace. Lorsque le noyau Linux crée un nouveau processus, il appellera la fonction alloc\_pid pour allouer un PID dans un namespace, et si le drapeau PIDNS\_HASH\_ADDING n'est pas défini, la fonction alloc\_pid retournera une erreur -ENOMEM. C'est pourquoi vous avez obtenu l'erreur "Cannot allocate memory".

Vous pouvez résoudre ce problème en utilisant l'option '-f' :
```
```
unshare -fp /bin/bash
```
Si vous exécutez unshare avec l'option '-f', unshare va bifurquer un nouveau processus après avoir créé le nouveau namespace pid. Et exécuter /bin/bash dans le nouveau processus. Le nouveau processus sera le pid 1 du nouveau namespace pid. Ensuite, bash va également bifurquer plusieurs sous-processus pour effectuer certaines tâches. Comme bash lui-même est le pid 1 du nouveau namespace pid, ses sous-processus peuvent se terminer sans aucun problème.

Copié depuis [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### Vérifiez dans quel espace de noms se trouve votre processus
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Trouver tous les espaces de noms réseau

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrer dans un espace de noms réseau
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
```markdown
Aussi, vous pouvez seulement **entrer dans un autre espace de noms de processus si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/net`).

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
