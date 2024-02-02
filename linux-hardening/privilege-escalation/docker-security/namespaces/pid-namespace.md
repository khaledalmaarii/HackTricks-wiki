# Espace de noms PID

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

L'espace de noms PID (Process IDentifier) est une fonctionnalité du noyau Linux qui fournit l'isolation des processus en permettant à un groupe de processus d'avoir leur propre ensemble de PIDs uniques, séparés des PIDs dans d'autres espaces de noms. Cela est particulièrement utile dans la conteneurisation, où l'isolation des processus est essentielle pour la sécurité et la gestion des ressources.

Lorsqu'un nouvel espace de noms PID est créé, le premier processus dans cet espace de noms se voit attribuer le PID 1. Ce processus devient le processus "init" du nouvel espace de noms et est responsable de la gestion des autres processus au sein de l'espace de noms. Chaque processus subséquent créé dans l'espace de noms aura un PID unique au sein de cet espace de noms, et ces PIDs seront indépendants des PIDs dans d'autres espaces de noms.

Du point de vue d'un processus au sein d'un espace de noms PID, il ne peut voir que les autres processus dans le même espace de noms. Il n'est pas conscient des processus dans d'autres espaces de noms et ne peut pas interagir avec eux en utilisant les outils de gestion de processus traditionnels (par exemple, `kill`, `wait`, etc.). Cela fournit un niveau d'isolation qui aide à empêcher les processus d'interférer les uns avec les autres.

### Comment ça fonctionne :

1. Lorsqu'un nouveau processus est créé (par exemple, en utilisant l'appel système `clone()`), le processus peut être affecté à un nouvel espace de noms PID ou à un espace existant. **Si un nouvel espace de noms est créé, le processus devient le processus "init" de cet espace de noms**.
2. Le **noyau** maintient une **correspondance entre les PIDs dans le nouvel espace de noms et les PIDs correspondants** dans l'espace de noms parent (c'est-à-dire, l'espace de noms à partir duquel le nouvel espace a été créé). Cette correspondance **permet au noyau de traduire les PIDs lorsque nécessaire**, comme lors de l'envoi de signaux entre processus dans différents espaces de noms.
3. **Les processus au sein d'un espace de noms PID ne peuvent voir et interagir qu'avec d'autres processus dans le même espace de noms**. Ils ne sont pas conscients des processus dans d'autres espaces de noms, et leurs PIDs sont uniques au sein de leur espace de noms.
4. Lorsqu'un **espace de noms PID est détruit** (par exemple, lorsque le processus "init" de l'espace de noms se termine), **tous les processus au sein de cet espace de noms sont terminés**. Cela garantit que toutes les ressources associées à l'espace de noms sont correctement nettoyées.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Erreur : bash: fork: Impossible d'allouer de la mémoire</summary>

Si vous exécutez la ligne précédente sans `-f`, vous obtiendrez cette erreur.\
L'erreur est causée par le fait que le processus PID 1 se termine dans le nouveau namespace.

Après le démarrage de bash, bash va créer plusieurs nouveaux sous-processus pour faire certaines choses. Si vous exécutez unshare sans -f, bash aura le même pid que le processus "unshare" actuel. Le processus "unshare" actuel appelle l'appel système unshare, crée un nouveau pid namespace, mais le processus "unshare" actuel n'est pas dans le nouveau pid namespace. C'est le comportement souhaité du noyau linux : le processus A crée un nouveau namespace, le processus A lui-même ne sera pas placé dans le nouveau namespace, seuls les sous-processus du processus A seront placés dans le nouveau namespace. Donc, lorsque vous exécutez :
</details>
```
unshare -p /bin/bash
```
Le processus unshare exécutera /bin/bash, et /bin/bash engendrera plusieurs sous-processus, le premier sous-processus de bash deviendra le PID 1 du nouveau namespace, et le sous-processus se terminera après avoir accompli sa tâche. Ainsi, le PID 1 du nouveau namespace se termine.

Le processus PID 1 a une fonction spéciale : il doit devenir le processus parent de tous les processus orphelins. Si le processus PID 1 dans le namespace racine se termine, le noyau paniquera. Si le processus PID 1 dans un sous-namespace se termine, le noyau linux appellera la fonction disable\_pid\_allocation, qui nettoiera le drapeau PIDNS\_HASH\_ADDING dans ce namespace. Lorsque le noyau linux crée un nouveau processus, il appellera la fonction alloc\_pid pour allouer un PID dans un namespace, et si le drapeau PIDNS\_HASH\_ADDING n'est pas défini, la fonction alloc\_pid retournera une erreur -ENOMEM. C'est pourquoi vous avez obtenu l'erreur "Cannot allocate memory".

Vous pouvez résoudre ce problème en utilisant l'option '-f' :
```
unshare -fp /bin/bash
```
```markdown
Si vous exécutez unshare avec l'option '-f', unshare va forker un nouveau processus après avoir créé le nouveau pid namespace. Et exécuter /bin/bash dans le nouveau processus. Le nouveau processus sera le pid 1 du nouveau pid namespace. Ensuite, bash va également forker plusieurs sous-processus pour effectuer certaines tâches. Comme bash lui-même est le pid 1 du nouveau pid namespace, ses sous-processus peuvent se terminer sans aucun problème.

Copié depuis [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous vous assurez que le nouveau mount namespace a une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

#### Docker
```
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Vérifiez dans quel espace de noms se trouve votre processus
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Trouver tous les espaces de noms PID

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Notez que l'utilisateur root de l'espace de noms PID initial (par défaut) peut voir tous les processus, même ceux dans de nouveaux espaces de noms PID, c'est pourquoi nous pouvons voir tous les espaces de noms PID.

### Entrer dans un espace de noms PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Lorsque vous entrez dans un espace de noms PID depuis l'espace de noms par défaut, vous pourrez toujours voir tous les processus. Et le processus de cet espace de noms PID pourra voir le nouveau bash dans l'espace de noms PID.

De plus, vous ne pouvez **entrer dans l'espace de noms PID d'un autre processus que si vous êtes root**. Et vous ne pouvez **pas entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/pid`)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
