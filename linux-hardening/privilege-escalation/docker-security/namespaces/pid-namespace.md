# Espace de noms PID

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

L'espace de noms PID (Process IDentifier) est une fonctionnalité du noyau Linux qui permet l'isolation des processus en permettant à un groupe de processus d'avoir son propre ensemble de PID uniques, séparés des PID dans d'autres espaces de noms. Cela est particulièrement utile dans la conteneurisation, où l'isolation des processus est essentielle pour la sécurité et la gestion des ressources.

Lorsqu'un nouvel espace de noms PID est créé, le premier processus de cet espace de noms se voit attribuer le PID 1. Ce processus devient le processus "init" du nouvel espace de noms et est responsable de la gestion des autres processus dans l'espace de noms. Chaque processus ultérieur créé dans l'espace de noms aura un PID unique dans cet espace de noms, et ces PID seront indépendants des PID dans d'autres espaces de noms.

Du point de vue d'un processus dans un espace de noms PID, il ne peut voir que les autres processus dans le même espace de noms. Il n'est pas conscient des processus dans d'autres espaces de noms, et il ne peut pas interagir avec eux en utilisant des outils de gestion de processus traditionnels (par exemple, `kill`, `wait`, etc.). Cela fournit un niveau d'isolation qui aide à empêcher les processus de s'interférer les uns avec les autres.

### Comment ça marche :

1. Lorsqu'un nouveau processus est créé (par exemple, en utilisant l'appel système `clone()`), le processus peut être affecté à un espace de noms PID nouveau ou existant. **Si un nouvel espace de noms est créé, le processus devient le processus "init" de cet espace de noms**.
2. Le **noyau** maintient une **correspondance entre les PID dans le nouvel espace de noms et les PID correspondants** dans l'espace de noms parent (c'est-à-dire l'espace de noms à partir duquel le nouvel espace de noms a été créé). Cette correspondance **permet au noyau de traduire les PID lorsque cela est nécessaire**, par exemple lors de l'envoi de signaux entre des processus dans différents espaces de noms.
3. **Les processus dans un espace de noms PID ne peuvent voir et interagir qu'avec les autres processus dans le même espace de noms**. Ils ne sont pas conscients des processus dans d'autres espaces de noms, et leurs PID sont uniques dans leur espace de noms.
4. Lorsqu'un **espace de noms PID est détruit** (par exemple, lorsque le processus "init" de l'espace de noms quitte), **tous les processus dans cet espace de noms sont terminés**. Cela garantit que toutes les ressources associées à l'espace de noms sont correctement nettoyées.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Erreur : bash: fork : Impossible d'allouer de la mémoire</summary>

Si vous exécutez la ligne précédente sans `-f`, vous obtiendrez cette erreur.\
L'erreur est causée par la sortie du processus PID 1 dans le nouveau namespace.

Après le démarrage de bash, celui-ci va créer plusieurs nouveaux sous-processus pour effectuer des actions. Si vous exécutez unshare sans -f, bash aura le même PID que le processus "unshare" actuel. Le processus "unshare" actuel appelle le système unshare, crée un nouveau namespace PID, mais le processus "unshare" actuel n'est pas dans le nouveau namespace PID. C'est le comportement souhaité du noyau Linux : le processus A crée un nouveau namespace, le processus A lui-même ne sera pas mis dans le nouveau namespace, seuls les sous-processus du processus A seront mis dans le nouveau namespace. Donc, lorsque vous exécutez :
```
unshare -p /bin/bash
```
Le processus unshare exécutera /bin/bash, et /bin/bash créera plusieurs sous-processus. Le premier sous-processus de bash deviendra le PID 1 du nouveau namespace, et le sous-processus se terminera après avoir terminé son travail. Ainsi, le PID 1 du nouveau namespace se termine.

Le processus PID 1 a une fonction spéciale : il doit devenir le processus parent de tous les processus orphelins. Si le processus PID 1 dans le namespace racine se termine, le noyau panique. Si le processus PID 1 dans un sous-namespace se termine, le noyau Linux appellera la fonction disable\_pid\_allocation, qui nettoiera le drapeau PIDNS\_HASH\_ADDING dans ce namespace. Lorsque le noyau Linux crée un nouveau processus, il appelle la fonction alloc\_pid pour allouer un PID dans un namespace, et si le drapeau PIDNS\_HASH\_ADDING n'est pas défini, la fonction alloc\_pid renverra une erreur -ENOMEM. C'est pourquoi vous obtenez l'erreur "Cannot allocate memory".

Vous pouvez résoudre ce problème en utilisant l'option '-f':
```
unshare -fp /bin/bash
```
Si vous exécutez unshare avec l'option '-f', unshare va créer un nouveau processus après avoir créé le nouveau namespace pid. Et exécuter /bin/bash dans le nouveau processus. Le nouveau processus sera le pid 1 du nouveau namespace pid. Ensuite, bash va également créer plusieurs sous-processus pour effectuer des tâches. Comme bash lui-même est le pid 1 du nouveau namespace pid, ses sous-processus peuvent se terminer sans aucun problème.

Copié depuis [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous vous assurez que le nouveau namespace de montage a une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Vérifier dans quel namespace se trouve votre processus
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
Lorsque vous entrez dans un espace de noms PID à partir de l'espace de noms par défaut, vous pourrez toujours voir tous les processus. Et le processus de cet espace de noms PID pourra voir le nouveau bash sur l'espace de noms PID.

De plus, vous ne pouvez **entrer dans un autre espace de noms de processus que si vous êtes root**. Et vous ne pouvez **pas entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/pid`).
