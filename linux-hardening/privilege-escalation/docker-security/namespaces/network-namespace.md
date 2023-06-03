## Espace de noms réseau

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Un espace de noms réseau est une fonctionnalité du noyau Linux qui permet l'isolation de la pile réseau, permettant à **chaque espace de noms réseau d'avoir sa propre configuration réseau indépendante**, interfaces, adresses IP, tables de routage et règles de pare-feu. Cette isolation est utile dans divers scénarios, tels que la conteneurisation, où chaque conteneur doit avoir sa propre configuration réseau, indépendante des autres conteneurs et du système hôte.

### Comment ça marche :

1. Lorsqu'un nouvel espace de noms réseau est créé, il démarre avec une **pile réseau complètement isolée**, sans **interfaces réseau** à l'exception de l'interface de bouclage (lo). Cela signifie que les processus s'exécutant dans le nouvel espace de noms réseau ne peuvent pas communiquer avec les processus dans d'autres espaces de noms ou le système hôte par défaut.
2. Des **interfaces réseau virtuelles**, telles que des paires veth, peuvent être créées et déplacées entre des espaces de noms réseau. Cela permet d'établir une connectivité réseau entre les espaces de noms ou entre un espace de noms et le système hôte. Par exemple, une extrémité d'une paire veth peut être placée dans l'espace de noms réseau d'un conteneur, et l'autre extrémité peut être connectée à un **pont** ou une autre interface réseau dans l'espace de noms hôte, fournissant une connectivité réseau au conteneur.
3. Les interfaces réseau au sein d'un espace de noms peuvent avoir leurs **propres adresses IP, tables de routage et règles de pare-feu**, indépendantes des autres espaces de noms. Cela permet aux processus dans différents espaces de noms réseau d'avoir des configurations réseau différentes et de fonctionner comme s'ils s'exécutaient sur des systèmes en réseau distincts.
4. Les processus peuvent se déplacer entre les espaces de noms en utilisant l'appel système `setns()`, ou créer de nouveaux espaces de noms en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWNET`. Lorsqu'un processus se déplace vers un nouvel espace de noms ou en crée un, il commencera à utiliser la configuration réseau et les interfaces associées à cet espace de noms.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
En montant une nouvelle instance du système de fichiers `/proc` en utilisant le paramètre `--mount-proc`, vous vous assurez que le nouveau namespace de montage a une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

<details>

<summary>Erreur : bash: fork: Cannot allocate memory</summary>

Si vous exécutez la ligne précédente sans `-f`, vous obtiendrez cette erreur.\
L'erreur est causée par la sortie du processus PID 1 dans le nouveau namespace.

Après le démarrage de bash, celui-ci va créer plusieurs nouveaux sous-processus pour effectuer des actions. Si vous exécutez unshare sans -f, bash aura le même PID que le processus "unshare" actuel. Le processus "unshare" actuel appelle le système d'appel unshare, crée un nouveau namespace PID, mais le processus "unshare" actuel n'est pas dans le nouveau namespace PID. C'est le comportement souhaité du noyau Linux : le processus A crée un nouveau namespace, le processus A lui-même ne sera pas mis dans le nouveau namespace, seuls les sous-processus du processus A seront mis dans le nouveau namespace. Ainsi, lorsque vous exécutez :
```
unshare -p /bin/bash
```
Le processus unshare exécutera /bin/bash, et /bin/bash créera plusieurs sous-processus, le premier sous-processus de bash deviendra le PID 1 du nouveau namespace, et le sous-processus se terminera après avoir terminé son travail. Ainsi, le PID 1 du nouveau namespace se termine.

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
# Run ifconfig or ip -a
```
### &#x20;Vérifier dans quel namespace se trouve votre processus
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
{% endcode %}

### Entrer dans un espace de noms réseau
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
De plus, vous ne pouvez **entrer dans un autre espace de noms de processus que si vous êtes root**. Et vous ne pouvez **pas entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/net`).
