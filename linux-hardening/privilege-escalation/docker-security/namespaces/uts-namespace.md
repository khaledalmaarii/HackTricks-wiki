# Espace de noms UTS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Un espace de noms UTS (UNIX Time-Sharing System) est une fonctionnalité du noyau Linux qui fournit une **isolation de deux identificateurs système** : le **nom d'hôte** et le **domaine NIS** (Network Information Service). Cette isolation permet à chaque espace de noms UTS d'avoir son **propre nom d'hôte et domaine NIS indépendants**, ce qui est particulièrement utile dans les scénarios de conteneurisation où chaque conteneur doit apparaître comme un système séparé avec son propre nom d'hôte.

### Comment ça marche :

1. Lorsqu'un nouvel espace de noms UTS est créé, il démarre avec une **copie du nom d'hôte et du domaine NIS de son espace de noms parent**. Cela signifie qu'à la création, le nouvel espace de noms **partage les mêmes identificateurs que son parent**. Cependant, toute modification ultérieure du nom d'hôte ou du domaine NIS dans l'espace de noms n'affectera pas les autres espaces de noms.
2. Les processus dans un espace de noms UTS **peuvent changer le nom d'hôte et le domaine NIS** en utilisant les appels système `sethostname()` et `setdomainname()`, respectivement. Ces modifications sont locales à l'espace de noms et n'affectent pas les autres espaces de noms ou le système hôte.
3. Les processus peuvent passer d'un espace de noms à un autre en utilisant l'appel système `setns()` ou créer de nouveaux espaces de noms en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWUTS`. Lorsqu'un processus passe à un nouvel espace de noms ou en crée un, il commencera à utiliser le nom d'hôte et le domaine NIS associés à cet espace de noms.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
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
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Trouver tous les espaces de noms UTS

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrer dans un espace de noms UTS
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
### Changer le nom d'hôte

Il est possible de changer le nom d'hôte d'un conteneur Docker en modifiant le fichier `/proc/sys/kernel/hostname` à l'intérieur du conteneur. Cependant, cela ne changera pas le nom d'hôte de l'hôte réel.

Pour changer le nom d'hôte de l'hôte réel, vous devez modifier le fichier `/etc/hostname` et exécuter la commande `hostname` avec le nouveau nom d'hôte en tant qu'argument. Cela nécessite des privilèges root.
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
