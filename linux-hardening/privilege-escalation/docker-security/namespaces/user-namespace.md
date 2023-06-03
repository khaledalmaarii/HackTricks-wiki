# Espace utilisateur

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Un espace utilisateur est une fonctionnalité du noyau Linux qui **fournit une isolation des mappages d'ID utilisateur et de groupe**, permettant à chaque espace utilisateur d'avoir son **propre ensemble d'ID utilisateur et de groupe**. Cette isolation permet aux processus s'exécutant dans différents espaces utilisateur d'avoir des **privilèges et une propriété différents**, même s'ils partagent les mêmes ID utilisateur et de groupe numériques.

Les espaces utilisateur sont particulièrement utiles dans la conteneurisation, où chaque conteneur doit avoir son propre ensemble indépendant d'ID utilisateur et de groupe, permettant une meilleure sécurité et une meilleure isolation entre les conteneurs et le système hôte.

### Comment ça marche :

1. Lorsqu'un nouvel espace utilisateur est créé, il **commence avec un ensemble vide de mappages d'ID utilisateur et de groupe**. Cela signifie que tout processus s'exécutant dans le nouvel espace utilisateur n'aura **initialement aucun privilège en dehors de l'espace utilisateur**.
2. Des mappages d'ID peuvent être établis entre les ID utilisateur et de groupe dans le nouvel espace et ceux dans l'espace parent (ou hôte). Cela **permet aux processus dans le nouvel espace d'avoir des privilèges et une propriété correspondant aux ID utilisateur et de groupe dans l'espace parent**. Cependant, les mappages d'ID peuvent être restreints à des plages et des sous-ensembles d'ID spécifiques, permettant un contrôle fin sur les privilèges accordés aux processus dans le nouvel espace.
3. Dans un espace utilisateur, **les processus peuvent avoir des privilèges root complets (UID 0) pour les opérations à l'intérieur de l'espace**, tout en ayant des privilèges limités à l'extérieur de l'espace. Cela permet aux **conteneurs de s'exécuter avec des capacités similaires à root dans leur propre espace sans avoir de privilèges root complets sur le système hôte**.
4. Les processus peuvent passer d'un espace à un autre en utilisant l'appel système `setns()` ou créer de nouveaux espaces en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWUSER`. Lorsqu'un processus passe à un nouvel espace ou en crée un, il commencera à utiliser les mappages d'ID utilisateur et de groupe associés à cet espace. 

## Laboratoire :

### Créer différents espaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
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
```
Pour utiliser l'espace de noms utilisateur, le démon Docker doit être démarré avec **`--userns-remap=default`** (Dans Ubuntu 14.04, cela peut être fait en modifiant `/etc/default/docker` puis en exécutant `sudo service docker restart`)

### &#x20;Vérifiez dans quel espace de noms se trouve votre processus
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Il est possible de vérifier la carte d'utilisateur du conteneur Docker avec:
```bash
cat /proc/self/uid_map 
         0          0 4294967295  --> Root is root in host
         0     231072      65536  --> Root is 231072 userid in host
```
Ou depuis l'hôte avec:
```bash
cat /proc/<pid>/uid_map 
```
### Trouver tous les espaces de noms utilisateur

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrer dans un espace de noms utilisateur
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Vous ne pouvez entrer dans un autre espace de processus que si vous êtes root. Et vous ne pouvez pas entrer dans un autre espace sans un descripteur pointant vers celui-ci (comme `/proc/self/ns/user`).

### Créer un nouvel espace de noms utilisateur (avec des mappages)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %} (This is a markdown tag and should not be translated)
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Récupération des capacités

Dans le cas des espaces de noms utilisateur, **lorsqu'un nouvel espace de noms utilisateur est créé, le processus qui entre dans l'espace de noms se voit accorder un ensemble complet de capacités dans cet espace de noms**. Ces capacités permettent au processus d'effectuer des opérations privilégiées telles que le **montage** de **systèmes de fichiers**, la création de périphériques ou la modification de la propriété des fichiers, mais **uniquement dans le contexte de son espace de noms utilisateur**.

Par exemple, lorsque vous avez la capacité `CAP_SYS_ADMIN` dans un espace de noms utilisateur, vous pouvez effectuer des opérations qui nécessitent généralement cette capacité, comme le montage de systèmes de fichiers, mais uniquement dans le contexte de votre espace de noms utilisateur. Toutes les opérations que vous effectuez avec cette capacité n'affecteront pas le système hôte ou les autres espaces de noms.

{% hint style="warning" %}
Par conséquent, même si l'obtention d'un nouveau processus à l'intérieur d'un nouvel espace de noms utilisateur **vous redonnera toutes les capacités** (CapEff: 000001ffffffffff), vous ne pouvez en réalité **utiliser que celles liées à l'espace de noms** (comme le montage) mais pas toutes. Ainsi, cela seul n'est pas suffisant pour s'échapper d'un conteneur Docker.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
