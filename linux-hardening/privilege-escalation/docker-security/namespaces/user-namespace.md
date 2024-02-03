# Espace de noms utilisateur

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

Un espace de noms utilisateur est une fonctionnalité du noyau Linux qui **fournit l'isolation des mappages d'ID d'utilisateur et de groupe**, permettant à chaque espace de noms utilisateur d'avoir son **propre ensemble d'ID d'utilisateur et de groupe**. Cette isolation permet aux processus s'exécutant dans différents espaces de noms utilisateur d'**avoir différents privilèges et propriétés**, même s'ils partagent les mêmes ID d'utilisateur et de groupe numériquement.

Les espaces de noms utilisateur sont particulièrement utiles dans la conteneurisation, où chaque conteneur doit avoir son propre ensemble indépendant d'ID d'utilisateur et de groupe, permettant une meilleure sécurité et isolation entre les conteneurs et le système hôte.

### Comment ça fonctionne :

1. Lorsqu'un nouvel espace de noms utilisateur est créé, il **commence avec un ensemble vide de mappages d'ID d'utilisateur et de groupe**. Cela signifie que tout processus s'exécutant dans le nouvel espace de noms utilisateur **n'aura initialement aucun privilège à l'extérieur de l'espace de noms**.
2. Des mappages d'ID peuvent être établis entre les ID d'utilisateur et de groupe dans le nouvel espace de noms et ceux dans l'espace de noms parent (ou hôte). Cela **permet aux processus dans le nouvel espace de noms d'avoir des privilèges et une propriété correspondant aux ID d'utilisateur et de groupe dans l'espace de noms parent**. Cependant, les mappages d'ID peuvent être restreints à des plages et des sous-ensembles d'ID spécifiques, permettant un contrôle précis sur les privilèges accordés aux processus dans le nouvel espace de noms.
3. Au sein d'un espace de noms utilisateur, **les processus peuvent avoir des privilèges de root complets (UID 0) pour les opérations à l'intérieur de l'espace de noms**, tout en ayant des privilèges limités à l'extérieur de l'espace de noms. Cela permet **aux conteneurs de fonctionner avec des capacités similaires à root au sein de leur propre espace de noms sans avoir des privilèges de root complets sur le système hôte**.
4. Les processus peuvent se déplacer entre les espaces de noms en utilisant l'appel système `setns()` ou créer de nouveaux espaces de noms en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWUSER`. Lorsqu'un processus se déplace vers un nouvel espace de noms ou en crée un, il commencera à utiliser les mappages d'ID d'utilisateur et de groupe associés à cet espace de noms.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
En montant une nouvelle instance du système de fichiers `/proc` avec le paramètre `--mount-proc`, vous garantissez que le nouveau namespace de montage dispose d'une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

<details>

<summary>Erreur : bash: fork: Impossible d'allouer de la mémoire</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur se produit en raison de la manière dont Linux gère les nouveaux namespaces PID (Process ID). Les détails clés et la solution sont décrits ci-dessous :

1. **Explication du problème** :
- Le noyau Linux permet à un processus de créer de nouveaux namespaces en utilisant l'appel système `unshare`. Cependant, le processus qui initie la création d'un nouveau namespace PID (appelé processus "unshare") n'entre pas dans le nouveau namespace ; seuls ses processus enfants le font.
- Exécuter `%unshare -p /bin/bash%` démarre `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants sont dans le namespace PID original.
- Le premier processus enfant de `/bin/bash` dans le nouveau namespace devient PID 1. Lorsque ce processus se termine, il déclenche le nettoyage du namespace s'il n'y a pas d'autres processus, car le PID 1 a le rôle spécial d'adopter les processus orphelins. Le noyau Linux désactivera alors l'allocation de PID dans ce namespace.

2. **Conséquence** :
- La sortie du PID 1 dans un nouveau namespace entraîne le nettoyage du drapeau `PIDNS_HASH_ADDING`. Cela a pour résultat que la fonction `alloc_pid` échoue à allouer un nouveau PID lors de la création d'un nouveau processus, produisant l'erreur "Impossible d'allouer de la mémoire".

3. **Solution** :
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option fait en sorte que `unshare` fork un nouveau processus après avoir créé le nouveau namespace PID.
- Exécuter `%unshare -fp /bin/bash%` garantit que la commande `unshare` elle-même devient PID 1 dans le nouveau namespace. `/bin/bash` et ses processus enfants sont alors correctement contenus dans ce nouveau namespace, empêchant la sortie prématurée du PID 1 et permettant une allocation normale des PID.

En s'assurant que `unshare` est exécuté avec le drapeau `-f`, le nouveau namespace PID est correctement maintenu, permettant à `/bin/bash` et à ses sous-processus de fonctionner sans rencontrer l'erreur d'allocation de mémoire.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Pour utiliser l'espace de noms utilisateur, le démon Docker doit être démarré avec **`--userns-remap=default`** (Sous Ubuntu 14.04, cela peut être fait en modifiant `/etc/default/docker` puis en exécutant `sudo service docker restart`)

### &#x20;Vérifiez dans quel espace de noms se trouve votre processus
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Il est possible de vérifier la correspondance des utilisateurs depuis le conteneur Docker avec :
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ou depuis l'hôte avec :
```bash
cat /proc/<pid>/uid_map
```
### Trouver tous les espaces de noms d'utilisateur

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrer dans un espace de noms utilisateur
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Aussi, vous pouvez seulement **entrer dans un autre espace de noms de processus si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/user`).

### Créer un nouvel espace de noms Utilisateur (avec des mappages)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Récupération des capacités

Dans le cas des espaces de noms utilisateur, **lorsqu'un nouvel espace de noms utilisateur est créé, le processus qui entre dans l'espace de noms se voit accorder un ensemble complet de capacités au sein de cet espace de noms**. Ces capacités permettent au processus d'effectuer des opérations privilégiées telles que **le montage** de **systèmes de fichiers**, la création de périphériques ou la modification de la propriété des fichiers, mais **uniquement dans le contexte de son espace de noms utilisateur**.

Par exemple, lorsque vous disposez de la capacité `CAP_SYS_ADMIN` au sein d'un espace de noms utilisateur, vous pouvez effectuer des opérations qui nécessitent généralement cette capacité, comme le montage de systèmes de fichiers, mais uniquement dans le contexte de votre espace de noms utilisateur. Toutes les opérations que vous effectuez avec cette capacité n'affecteront pas le système hôte ou d'autres espaces de noms.

{% hint style="warning" %}
Par conséquent, même si obtenir un nouveau processus à l'intérieur d'un nouvel espace de noms utilisateur **vous redonne toutes les capacités** (CapEff: 000001ffffffffff), vous pouvez en réalité **utiliser uniquement celles liées à l'espace de noms** (le montage par exemple) mais pas toutes. Ainsi, cela seul n'est pas suffisant pour s'échapper d'un conteneur Docker.
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
# Références
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
