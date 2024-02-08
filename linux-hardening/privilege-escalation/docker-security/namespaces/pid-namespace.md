# Espace de noms PID

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Informations de base

L'espace de noms PID (Process IDentifier) est une fonctionnalité du noyau Linux qui fournit une isolation des processus en permettant à un groupe de processus d'avoir son propre ensemble de PID uniques, séparés des PID dans d'autres espaces de noms. Cela est particulièrement utile dans la conteneurisation, où l'isolation des processus est essentielle pour la sécurité et la gestion des ressources.

Lorsqu'un nouvel espace de noms PID est créé, le premier processus de cet espace de noms se voit attribuer le PID 1. Ce processus devient le processus "init" du nouvel espace de noms et est responsable de la gestion des autres processus au sein de l'espace de noms. Chaque processus ultérieur créé dans l'espace de noms aura un PID unique dans cet espace de noms, et ces PID seront indépendants des PID dans d'autres espaces de noms.

Du point de vue d'un processus au sein d'un espace de noms PID, il ne peut voir que les autres processus dans le même espace de noms. Il n'est pas conscient des processus dans d'autres espaces de noms, et il ne peut pas interagir avec eux en utilisant des outils de gestion de processus traditionnels (par exemple, `kill`, `wait`, etc.). Cela offre un niveau d'isolation qui aide à empêcher les processus de perturber les uns les autres.

### Fonctionnement :

1. Lorsqu'un nouveau processus est créé (par exemple, en utilisant l'appel système `clone()`), le processus peut être affecté à un espace de noms PID nouveau ou existant. **Si un nouvel espace de noms est créé, le processus devient le processus "init" de cet espace de noms**.
2. Le **noyau** maintient une **correspondance entre les PIDs dans le nouvel espace de noms et les PIDs correspondants** dans l'espace de noms parent (c'est-à-dire l'espace de noms à partir duquel le nouvel espace de noms a été créé). Cette correspondance **permet au noyau de traduire les PIDs lorsque cela est nécessaire**, par exemple lors de l'envoi de signaux entre des processus dans des espaces de noms différents.
3. **Les processus au sein d'un espace de noms PID ne peuvent voir et interagir qu'avec d'autres processus dans le même espace de noms**. Ils ne sont pas conscients des processus dans d'autres espaces de noms, et leurs PIDs sont uniques dans leur espace de noms.
4. Lorsqu'un **espace de noms PID est détruit** (par exemple, lorsque le processus "init" de l'espace de noms se termine), **tous les processus au sein de cet espace de noms sont terminés**. Cela garantit que toutes les ressources associées à l'espace de noms sont correctement nettoyées.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Erreur : bash: fork: Impossible d'allouer de la mémoire</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur est rencontrée en raison de la manière dont Linux gère les nouveaux espaces de noms PID (Identifiant de Processus). Les détails clés et la solution sont décrits ci-dessous :

1. **Explication du Problème** :
- Le noyau Linux permet à un processus de créer de nouveaux espaces de noms en utilisant l'appel système `unshare`. Cependant, le processus qui initie la création d'un nouvel espace de noms PID (appelé le processus "unshare") n'entre pas dans le nouvel espace de noms ; seuls ses processus enfants le font.
- L'exécution de `%unshare -p /bin/bash%` démarre `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants se trouvent dans l'espace de noms PID d'origine.
- Le premier processus enfant de `/bin/bash` dans le nouvel espace de noms devient le PID 1. Lorsque ce processus se termine, il déclenche la suppression de l'espace de noms s'il n'y a pas d'autres processus, car le PID 1 a le rôle spécial d'adopter les processus orphelins. Le noyau Linux désactive alors l'allocation de PID dans cet espace de noms.

2. **Conséquence** :
- La sortie du PID 1 dans un nouvel espace de noms entraîne le nettoyage du drapeau `PIDNS_HASH_ADDING`. Cela provoque l'échec de la fonction `alloc_pid` pour allouer un nouveau PID lors de la création d'un nouveau processus, produisant l'erreur "Impossible d'allouer de la mémoire".

3. **Solution** :
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option fait que `unshare` fork un nouveau processus après la création du nouvel espace de noms PID.
- L'exécution de `%unshare -fp /bin/bash%` garantit que la commande `unshare` elle-même devient le PID 1 dans le nouvel espace de noms. `/bin/bash` et ses processus enfants sont alors en toute sécurité contenus dans ce nouvel espace de noms, empêchant la sortie prématurée du PID 1 et permettant une allocation normale des PID.

En veillant à ce que `unshare` s'exécute avec le drapeau `-f`, le nouvel espace de noms PID est correctement maintenu, permettant à `/bin/bash` et à ses sous-processus de fonctionner sans rencontrer l'erreur d'allocation de mémoire.

</details>

En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous vous assurez que le nouvel espace de noms de montage a une **vue précise et isolée des informations de processus spécifiques à cet espace de noms**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Vérifier dans quel espace de noms se trouve votre processus
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

Notez que l'utilisateur root de l'espace de noms PID initial (par défaut) peut voir tous les processus, même ceux des nouveaux espaces de noms PID, c'est pourquoi nous pouvons voir tous les espaces de noms PID.

### Entrer dans un espace de noms PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Lorsque vous entrez dans un espace de noms PID à partir de l'espace de noms par défaut, vous pourrez toujours voir tous les processus. Et le processus de cet espace de noms PID pourra voir le nouveau bash sur l'espace de noms PID.

De plus, vous ne pouvez **entrer dans un autre espace de noms de processus que si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/pid`)

## Références
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
