# Espace de noms réseau

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

Un espace de noms réseau est une fonctionnalité du noyau Linux qui fournit l'isolation de la pile réseau, permettant **à chaque espace de noms réseau d'avoir sa propre configuration réseau indépendante**, interfaces, adresses IP, tables de routage et règles de pare-feu. Cette isolation est utile dans divers scénarios, tels que la conteneurisation, où chaque conteneur doit avoir sa propre configuration réseau, indépendante des autres conteneurs et du système hôte.

### Fonctionnement :

1. Lorsqu'un nouvel espace de noms réseau est créé, il commence avec une **pile réseau complètement isolée**, sans **aucune interface réseau** à l'exception de l'interface de bouclage (lo). Cela signifie que les processus s'exécutant dans le nouvel espace de noms réseau ne peuvent pas communiquer par défaut avec les processus dans d'autres espaces de noms ou le système hôte.
2. Des **interfaces réseau virtuelles**, telles que des paires veth, peuvent être créées et déplacées entre les espaces de noms réseau. Cela permet d'établir une connectivité réseau entre les espaces de noms ou entre un espace de noms et le système hôte. Par exemple, une extrémité d'une paire veth peut être placée dans l'espace de noms réseau d'un conteneur, et l'autre extrémité peut être connectée à un **pont** ou à une autre interface réseau dans l'espace de noms hôte, fournissant une connectivité réseau au conteneur.
3. Les interfaces réseau au sein d'un espace de noms peuvent avoir **leurs propres adresses IP, tables de routage et règles de pare-feu**, indépendamment des autres espaces de noms. Cela permet aux processus dans différents espaces de noms réseau d'avoir différentes configurations réseau et d'opérer comme s'ils étaient sur des systèmes en réseau séparés.
4. Les processus peuvent se déplacer entre les espaces de noms en utilisant l'appel système `setns()`, ou créer de nouveaux espaces de noms en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWNET`. Lorsqu'un processus se déplace vers un nouvel espace de noms ou en crée un, il commencera à utiliser la configuration réseau et les interfaces associées à cet espace de noms.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
En montant une nouvelle instance du système de fichiers `/proc` avec le paramètre `--mount-proc`, vous garantissez que le nouveau namespace de montage dispose d'une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

<details>

<summary>Erreur : bash: fork: Impossible d'allouer de la mémoire</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur est rencontrée en raison de la manière dont Linux gère les nouveaux namespaces PID (Process ID). Les détails clés et la solution sont décrits ci-dessous :

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
Vous pouvez également **entrer dans un autre espace de noms de processus uniquement si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/net`).

# Références
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
