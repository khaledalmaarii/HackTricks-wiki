# DDexec / EverythingExec

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Contexte

Sous Linux, pour exécuter un programme, il doit exister sous forme de fichier, il doit être accessible d'une manière ou d'une autre à travers la hiérarchie du système de fichiers (c'est juste le fonctionnement de `execve()`). Ce fichier peut résider sur le disque ou en ram (tmpfs, memfd) mais vous avez besoin d'un chemin de fichier. Cela a rendu très facile de contrôler ce qui est exécuté sur un système Linux, cela facilite la détection des menaces et des outils des attaquants ou de les empêcher d'essayer d'exécuter quoi que ce soit de leur part (par exemple, ne pas permettre aux utilisateurs non privilégiés de placer des fichiers exécutables n'importe où).

Mais cette technique est là pour changer tout cela. Si vous ne pouvez pas démarrer le processus que vous voulez... **alors vous détournez un processus déjà existant**.

Cette technique vous permet de **contourner les techniques de protection communes telles que lecture seule, noexec, liste blanche de noms de fichiers, liste blanche de hachages...**

## Dépendances

Le script final dépend des outils suivants pour fonctionner, ils doivent être accessibles dans le système que vous attaquez (par défaut, vous les trouverez partout) :
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## La technique

Si vous êtes capable de modifier arbitrairement la mémoire d'un processus, alors vous pouvez le prendre en charge. Cela peut être utilisé pour détourner un processus déjà existant et le remplacer par un autre programme. Nous pouvons y parvenir soit en utilisant l'appel système `ptrace()` (qui nécessite que vous ayez la capacité d'exécuter des appels système ou que gdb soit disponible sur le système), soit, de manière plus intéressante, en écrivant dans `/proc/$pid/mem`.

Le fichier `/proc/$pid/mem` est une correspondance un à un de l'espace d'adressage entier d'un processus (_par exemple_ de `0x0000000000000000` à `0x7ffffffffffff000` en x86-64). Cela signifie que lire ou écrire dans ce fichier à un décalage `x` revient à lire ou à modifier le contenu à l'adresse virtuelle `x`.

Maintenant, nous avons quatre problèmes de base à affronter :

* En général, seuls le root et le propriétaire du programme du fichier peuvent le modifier.
* ASLR.
* Si nous essayons de lire ou d'écrire à une adresse non mappée dans l'espace d'adressage du programme, nous obtiendrons une erreur d'E/S.

Ces problèmes ont des solutions qui, bien qu'elles ne soient pas parfaites, sont bonnes :

* La plupart des interpréteurs de commandes permettent la création de descripteurs de fichiers qui seront ensuite hérités par les processus enfants. Nous pouvons créer un fd pointant vers le fichier `mem` du shell avec des permissions d'écriture... ainsi les processus enfants qui utilisent ce fd pourront modifier la mémoire du shell.
* ASLR n'est même pas un problème, nous pouvons vérifier le fichier `maps` du shell ou tout autre du procfs afin d'obtenir des informations sur l'espace d'adressage du processus.
* Donc, nous devons utiliser `lseek()` sur le fichier. Depuis le shell, cela ne peut pas être fait à moins d'utiliser le fameux `dd`.

### Plus en détail

Les étapes sont relativement faciles et ne nécessitent aucune sorte d'expertise pour les comprendre :

* Analyser le binaire que nous voulons exécuter et le chargeur pour découvrir quelles cartographies ils nécessitent. Ensuite, créer un "shellcode" qui effectuera, en gros, les mêmes étapes que le noyau lors de chaque appel à `execve()` :
* Créer les cartographies mentionnées.
* Lire les binaires dans celles-ci.
* Configurer les permissions.
* Finalement initialiser la pile avec les arguments pour le programme et placer le vecteur auxiliaire (nécessaire par le chargeur).
* Sauter dans le chargeur et le laisser faire le reste (charger les bibliothèques nécessaires au programme).
* Obtenir du fichier `syscall` l'adresse à laquelle le processus retournera après l'appel système qu'il est en train d'exécuter.
* Écraser cet endroit, qui sera exécutable, avec notre shellcode (à travers `mem` nous pouvons modifier des pages non inscriptibles).
* Passer le programme que nous voulons exécuter à l'entrée standard du processus (sera `read()` par ledit "shellcode").
* À ce stade, c'est au chargeur de charger les bibliothèques nécessaires pour notre programme et de sauter dedans.

**Consultez l'outil sur** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Au 12/12/2022, j'ai trouvé un certain nombre d'alternatives à `dd`, dont l'une, `tail`, est actuellement le programme par défaut utilisé pour `lseek()` à travers le fichier `mem` (qui était le seul but de l'utilisation de `dd`). Les alternatives sont :
```bash
tail
hexdump
cmp
xxd
```
Définissant la variable `SEEKER`, vous pouvez changer le chercheur utilisé, _par exemple_ :
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Si vous trouvez un autre chercheur valide non implémenté dans le script, vous pouvez toujours l'utiliser en définissant la variable `SEEKER_ARGS` :
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloquez cela, EDRs.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
