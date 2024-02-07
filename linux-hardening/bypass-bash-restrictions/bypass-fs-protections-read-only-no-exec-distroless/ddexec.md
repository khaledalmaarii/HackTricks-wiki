# DDexec / EverythingExec

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Contexte

Sous Linux, pour exécuter un programme, il doit exister sous forme de fichier, être accessible d'une manière ou d'une autre à travers la hiérarchie du système de fichiers (c'est ainsi que `execve()` fonctionne). Ce fichier peut résider sur le disque ou en mémoire (tmpfs, memfd) mais vous avez besoin d'un chemin d'accès. Cela a rendu très facile le contrôle de ce qui est exécuté sur un système Linux, cela facilite la détection des menaces et des outils des attaquants ou les empêche de tenter d'exécuter quoi que ce soit de leur part (_par exemple_ en n'autorisant pas aux utilisateurs non privilégiés de placer des fichiers exécutables n'importe où).

Mais cette technique est là pour changer tout cela. Si vous ne pouvez pas démarrer le processus que vous voulez... **alors vous en détournez un déjà existant**.

Cette technique vous permet de **contourner des techniques de protection courantes telles que lecture seule, noexec, liste blanche de noms de fichiers, liste blanche de hachages...**

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

Si vous êtes capable de modifier arbitrairement la mémoire d'un processus, vous pouvez le prendre en main. Cela peut être utilisé pour détourner un processus existant et le remplacer par un autre programme. Nous pouvons y parvenir en utilisant soit l'appel système `ptrace()` (qui nécessite que vous ayez la capacité d'exécuter des appels système ou que gdb soit disponible sur le système), soit, de manière plus intéressante, en écrivant dans `/proc/$pid/mem`.

Le fichier `/proc/$pid/mem` est un mappage un à un de l'espace d'adressage complet d'un processus (par exemple, de `0x0000000000000000` à `0x7ffffffffffff000` en x86-64). Cela signifie que lire ou écrire dans ce fichier à un décalage `x` revient à lire ou modifier le contenu à l'adresse virtuelle `x`.

Maintenant, nous avons quatre problèmes de base à résoudre :

- En général, seul root et le propriétaire du programme du fichier peuvent le modifier.
- ASLR.
- Si nous essayons de lire ou d'écrire à une adresse non mappée dans l'espace d'adressage du programme, nous obtiendrons une erreur d'E/S.

Ces problèmes ont des solutions qui, bien qu'elles ne soient pas parfaites, sont bonnes :

- La plupart des interprètes de commandes permettent la création de descripteurs de fichiers qui seront ensuite hérités par les processus enfants. Nous pouvons créer un descripteur de fichier pointant vers le fichier `mem` de la console avec des autorisations d'écriture... donc les processus enfants qui utilisent ce descripteur pourront modifier la mémoire de la console.
- ASLR n'est même pas un problème, nous pouvons consulter le fichier `maps` de la console ou tout autre fichier de procfs pour obtenir des informations sur l'espace d'adressage du processus.
- Nous devons donc utiliser `lseek()` sur le fichier. Depuis la console, cela ne peut pas être fait sauf en utilisant le tristement célèbre `dd`.

### En détail

Les étapes sont relativement simples et ne nécessitent aucune expertise particulière pour les comprendre :

- Analyser le binaire que nous voulons exécuter et le chargeur pour savoir quels mappages ils nécessitent. Ensuite, concevoir un "shell"code qui effectuera, en gros, les mêmes étapes que le noyau lors de chaque appel à `execve()` :
- Créer lesdits mappages.
- Lire les binaires dans ces mappages.
- Configurer les autorisations.
- Enfin, initialiser la pile avec les arguments du programme et placer le vecteur auxiliaire (nécessaire par le chargeur).
- Sauter dans le chargeur et le laisser faire le reste (charger les bibliothèques nécessaires au programme).
- Obtenir à partir du fichier `syscall` l'adresse vers laquelle le processus retournera après l'appel système qu'il exécute.
- Écraser cet emplacement, qui sera exécutable, avec notre shellcode (à travers `mem` nous pouvons modifier des pages non inscriptibles).
- Passer le programme que nous voulons exécuter à l'entrée standard du processus (sera `lu()` par ledit "shell"code).
- À ce stade, il revient au chargeur de charger les bibliothèques nécessaires pour notre programme et de sauter dedans.

**Consultez l'outil sur** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Il existe plusieurs alternatives à `dd`, dont `tail`, qui est actuellement le programme par défaut utilisé pour `lseek()` à travers le fichier `mem` (qui était le seul but de l'utilisation de `dd`). Ces alternatives sont :
```bash
tail
hexdump
cmp
xxd
```
En définissant la variable `SEEKER`, vous pouvez changer le seeker utilisé, _par exemple_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Si vous trouvez un autre seeker valide non implémenté dans le script, vous pouvez toujours l'utiliser en définissant la variable `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloquez ceci, EDRs.

# Références
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
