# DDexec / EverythingExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Contexte

Sous Linux, pour exécuter un programme, il doit exister en tant que fichier, il doit être accessible d'une manière ou d'une autre via la hiérarchie du système de fichiers (c'est ainsi que `execve()` fonctionne). Ce fichier peut résider sur le disque ou en mémoire (tmpfs, memfd), mais vous avez besoin d'un chemin d'accès. Cela facilite grandement le contrôle de ce qui est exécuté sur un système Linux, cela facilite la détection des menaces et des outils des attaquants ou les empêche d'essayer d'exécuter quoi que ce soit de leur part (_par exemple_, en n'autorisant pas les utilisateurs non privilégiés à placer des fichiers exécutables n'importe où).

Mais cette technique est là pour changer tout cela. Si vous ne pouvez pas démarrer le processus que vous voulez... **alors vous détournez un processus déjà existant**.

Cette technique vous permet de contourner les techniques de protection courantes telles que la lecture seule, noexec, la liste blanche des noms de fichiers, la liste blanche des hachages...

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

Si vous êtes capable de modifier arbitrairement la mémoire d'un processus, vous pouvez le prendre en main. Cela peut être utilisé pour détourner un processus existant et le remplacer par un autre programme. Nous pouvons y parvenir en utilisant soit l'appel système `ptrace()` (qui nécessite la possibilité d'exécuter des appels système ou d'avoir gdb disponible sur le système), soit, de manière plus intéressante, en écrivant dans `/proc/$pid/mem`.

Le fichier `/proc/$pid/mem` est une correspondance un-à-un de l'espace d'adressage complet d'un processus (par exemple, de `0x0000000000000000` à `0x7ffffffffffff000` en x86-64). Cela signifie que la lecture ou l'écriture dans ce fichier à un décalage `x` revient à lire ou modifier le contenu à l'adresse virtuelle `x`.

Maintenant, nous devons faire face à quatre problèmes de base :

- En général, seul le superutilisateur et le propriétaire du programme peuvent le modifier.
- ASLR.
- Si nous essayons de lire ou d'écrire à une adresse non mappée dans l'espace d'adressage du programme, nous obtiendrons une erreur d'E/S.

Ces problèmes ont des solutions qui, bien qu'elles ne soient pas parfaites, sont bonnes :

- La plupart des interpréteurs de commandes permettent la création de descripteurs de fichiers qui seront ensuite hérités par les processus enfants. Nous pouvons créer un descripteur de fichier pointant vers le fichier `mem` de la coquille avec des permissions d'écriture... ainsi, les processus enfants qui utilisent ce descripteur de fichier pourront modifier la mémoire de la coquille.
- ASLR n'est même pas un problème, nous pouvons consulter le fichier `maps` de la coquille ou tout autre fichier du procfs afin d'obtenir des informations sur l'espace d'adressage du processus.
- Nous devons donc utiliser `lseek()` sur le fichier. Depuis la coquille, cela ne peut pas être fait sauf en utilisant le tristement célèbre `dd`.

### En détail

Les étapes sont relativement simples et ne nécessitent aucune expertise particulière pour les comprendre :

- Analyser le binaire que nous voulons exécuter et le chargeur pour savoir quelles correspondances ils nécessitent. Ensuite, créer un "shell"code qui effectuera, en gros, les mêmes étapes que le noyau lors de chaque appel à `execve()` :
- Créer lesdites correspondances.
- Lire les binaires dans ces correspondances.
- Configurer les permissions.
- Enfin, initialiser la pile avec les arguments du programme et placer le vecteur auxiliaire (nécessaire par le chargeur).
- Sauter dans le chargeur et le laisser faire le reste (charger les bibliothèques nécessaires au programme).
- Obtenir à partir du fichier `syscall` l'adresse vers laquelle le processus retournera après l'appel système qu'il exécute.
- Écraser cet emplacement, qui sera exécutable, avec notre shellcode (à travers `mem`, nous pouvons modifier les pages non inscriptibles).
- Passer le programme que nous voulons exécuter à l'entrée standard du processus (sera `lu()` par ledit "shell"code).
- À ce stade, il revient au chargeur de charger les bibliothèques nécessaires à notre programme et de sauter dedans.

**Consultez l'outil sur** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Au 12/12/2022, j'ai trouvé plusieurs alternatives à `dd`, dont l'une, `tail`, est actuellement le programme par défaut utilisé pour `lseek()` à travers le fichier `mem` (qui était le seul but d'utilisation de `dd`). Ces alternatives sont :
```bash
tail
hexdump
cmp
xxd
```
En définissant la variable `SEEKER`, vous pouvez changer le chercheur utilisé, par exemple:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Si vous trouvez un autre chercheur valide qui n'est pas implémenté dans le script, vous pouvez toujours l'utiliser en définissant la variable `SEEKER_ARGS` :
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloquez cela, EDRs.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PRs au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
