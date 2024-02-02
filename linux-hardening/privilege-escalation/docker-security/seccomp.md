# Seccomp

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

**Seccomp** ou mode de calcul sécurisé, en résumé, est une fonctionnalité du noyau Linux qui peut agir comme **filtre de syscall**.\
Seccomp a 2 modes.

**seccomp** (abréviation de **mode de calcul sécurisé**) est une facilité de sécurité informatique dans le **noyau Linux**. seccomp permet à un processus de faire une transition à sens unique vers un état "sécurisé" où **il ne peut effectuer aucun appel système sauf** `exit()`, `sigreturn()`, `read()` et `write()` vers des descripteurs de fichiers **déjà ouverts**. S'il tente tout autre appel système, le **noyau** **terminera** le **processus** avec SIGKILL ou SIGSYS. En ce sens, il ne virtualise pas les ressources du système mais isole complètement le processus de celles-ci.

Le mode seccomp est **activé via l'appel système `prctl(2)`** en utilisant l'argument `PR_SET_SECCOMP`, ou (depuis le noyau Linux 3.17) via l'appel système `seccomp(2)`. Le mode seccomp était auparavant activé en écrivant dans un fichier, `/proc/self/seccomp`, mais cette méthode a été supprimée au profit de `prctl()`. Dans certaines versions du noyau, seccomp désactive l'instruction x86 `RDTSC`, qui retourne le nombre de cycles de processeur écoulés depuis la mise sous tension, utilisée pour un chronométrage de haute précision.

**seccomp-bpf** est une extension de seccomp qui permet **le filtrage des appels système à l'aide d'une politique configurable** mise en œuvre à l'aide de règles de Berkeley Packet Filter. Il est utilisé par OpenSSH et vsftpd ainsi que par les navigateurs web Google Chrome/Chromium sur Chrome OS et Linux. (À cet égard, seccomp-bpf atteint une fonctionnalité similaire, mais avec plus de flexibilité et de meilleures performances, à l'ancien systrace—qui semble ne plus être pris en charge pour Linux.)

### **Mode Original/Strict**

Dans ce mode, Seccomp **n'autorise que les syscalls** `exit()`, `sigreturn()`, `read()` et `write()` vers des descripteurs de fichiers déjà ouverts. Si tout autre syscall est effectué, le processus est tué en utilisant SIGKILL

{% code title="seccomp_strict.c" %}
```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
{% endcode %}

### Seccomp-bpf

Ce mode permet **le filtrage des appels système en utilisant une politique configurable** mise en œuvre à l'aide des règles de Berkeley Packet Filter.

{% code title="seccomp_bpf.c" %}
```c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
{% endcode %}

## Seccomp dans Docker

**Seccomp-bpf** est pris en charge par **Docker** pour restreindre les **appels système** depuis les conteneurs, réduisant ainsi efficacement la surface d'attaque. Vous pouvez trouver les **appels système bloqués** par **défaut** sur [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) et le **profil seccomp par défaut** peut être trouvé ici [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Vous pouvez exécuter un conteneur docker avec une politique **seccomp différente** avec :
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Si vous souhaitez par exemple **interdire** à un conteneur d'exécuter certains **appels système** comme `uname`, vous pourriez télécharger le profil par défaut depuis [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) et simplement **retirer la chaîne `uname` de la liste**.\
Si vous voulez vous assurer qu'**un binaire ne fonctionne pas à l'intérieur d'un conteneur docker**, vous pourriez utiliser strace pour lister les appels système utilisés par le binaire, puis les interdire.\
Dans l'exemple suivant, les **appels système** de `uname` sont découverts :
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Si vous utilisez **Docker juste pour lancer une application**, vous pouvez la **profiler** avec **`strace`** et **autoriser uniquement les appels système** dont elle a besoin.
{% endhint %}

### Exemple de politique Seccomp

Pour illustrer la fonctionnalité Seccomp, créons un profil Seccomp qui désactive l'appel système "chmod" comme ci-dessous.
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Dans le profil ci-dessus, nous avons défini l'action par défaut sur "allow" et créé une liste noire pour désactiver "chmod". Pour plus de sécurité, nous pouvons définir l'action par défaut sur "drop" et créer une liste blanche pour activer sélectivement les appels système.
La sortie suivante montre l'appel "chmod" renvoyant une erreur car il est désactivé dans le profil seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
La sortie suivante montre la commande "docker inspect" affichant le profil :
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Désactiver dans Docker

Lancez un conteneur avec le drapeau : **`--security-opt seccomp=unconfined`**

À partir de Kubernetes 1.19, **seccomp est activé par défaut pour tous les Pods**. Cependant, le profil seccomp par défaut appliqué aux Pods est le profil "**RuntimeDefault**", qui est **fourni par le runtime de conteneur** (par exemple, Docker, containerd). Le profil "RuntimeDefault" autorise la plupart des appels système tout en bloquant quelques-uns qui sont considérés comme dangereux ou généralement non requis par les conteneurs.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
