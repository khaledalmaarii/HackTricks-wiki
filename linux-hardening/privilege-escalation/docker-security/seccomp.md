## Seccomp

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

**Seccomp** ou Secure Computing mode, en résumé, est une fonctionnalité du noyau Linux qui peut agir comme un **filtre syscall**.\
Seccomp a 2 modes.

**seccomp** (abréviation de **mode de calcul sécurisé**) est une fonctionnalité de sécurité informatique dans le **noyau Linux**. seccomp permet à un processus de passer dans un état "sécurisé" où **il ne peut pas effectuer d'appels système sauf** `exit()`, `sigreturn()`, `read()` et `write()` à des descripteurs de fichiers **déjà ouverts**. S'il tente d'effectuer d'autres appels système, le **noyau** **terminera** le **processus** avec SIGKILL ou SIGSYS. En ce sens, il ne virtualise pas les ressources du système mais isole complètement le processus de celles-ci.

Le mode seccomp est **activé via l'appel système `prctl(2)`** en utilisant l'argument `PR_SET_SECCOMP`, ou (depuis le noyau Linux 3.17) via l'appel système `seccomp(2)`. Le mode seccomp était activé en écrivant dans un fichier, `/proc/self/seccomp`, mais cette méthode a été supprimée en faveur de `prctl()`. Dans certaines versions du noyau, seccomp désactive l'instruction x86 `RDTSC`, qui renvoie le nombre de cycles de processeur écoulés depuis la mise sous tension, utilisée pour la synchronisation de haute précision.

**seccomp-bpf** est une extension de seccomp qui permet **le filtrage des appels système à l'aide d'une politique configurable** implémentée à l'aide de règles Berkeley Packet Filter. Il est utilisé par OpenSSH et vsftpd ainsi que par les navigateurs Web Google Chrome/Chromium sur Chrome OS et Linux. (À cet égard, seccomp-bpf atteint une fonctionnalité similaire, mais avec plus de flexibilité et de meilleures performances, à l'ancien systrace - qui semble ne plus être pris en charge pour Linux.)

### **Mode original/strict**

Dans ce mode, Seccomp **ne permet que les appels système** `exit()`, `sigreturn()`, `read()` et `write()` aux descripteurs de fichiers déjà ouverts. Si un autre appel système est effectué, le processus est tué en utilisant SIGKILL.

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

Ce mode permet de filtrer les appels système à l'aide d'une politique configurable implémentée à l'aide de règles Berkeley Packet Filter. 

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

**Seccomp-bpf** est pris en charge par **Docker** pour restreindre les **appels système** des conteneurs, réduisant ainsi efficacement la surface d'attaque. Vous pouvez trouver les **appels système bloqués** par **défaut** dans [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) et le **profil seccomp par défaut** peut être trouvé ici [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Vous pouvez exécuter un conteneur Docker avec une **politique seccomp différente** avec:
```bash
docker run --rm \
             -it \
             --security-opt seccomp=/path/to/seccomp/profile.json \
             hello-world
```
Si vous voulez par exemple **interdire** à un conteneur d'exécuter certains **appels système** tels que `uname`, vous pouvez télécharger le profil par défaut depuis [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) et simplement **supprimer la chaîne `uname` de la liste**.\
Si vous voulez vous assurer qu'**un binaire ne fonctionne pas à l'intérieur d'un conteneur Docker**, vous pouvez utiliser strace pour lister les appels système utilisés par le binaire, puis les interdire.\
Dans l'exemple suivant, les **appels système** de `uname` sont découverts:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Si vous utilisez **Docker uniquement pour lancer une application**, vous pouvez **le profiler** avec **`strace`** et **autoriser uniquement les appels système** dont il a besoin.
{% endhint %}

### Exemple de politique Seccomp

Pour illustrer la fonctionnalité Seccomp, créons un profil Seccomp désactivant l'appel système "chmod" comme ci-dessous.
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
Dans le profil ci-dessus, nous avons défini l'action par défaut sur "autoriser" et créé une liste noire pour désactiver "chmod". Pour être plus sûr, nous pouvons définir l'action par défaut sur "refuser" et créer une liste blanche pour activer sélectivement les appels système.\
La sortie suivante montre l'appel "chmod" renvoyant une erreur car il est désactivé dans le profil seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Le résultat suivant montre la commande "docker inspect" affichant le profil :
```json
           "SecurityOpt": [
                "seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
            ],
```
### Désactivation dans Docker

Lancez un conteneur avec le flag: **`--security-opt seccomp=unconfined`**

À partir de Kubernetes 1.19, **seccomp est activé par défaut pour tous les Pods**. Cependant, le profil seccomp par défaut appliqué aux Pods est le profil "**RuntimeDefault**", qui est **fourni par le runtime de conteneurs** (par exemple, Docker, containerd). Le profil "RuntimeDefault" permet la plupart des appels système tout en bloquant quelques-uns considérés comme dangereux ou non généralement requis par les conteneurs.
