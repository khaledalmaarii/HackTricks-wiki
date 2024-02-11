# Seccomp

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

**Seccomp**, wat staan vir Secure Computing Mode, is 'n sekuriteitskenmerk van die **Linux-kernel wat ontwerp is om stelseloproepe te filtreer**. Dit beperk prosesse tot 'n beperkte stel stelseloproepe (`exit()`, `sigreturn()`, `read()` en `write()` vir reeds-geopen lêerbeskrywers). As 'n proses probeer om iets anders te roep, word dit deur die kernel beëindig deur gebruik te maak van SIGKILL of SIGSYS. Hierdie meganisme virtualiseer nie hulpbronne nie, maar isoleer die proses daarvan.

Daar is twee maniere om seccomp te aktiveer: deur die `prctl(2)` stelseloproep met `PR_SET_SECCOMP`, of vir Linux-kernel 3.17 en hoër, die `seccomp(2)` stelseloproep. Die ouer metode om seccomp te aktiveer deur na `/proc/self/seccomp` te skryf, is verouderd en is vervang deur `prctl()`.

'n Verbetering, **seccomp-bpf**, voeg die vermoë by om stelseloproepe te filtreer met 'n aanpasbare beleid deur gebruik te maak van Berkeley Packet Filter (BPF) reëls. Hierdie uitbreiding word benut deur sagteware soos OpenSSH, vsftpd, en die Chrome/Chromium-webblaaier op Chrome OS en Linux vir buigsame en doeltreffende stelseloproep-filtrering, as 'n alternatief vir die nou nie-ondersteunde systrace vir Linux.

### **Oorspronklike/Strikte Modus**

In hierdie modus laat Seccomp **slegs die stelseloproepe toe** `exit()`, `sigreturn()`, `read()` en `write()` na reeds-geopen lêerbeskrywers. As enige ander stelseloproep gemaak word, word die proses doodgemaak deur gebruik te maak van SIGKILL.

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

Hierdie modus maak dit moontlik om **sistemaanroepings te filter deur gebruik te maak van 'n konfigureerbare beleid** wat geïmplementeer word deur gebruik te maak van Berkeley Packet Filter reëls.

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

## Seccomp in Docker

**Seccomp-bpf** word deur **Docker** ondersteun om die **syscalls** van die houers te beperk en sodoende die oppervlakte te verminder. Jy kan die **syscalls wat standaard geblokkeer word** vind by [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) en die **standaard seccomp-profiel** kan hier gevind word [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Jy kan 'n docker-houer uitvoer met 'n **verskillende seccomp-beleid** met:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
As jy byvoorbeeld 'n houer wil **verbied** om sekere **syscall** soos `uname` uit te voer, kan jy die verstek profiel aflaai vanaf [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) en net die `uname` string uit die lys **verwyder**.\
As jy seker wil maak dat **'n sekere binêre lêer nie binne 'n Docker-houer werk nie**, kan jy strace gebruik om die syscalls wat die binêre lêer gebruik, te lys en dit dan verbied.\
In die volgende voorbeeld word die **syscalls** van `uname` ontdek:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
As jy **Docker net gebruik om 'n toepassing te begin**, kan jy dit **profiler** met **`strace`** en slegs die syscalls toelaat wat dit nodig het.
{% endhint %}

### Voorbeeld Seccomp-beleid

[Voorbeeld van hier](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Om die Seccomp-funksie te illustreer, skep ons 'n Seccomp-profiel wat die "chmod" stelseloproep deaktiveer soos hieronder.
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
In die bogenoemde profiel het ons die verstekaksie op "toelaat" gestel en 'n swartlys geskep om "chmod" te deaktiveer. Om meer veilig te wees, kan ons die verstekaksie op "afwerp" stel en 'n witlys skep om selektief stelseloproepe toe te laat.\
Die volgende uitset toon die "chmod" oproep wat 'n fout teruggee omdat dit gedeaktiveer is in die seccomp-profiel.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Die volgende uitset toon die "docker inspect" wat die profiel vertoon:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Deaktiveer dit in Docker

Begin 'n houer met die vlag: **`--security-opt seccomp=unconfined`**

Vanaf Kubernetes 1.19, is **seccomp standaard geaktiveer vir alle Pods**. Die verstek seccomp profiel wat op die Pods toegepas word, is die "**RuntimeDefault**" profiel, wat **voorsien word deur die houer runtime** (bv. Docker, containerd). Die "RuntimeDefault" profiel laat die meeste stelseloproepe toe terwyl dit 'n paar blokkeer wat as gevaarlik beskou word of nie algemeen deur houers benodig word nie.

<details>

<summary><strong>Leer AWS hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
