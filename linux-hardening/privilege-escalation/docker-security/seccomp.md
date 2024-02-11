# Seccomp

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

**Seccomp**, inayosimama kwa Secure Computing mode, ni kipengele cha usalama cha **kernel ya Linux kilichoundwa kufanya uchujaji wa wito wa mfumo**. Inazuia michakato kwa seti ndogo ya wito wa mfumo (`exit()`, `sigreturn()`, `read()`, na `write()`) kwa file descriptors zilizofunguliwa tayari. Ikiwa mchakato unajaribu kuita kitu kingine chochote, unakomeshwa na kernel kwa kutumia SIGKILL au SIGSYS. Mfumo huu haufanyi upya rasilimali lakini unaisolate michakato kutoka kwazo.

Kuna njia mbili za kuwezesha seccomp: kupitia wito wa mfumo wa `prctl(2)` na `PR_SET_SECCOMP`, au kwa kernel za Linux 3.17 na zaidi, wito wa mfumo wa `seccomp(2)`. Njia ya zamani ya kuwezesha seccomp kwa kuandika kwenye `/proc/self/seccomp` imepitwa na wakati na badala yake kutumia `prctl()`.

Kuboresha, **seccomp-bpf**, inaongeza uwezo wa kuchuja wito wa mfumo kwa kutumia sera inayoweza kubadilishwa, kwa kutumia sheria za Berkeley Packet Filter (BPF). Programu kama OpenSSH, vsftpd, na vivinjari vya Chrome/Chromium kwenye Chrome OS na Linux hutumia kipengele hiki cha kuchuja wito wa mfumo kwa njia inayoweza kubadilika na yenye ufanisi, kutoa mbadala kwa systrace ambayo sasa haipatikani tena kwa Linux.

### **Njia ya Asili/Inayodhibitiwa**

Katika hali hii, Seccomp **inaruhusu tu wito wa mfumo** `exit()`, `sigreturn()`, `read()` na `write()` kwa file descriptors zilizofunguliwa tayari. Ikiwa wito wa mfumo mwingine wowote unafanywa, mchakato unauawa kwa kutumia SIGKILL.

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

Hii hali inaruhusu **uchujaji wa wito wa mfumo kwa kutumia sera inayoweza kusanidiwa** iliyotekelezwa kwa kutumia sheria za Berkeley Packet Filter.

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

## Seccomp katika Docker

**Seccomp-bpf** inasaidiwa na **Docker** ili kuzuia **syscalls** kutoka kwenye kontena na kupunguza eneo la hatari kwa ufanisi. Unaweza kupata **syscalls zilizozuiliwa** kwa **chaguo-msingi** katika [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) na **seccomp profile ya chaguo-msingi** inaweza kupatikana hapa [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Unaweza kuendesha kontena ya docker na sera ya **seccomp tofauti** na:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Ikiwa unataka, kwa mfano, **kuzuia** chombo cha kutekeleza baadhi ya **syscall** kama vile `uname` unaweza kupakua maelezo ya msingi kutoka [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) na tu **ondoa neno `uname` kutoka orodha**.\
Ikiwa unataka kuhakikisha kwamba **baadhi ya faili za binary hazifanyi kazi ndani ya kontena ya docker** unaweza kutumia strace kuorodhesha syscalls ambazo faili ya binary inatumia na kisha kuzizuia.\
Katika mfano ufuatao, **syscalls** za `uname` zinagunduliwa:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Ikiwa unatumia **Docker tu kuendesha programu**, unaweza **kuipima** na **`strace`** na **ruhusu tu syscalls** inayohitaji
{% endhint %}

### Mfano wa sera ya Seccomp

[Mfano kutoka hapa](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Ili kuelezea kipengele cha Seccomp, hebu tujenge maelezo ya Seccomp yanayozuia wito wa mfumo wa "chmod" kama ifuatavyo.
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
Katika wasifu uliopita, tumeweka hatua ya msingi kuwa "ruhusu" na tumeunda orodha nyeusi ya kuzima "chmod". Ili kuwa salama zaidi, tunaweza kuweka hatua ya msingi kuwa "ondoa" na kuunda orodha nyeupe ya kuwezesha wito wa mfumo kwa uchaguzi.\
Matokeo yanayofuata yanaweka wito wa "chmod" ukirudi kosa kwa sababu umewezeshwa katika wasifu wa seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Matokeo yafuatayo yanaweka wazi "docker inspect" yanayoonyesha maelezo ya wasifu:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Kuzima katika Docker

Zindua chombo na bendera: **`--security-opt seccomp=unconfined`**

Kuanzia Kubernetes 1.19, **seccomp imeamilishwa kwa chaguo-msingi kwa Pods zote**. Walakini, maelezo ya seccomp ya chaguo-msingi yanayotumiwa kwa Pods ni maelezo ya "**RuntimeDefault**", ambayo **hutolewa na runtime ya chombo** (k.m., Docker, containerd). Maelezo ya "RuntimeDefault" inaruhusu wito wa mfumo wengi wakati inazuia wachache ambao wanachukuliwa kuwa hatari au kwa ujumla sio lazima kwa vyombo.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
