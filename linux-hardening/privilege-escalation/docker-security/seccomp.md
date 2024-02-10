# Seccomp

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di base

**Seccomp**, che sta per Secure Computing mode, è una funzionalità di sicurezza del **kernel Linux progettata per filtrare le chiamate di sistema**. Limita i processi a un insieme limitato di chiamate di sistema (`exit()`, `sigreturn()`, `read()` e `write()` per i descrittori di file già aperti). Se un processo tenta di chiamare qualsiasi altra cosa, viene terminato dal kernel utilizzando SIGKILL o SIGSYS. Questo meccanismo non virtualizza le risorse ma isola il processo da esse.

Ci sono due modi per attivare seccomp: tramite la chiamata di sistema `prctl(2)` con `PR_SET_SECCOMP`, o per i kernel Linux 3.17 e successivi, la chiamata di sistema `seccomp(2)`. Il vecchio metodo di abilitazione di seccomp scrivendo su `/proc/self/seccomp` è stato deprecato a favore di `prctl()`.

Un miglioramento, **seccomp-bpf**, aggiunge la capacità di filtrare le chiamate di sistema con una policy personalizzabile, utilizzando regole Berkeley Packet Filter (BPF). Questa estensione viene sfruttata da software come OpenSSH, vsftpd e i browser Chrome/Chromium su Chrome OS e Linux per il filtraggio delle chiamate di sistema flessibile ed efficiente, offrendo un'alternativa alla ormai non supportata systrace per Linux.

### **Modalità originale/strict**

In questa modalità Seccomp **permette solo le chiamate di sistema** `exit()`, `sigreturn()`, `read()` e `write()` ai descrittori di file già aperti. Se viene effettuata qualsiasi altra chiamata di sistema, il processo viene terminato utilizzando SIGKILL.

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
### Seccomp-bpf

Questa modalità consente il **filtraggio delle chiamate di sistema utilizzando una policy configurabile** implementata tramite regole Berkeley Packet Filter.

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

**Seccomp-bpf** è supportato da **Docker** per limitare le **syscalls** dai container, riducendo efficacemente l'area di superficie. Puoi trovare le **syscalls bloccate** di **default** su [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) e il **profilo seccomp di default** può essere trovato qui [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Puoi eseguire un container Docker con una **politica seccomp diversa** usando:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Se vuoi ad esempio **proibire** a un container di eseguire alcune **syscall** come `uname`, puoi scaricare il profilo predefinito da [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) e semplicemente **rimuovere la stringa `uname` dalla lista**.\
Se vuoi assicurarti che **un determinato binario non funzioni all'interno di un container Docker**, puoi utilizzare strace per elencare le syscall utilizzate dal binario e poi proibirle.\
Nell'esempio seguente vengono scoperte le **syscall** di `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Se stai usando **Docker solo per avviare un'applicazione**, puoi **profilare** con **`strace`** e **consentire solo le syscalls** di cui ha bisogno
{% endhint %}

### Esempio di politica Seccomp

[Esempio da qui](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Per illustrare la funzionalità Seccomp, creiamo un profilo Seccomp che disabilita la chiamata di sistema "chmod" come segue.
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
Nel profilo sopra, abbiamo impostato l'azione predefinita su "allow" e creato una lista nera per disabilitare "chmod". Per essere più sicuri, possiamo impostare l'azione predefinita su "drop" e creare una lista bianca per abilitare selettivamente le chiamate di sistema.\
L'output seguente mostra la chiamata "chmod" che restituisce un errore perché è disabilitata nel profilo seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Il seguente output mostra il comando "docker inspect" che visualizza il profilo:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Disattivarlo in Docker

Avvia un container con il flag: **`--security-opt seccomp=unconfined`**

A partire da Kubernetes 1.19, **seccomp è abilitato per impostazione predefinita per tutti i Pod**. Tuttavia, il profilo seccomp predefinito applicato ai Pod è il profilo "**RuntimeDefault**", che è **fornito dal runtime del container** (ad esempio, Docker, containerd). Il profilo "RuntimeDefault" consente la maggior parte delle chiamate di sistema, bloccando alcune che sono considerate pericolose o non generalmente richieste dai container.

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
