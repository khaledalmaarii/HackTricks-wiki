# Seccomp

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Grundlegende Informationen

**Seccomp**, was für Secure Computing Mode steht, ist eine Sicherheitsfunktion des **Linux-Kernels, die Systemaufrufe filtert**. Sie beschränkt Prozesse auf eine begrenzte Anzahl von Systemaufrufen (`exit()`, `sigreturn()`, `read()` und `write()` für bereits geöffnete Dateideskriptoren). Wenn ein Prozess versucht, etwas anderes aufzurufen, wird er vom Kernel mit SIGKILL oder SIGSYS beendet. Dieser Mechanismus virtualisiert keine Ressourcen, sondern isoliert den Prozess von ihnen.

Es gibt zwei Möglichkeiten, Seccomp zu aktivieren: über den Systemaufruf `prctl(2)` mit `PR_SET_SECCOMP` oder für Linux-Kernel 3.17 und höher über den Systemaufruf `seccomp(2)`. Die ältere Methode, Seccomp durch Schreiben in `/proc/self/seccomp` zu aktivieren, wurde zugunsten von `prctl()` veraltet.

Eine Erweiterung namens **seccomp-bpf** ermöglicht das Filtern von Systemaufrufen mit einer anpassbaren Richtlinie unter Verwendung von Berkeley Packet Filter (BPF)-Regeln. Diese Erweiterung wird von Software wie OpenSSH, vsftpd und den Chrome/Chromium-Browsern unter Chrome OS und Linux genutzt, um eine flexible und effiziente Systemaufruffilterung zu ermöglichen und eine Alternative zum nicht mehr unterstützten systrace für Linux anzubieten.

### **Original/Strict-Modus**

In diesem Modus erlaubt Seccomp **nur die Systemaufrufe** `exit()`, `sigreturn()`, `read()` und `write()` für bereits geöffnete Dateideskriptoren. Wenn ein anderer Systemaufruf gemacht wird, wird der Prozess mit SIGKILL beendet.

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

Dieser Modus ermöglicht das **Filtern von Systemaufrufen mithilfe einer konfigurierbaren Richtlinie**, die mit Hilfe von Berkeley Packet Filter-Regeln implementiert wird.

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

**Seccomp-bpf** wird von **Docker** unterstützt, um die **Syscalls** aus den Containern einzuschränken und so die Angriffsfläche effektiv zu verringern. Die standardmäßig **blockierten Syscalls** finden Sie unter [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) und das **Standard-Seccomp-Profil** finden Sie hier [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Sie können einen Docker-Container mit einer **anderen Seccomp-Richtlinie** ausführen mit:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Wenn Sie beispielsweise einem Container das Ausführen bestimmter Systemaufrufe wie `uname` verbieten möchten, können Sie das Standardprofil von [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) herunterladen und einfach den String `uname` aus der Liste entfernen.\
Wenn Sie sicherstellen möchten, dass **eine bestimmte Binärdatei in einem Docker-Container nicht funktioniert**, können Sie strace verwenden, um die verwendeten Systemaufrufe der Binärdatei aufzulisten und sie dann zu verbieten.\
Im folgenden Beispiel werden die Systemaufrufe von `uname` entdeckt:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Wenn Sie Docker nur verwenden, um eine Anwendung zu starten, können Sie sie mit `strace` profilieren und nur die benötigten Systemaufrufe zulassen.
{% endhint %}

### Beispiel für eine Seccomp-Richtlinie

[Beispiel von hier](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Um das Seccomp-Feature zu veranschaulichen, erstellen wir ein Seccomp-Profil, das den Systemaufruf "chmod" deaktiviert, wie unten dargestellt.
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
Im obigen Profil haben wir die Standardaktion auf "allow" gesetzt und eine Blacklist erstellt, um "chmod" zu deaktivieren. Um sicherer zu sein, können wir die Standardaktion auf "drop" setzen und eine Whitelist erstellen, um selektiv Systemaufrufe zu aktivieren.\
Die folgende Ausgabe zeigt den Aufruf von "chmod", der einen Fehler zurückgibt, weil er im Seccomp-Profil deaktiviert ist.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Der folgende Output zeigt das Ergebnis von "docker inspect", das das Profil anzeigt:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Deaktivieren Sie es in Docker

Starten Sie einen Container mit der Option: **`--security-opt seccomp=unconfined`**

Ab Kubernetes 1.19 ist **seccomp standardmäßig für alle Pods aktiviert**. Die Standard-Seccomp-Profil, das auf die Pods angewendet wird, ist das "**RuntimeDefault**" Profil, das vom Container-Runtime (z.B. Docker, containerd) bereitgestellt wird. Das "RuntimeDefault" Profil erlaubt die meisten Systemaufrufe, blockiert jedoch einige, die als gefährlich oder für Container im Allgemeinen nicht erforderlich angesehen werden.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
