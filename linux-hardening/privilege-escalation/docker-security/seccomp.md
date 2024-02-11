# Seccomp

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

**Seccomp**, co oznacza tryb bezpiecznego obliczania, to funkcja bezpieczeństwa **jądra Linuxa, która filtruje wywołania systemowe**. Ogranicza procesy do ograniczonego zestawu wywołań systemowych (`exit()`, `sigreturn()`, `read()` i `write()`) dla już otwartych deskryptorów plików. Jeśli proces próbuje wywołać coś innego, zostaje zakończony przez jądro za pomocą sygnałów SIGKILL lub SIGSYS. Ten mechanizm nie wirtualizuje zasobów, ale izoluje proces od nich.

Istnieją dwie metody aktywacji seccomp: za pomocą wywołania systemowego `prctl(2)` z `PR_SET_SECCOMP` lub dla jąder Linuxa w wersji 3.17 i nowszych, za pomocą wywołania systemowego `seccomp(2)`. Starsza metoda aktywacji seccomp poprzez zapis do `/proc/self/seccomp` została zastąpiona przez `prctl()`.

Rozszerzenie **seccomp-bpf** dodaje możliwość filtrowania wywołań systemowych za pomocą konfigurowalnej polityki, używając reguł Berkeley Packet Filter (BPF). To rozszerzenie jest wykorzystywane przez oprogramowanie takie jak OpenSSH, vsftpd i przeglądarki Chrome/Chromium w systemach Chrome OS i Linux do elastycznego i wydajnego filtrowania wywołań systemowych, oferując alternatywę dla nieobsługiwanego już systrace dla Linuxa.

### **Tryb oryginalny/ścisły**

W tym trybie Seccomp **pozwala tylko na wywołania systemowe** `exit()`, `sigreturn()`, `read()` i `write()` dla już otwartych deskryptorów plików. Jeśli zostanie wykonane jakiekolwiek inne wywołanie systemowe, proces zostaje zabity za pomocą sygnału SIGKILL.

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

Ten tryb umożliwia **filtrowanie wywołań systemowych za pomocą konfigurowalnej polityki** zaimplementowanej przy użyciu reguł Berkeley Packet Filter.

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

## Seccomp w Dockerze

**Seccomp-bpf** jest obsługiwany przez **Docker** w celu ograniczenia **syscalls** z kontenerów, co skutecznie zmniejsza powierzchnię ataku. Możesz znaleźć **zablokowane syscalls** domyślnie w [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) a domyślny profil seccomp można znaleźć tutaj [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Możesz uruchomić kontener Docker z **inną polityką seccomp** za pomocą:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Jeśli chcesz na przykład **zabronić** kontenerowi wykonywania niektórych **syscalli**, takich jak `uname`, możesz pobrać domyślny profil ze strony [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) i po prostu **usunąć ciąg `uname` z listy**.\
Jeśli chcesz upewnić się, że **jakiś plik binarny nie działa wewnątrz kontenera Docker**, możesz użyć narzędzia strace, aby wyświetlić listę syscalli, których używa ten plik binarny, a następnie je zabronić.\
W poniższym przykładzie odkrywane są **syscalli** dla `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Jeśli używasz **Dockera tylko do uruchomienia aplikacji**, możesz **profilować** go za pomocą **`strace`** i **pozwolić tylko na wywołania systemowe**, których potrzebuje.
{% endhint %}

### Przykładowa polityka Seccomp

[Przykład stąd](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Aby zilustrować funkcję Seccomp, stwórzmy profil Seccomp, który wyłącza wywołanie systemowe "chmod" jak poniżej.
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
W powyższym profilu ustawiliśmy domyślną akcję na "allow" i utworzyliśmy czarną listę, aby wyłączyć "chmod". Aby być bardziej bezpiecznym, możemy ustawić domyślną akcję na "drop" i utworzyć białą listę, aby selektywnie włączać wywołania systemowe.\
Poniższy wynik pokazuje, że wywołanie "chmod" zwraca błąd, ponieważ jest wyłączone w profilu seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Poniższy wynik pokazuje "docker inspect" wyświetlający profil:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Wyłącz to w Dockerze

Uruchom kontener z flagą: **`--security-opt seccomp=unconfined`**

Od wersji Kubernetes 1.19, **seccomp jest domyślnie włączony dla wszystkich Podów**. Jednak domyślny profil seccomp stosowany do Podów to profil "**RuntimeDefault**", który jest **dostarczany przez kontenerowy runtime** (np. Docker, containerd). Profil "RuntimeDefault" pozwala na większość wywołań systemowych, blokując jednocześnie kilka, które są uważane za niebezpieczne lub ogólnie nie wymagane przez kontenery. 

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
