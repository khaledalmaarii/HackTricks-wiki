# Seccomp

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану в HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв.

</details>

## Базова інформація

**Seccomp**, що означає Secure Computing mode, є функцією безпеки **ядра Linux, призначеною для фільтрації системних викликів**. Він обмежує процеси до обмеженого набору системних викликів (`exit()`, `sigreturn()`, `read()` та `write()` для вже відкритих файлових дескрипторів). Якщо процес намагається викликати щось інше, він завершується ядром за допомогою SIGKILL або SIGSYS. Цей механізм не віртуалізує ресурси, але ізолює процес від них.

Є два способи активації seccomp: через системний виклик `prctl(2)` з `PR_SET_SECCOMP`, або для ядер Linux версії 3.17 і вище, системний виклик `seccomp(2)`. Старий метод активації seccomp шляхом запису в `/proc/self/seccomp` був застарілий на користь `prctl()`.

Покращення, **seccomp-bpf**, додає можливість фільтрувати системні виклики з налаштовуваною політикою, використовуючи правила Berkeley Packet Filter (BPF). Це розширення використовується програмним забезпеченням, таким як OpenSSH, vsftpd та браузери Chrome/Chromium на Chrome OS та Linux для гнучкого та ефективного фільтрування системних викликів, пропонуючи альтернативу тепер не підтримуваному systrace для Linux.

### **Оригінальний/Строгий режим**

У цьому режимі Seccomp **дозволяє лише системні виклики** `exit()`, `sigreturn()`, `read()` та `write()` для вже відкритих файлових дескрипторів. Якщо будь-який інший системний виклик виконується, процес вбивається за допомогою SIGKILL

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

Цей режим дозволяє **фільтрувати системні виклики за допомогою налаштованої політики**, реалізованої за допомогою правил фільтрації пакетів Berkeley.

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

## Seccomp в Docker

**Seccomp-bpf** підтримується **Docker** для обмеження **syscalls** з контейнерів, що ефективно зменшує площу атаки. Ви можете знайти **заблоковані syscalls** за **замовчуванням** на [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) та **профіль за замовчуванням seccomp** можна знайти тут [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Ви можете запустити контейнер **Docker** з **іншою політикою seccomp** за допомогою:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Якщо ви, наприклад, хочете **заборонити** контейнеру виконувати деякі **системні виклики**, такі як `uname`, ви можете завантажити профіль за замовчуванням з [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) і просто **видалити рядок `uname` зі списку**.\
Якщо ви хочете переконатися, що **деякий виконуваний файл не працює всередині контейнера Docker**, ви можете використовувати strace, щоб перерахувати системні виклики, які використовує цей виконуваний файл, а потім заборонити їх.\
У наступному прикладі виявлені **системні виклики** `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Якщо ви використовуєте **Docker лише для запуску додатка**, ви можете **створити профіль** за допомогою **`strace`** та **дозволити лише необхідні системні виклики**.
{% endhint %}

### Приклад політики Seccomp

[Приклад звідси](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Щоб проілюструвати функцію Seccomp, давайте створимо профіль Seccomp, який вимикає системний виклик "chmod".
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
У вищезазначеному профілі ми встановили дію за замовчуванням на "дозвіл" і створили чорний список для вимкнення "chmod". Щоб бути більш безпечним, ми можемо встановити дію за замовчуванням на відмову і створити білий список для вибіркового увімкнення системних викликів.\
Наведений нижче вивід показує, що виклик "chmod" повертає помилку через його вимкнення в профілі seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Наступний вивід показує "docker inspect", що відображає профіль:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Вимкніть його в Docker

Запустіть контейнер з прапорцем: **`--security-opt seccomp=unconfined`**

З початку версії Kubernetes 1.19, **seccomp увімкнено за замовчуванням для всіх Подів**. Однак профіль seccomp за замовчуванням, який застосовується до Подів, - це профіль "**RuntimeDefault**", який **надається контейнерним середовищем виконання** (наприклад, Docker, containerd). Профіль "RuntimeDefault" дозволяє більшість системних викликів, блокуючи кілька, які вважаються небезпечними або загалом не потрібними для контейнерів.
