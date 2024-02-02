# Seccomp

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

**Seccomp** ou modo de Computação Segura, em resumo, é um recurso do kernel do Linux que pode atuar como **filtro de syscall**.\
O Seccomp possui 2 modos.

**seccomp** (abreviação de **modo de computação segura**) é uma facilidade de segurança de computador no **kernel do Linux**. seccomp permite que um processo faça uma transição unidirecional para um estado "seguro" onde **não pode fazer nenhuma chamada de sistema exceto** `exit()`, `sigreturn()`, `read()` e `write()` para descritores de arquivo **já abertos**. Caso tente realizar qualquer outra chamada de sistema, o **kernel** irá **terminar** o **processo** com SIGKILL ou SIGSYS. Nesse sentido, ele não virtualiza os recursos do sistema, mas isola completamente o processo deles.

O modo seccomp é **ativado através da chamada de sistema `prctl(2)`** usando o argumento `PR_SET_SECCOMP`, ou (desde o kernel do Linux 3.17) através da chamada de sistema `seccomp(2)`. O modo seccomp costumava ser ativado escrevendo em um arquivo, `/proc/self/seccomp`, mas este método foi removido em favor de `prctl()`. Em algumas versões do kernel, seccomp desabilita a instrução x86 `RDTSC`, que retorna o número de ciclos do processador desde o início, usada para cronometragem de alta precisão.

**seccomp-bpf** é uma extensão do seccomp que permite **filtrar chamadas de sistema usando uma política configurável** implementada usando regras do Berkeley Packet Filter. É utilizado pelo OpenSSH e vsftpd, bem como pelos navegadores web Google Chrome/Chromium no Chrome OS e Linux. (Neste aspecto, seccomp-bpf alcança funcionalidade similar, mas com mais flexibilidade e melhor desempenho, em comparação ao antigo systrace — que parece não ser mais suportado para Linux.)

### **Modo Original/Estrito**

Neste modo, o Seccomp **só permite as syscalls** `exit()`, `sigreturn()`, `read()` e `write()` para descritores de arquivo já abertos. Se qualquer outra syscall for feita, o processo é morto usando SIGKILL

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

Este modo permite o **filtragem de chamadas de sistema usando uma política configurável** implementada usando regras do Berkeley Packet Filter.

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

## Seccomp no Docker

**Seccomp-bpf** é suportado pelo **Docker** para restringir os **syscalls** dos contêineres, diminuindo efetivamente a área de exposição. Você pode encontrar os **syscalls bloqueados** por **padrão** em [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) e o **perfil seccomp padrão** pode ser encontrado aqui [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Você pode executar um contêiner docker com uma política **seccomp diferente** com:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Se você quiser, por exemplo, **proibir** um container de executar alguma **syscall** como `uname`, você poderia baixar o perfil padrão de [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) e simplesmente **remover a string `uname` da lista**.\
Se você quiser garantir que **algum binário não funcione dentro de um container docker**, você poderia usar strace para listar as syscalls que o binário está usando e então proibi-las.\
No seguinte exemplo, as **syscalls** de `uname` são descobertas:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Se você estiver usando **Docker apenas para iniciar uma aplicação**, você pode **perfilá-la** com **`strace`** e **permitir apenas as chamadas de sistema** de que ela precisa
{% endhint %}

### Exemplo de política Seccomp

Para ilustrar o recurso Seccomp, vamos criar um perfil Seccomp desabilitando a chamada de sistema "chmod" conforme abaixo.
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
No perfil acima, definimos a ação padrão para "permitir" e criamos uma lista negra para desativar "chmod". Para ser mais seguro, podemos definir a ação padrão para rejeitar e criar uma lista branca para habilitar seletivamente chamadas de sistema.
A saída a seguir mostra a chamada "chmod" retornando erro porque está desativada no perfil seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
A saída a seguir mostra o "docker inspect" exibindo o perfil:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Desativar no Docker

Inicie um container com a flag: **`--security-opt seccomp=unconfined`**

A partir do Kubernetes 1.19, **seccomp está habilitado por padrão para todos os Pods**. No entanto, o perfil seccomp padrão aplicado aos Pods é o perfil "**RuntimeDefault**", que é **fornecido pelo runtime do container** (por exemplo, Docker, containerd). O perfil "RuntimeDefault" permite a maioria das chamadas de sistema enquanto bloqueia algumas que são consideradas perigosas ou geralmente não necessárias para containers.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
