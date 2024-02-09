# Docker --privileged

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## O Que Afeta

Quando você executa um contêiner como privilegiado, estas são as proteções que você está desabilitando:

### Montar /dev

Em um contêiner privilegiado, todos os **dispositivos podem ser acessados em `/dev/`**. Portanto, você pode **escapar** ao **montar** o disco do host.

{% tabs %}
{% tab title="Dentro do contêiner padrão" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title = "Dentro do Contêiner com Privilégios" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
### Sistemas de arquivos de kernel somente leitura

Os sistemas de arquivos de kernel fornecem um mecanismo para um processo modificar o comportamento do kernel. No entanto, quando se trata de processos de contêineres, queremos impedi-los de fazer quaisquer alterações no kernel. Portanto, montamos os sistemas de arquivos de kernel como **somente leitura** dentro do contêiner, garantindo que os processos do contêiner não possam modificar o kernel.
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title = "Dentro do Contêiner com Privilégios" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
### Mascaramento sobre sistemas de arquivos do kernel

O sistema de arquivos **/proc** é seletivamente gravável, mas por motivos de segurança, certas partes são protegidas contra acesso de escrita e leitura ao serem sobrepostas com **tmpfs**, garantindo que os processos do contêiner não possam acessar áreas sensíveis.

{% hint style="info" %}
**tmpfs** é um sistema de arquivos que armazena todos os arquivos na memória virtual. O tmpfs não cria nenhum arquivo no seu disco rígido. Portanto, se você desmontar um sistema de arquivos tmpfs, todos os arquivos nele serão perdidos para sempre.
{% endhint %}

{% tabs %}
{% tab title="Dentro do contêiner padrão" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Dentro do Contêiner com Privilégios" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
### Capacidades do Linux

As engines de contêineres iniciam os contêineres com um **número limitado de capacidades** para controlar o que acontece dentro do contêiner por padrão. Os contêineres **privilegiados** têm **todas** as **capacidades** acessíveis. Para aprender sobre capacidades, leia:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Dentro do contêiner padrão" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title = "Dentro do Contêiner com Privilégios" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{% endtab %}
{% endtabs %}

Você pode manipular as capacidades disponíveis para um contêiner sem executar no modo `--privileged` usando as flags `--cap-add` e `--cap-drop`.

### Seccomp

**Seccomp** é útil para **limitar** as **syscalls** que um contêiner pode chamar. Um perfil seccomp padrão é habilitado por padrão ao executar contêineres docker, mas no modo privilegiado ele é desativado. Saiba mais sobre Seccomp aqui:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title = "Dentro do Contêiner com Privilégios" %}
```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```
{% endtab %}
{% endtabs %}
```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```
Também, observe que quando o Docker (ou outros CRIs) são usados em um cluster **Kubernetes**, o **filtro seccomp é desativado por padrão**

### AppArmor

**AppArmor** é um aprimoramento do kernel para confinar **containers** a um **conjunto limitado** de **recursos** com **perfis por programa**. Quando você executa com a flag `--privileged`, essa proteção é desativada.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Executar um contêiner com a flag `--privileged` desabilita **rótulos SELinux**, fazendo com que herde o rótulo do mecanismo do contêiner, normalmente `unconfined`, concedendo acesso total semelhante ao mecanismo do contêiner. No modo sem privilégios, ele usa `container_runtime_t`, enquanto no modo root, `spc_t` é aplicado.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## O que não afeta

### Namespaces

Os namespaces **NÃO são afetados** pela flag `--privileged`. Mesmo que não tenham as restrições de segurança ativadas, eles **não veem todos os processos no sistema ou na rede do host, por exemplo**. Os usuários podem desativar namespaces individuais usando as flags dos motores de contêiner **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{% tabs %}
{% tab title="Dentro do contêiner privilegiado padrão" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Dentro do Contêiner --pid=host" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
{% endtab %}
{% endtabs %}

### Namespace de usuário

**Por padrão, os motores de contêineres não utilizam namespaces de usuário, exceto para contêineres sem raiz**, que os requerem para montagem de sistema de arquivos e uso de vários UIDs. Os namespaces de usuário, essenciais para contêineres sem raiz, não podem ser desativados e melhoram significativamente a segurança ao restringir privilégios.

## Referências

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
