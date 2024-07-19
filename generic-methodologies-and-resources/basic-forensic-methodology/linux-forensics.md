# Linux Forensics

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) para construir e **automatizar fluxos de trabalho** facilmente com as **ferramentas** comunitárias **mais avançadas** do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Coleta Inicial de Informações

### Informações Básicas

Primeiramente, é recomendado ter um **USB** com **binários e bibliotecas bem conhecidos** (você pode apenas pegar o ubuntu e copiar as pastas _/bin_, _/sbin_, _/lib,_ e _/lib64_), então monte o USB e modifique as variáveis de ambiente para usar esses binários:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Uma vez que você tenha configurado o sistema para usar binários bons e conhecidos, você pode começar **a extrair algumas informações básicas**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Informações suspeitas

Ao obter as informações básicas, você deve verificar coisas estranhas, como:

* **Processos root** geralmente são executados com PIDS baixos, então se você encontrar um processo root com um PID grande, pode suspeitar
* Verifique os **logins registrados** de usuários sem um shell dentro de `/etc/passwd`
* Verifique os **hashes de senha** dentro de `/etc/shadow` para usuários sem um shell

### Dump de Memória

Para obter a memória do sistema em execução, é recomendado usar [**LiME**](https://github.com/504ensicsLabs/LiME).\
Para **compilá-lo**, você precisa usar o **mesmo kernel** que a máquina vítima está usando.

{% hint style="info" %}
Lembre-se de que você **não pode instalar LiME ou qualquer outra coisa** na máquina vítima, pois isso fará várias alterações nela
{% endhint %}

Então, se você tiver uma versão idêntica do Ubuntu, pode usar `apt-get install lime-forensics-dkms`\
Em outros casos, você precisa baixar [**LiME**](https://github.com/504ensicsLabs/LiME) do github e compilá-lo com os cabeçalhos de kernel corretos. Para **obter os cabeçalhos de kernel exatos** da máquina vítima, você pode simplesmente **copiar o diretório** `/lib/modules/<versão do kernel>` para sua máquina e, em seguida, **compilar** LiME usando-os:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME suporta 3 **formatos**:

* Raw (cada segmento concatenado)
* Padded (igual ao raw, mas com zeros nos bits à direita)
* Lime (formato recomendado com metadados)

LiME também pode ser usado para **enviar o dump via rede** em vez de armazená-lo no sistema usando algo como: `path=tcp:4444`

### Imagem de Disco

#### Desligando

Primeiro de tudo, você precisará **desligar o sistema**. Isso nem sempre é uma opção, pois às vezes o sistema será um servidor de produção que a empresa não pode se dar ao luxo de desligar.\
Existem **2 maneiras** de desligar o sistema, um **desligamento normal** e um **desligamento "puxar o plugue"**. O primeiro permitirá que os **processos terminem normalmente** e o **sistema de arquivos** seja **sincronizado**, mas também permitirá que o possível **malware** **destrua evidências**. A abordagem "puxar o plugue" pode acarretar **alguma perda de informação** (não muita informação será perdida, pois já tiramos uma imagem da memória) e o **malware não terá nenhuma oportunidade** de fazer algo a respeito. Portanto, se você **suspeitar** que pode haver um **malware**, apenas execute o **comando** **`sync`** no sistema e puxe o plugue.

#### Tirando uma imagem do disco

É importante notar que **antes de conectar seu computador a qualquer coisa relacionada ao caso**, você precisa ter certeza de que ele será **montado como somente leitura** para evitar modificar qualquer informação.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Análise pré-imagem do disco

Imagens de uma imagem de disco sem mais dados.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas** comunitárias **mais avançadas** do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## Pesquisar por Malware conhecido

### Arquivos de Sistema Modificados

O Linux oferece ferramentas para garantir a integridade dos componentes do sistema, crucial para identificar arquivos potencialmente problemáticos.

* **Sistemas baseados em RedHat**: Use `rpm -Va` para uma verificação abrangente.
* **Sistemas baseados em Debian**: `dpkg --verify` para verificação inicial, seguido de `debsums | grep -v "OK$"` (após instalar `debsums` com `apt-get install debsums`) para identificar quaisquer problemas.

### Detectores de Malware/Rootkit

Leia a página a seguir para aprender sobre ferramentas que podem ser úteis para encontrar malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Pesquisar programas instalados

Para pesquisar efetivamente programas instalados em sistemas Debian e RedHat, considere aproveitar logs do sistema e bancos de dados juntamente com verificações manuais em diretórios comuns.

* Para Debian, inspecione _**`/var/lib/dpkg/status`**_ e _**`/var/log/dpkg.log`**_ para obter detalhes sobre instalações de pacotes, usando `grep` para filtrar informações específicas.
* Usuários do RedHat podem consultar o banco de dados RPM com `rpm -qa --root=/mntpath/var/lib/rpm` para listar pacotes instalados.

Para descobrir software instalado manualmente ou fora desses gerenciadores de pacotes, explore diretórios como _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ e _**`/sbin`**_. Combine listagens de diretórios com comandos específicos do sistema para identificar executáveis não associados a pacotes conhecidos, aprimorando sua busca por todos os programas instalados.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas** comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## Recuperar Binários em Execução Deletados

Imagine um processo que foi executado de /tmp/exec e depois deletado. É possível extraí-lo
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspecionar locais de Autostart

### Tarefas Agendadas
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### Serviços

Caminhos onde um malware poderia ser instalado como um serviço:

* **/etc/inittab**: Chama scripts de inicialização como rc.sysinit, direcionando para scripts de inicialização.
* **/etc/rc.d/** e **/etc/rc.boot/**: Contêm scripts para inicialização de serviços, sendo o último encontrado em versões mais antigas do Linux.
* **/etc/init.d/**: Usado em certas versões do Linux como Debian para armazenar scripts de inicialização.
* Os serviços também podem ser ativados via **/etc/inetd.conf** ou **/etc/xinetd/**, dependendo da variante do Linux.
* **/etc/systemd/system**: Um diretório para scripts do gerenciador de sistema e serviços.
* **/etc/systemd/system/multi-user.target.wants/**: Contém links para serviços que devem ser iniciados em um nível de execução multiusuário.
* **/usr/local/etc/rc.d/**: Para serviços personalizados ou de terceiros.
* **\~/.config/autostart/**: Para aplicativos de inicialização automática específicos do usuário, que podem ser um esconderijo para malware direcionado ao usuário.
* **/lib/systemd/system/**: Arquivos de unidade padrão do sistema fornecidos por pacotes instalados.

### Módulos do Kernel

Módulos do kernel Linux, frequentemente utilizados por malware como componentes de rootkit, são carregados na inicialização do sistema. Os diretórios e arquivos críticos para esses módulos incluem:

* **/lib/modules/$(uname -r)**: Contém módulos para a versão do kernel em execução.
* **/etc/modprobe.d**: Contém arquivos de configuração para controlar o carregamento de módulos.
* **/etc/modprobe** e **/etc/modprobe.conf**: Arquivos para configurações globais de módulos.

### Outros Locais de Autostart

O Linux emprega vários arquivos para executar automaticamente programas na entrada do usuário, potencialmente abrigando malware:

* **/etc/profile.d/**\*, **/etc/profile**, e **/etc/bash.bashrc**: Executados para qualquer login de usuário.
* **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, e **\~/.config/autostart**: Arquivos específicos do usuário que são executados em seu login.
* **/etc/rc.local**: Executa após todos os serviços do sistema terem sido iniciados, marcando o fim da transição para um ambiente multiusuário.

## Examinar Logs

Sistemas Linux rastreiam atividades de usuários e eventos do sistema através de vários arquivos de log. Esses logs são fundamentais para identificar acessos não autorizados, infecções por malware e outros incidentes de segurança. Os principais arquivos de log incluem:

* **/var/log/syslog** (Debian) ou **/var/log/messages** (RedHat): Capturam mensagens e atividades em todo o sistema.
* **/var/log/auth.log** (Debian) ou **/var/log/secure** (RedHat): Registram tentativas de autenticação, logins bem-sucedidos e falhados.
* Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` para filtrar eventos de autenticação relevantes.
* **/var/log/boot.log**: Contém mensagens de inicialização do sistema.
* **/var/log/maillog** ou **/var/log/mail.log**: Registra atividades do servidor de e-mail, útil para rastrear serviços relacionados a e-mail.
* **/var/log/kern.log**: Armazena mensagens do kernel, incluindo erros e avisos.
* **/var/log/dmesg**: Contém mensagens do driver de dispositivo.
* **/var/log/faillog**: Registra tentativas de login falhadas, auxiliando em investigações de violação de segurança.
* **/var/log/cron**: Registra execuções de trabalhos cron.
* **/var/log/daemon.log**: Rastreia atividades de serviços em segundo plano.
* **/var/log/btmp**: Documenta tentativas de login falhadas.
* **/var/log/httpd/**: Contém logs de erro e acesso do Apache HTTPD.
* **/var/log/mysqld.log** ou **/var/log/mysql.log**: Registra atividades do banco de dados MySQL.
* **/var/log/xferlog**: Registra transferências de arquivos FTP.
* **/var/log/**: Sempre verifique se há logs inesperados aqui.

{% hint style="info" %}
Os logs do sistema Linux e subsistemas de auditoria podem ser desativados ou excluídos em um incidente de intrusão ou malware. Como os logs em sistemas Linux geralmente contêm algumas das informações mais úteis sobre atividades maliciosas, intrusos rotineiramente os excluem. Portanto, ao examinar os arquivos de log disponíveis, é importante procurar lacunas ou entradas fora de ordem que possam ser uma indicação de exclusão ou adulteração.
{% endhint %}

**O Linux mantém um histórico de comandos para cada usuário**, armazenado em:

* \~/.bash\_history
* \~/.zsh\_history
* \~/.zsh\_sessions/\*
* \~/.python\_history
* \~/.\*\_history

Além disso, o comando `last -Faiwx` fornece uma lista de logins de usuários. Verifique-o para logins desconhecidos ou inesperados.

Verifique arquivos que podem conceder privilégios extras:

* Revise `/etc/sudoers` para privilégios de usuário não antecipados que podem ter sido concedidos.
* Revise `/etc/sudoers.d/` para privilégios de usuário não antecipados que podem ter sido concedidos.
* Examine `/etc/groups` para identificar quaisquer associações ou permissões de grupo incomuns.
* Examine `/etc/passwd` para identificar quaisquer associações ou permissões de grupo incomuns.

Alguns aplicativos também geram seus próprios logs:

* **SSH**: Examine _\~/.ssh/authorized\_keys_ e _\~/.ssh/known\_hosts_ para conexões remotas não autorizadas.
* **Gnome Desktop**: Verifique _\~/.recently-used.xbel_ para arquivos acessados recentemente via aplicativos Gnome.
* **Firefox/Chrome**: Verifique o histórico do navegador e downloads em _\~/.mozilla/firefox_ ou _\~/.config/google-chrome_ para atividades suspeitas.
* **VIM**: Revise _\~/.viminfo_ para detalhes de uso, como caminhos de arquivos acessados e histórico de pesquisa.
* **Open Office**: Verifique o acesso recente a documentos que podem indicar arquivos comprometidos.
* **FTP/SFTP**: Revise logs em _\~/.ftp\_history_ ou _\~/.sftp\_history_ para transferências de arquivos que podem ser não autorizadas.
* **MySQL**: Investigue _\~/.mysql\_history_ para consultas MySQL executadas, potencialmente revelando atividades não autorizadas no banco de dados.
* **Less**: Analise _\~/.lesshst_ para histórico de uso, incluindo arquivos visualizados e comandos executados.
* **Git**: Examine _\~/.gitconfig_ e projeto _.git/logs_ para alterações em repositórios.

### Logs USB

[**usbrip**](https://github.com/snovvcrash/usbrip) é um pequeno software escrito em Python 3 puro que analisa arquivos de log do Linux (`/var/log/syslog*` ou `/var/log/messages*` dependendo da distribuição) para construir tabelas de histórico de eventos USB.

É interessante **saber todos os USBs que foram usados** e será mais útil se você tiver uma lista autorizada de USBs para encontrar "eventos de violação" (o uso de USBs que não estão dentro dessa lista).

### Instalação
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Exemplos
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Mais exemplos e informações dentro do github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas** comunitárias **mais avançadas** do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}

## Revisar Contas de Usuário e Atividades de Logon

Examine o _**/etc/passwd**_, _**/etc/shadow**_ e **logs de segurança** em busca de nomes ou contas incomuns criadas e ou usadas em estreita proximidade com eventos não autorizados conhecidos. Além disso, verifique possíveis ataques de força bruta sudo.\
Além disso, verifique arquivos como _**/etc/sudoers**_ e _**/etc/groups**_ em busca de privilégios inesperados concedidos a usuários.\
Finalmente, procure contas com **senhas ausentes** ou **senhas facilmente adivinháveis**.

## Examinar Sistema de Arquivos

### Analisando Estruturas de Sistema de Arquivos em Investigações de Malware

Ao investigar incidentes de malware, a estrutura do sistema de arquivos é uma fonte crucial de informações, revelando tanto a sequência de eventos quanto o conteúdo do malware. No entanto, os autores de malware estão desenvolvendo técnicas para dificultar essa análise, como modificar timestamps de arquivos ou evitar o sistema de arquivos para armazenamento de dados.

Para combater esses métodos anti-forenses, é essencial:

* **Realizar uma análise de linha do tempo completa** usando ferramentas como **Autopsy** para visualizar linhas do tempo de eventos ou `mactime` do **Sleuth Kit** para dados de linha do tempo detalhados.
* **Investigar scripts inesperados** no $PATH do sistema, que podem incluir scripts shell ou PHP usados por atacantes.
* **Examinar `/dev` em busca de arquivos atípicos**, pois tradicionalmente contém arquivos especiais, mas pode abrigar arquivos relacionados a malware.
* **Procurar arquivos ou diretórios ocultos** com nomes como ".. " (ponto ponto espaço) ou "..^G" (ponto ponto controle-G), que podem ocultar conteúdo malicioso.
* **Identificar arquivos setuid root** usando o comando: `find / -user root -perm -04000 -print` Isso encontra arquivos com permissões elevadas, que podem ser abusadas por atacantes.
* **Revisar timestamps de exclusão** em tabelas de inode para detectar exclusões em massa de arquivos, possivelmente indicando a presença de rootkits ou trojans.
* **Inspecionar inodes consecutivos** em busca de arquivos maliciosos próximos após identificar um, pois podem ter sido colocados juntos.
* **Verificar diretórios binários comuns** (_/bin_, _/sbin_) em busca de arquivos recentemente modificados, pois estes podem ter sido alterados por malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Note que um **atacante** pode **modificar** o **tempo** para fazer **arquivos parecerem** **legítimos**, mas ele **não pode** modificar o **inode**. Se você descobrir que um **arquivo** indica que foi criado e modificado ao **mesmo tempo** que o restante dos arquivos na mesma pasta, mas o **inode** é **inesperadamente maior**, então os **timestamps desse arquivo foram modificados**.
{% endhint %}

## Comparar arquivos de diferentes versões de sistema de arquivos

### Resumo da Comparação de Versões de Sistema de Arquivos

Para comparar versões de sistema de arquivos e identificar mudanças, usamos comandos simplificados `git diff`:

* **Para encontrar novos arquivos**, compare dois diretórios:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Para conteúdo modificado**, liste as alterações ignorando linhas específicas:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Para detectar arquivos deletados**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **As opções de filtro** (`--diff-filter`) ajudam a restringir a mudanças específicas, como arquivos adicionados (`A`), excluídos (`D`) ou modificados (`M`).
* `A`: Arquivos adicionados
* `C`: Arquivos copiados
* `D`: Arquivos excluídos
* `M`: Arquivos modificados
* `R`: Arquivos renomeados
* `T`: Mudanças de tipo (por exemplo, arquivo para symlink)
* `U`: Arquivos não mesclados
* `X`: Arquivos desconhecidos
* `B`: Arquivos quebrados

## Referências

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Livro: Guia de Campo de Análise Forense de Malware para Sistemas Linux: Guias de Campo de Análise Digital**

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=linux-forensics) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas comunitárias mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=linux-forensics" %}
