# Docker 소켓 남용을 통한 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 해킹 기교를 공유하세요.

</details>

가끔은 **도커 소켓에 액세스**만 있고 이를 사용하여 **권한을 상승**시키고 싶을 때가 있습니다. 일부 작업은 매우 의심스러울 수 있으며 피하고 싶을 수 있으므로 권한 상승에 유용한 다양한 플래그를 찾을 수 있습니다:

### 마운트를 통해

루트로 실행되는 컨테이너에서 **파일 시스템의 다른 부분을 마운트**하고 **접근**할 수 있습니다.\
또한 **마운트를 남용하여 컨테이너 내에서 권한을 상승**시킬 수도 있습니다.

* **`-v /:/host`** -> 호스트 파일 시스템을 컨테이너에 마운트하여 **호스트 파일 시스템을 읽을 수 있습니다.**
* 호스트와 동일한 환경에서 컨테이너에 있지만 다른 방어 메커니즘을 비활성화하려면 다음과 같은 플래그를 사용할 수 있습니다:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> 이전 방법과 유사하지만 여기서는 **장치 디스크를 마운트**합니다. 그런 다음 컨테이너 내에서 `mount /dev/sda1 /mnt`를 실행하여 `/mnt`에서 **호스트 파일 시스템에 액세스**할 수 있습니다.
* 호스트에서 `fdisk -l`을 실행하여 마운트할 `</dev/sda1>` 장치를 찾습니다.
* **`-v /tmp:/host`** -> 호스트에서 **특정 디렉토리만 마운트**할 수 있는 경우 호스트 내에서 액세스할 수 있습니다. 마운트하고 마운트된 디렉토리에 **suid**가 있는 **`/bin/bash`**를 만들어 호스트에서 실행하여 루트로 상승할 수 있습니다.

{% hint style="info" %}
아마도 `/tmp` 폴더를 마운트할 수 없을 수도 있지만 **다른 쓰기 가능한 폴더**를 마운트할 수 있습니다. `find / -writable -type d 2>/dev/null`를 사용하여 쓰기 가능한 디렉토리를 찾을 수 있습니다.

**모든 리눅스 머신의 디렉토리가 suid 비트를 지원하지는 않습니다!** suid 비트를 지원하는 디렉토리를 확인하려면 `mount | grep -v "nosuid"`를 실행하세요. 일반적으로 `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` 및 `/var/lib/lxcfs`는 suid 비트를 지원하지 않습니다.

또한, **`/etc`** 또는 **구성 파일을 포함하는 다른 폴더**를 **마운트**할 수 있다면 도커 컨테이너에서 루트로 실행하여 호스트에서 **남용**하고 권한을 상승할 수 있습니다 (아마도 `/etc/shadow` 수정).
{% endhint %}

### 컨테이너에서 탈출

* **`--privileged`** -> 이 플래그를 사용하면 [컨테이너에서 모든 격리가 제거](docker-privileged.md#what-affects)됩니다. [루트로 권한 상승하기](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape) 기술을 확인하세요.
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> [기능을 남용하여 권한 상승](../linux-capabilities.md)을 위해 **그 기능을 컨테이너에 부여**하고 다른 exploit이 작동하지 못하도록 다른 보호 방법을 비활성화하세요.

### Curl

이 페이지에서는 도커 플래그를 사용하여 권한 상승하는 방법을 논의했으며, 이러한 방법을 사용하여 curl 명령을 사용하여 **이러한 방법을 남용하는 방법**을 찾을 수 있습니다:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 해킹 기교를 공유하세요.

</details>
