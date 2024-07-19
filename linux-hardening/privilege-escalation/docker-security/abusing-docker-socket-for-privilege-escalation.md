# Docker 소켓을 이용한 권한 상승

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

때때로 **docker 소켓에 접근할 수** 있으며 이를 사용하여 **권한을 상승시키고자** 할 수 있습니다. 일부 작업은 매우 의심스러울 수 있으므로 피하고 싶을 수 있습니다. 여기에서 권한 상승에 유용할 수 있는 다양한 플래그를 찾을 수 있습니다:

### 마운트를 통한 방법

루트로 실행되는 컨테이너에서 **파일 시스템**의 다양한 부분을 **마운트**하고 **접근**할 수 있습니다.\
컨테이너 내부에서 권한을 상승시키기 위해 **마운트를 악용할** 수도 있습니다.

* **`-v /:/host`** -> 호스트 파일 시스템을 컨테이너에 마운트하여 **호스트 파일 시스템을 읽을 수 있습니다.**
* **호스트에 있는 것처럼 느끼고 싶지만 컨테이너에 있는 경우** 다음과 같은 플래그를 사용하여 다른 방어 메커니즘을 비활성화할 수 있습니다:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> 이전 방법과 유사하지만 여기서는 **디바이스 디스크를 마운트**하고 있습니다. 그런 다음 컨테이너 내부에서 `mount /dev/sda1 /mnt`를 실행하면 **/mnt**에서 **호스트 파일 시스템에 접근**할 수 있습니다.
* 호스트에서 `fdisk -l`을 실행하여 마운트할 `</dev/sda1>` 디바이스를 찾습니다.
* **`-v /tmp:/host`** -> 어떤 이유로 호스트에서 **일부 디렉토리만 마운트할 수** 있고 호스트 내부에 접근할 수 있는 경우, 이를 마운트하고 마운트된 디렉토리에 **suid**가 있는 **`/bin/bash`**를 생성하여 **호스트에서 실행하고 루트로 상승**할 수 있습니다.

{% hint style="info" %}
`/tmp` 폴더를 마운트할 수 없을 수도 있지만 **다른 쓰기 가능한 폴더**를 마운트할 수 있습니다. 쓰기 가능한 디렉토리를 찾으려면: `find / -writable -type d 2>/dev/null`을 사용하세요.

**리눅스 머신의 모든 디렉토리가 suid 비트를 지원하는 것은 아닙니다!** suid 비트를 지원하는 디렉토리를 확인하려면 `mount | grep -v "nosuid"`를 실행하세요. 예를 들어 일반적으로 `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup`, `/var/lib/lxcfs`는 suid 비트를 지원하지 않습니다.

또한 **`/etc`** 또는 **구성 파일이 포함된 다른 폴더**를 마운트할 수 있다면, 컨테이너에서 루트로 이를 변경하여 **호스트에서 악용하고 권한을 상승시킬 수 있습니다** (예: `/etc/shadow` 수정).
{% endhint %}

### 컨테이너에서 탈출하기

* **`--privileged`** -> 이 플래그를 사용하면 [컨테이너의 모든 격리를 제거합니다](docker-privileged.md#what-affects). [루트로 권한 상승하기 위해 특권 컨테이너에서 탈출하는 기술](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape)을 확인하세요.
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> [권한을 악용하여 권한 상승하기 위해](../linux-capabilities.md), **해당 권한을 컨테이너에 부여하고** 익스플로잇이 작동하는 것을 방지할 수 있는 다른 보호 방법을 비활성화하세요.

### Curl

이 페이지에서는 docker 플래그를 사용하여 권한을 상승시키는 방법에 대해 논의했습니다. **curl** 명령을 사용하여 이러한 방법을 악용하는 **방법을 찾을 수 있습니다**: 

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
