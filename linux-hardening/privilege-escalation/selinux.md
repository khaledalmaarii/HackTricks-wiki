<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


# 컨테이너에서의 SELinux

[Redhat 문서에서의 소개 및 예제](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux)은 **라벨링 시스템**입니다. 모든 **프로세스**와 모든 **파일 시스템 객체**에는 **라벨**이 있습니다. SELinux 정책은 시스템의 **다른 모든 라벨과 함께 프로세스 라벨이 수행할 수 있는 작업에 대한 규칙**을 정의합니다.

컨테이너 엔진은 일반적으로 `container_t`라는 단일한 제한된 SELinux 라벨로 **컨테이너 프로세스를 시작**하고, 그 안에 있는 컨테이너를 `container_file_t`로 라벨링합니다. SELinux 정책 규칙은 기본적으로 **`container_t` 프로세스는 `container_file_t`로 라벨링된 파일만 읽기/쓰기/실행**할 수 있다고 말합니다. 컨테이너 프로세스가 컨테이너를 벗어나 호스트에 있는 콘텐츠에 쓰려고 하면, Linux 커널은 액세스를 거부하고 컨테이너 프로세스가 `container_file_t`로 라벨링된 콘텐츠에만 쓸 수 있도록 허용합니다.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux 사용자

일반 Linux 사용자 외에도 SELinux 사용자가 있습니다. SELinux 사용자는 SELinux 정책의 일부입니다. 각 Linux 사용자는 정책의 일부로 SELinux 사용자에 매핑됩니다. 이를 통해 Linux 사용자는 SELinux 사용자에게 적용된 제한과 보안 규칙 및 메커니즘을 상속받을 수 있습니다.


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
