# Docker 보안

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 **가장 고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **기본 Docker 엔진 보안**

**Docker 엔진**은 컨테이너를 격리하기 위해 Linux 커널의 **네임스페이스**와 **Cgroups**를 사용하여 기본적인 보안 계층을 제공합니다. **캐퍼빌리티 드롭**, **Seccomp**, **SELinux/AppArmor**를 통해 추가적인 보호가 제공되어 컨테이너 격리가 강화됩니다. **인증 플러그인**을 사용하여 사용자 작업을 더 제한할 수 있습니다.

![Docker 보안](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Docker 엔진에 안전한 액세스

Docker 엔진은 로컬로는 Unix 소켓을 통해, 원격으로는 HTTP를 사용하여 액세스할 수 있습니다. 원격 액세스의 경우, 기밀성, 무결성 및 인증을 보장하기 위해 HTTPS 및 **TLS**를 사용하는 것이 중요합니다.

Ubuntu 시스템에서 Docker는 기본적으로 `unix:///var/run/docker.sock`에서 Unix 소켓을 수신합니다. Docker의 시작 옵션은 `/etc/default/docker`에 정의됩니다. Docker API 및 클라이언트에 원격 액세스를 활성화하려면 다음 설정을 추가하여 Docker 데몬을 HTTP 소켓으로 노출하세요:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
그러나 Docker 데몬을 HTTP로 노출하는 것은 보안 문제로 인해 권장되지 않습니다. 연결을 안전하게 하려면 HTTPS를 사용하는 것이 좋습니다. 연결을 보호하는 두 가지 주요 방법이 있습니다:

1. 클라이언트가 서버의 신원을 확인합니다.
2. 클라이언트와 서버가 서로의 신원을 상호 인증합니다.

인증서는 서버의 신원을 확인하는 데 사용됩니다. 두 방법에 대한 자세한 예제는 [**이 안내서**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)를 참조하십시오.

### 컨테이너 이미지의 보안

컨테이너 이미지는 개인 또는 공개 저장소에 저장할 수 있습니다. Docker는 컨테이너 이미지를 위한 여러 저장 옵션을 제공합니다:

* [**Docker Hub**](https://hub.docker.com): Docker의 공개 레지스트리 서비스.
* [**Docker Registry**](https://github.com/docker/distribution): 사용자가 자체 레지스트리를 호스팅할 수 있도록 하는 오픈 소스 프로젝트.
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): 역할 기반 사용자 인증 및 LDAP 디렉터리 서비스 통합을 제공하는 Docker의 상용 레지스트리 옵션.

### 이미지 스캔

컨테이너에는 기본 이미지 또는 기본 이미지 위에 설치된 소프트웨어로 인해 **보안 취약점**이 있을 수 있습니다. Docker는 **Nautilus**라는 프로젝트를 진행 중이며 이 프로젝트는 컨테이너의 보안 취약점을 스캔하고 취약점을 나열합니다. Nautilus는 각 컨테이너 이미지 레이어를 취약점 저장소와 비교하여 보안 취약점을 식별하는 방식으로 작동합니다.

자세한 내용은 [**여기를 읽어보세요**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

**`docker scan`** 명령을 사용하면 이미지 이름 또는 ID를 사용하여 기존 Docker 이미지를 스캔할 수 있습니다. 예를 들어, 다음 명령을 실행하여 hello-world 이미지를 스캔할 수 있습니다:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker 이미지 서명

도커 이미지 서명은 컨테이너에서 사용되는 이미지의 보안과 무결성을 보장합니다. 다음은 간략한 설명입니다:

- **도커 콘텐츠 신뢰(Docker Content Trust)**는 이미지 서명을 관리하기 위해 The Update Framework (TUF)를 기반으로 하는 Notary 프로젝트를 활용합니다. 자세한 정보는 [Notary](https://github.com/docker/notary) 및 [TUF](https://theupdateframework.github.io)를 참조하십시오.
- 도커 콘텐츠 신뢰를 활성화하려면 `export DOCKER_CONTENT_TRUST=1`을 설정하십시오. 이 기능은 도커 버전 1.10 이후에 기본적으로 꺼져 있습니다.
- 이 기능을 활성화하면 서명된 이미지만 다운로드할 수 있습니다. 초기 이미지 푸시는 루트 및 태깅 키에 대한 암호를 설정해야 하며, 도커는 보안을 강화하기 위해 Yubikey도 지원합니다. 자세한 내용은 [여기](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)에서 확인할 수 있습니다.
- 콘텐츠 신뢰가 활성화된 상태에서 서명되지 않은 이미지를 가져오려고 시도하면 "No trust data for latest" 오류가 발생합니다.
- 첫 번째 이후의 이미지 푸시에 대해 도커는 이미지에 서명하기 위해 저장소 키의 암호를 요청합니다.

개인 키를 백업하려면 다음 명령을 사용하십시오:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Docker 호스트를 전환할 때는 작업을 유지하기 위해 루트 및 저장소 키를 이동해야 합니다.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축** 및 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 컨테이너 보안 기능

<details>

<summary>컨테이너 보안 기능 요약</summary>

**주요 프로세스 격리 기능**

컨테이너 환경에서 프로젝트 및 프로세스를 격리하는 것은 보안 및 자원 관리에 매우 중요합니다. 다음은 주요 개념을 간단히 설명한 것입니다:

**네임스페이스**

* **목적**: 프로세스, 네트워크 및 파일 시스템과 같은 리소스의 격리를 보장합니다. 특히 Docker에서는 네임스페이스가 컨테이너의 프로세스를 호스트 및 다른 컨테이너와 분리합니다.
* **`unshare` 사용**: `unshare` 명령어(또는 해당 시스콜)를 사용하여 새로운 네임스페이스를 생성하여 추가적인 격리 계층을 제공합니다. 그러나 Kubernetes는 이를 기본적으로 차단하지 않지만 Docker는 차단합니다.
* **제한**: 새로운 네임스페이스를 생성하더라도 프로세스가 호스트의 기본 네임스페이스로 되돌아가는 것을 허용하지 않습니다. 호스트 네임스페이스에 침투하려면 일반적으로 호스트의 `/proc` 디렉토리에 액세스해야 하며, `nsenter`를 사용하여 진입해야 합니다.

**제어 그룹 (CGroups)**

* **기능**: 프로세스 간 자원을 할당하는 데 주로 사용됩니다.
* **보안 측면**: CGroups 자체는 격리 보안을 제공하지 않지만, `release_agent` 기능을 통해 잘못 구성된 경우 무단 액세스에 악용될 수 있습니다.

**능력 제한**

* **중요성**: 프로세스 격리를 위한 중요한 보안 기능입니다.
* **기능**: 특정 능력을 삭제함으로써 루트 프로세스가 수행할 수 있는 작업을 제한합니다. 프로세스가 루트 권한으로 실행되더라도 필요한 능력이 없으면 특권 작업을 실행할 수 없으며, 시스콜이 권한이 부족하여 실패합니다.

이것은 프로세스가 다른 능력을 삭제한 후 남은 **능력**입니다:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

도커에서 기본으로 활성화되어 있습니다. 프로세스가 호출할 수 있는 시스콜을 **더 제한하는 데 도움**이 됩니다.\
**기본 도커 Seccomp 프로필**은 [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)에서 찾을 수 있습니다.

**AppArmor**

도커에는 활성화할 수 있는 템플릿이 있습니다: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

이를 통해 기능, 시스콜, 파일 및 폴더 접근을 줄일 수 있습니다...

</details>

### 네임스페이스

**네임스페이스**는 Linux 커널의 기능으로, 하나의 **프로세스 집합**이 **한 세트의 리소스를 보는** 동안 **다른** 프로세스 집합이 **다른** 세트의 리소스를 보도록 커널 리소스를 분할합니다. 이 기능은 동일한 네임스페이스를 가진 리소스와 프로세스 세트를 가지고 있지만 해당 네임스페이스는 서로 다른 리소스를 참조합니다. 리소스는 여러 공간에 존재할 수 있습니다.

도커는 컨테이너 격리를 달성하기 위해 다음과 같은 Linux 커널 네임스페이스를 활용합니다:

* pid 네임스페이스
* mount 네임스페이스
* network 네임스페이스
* ipc 네임스페이스
* UTS 네임스페이스

**네임스페이스에 대한 자세한 정보**는 다음 페이지를 확인하십시오:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linux 커널 기능인 **cgroups**는 일련의 프로세스 사이에서 **cpu, 메모리, io, 네트워크 대역폭과 같은 리소스를 제한**하는 기능을 제공합니다. 도커는 특정 컨테이너에 대한 리소스 제어를 가능하게 하는 cgroup 기능을 사용하여 컨테이너를 생성할 수 있습니다.\
다음은 사용자 공간 메모리가 500m로 제한되고, 커널 메모리가 50m로 제한되며, CPU 공유가 512로, blkioweight가 400으로 설정된 컨테이너입니다. CPU 공유는 컨테이너의 CPU 사용량을 제어하는 비율입니다. 기본값은 1024이며 0에서 1024 사이의 범위를 가집니다. CPU 리소스 충돌이 발생하는 경우 CPU 공유가 1024인 세 개의 컨테이너가 동일한 CPU 공유를 가지고 있다면 각 컨테이너는 CPU의 최대 33%를 사용할 수 있습니다. blkio-weight는 컨테이너의 IO를 제어하는 비율입니다. 기본값은 500이며 10에서 1000 사이의 범위를 가집니다.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
컨테이너의 cgroup을 얻으려면 다음을 수행할 수 있습니다:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
더 많은 정보를 확인하려면:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capabilities

Capabilities는 루트 사용자에게 허용될 수 있는 기능을 **더 세밀하게 제어**할 수 있게 합니다. Docker는 Linux 커널 기능을 사용하여 **사용자 유형과 관계없이 컨테이너 내에서 수행할 수 있는 작업을 제한**합니다.

도커 컨테이너가 실행될 때, **프로세스는 격리에서 탈출할 수 있는 민감한 기능을 제거**합니다. 이는 프로세스가 민감한 작업을 수행하고 탈출할 수 없도록 보장합니다:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Docker에서 Seccomp

이는 Docker가 컨테이너 내에서 사용할 수 있는 **syscalls를 제한**하는 보안 기능입니다:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### Docker에서 AppArmor

**AppArmor**는 **프로그램별 프로필**을 사용하여 **컨테이너를 제한된 리소스로 제한**하는 커널 개선 기능입니다.:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### Docker에서 SELinux

* **라벨링 시스템**: SELinux는 모든 프로세스와 파일 시스템 객체에 고유한 라벨을 할당합니다.
* **정책 강제**: 프로세스 라벨이 시스템 내 다른 라벨에 대해 수행할 수 있는 작업을 정의하는 보안 정책을 강제합니다.
* **컨테이너 프로세스 라벨**: 컨테이너 엔진이 컨테이너 프로세스를 시작할 때, 일반적으로 `container_t`로 할당됩니다.
* **컨테이너 내 파일 라벨링**: 컨테이너 내 파일은 일반적으로 `container_file_t`로 라벨이 지정됩니다.
* **정책 규칙**: SELinux 정책은 주로 `container_t` 라벨을 가진 프로세스가 `container_file_t`로 라벨이 지정된 파일과만 상호 작용(읽기, 쓰기, 실행)할 수 있도록 보장합니다.

이 메커니즘은 컨테이너 내 프로세스가 침해당해도 해당 라벨을 가진 객체와만 상호 작용하도록 보장하여, 이러한 침해로부터 발생할 수 있는 잠재적인 피해를 크게 제한합니다.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Docker에서 권한 부여 플러그인은 Docker 데몬에 대한 요청을 허용하거나 차단하는 보안에서 중요한 역할을 합니다. 이 결정은 두 가지 주요 컨텍스트를 검토하여 내립니다:

* **인증 컨텍스트**: 사용자에 대한 포괄적인 정보를 포함하며, 사용자가 누구이며 어떻게 인증되었는지에 대한 정보를 제공합니다.
* **명령어 컨텍스트**: 요청과 관련된 모든 관련 데이터를 포함합니다.

이러한 컨텍스트는 인증된 사용자로부터의 합법적인 요청만 처리되도록 보장하여 Docker 작업의 보안을 강화합니다.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## 컨테이너로부터의 DoS

컨테이너가 사용할 수 있는 리소스를 제대로 제한하지 않으면, 침해당한 컨테이너가 실행 중인 호스트에 DoS를 발생시킬 수 있습니다.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* 대역폭 DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## 흥미로운 Docker 플래그

### --privileged 플래그

다음 페이지에서 **`--privileged` 플래그가 의미하는 것**을 배울 수 있습니다:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

공격자가 낮은 권한 사용자로 액세스를 획득한 컨테이너를 실행 중인 경우, **잘못 구성된 suid 이진 파일**이 있는 경우, 공격자는 이를 악용하여 컨테이너 내에서 **권한 상승**을 할 수 있습니다. 이로 인해 컨테이너를 탈출할 수도 있습니다.

**`no-new-privileges`** 옵션을 활성화하여 컨테이너를 실행하면 이러한 권한 상승을 **방지**할 수 있습니다.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### 기타
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
더 많은 **`--security-opt`** 옵션을 확인하려면 다음을 참조하세요: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## 기타 보안 고려 사항

### 비밀 관리: 최상의 실천 방법

도커 이미지에 비밀을 직접 포함하거나 환경 변수를 사용하는 것을 피하는 것이 중요합니다. 이러한 방법은 `docker inspect` 또는 `exec`와 같은 명령을 통해 컨테이너에 액세스 권한이 있는 사람에게 민감한 정보를 노출시킵니다.

**도커 볼륨**은 민감한 정보에 액세스하는 데 권장되는 안전한 대안입니다. 이들은 메모리 내 임시 파일 시스템으로 사용될 수 있으며, `docker inspect` 및 로깅과 관련된 위험을 완화합니다. 그러나 루트 사용자 및 컨테이너에 `exec` 액세스 권한이 있는 사용자는 여전히 비밀을 액세스할 수 있습니다.

**도커 시크릿**은 민감한 정보를 처리하는 더 안전한 방법을 제공합니다. 이미지 빌드 단계 중에 비밀이 필요한 경우, **BuildKit**은 빌드 시간 시크릿을 지원하는 효율적인 솔루션을 제공하여 빌드 속도를 향상시키고 추가 기능을 제공합니다.

BuildKit을 활용하기 위해 세 가지 방법으로 활성화할 수 있습니다:

1. 환경 변수를 통해: `export DOCKER_BUILDKIT=1`
2. 명령어에 접두사를 붙여: `DOCKER_BUILDKIT=1 docker build .`
3. 도커 구성에서 기본적으로 활성화: `{ "features": { "buildkit": true } }`, 이후 도커 재시작.

BuildKit은 `--secret` 옵션을 사용하여 빌드 시간 시크릿을 사용할 수 있도록 하며, 이러한 비밀이 이미지 빌드 캐시나 최종 이미지에 포함되지 않도록 보장합니다.
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
실행 중인 컨테이너에서 필요한 비밀은 **Docker Compose와 Kubernetes**이 강력한 솔루션을 제공합니다. Docker Compose는 시크릿 파일을 지정하기 위해 서비스 정의에서 `secrets` 키를 활용하며, 이는 `docker-compose.yml` 예시에서 확인할 수 있습니다:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
이 구성은 Docker Compose를 사용하여 서비스를 시작할 때 시크릿을 사용할 수 있게 합니다.

Kubernetes 환경에서는 시크릿이 네이티브로 지원되며 [Helm-Secrets](https://github.com/futuresimple/helm-secrets)와 같은 도구로 더욱 효율적으로 관리할 수 있습니다. Kubernetes의 Role Based Access Controls (RBAC)는 Docker Enterprise와 유사하게 시크릿 관리 보안을 강화합니다.

### gVisor

**gVisor**는 Go로 작성된 응용 프로그램 커널로, Linux 시스템 표면의 상당 부분을 구현합니다. 응용 프로그램과 호스트 커널 사이의 **격리 경계를 제공하는** [Open Container Initiative (OCI)](https://www.opencontainers.org) 런타임인 `runsc`를 포함하고 있습니다. `runsc` 런타임은 Docker와 Kubernetes와 통합되어 샌드박스 컨테이너를 간단히 실행할 수 있게 합니다.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers**는 가벼운 가상 머신을 사용하여 컨테이너와 유사한 성능을 제공하지만 **하드웨어 가상화 기술을 사용하여 더 강력한 워크로드 격리**를 제공하는 안전한 컨테이너 런타임을 구축하기 위해 노력하는 오픈 소스 커뮤니티입니다.

{% embed url="https://katacontainers.io/" %}

### 요약 팁

* **`--privileged` 플래그를 사용하지 않거나** [**컨테이너 내부에 Docker 소켓을 마운트하지 마세요**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Docker 소켓을 사용하면 컨테이너를 생성할 수 있으므로, 예를 들어 `--privileged` 플래그를 사용하여 다른 컨테이너를 실행하는 등 호스트를 완전히 제어할 수 있습니다.
* **컨테이너 내부에서 루트로 실행하지 마세요.** [**다른 사용자**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **와** [**사용자 네임스페이스**](https://docs.docker.com/engine/security/userns-remap/) **를 사용하세요.** 컨테이너 내의 루트는 사용자 네임스페이스로 재매핑되지 않는 한 호스트와 동일합니다. 주로 Linux 네임스페이스, 기능 및 cgroups에 의해 약간 제한됩니다.
* [**모든 기능을 삭제하고**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **필요한 것만 활성화하세요** (`--cap-add=...`). 많은 워크로드는 어떤 기능도 필요로 하지 않으며, 추가하면 잠재적인 공격 범위가 증가합니다.
* **프로세스가 더 많은 권한을 얻는 것을 방지하기 위해** [**“no-new-privileges” 보안 옵션을 사용하세요**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/). 예를 들어 suid 이진 파일을 통해 권한을 더 얻는 것을 방지합니다.
* **컨테이너에 사용 가능한 자원을 제한하세요**. 자원 제한은 머신을 서비스 거부 공격으로부터 보호할 수 있습니다.
* **[seccomp](https://docs.docker.com/engine/security/seccomp/)**, **[AppArmor](https://docs.docker.com/engine/security/apparmor/)** **(또는 SELinux)** 프로필을 조정하여 컨테이너에서 사용 가능한 작업 및 시스템 호출을 필요한 최소한으로 제한하세요.
* **[공식 Docker 이미지](https://docs.docker.com/docker-hub/official\_images/)를 사용하고 서명을 요구하거나 해당 이미지를 기반으로 직접 빌드하세요.** 백도어가 있는 이미지를 상속하거나 사용하지 마세요. 또한 루트 키, 패스프레이즈를 안전한 위치에 저장하세요. Docker는 UCP를 사용하여 키를 관리할 계획입니다.
* **이미지를 정기적으로 다시 빌드하여 호스트 및 이미지에 보안 패치를 적용하세요.**
* **시크릿을 현명하게 관리하여 공격자가 액세스하기 어렵게 만드세요.**
* **도커 데몬을 노출하는 경우 HTTPS를 사용하세요**. 클라이언트 및 서버 인증을 사용합니다.
* **Dockerfile에서는 ADD 대신 COPY를 선호하세요**. ADD는 자동으로 압축 해제하고 URL에서 파일을 복사할 수 있습니다. COPY는 이러한 기능이 없습니다. 가능한 경우 ADD 사용을 피하여 원격 URL 및 Zip 파일을 통한 공격에 취약하지 않도록 합니다.
* **각 마이크로 서비스에 대해 별도의 컨테이너를 사용하세요.**
* **컨테이너 이미지를 더 작게 유지하세요.**
<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.
