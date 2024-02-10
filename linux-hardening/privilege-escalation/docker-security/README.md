# Docker 보안

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축 및 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **기본 Docker Engine 보안**

**Docker 엔진**은 Linux 커널의 **Namespaces**와 **Cgroups**를 사용하여 컨테이너를 격리시켜 기본적인 보안 계층을 제공합니다. **Capabilities dropping**, **Seccomp**, **SELinux/AppArmor**을 통해 추가적인 보호가 제공되어 컨테이너 격리가 강화됩니다. **인증 플러그인**을 사용하여 사용자 작업을 제한할 수도 있습니다.

![Docker Security](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Docker Engine에 대한 안전한 액세스

Docker 엔진은 로컬로는 Unix 소켓을 통해, 원격으로는 HTTP를 사용하여 액세스할 수 있습니다. 원격 액세스의 경우, 기밀성, 무결성 및 인증을 보장하기 위해 HTTPS와 **TLS**를 사용하는 것이 중요합니다.

Docker 엔진은 기본적으로 `unix:///var/run/docker.sock`에서 Unix 소켓을 수신 대기합니다. Ubuntu 시스템에서 Docker의 시작 옵션은 `/etc/default/docker`에 정의됩니다. Docker API 및 클라이언트에 대한 원격 액세스를 활성화하려면 다음 설정을 추가하여 Docker 데몬을 HTTP 소켓으로 노출하세요:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
그러나 Docker 데몬을 HTTP로 노출하는 것은 보안상의 이유로 권장되지 않습니다. HTTPS를 사용하여 연결을 보안하는 것이 좋습니다. 연결을 보안하기 위해 두 가지 주요 접근 방식이 있습니다:
1. 클라이언트가 서버의 신원을 확인합니다.
2. 클라이언트와 서버가 상호 인증을 수행합니다.

서버의 신원을 확인하기 위해 인증서를 사용합니다. 두 가지 방법에 대한 자세한 예제는 [**이 가이드**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)를 참조하십시오.

### 컨테이너 이미지의 보안

컨테이너 이미지는 개인 또는 공개 저장소에 저장될 수 있습니다. Docker는 컨테이너 이미지에 대해 여러 저장 옵션을 제공합니다:

* **[Docker Hub](https://hub.docker.com)**: Docker의 공개 레지스트리 서비스입니다.
* **[Docker Registry](https://github.com/docker/distribution)**: 사용자가 자체 레지스트리를 호스팅할 수 있는 오픈 소스 프로젝트입니다.
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: Docker의 상용 레지스트리 제공으로, 역할 기반 사용자 인증 및 LDAP 디렉터리 서비스와의 통합 기능을 제공합니다.

### 이미지 스캔

컨테이너는 기본 이미지 또는 기본 이미지 위에 설치된 소프트웨어로 인해 **보안 취약점**을 가질 수 있습니다. Docker는 **Nautilus**라는 프로젝트를 통해 컨테이너의 보안 취약점을 스캔하고 목록화하는 작업을 진행하고 있습니다. Nautilus는 각 컨테이너 이미지 레이어를 취약점 저장소와 비교하여 보안 취약점을 식별합니다.

자세한 내용은 [**이 문서**](https://docs.docker.com/engine/scan/)를 참조하십시오.

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
trivy -q -f json <ontainer_name>:<tag>
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

Docker 이미지 서명은 컨테이너에서 사용되는 이미지의 보안과 무결성을 보장합니다. 다음은 간략한 설명입니다:

- **Docker Content Trust**는 이미지 서명을 관리하기 위해 The Update Framework (TUF)를 기반으로 한 Notary 프로젝트를 사용합니다. 자세한 내용은 [Notary](https://github.com/docker/notary)와 [TUF](https://theupdateframework.github.io)를 참조하십시오.
- Docker content trust를 활성화하려면 `export DOCKER_CONTENT_TRUST=1`을 설정하십시오. 이 기능은 Docker 버전 1.10 이후로 기본적으로 꺼져 있습니다.
- 이 기능을 활성화하면 서명된 이미지만 다운로드할 수 있습니다. 초기 이미지 푸시는 루트 및 태깅 키에 대한 암호를 설정해야 하며, Docker는 보안을 강화하기 위해 Yubikey도 지원합니다. 자세한 내용은 [여기](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)에서 확인할 수 있습니다.
- content trust가 활성화된 상태에서 서명되지 않은 이미지를 가져오려고 하면 "No trust data for latest" 오류가 발생합니다.
- 첫 번째 이후의 이미지 푸시에서는 Docker가 이미지에 서명하기 위해 저장소 키의 암호를 요청합니다.

개인 키를 백업하려면 다음 명령을 사용하십시오:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
도커 호스트를 전환할 때는 루트 및 저장소 키를 이동하여 작업을 유지해야 합니다.


***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 자동화할 수 있습니다.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 컨테이너 보안 기능

<details>

<summary>컨테이너 보안 기능 요약</summary>

### 주요 프로세스 격리 기능

컨테이너화된 환경에서 프로젝트와 프로세스를 격리하는 것은 보안과 리소스 관리에 있어서 매우 중요합니다. 다음은 주요 개념의 간단한 설명입니다:

#### **네임스페이스**
- **목적**: 프로세스, 네트워크 및 파일 시스템과 같은 리소스의 격리를 보장합니다. 특히 도커에서는 네임스페이스가 컨테이너의 프로세스를 호스트 및 다른 컨테이너와 분리합니다.
- **`unshare` 사용**: `unshare` 명령어(또는 해당 시스콜)를 사용하여 새로운 네임스페이스를 생성하여 추가적인 격리 계층을 제공합니다. 그러나 쿠버네티스는 이를 기본적으로 차단하지 않지만 도커는 차단합니다.
- **제한 사항**: 새로운 네임스페이스를 생성하는 것은 프로세스가 호스트의 기본 네임스페이스로 되돌아갈 수 없게 합니다. 호스트 네임스페이스에 침투하려면 일반적으로 호스트의 `/proc` 디렉토리에 액세스해야 하며, `nsenter`를 사용하여 진입해야 합니다.

#### **컨트롤 그룹 (CGroups)**
- **기능**: 프로세스 간 리소스 할당에 주로 사용됩니다.
- **보안 측면**: CGroups 자체는 격리 보안을 제공하지 않지만, 잘못 구성된 경우 `release_agent` 기능을 악용하여 무단 액세스를 할 수 있습니다.

#### **권한 제한**
- **중요성**: 프로세스 격리를 위한 중요한 보안 기능입니다.
- **기능**: 특정 권한을 삭제함으로써 루트 프로세스가 수행할 수 있는 작업을 제한합니다. 프로세스가 루트 권한으로 실행되더라도 필요한 권한이 없으면 권한이 부족하여 시스콜이 실패합니다.

다음은 프로세스가 다른 권한을 삭제한 후 남은 권한입니다:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Docker에서는 기본적으로 활성화되어 있습니다. 이는 프로세스가 호출할 수 있는 시스콜을 더 제한하는 데 도움이 됩니다.\
**기본 Docker Seccomp 프로필**은 [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)에서 찾을 수 있습니다.

**AppArmor**

Docker에는 활성화할 수 있는 템플릿이 있습니다: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

이를 통해 기능, 시스콜, 파일 및 폴더에 대한 액세스를 제한할 수 있습니다...

</details>

### 네임스페이스

**네임스페이스**는 Linux 커널의 기능으로, 하나의 **리소스 집합**을 볼 수 있는 **프로세스 집합**과 **다른** 리소스 집합을 볼 수 있는 **다른** 프로세스 집합으로 커널 리소스를 분할합니다. 이 기능은 동일한 네임스페이스를 가진 리소스와 프로세스 집합이 있지만, 해당 네임스페이스는 서로 다른 리소스를 참조합니다. 리소스는 여러 네임스페이스에 존재할 수 있습니다.

Docker는 컨테이너 격리를 위해 다음과 같은 Linux 커널 네임스페이스를 사용합니다:

* pid 네임스페이스
* mount 네임스페이스
* network 네임스페이스
* ipc 네임스페이스
* UTS 네임스페이스

**네임스페이스에 대한 자세한 정보**는 다음 페이지를 참조하세요:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linux 커널 기능인 **cgroups**는 프로세스 집합에 대한 cpu, 메모리, io, 네트워크 대역폭과 같은 리소스를 제한하는 기능을 제공합니다. Docker는 cgroup 기능을 사용하여 특정 컨테이너의 리소스 제어를 가능하게 합니다.\
다음은 사용자 공간 메모리가 500m로 제한되고, 커널 메모리가 50m로 제한되며, CPU 공유가 512로 설정된 컨테이너의 예입니다. CPU 공유는 컨테이너의 CPU 사용량을 제어하는 비율입니다. 기본값은 1024이며, 0에서 1024 사이의 범위를 가집니다. CPU 리소스 경합이 발생하는 경우 CPU 공유가 1024인 세 개의 컨테이너는 각각 CPU의 33%까지 사용할 수 있습니다. blkio-weight는 컨테이너의 IO를 제어하는 비율입니다. 기본값은 500이며, 10에서 1000 사이의 범위를 가집니다.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
컨테이너의 cgroup을 얻으려면 다음을 수행할 수 있습니다:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
더 많은 정보를 확인하려면 다음을 참조하십시오:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capabilities

Capabilities는 root 사용자에게 허용할 수 있는 기능을 **더 세밀하게 제어**할 수 있게 합니다. Docker는 Linux 커널 기능을 사용하여 **컨테이너 내에서 수행할 수 있는 작업을 제한**합니다.

Docker 컨테이너가 실행될 때, **프로세스는 격리에서 탈출할 수 있는 민감한 기능을 제거**합니다. 이렇게 함으로써 프로세스가 민감한 작업을 수행하고 탈출하는 것을 방지하려고 합니다:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Docker에서의 Seccomp

이는 Docker가 컨테이너 내에서 사용할 수 있는 **시스콜을 제한**하는 보안 기능입니다:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### Docker에서의 AppArmor

**AppArmor**은 **컨테이너**를 **제한된** **리소스**와 **프로그램별 프로파일**로 제한하는 커널 개선 기능입니다:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### Docker에서의 SELinux

- **라벨링 시스템**: SELinux는 모든 프로세스와 파일 시스템 객체에 고유한 라벨을 할당합니다.
- **정책 강제**: 시스템 내에서 프로세스 라벨이 다른 라벨에 대해 수행할 수 있는 작업을 정의하는 보안 정책을 강제합니다.
- **컨테이너 프로세스 라벨**: 컨테이너 엔진이 컨테이너 프로세스를 시작할 때, 일반적으로 `container_t`로 제한된 SELinux 라벨이 할당됩니다.
- **컨테이너 내 파일 라벨링**: 컨테이너 내의 파일은 일반적으로 `container_file_t`로 라벨이 지정됩니다.
- **정책 규칙**: SELinux 정책은 주로 `container_t` 라벨을 가진 프로세스가 `container_file_t`로 라벨이 지정된 파일과만 상호 작용(읽기, 쓰기, 실행)할 수 있도록 보장합니다.

이 메커니즘은 컨테이너 내의 프로세스가 침해당하더라도 해당 라벨을 가진 객체와만 상호 작용하도록 제한함으로써, 이러한 침해로 인한 잠재적인 피해를 크게 제한합니다.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Docker에서 인증 플러그인은 Docker 데몬에 대한 요청을 허용할지 또는 차단할지 결정하는 보안에서 중요한 역할을 합니다. 이 결정은 두 가지 주요 컨텍스트를 검토하여 이루어집니다:

- **인증 컨텍스트**: 이는 사용자에 대한 포괄적인 정보를 포함하며, 사용자가 누구이며 어떻게 인증되었는지 등을 나타냅니다.
- **명령 컨텍스트**: 이는 수행되는 요청과 관련된 모든 관련 데이터를 포함합니다.

이러한 컨텍스트는 인증된 사용자로부터의 합법적인 요청만 처리되도록 보장하여 Docker 작업의 보안을 강화합니다.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## 컨테이너로부터의 DoS

컨테이너가 사용할 수 있는 리소스를 제대로 제한하지 않으면, 침해당한 컨테이너가 실행 중인 호스트에 DoS 공격을 가할 수 있습니다.

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

다음 페이지에서는 **`--privileged` 플래그가 의미하는 바**를 알 수 있습니다:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

저 권한 사용자로서 접근 권한을 획득한 공격자가 있는 컨테이너를 실행하고 있다면, **잘못 구성된 suid 바이너리**를 악용하여 컨테이너 내에서 권한 상승을 시도할 수 있습니다. 이로 인해 컨테이너를 탈출할 수 있을 수도 있습니다.

**`no-new-privileges`** 옵션을 사용하여 컨테이너를 실행하면 이러한 권한 상승을 방지할 수 있습니다.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### 기타

In addition to the security measures mentioned above, there are a few other considerations to keep in mind when it comes to Docker security.

##### 1. Limit Container Capabilities

By default, Docker containers have the same capabilities as the host system. This means that if a container is compromised, the attacker will have the same level of access as the host. To mitigate this risk, it is recommended to limit the capabilities of the containers by using the `--cap-drop` flag when running the container. This flag allows you to drop specific capabilities from the container, reducing the attack surface.

##### 2. Use Read-Only File Systems

Another way to enhance Docker security is by using read-only file systems for containers. This prevents any modifications to the file system within the container, making it more difficult for attackers to persist their changes. You can enable read-only file systems by using the `--read-only` flag when running the container.

##### 3. Monitor Container Activity

Monitoring container activity is crucial for detecting any suspicious behavior or unauthorized access. Docker provides several tools and commands that can help with this, such as `docker stats`, `docker events`, and `docker logs`. By regularly monitoring container activity, you can quickly identify any potential security issues and take appropriate action.

##### 4. Regularly Update Docker Images

Keeping your Docker images up to date is essential for maintaining security. Docker images often contain vulnerabilities that can be exploited by attackers. By regularly updating your images, you can ensure that any known vulnerabilities are patched and reduce the risk of a successful attack.

##### 5. Implement Network Segmentation

To further enhance Docker security, consider implementing network segmentation. This involves dividing your Docker environment into separate networks or subnets, each with its own set of access controls. By isolating containers into different networks, you can limit the impact of a potential breach and prevent lateral movement within your Docker environment.

##### 6. Harden the Host System

Lastly, don't forget to harden the host system that runs Docker. This includes applying security patches, disabling unnecessary services, and implementing strong access controls. By securing the host system, you can protect the Docker environment from external threats and reduce the risk of privilege escalation.

By following these additional security measures, you can further strengthen the security of your Docker environment and minimize the risk of unauthorized access or data breaches.
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

### 비밀 관리: 최상의 방법

Docker 이미지에 비밀을 직접 포함하거나 환경 변수를 사용하는 것은 중요한 정보를 `docker inspect` 또는 `exec`와 같은 명령을 통해 컨테이너에 액세스 할 수 있는 모든 사용자에게 노출시키므로 피해야합니다.

**Docker 볼륨**은 민감한 정보에 액세스하기 위해 권장되는 안전한 대안입니다. 이들은 `docker inspect` 및 로깅과 관련된 위험을 완화하기 위해 메모리 내 임시 파일 시스템으로 사용될 수 있습니다. 그러나 루트 사용자 및 컨테이너에 대한 `exec` 액세스 권한이 있는 사용자는 여전히 비밀을 액세스 할 수 있습니다.

**Docker 시크릿**은 민감한 정보를 처리하기 위한 더욱 안전한 방법을 제공합니다. 이미지 빌드 단계에서 시크릿이 필요한 경우, **BuildKit**은 빌드 시간 시크릿을 지원하여 빌드 속도를 향상시키고 추가 기능을 제공하는 효율적인 솔루션을 제공합니다.

BuildKit을 활용하기 위해 다음 세 가지 방법으로 활성화할 수 있습니다:

1. 환경 변수를 통해: `export DOCKER_BUILDKIT=1`
2. 명령어에 접두사로: `DOCKER_BUILDKIT=1 docker build .`
3. Docker 구성에서 기본적으로 활성화: `{ "features": { "buildkit": true } }` 다음에 Docker 재시작.

BuildKit은 `--secret` 옵션을 사용하여 빌드 시간 시크릿을 사용할 수 있으며, 이러한 시크릿이 이미지 빌드 캐시 또는 최종 이미지에 포함되지 않도록 보장합니다. 다음과 같은 명령을 사용합니다:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
실행 중인 컨테이너에서 필요한 비밀 정보에 대해 **Docker Compose와 Kubernetes**는 견고한 솔루션을 제공합니다. Docker Compose는 `docker-compose.yml` 예시에서 보여지는 것처럼 서비스 정의에서 `secrets` 키를 사용하여 비밀 파일을 지정합니다.
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
이 구성은 Docker Compose를 사용하여 서비스를 시작할 때 비밀을 사용할 수 있게 합니다.

Kubernetes 환경에서는 비밀을 기본적으로 지원하며 [Helm-Secrets](https://github.com/futuresimple/helm-secrets)와 같은 도구로 추가로 관리할 수 있습니다. Kubernetes의 Role Based Access Controls (RBAC)는 Docker Enterprise와 유사한 비밀 관리 보안을 강화합니다.

### gVisor

**gVisor**는 Go로 작성된 응용 프로그램 커널로, Linux 시스템 표면의 상당 부분을 구현합니다. 이는 애플리케이션과 호스트 커널 사이의 격리 경계를 제공하는 [Open Container Initiative (OCI)](https://www.opencontainers.org) 런타임인 `runsc`를 포함합니다. `runsc` 런타임은 Docker와 Kubernetes와 통합되어 샌드박스 컨테이너를 간편하게 실행할 수 있도록 합니다.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers**는 가벼운 가상 머신을 사용하여 컨테이너와 유사한 성능을 제공하면서 **하드웨어 가상화 기술을 사용하여 더 강력한 워크로드 격리**를 제공하려는 오픈 소스 커뮤니티입니다.

{% embed url="https://katacontainers.io/" %}

### 요약 팁

* **`--privileged` 플래그를 사용하지 마세요.** [**컨테이너 내부에 Docker 소켓을 마운트하지 마세요**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Docker 소켓은 컨테이너를 생성하는 데 사용되므로 `--privileged` 플래그를 사용하여 다른 컨테이너를 실행하는 것과 같이 호스트를 완전히 제어하는 간단한 방법입니다.
* **컨테이너 내부에서 root로 실행하지 마세요.** [**다른 사용자**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **와** [**사용자 네임스페이스**](https://docs.docker.com/engine/security/userns-remap/)**를 사용하세요.** 컨테이너 내부의 root는 사용자 네임스페이스로 재매핑되지 않는 한 호스트와 동일합니다. 주로 Linux 네임스페이스, 기능 및 cgroups에 의해 약간 제한됩니다.
* [**모든 기능을 삭제하세요**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) 및 필요한 기능만 활성화하세요** (`--cap-add=...`). 많은 워크로드는 어떤 기능도 필요로하지 않으며, 기능을 추가하면 잠재적인 공격 범위가 증가합니다.
* [**“no-new-privileges” 보안 옵션을 사용하세요**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)**.** 이를 통해 프로세스가 suid 이진 파일을 통해 권한을 더 얻는 것을 방지할 수 있습니다.
* [**컨테이너에 사용 가능한 리소스를 제한하세요**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** 리소스 제한은 서비스 거부 공격으로부터 시스템을 보호할 수 있습니다.
* **[seccomp](https://docs.docker.com/engine/security/seccomp/)**, **[AppArmor](https://docs.docker.com/engine/security/apparmor/)** (또는 SELinux) 프로필을 조정하여 컨테이너에 대해 사용 가능한 작업 및 시스콜을 최소한으로 제한하세요.
* [**공식 Docker 이미지**](https://docs.docker.com/docker-hub/official\_images/) **를 사용하고 서명을 요구하세요** 또는 해당 이미지를 기반으로 직접 빌드하세요. 상속받거나 [backdoored](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) 이미지를 사용하지 마세요. 또한 루트 키와 암호를 안전한 장소에 저장하세요. Docker는 UCP를 사용하여 키를 관리할 계획입니다.
* **정기적으로 이미지를 다시 빌드하여 호스트 및 이미지에 보안 패치를 적용하세요.**
* **비밀을 현명하게 관리하세요**. 공격자가 액세스하기 어렵도록 보호하세요.
* Docker 데몬을 노출하는 경우 HTTPS를 사용하여 클라이언트 및 서버 인증을 수행하세요.
* Dockerfile에서 **ADD 대신 COPY를 사용하세요**. ADD는 자동으로 압축 파일을 추출하고 URL에서 파일을 복사할 수 있습니다. COPY는 이러한 기능을 갖고 있지 않습니다. 가능한 경우, 원격 URL 및 Zip 파일을 통한 공격에 취약하지 않도록 ADD 사용을 피하세요.
* 각 마이크로 서비스에 **별도의 컨테이너를 사용하세요**.
* 컨테이너 내부에 **ssh를 설치하지 마세요**. "docker exec"를 사용하여 컨테이너에 ssh를 사용할 수 있습니다.
* **더 작은** 컨테이너 **이미지를 사용하세요**

## Docker Breakout / Privilege Escalation

Docker 컨테이너 내부에 있거나 **docker 그룹의 사용자에게 액세스 권한이 있는 경우**, **탈출 및 권한 상승**을 시도할 수 있습니다:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker Authentication Plugin Bypass

Docker 소켓에 액세스하거나 **docker 그룹의 사용자에게 액세스 권한이 있지만 docker 인증 플러그인에 의해 작업이 제한되는 경우**, **우회할 수 있는지 확인하세요**:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Docker 강화

* [**docker-bench-security**](https://github.com/docker/docker-bench-security) 도구는 프로덕션 환경에서 Docker 컨테이너를 배포하는 데 관련된 수십 가지 일반적인 모범 사례를 확인하는 스크립트입니다. 이러한 테스트는 모두 자동화되며 [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/)을 기반으로 합니다.\
도커를 실행하는 호스트 또는 충분한 권한을 갖춘 컨테이너에서
다른 방법으로 HackTricks를 지원할 수 있습니다:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기술을 공유하세요.

</details>
