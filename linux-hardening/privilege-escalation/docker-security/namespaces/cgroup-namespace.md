# CGroup Namespace

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로에서 영웅까지 AWS 해킹을 배워보세요</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 기본 정보

cgroup 네임스페이스는 **네임스페이스 내에서 실행되는 프로세스의 cgroup 계층 구조를 격리**하는 Linux 커널 기능입니다. **control groups**의 약자인 cgroups는 CPU, 메모리, I/O와 같은 **시스템 리소스에 대한 제한을 관리하고 강제로 적용**할 수 있는 커널 기능입니다.

cgroup 네임스페이스는 PID, 마운트, 네트워크 등과 같은 다른 네임스페이스 유형과는 달리 별도의 네임스페이스 유형은 아니지만, 네임스페이스 격리 개념과 관련이 있습니다. **cgroup 네임스페이스는 cgroup 계층 구조의 뷰를 가상화**하여, cgroup 네임스페이스 내에서 실행되는 프로세스는 호스트 또는 다른 네임스페이스에서 실행되는 프로세스와는 다른 계층 구조 뷰를 가집니다.

### 작동 방식:

1. 새로운 cgroup 네임스페이스가 생성되면, **생성 프로세스의 cgroup을 기반으로 cgroup 계층 구조의 뷰로 시작**합니다. 이는 cgroup 네임스페이스 내에서 실행되는 프로세스가 전체 cgroup 계층 구조의 하위 집합만 볼 수 있도록 제한됨을 의미합니다.
2. cgroup 네임스페이스 내의 프로세스는 **자신의 cgroup을 계층 구조의 루트로 볼 수** 있습니다. 이는 네임스페이스 내부의 프로세스 관점에서 자신의 cgroup이 루트로 표시되며, 자신의 하위 트리 외의 cgroup에는 액세스할 수 없음을 의미합니다.
3. cgroup 네임스페이스는 리소스의 격리를 직접 제공하지 않습니다. **리소스 제어와 격리는 cgroup** 서브시스템(예: cpu, 메모리 등)에 의해 여전히 적용됩니다.

CGroups에 대한 자세한 정보는 다음을 참조하세요:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Lab:

### 다른 네임스페이스 생성

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
`--mount-proc` 매개변수를 사용하여 `/proc` 파일 시스템의 새로운 인스턴스를 마운트함으로써, 새로운 마운트 네임스페이스가 해당 네임스페이스에 특정한 프로세스 정보에 대한 정확하고 격리된 뷰를 가지도록 보장합니다.

<details>

<summary>오류: bash: fork: 메모리를 할당할 수 없음</summary>

`unshare`를 `-f` 옵션 없이 실행하면, Linux가 새로운 PID (프로세스 ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 주요 세부 정보와 해결 방법은 아래와 같습니다:

1. **문제 설명**:
- Linux 커널은 `unshare` 시스템 호출을 사용하여 프로세스가 새로운 네임스페이스를 생성할 수 있게 합니다. 그러나 새로운 PID 네임스페이스를 생성하는 프로세스( "unshare" 프로세스라고 함)는 새로운 네임스페이스로 진입하지 않습니다. 오직 그 자식 프로세스들만이 진입합니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스들은 원래의 PID 네임스페이스에 속합니다.
- 새로운 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없다면 해당 네임스페이스를 정리하게 되는데, PID 1은 고아 프로세스를 책임지는 특별한 역할을 가지기 때문입니다. Linux 커널은 그런 다음 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:
- 새로운 네임스페이스에서 PID 1이 종료되면 `PIDNS_HASH_ADDING` 플래그가 정리됩니다. 이로 인해 `alloc_pid` 함수가 새로운 프로세스를 생성할 때 새로운 PID를 할당하지 못하고 "메모리를 할당할 수 없음" 오류가 발생합니다.

3. **해결 방법**:
- `-f` 옵션을 `unshare`와 함께 사용하여 이 문제를 해결할 수 있습니다. 이 옵션은 `unshare`가 새로운 PID 네임스페이스를 생성한 후에 새로운 프로세스를 포크합니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령 자체가 새로운 네임스페이스에서 PID 1이 되도록 보장됩니다. 그러면 `/bin/bash`와 그 자식 프로세스들은 이 새로운 네임스페이스 안에 안전하게 포함되어, PID 1의 조기 종료를 방지하고 정상적인 PID 할당이 가능해집니다.

`unshare`가 `-f` 플래그와 함께 실행되도록 보장함으로써, 새로운 PID 네임스페이스가 올바르게 유지되어 `/bin/bash`와 그 하위 프로세스들이 메모리 할당 오류를 겪지 않고 작동할 수 있습니다.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;현재 프로세스가 속한 네임스페이스 확인

To check which namespace your process is in, you can use the following command:

현재 프로세스가 속한 네임스페이스를 확인하려면 다음 명령을 사용할 수 있습니다:

```bash
cat /proc/$$/cgroup
```

This command will display the control groups associated with the current process. The output will include a line that starts with `0::/`, which indicates the cgroup namespace.

이 명령은 현재 프로세스와 관련된 컨트롤 그룹을 표시합니다. 출력에는 `0::/`로 시작하는 줄이 포함되어 있으며, 이는 cgroup 네임스페이스를 나타냅니다.
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### 모든 CGroup 네임스페이스 찾기

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### CGroup 네임스페이스 안으로 들어가기

{% endcode %}
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
또한, 당신은 root 권한이 있어야만 다른 프로세스 네임스페이스로 진입할 수 있습니다. 그리고 `/proc/self/ns/cgroup`와 같은 디스크립터가 가리키는 다른 네임스페이스로 진입할 수 없습니다.

## 참고 자료
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 당신의 해킹 기교를 공유하세요.

</details>
