# PID 네임스페이스

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

## 기본 정보

PID (Process IDentifier) 네임스페이스는 Linux 커널의 기능으로, 프로세스 그룹이 다른 네임스페이스와 별개의 고유한 PID 세트를 가질 수 있도록 하여 프로세스 격리를 제공합니다. 이는 컨테이너화에서 특히 중요한 보안 및 자원 관리를 위해 프로세스 격리를 가능하게 합니다.

새로운 PID 네임스페이스가 생성되면, 해당 네임스페이스의 첫 번째 프로세스는 PID 1이 할당됩니다. 이 프로세스는 새로운 네임스페이스의 "init" 프로세스가 되며, 네임스페이스 내의 다른 프로세스를 관리하는 역할을 담당합니다. 네임스페이스 내에서 생성되는 각 후속 프로세스는 해당 네임스페이스 내에서 고유한 PID를 가지며, 이러한 PID는 다른 네임스페이스의 PID와 독립적입니다.

PID 네임스페이스 내의 프로세스 관점에서는, 동일한 네임스페이스 내의 다른 프로세스만 볼 수 있습니다. 다른 네임스페이스의 프로세스를 인식하지 못하며, 전통적인 프로세스 관리 도구 (예: `kill`, `wait` 등)를 사용하여 해당 프로세스와 상호 작용할 수 없습니다. 이는 프로세스 간의 간섭을 방지하는 수준의 격리를 제공합니다.

### 작동 방식:

1. 새로운 프로세스가 생성될 때 (`clone()` 시스템 호출을 사용하여), 해당 프로세스는 새로운 또는 기존의 PID 네임스페이스에 할당될 수 있습니다. **새로운 네임스페이스가 생성되면, 해당 프로세스는 해당 네임스페이스의 "init" 프로세스가 됩니다**.
2. **커널**은 새로운 네임스페이스의 PID와 부모 네임스페이스 (즉, 새로운 네임스페이스가 생성된 네임스페이스)의 해당 PID 간의 **매핑을 유지**합니다. 이 매핑은 프로세스 간에 신호를 보낼 때와 같이 필요한 경우 커널이 PID를 변환할 수 있도록 합니다.
3. **PID 네임스페이스 내의 프로세스는 동일한 네임스페이스 내의 다른 프로세스만 볼 수 있으며 상호 작용**할 수 있습니다. 다른 네임스페이스의 프로세스를 인식하지 못하며, 해당 프로세스의 PID는 해당 네임스페이스 내에서 고유합니다.
4. **PID 네임스페이스가 파괴**될 때 (예: 네임스페이스의 "init" 프로세스가 종료될 때), 해당 네임스페이스 내의 모든 프로세스가 종료됩니다. 이는 네임스페이스와 관련된 모든 리소스가 올바르게 정리되도록 보장합니다.

## Lab:

### 다른 네임스페이스 생성

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>오류: bash: fork: 메모리를 할당할 수 없습니다</summary>

`unshare`를 `-f` 옵션 없이 실행하면, Linux가 새로운 PID (프로세스 ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 아래에 문제의 내용과 해결책이 설명되어 있습니다:

1. **문제 설명**:
- Linux 커널은 `unshare` 시스템 호출을 사용하여 프로세스가 새로운 네임스페이스를 생성할 수 있게 합니다. 그러나 새로운 PID 네임스페이스를 생성하는 프로세스(이를 "unshare" 프로세스라고 함)는 새로운 네임스페이스로 진입하지 않습니다. 오직 그 프로세스의 자식 프로세스만이 새로운 네임스페이스에 속합니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스는 원래의 PID 네임스페이스에 속하게 됩니다.
- 새로운 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없다면 네임스페이스를 정리하게 되는데, PID 1은 고아 프로세스를 책임지는 특별한 역할을 가지고 있습니다. Linux 커널은 그런 경우 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:
- 새로운 네임스페이스에서 PID 1이 종료되면 `PIDNS_HASH_ADDING` 플래그가 정리됩니다. 이로 인해 `alloc_pid` 함수가 새로운 프로세스를 생성할 때 새로운 PID를 할당하지 못하고 "메모리를 할당할 수 없습니다" 오류가 발생합니다.

3. **해결책**:
- `-f` 옵션을 `unshare`와 함께 사용하여 이 문제를 해결할 수 있습니다. 이 옵션은 `unshare`가 새로운 PID 네임스페이스를 생성한 후에 새로운 프로세스를 포크합니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령어 자체가 새로운 네임스페이스에서 PID 1이 되게 됩니다. 그러면 `/bin/bash`와 그 자식 프로세스는 이 새로운 네임스페이스 안에 안전하게 포함되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당이 가능해집니다.

`unshare`가 `-f` 플래그와 함께 실행되도록 보장함으로써, 새로운 PID 네임스페이스가 올바르게 유지되어 `/bin/bash`와 그 하위 프로세스가 메모리 할당 오류를 겪지 않고 작동할 수 있습니다.

</details>

`--mount-proc` 매개변수를 사용하여 `/proc` 파일 시스템의 새로운 인스턴스를 마운트함으로써, 새로운 마운트 네임스페이스는 해당 네임스페이스에 특정한 프로세스 정보에 대한 정확하고 격리된 뷰를 가지게 됩니다.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;어떤 네임스페이스에 프로세스가 있는지 확인하기

To check which namespace your process is in, you can use the following command:

프로세스가 어떤 네임스페이스에 있는지 확인하려면 다음 명령을 사용할 수 있습니다:

```bash
cat /proc/$$/ns/pid
```

This command will display the inode number of the PID namespace associated with your process.

이 명령은 프로세스와 관련된 PID 네임스페이스의 inode 번호를 표시합니다.
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### 모든 PID 네임스페이스 찾기

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

초기 (기본) PID 네임스페이스에서의 root 사용자는 새로운 PID 네임스페이스에 있는 프로세스들을 포함하여 모든 프로세스를 볼 수 있습니다. 그래서 우리는 모든 PID 네임스페이스를 볼 수 있습니다.

### PID 네임스페이스 안으로 들어가기
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
기본 네임스페이스에서 PID 네임스페이스로 진입하면 여전히 모든 프로세스를 볼 수 있습니다. 그리고 해당 PID 네임스페이스의 프로세스는 PID 네임스페이스에서의 새로운 bash를 볼 수 있습니다.

또한, **루트 권한이 있는 경우에만 다른 프로세스 PID 네임스페이스로 진입할 수 있습니다**. 그리고 **`/proc/self/ns/pid`와 같은 디스크립터가 가리키는 네임스페이스가 없는 경우에는 다른 네임스페이스로 진입할 수 없습니다**.

## 참고 자료
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
