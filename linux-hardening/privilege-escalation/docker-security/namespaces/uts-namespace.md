# UTS 네임스페이스

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 기본 정보

UTS (UNIX Time-Sharing System) 네임스페이스는 Linux 커널 기능으로, 두 개의 시스템 식별자인 **호스트 이름**과 **NIS** (Network Information Service) 도메인 이름을 **분리**합니다. 이 분리는 각 UTS 네임스페이스가 **독립적인 호스트 이름과 NIS 도메인 이름**을 가질 수 있도록 해줍니다. 이는 컨테이너화 시나리오에서 각 컨테이너가 별도의 시스템으로 보이기 위해 특히 유용합니다.

### 작동 방식:

1. 새로운 UTS 네임스페이스가 생성되면, **부모 네임스페이스로부터 호스트 이름과 NIS 도메인 이름의 사본을 가져옵니다**. 이는 새로운 네임스페이스가 생성될 때, **새로운 네임스페이스가 부모와 동일한 식별자를 공유**한다는 것을 의미합니다. 그러나 네임스페이스 내에서 호스트 이름이나 NIS 도메인 이름을 변경하더라도 다른 네임스페이스에는 영향을 주지 않습니다.
2. UTS 네임스페이스 내의 프로세스는 `sethostname()` 및 `setdomainname()` 시스템 호출을 사용하여 호스트 이름과 NIS 도메인 이름을 **변경**할 수 있습니다. 이러한 변경 사항은 네임스페이스 내에서만 적용되며 다른 네임스페이스나 호스트 시스템에는 영향을 주지 않습니다.
3. 프로세스는 `setns()` 시스템 호출을 사용하여 네임스페이스 간 이동하거나 `unshare()` 또는 `clone()` 시스템 호출을 사용하여 `CLONE_NEWUTS` 플래그와 함께 새로운 네임스페이스를 생성할 수 있습니다. 프로세스가 새로운 네임스페이스로 이동하거나 생성할 때 해당 네임스페이스와 관련된 호스트 이름과 NIS 도메인 이름을 사용하기 시작합니다.

## Lab:

### 다른 네임스페이스 생성

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
`--mount-proc` 매개변수를 사용하여 `/proc` 파일 시스템의 새로운 인스턴스를 마운트함으로써, 새로운 마운트 네임스페이스가 해당 네임스페이스에 특정한 프로세스 정보의 정확하고 격리된 뷰를 가지도록 보장합니다.

<details>

<summary>오류: bash: fork: 메모리 할당 불가능</summary>

`-f` 옵션 없이 `unshare`를 실행하면, Linux가 새로운 PID (프로세스 ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 주요 세부 정보와 해결 방법은 아래에 설명되어 있습니다:

1. **문제 설명**:
- Linux 커널은 `unshare` 시스템 호출을 사용하여 프로세스가 새로운 네임스페이스를 생성할 수 있게 합니다. 그러나 새로운 PID 네임스페이스를 생성하는 프로세스( "unshare" 프로세스라고 함)는 새로운 네임스페이스로 진입하지 않습니다. 오직 그 자식 프로세스들만이 진입합니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스들은 원래의 PID 네임스페이스에 속합니다.
- 새로운 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없다면 네임스페이스를 정리하게 되는데, PID 1은 고아 프로세스를 책임지는 특별한 역할을 가지고 있습니다. 그러면 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:
- 새로운 네임스페이스에서 PID 1이 종료되면 `PIDNS_HASH_ADDING` 플래그가 정리되어버립니다. 이로 인해 `alloc_pid` 함수가 새로운 프로세스를 생성할 때 새로운 PID를 할당하지 못하고 "메모리 할당 불가능" 오류가 발생합니다.

3. **해결 방법**:
- `-f` 옵션을 `unshare`와 함께 사용하여 이 문제를 해결할 수 있습니다. 이 옵션은 `unshare`가 새로운 PID 네임스페이스를 생성한 후에 새로운 프로세스를 fork합니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령어 자체가 새로운 네임스페이스에서 PID 1이 되도록 보장됩니다. 그러면 `/bin/bash`와 그 자식 프로세스들은 이 새로운 네임스페이스 안에 안전하게 포함되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당이 가능해집니다.

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
$ ls -l /proc/$$/ns
```

This command will display a list of namespaces that your process is currently a part of. The output will include the inode numbers of each namespace file.

이 명령은 현재 프로세스가 현재 속한 네임스페이스 목록을 표시합니다. 출력에는 각 네임스페이스 파일의 inode 번호가 포함됩니다.
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### 모든 UTS 네임스페이스 찾기

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### UTS 네임스페이스 안으로 들어가기
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
또한, 루트 권한이 있어야만 다른 프로세스 네임스페이스로 진입할 수 있습니다. 그리고 `/proc/self/ns/uts`와 같은 디스크립터가 가리키는 다른 네임스페이스로 디스크립터 없이는 진입할 수 없습니다.

### 호스트 이름 변경하기
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
## 참고 자료
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왑**](https://peass.creator-spring.com)을 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
