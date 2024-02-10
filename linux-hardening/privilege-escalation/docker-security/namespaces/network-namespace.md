# 네트워크 네임스페이스

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 기본 정보

네트워크 네임스페이스는 Linux 커널 기능으로, **각 네트워크 네임스페이스가 독립적인 네트워크 구성, 인터페이스, IP 주소, 라우팅 테이블 및 방화벽 규칙을 가질 수 있도록 격리**를 제공합니다. 이 격리는 컨테이너화와 같은 다양한 시나리오에서 유용하며, 각 컨테이너가 다른 컨테이너 및 호스트 시스템과 독립적인 네트워크 구성을 가져야 하는 경우에 사용됩니다.

### 작동 방식:

1. 새로운 네트워크 네임스페이스가 생성되면, **완전히 격리된 네트워크 스택**이 시작됩니다. 루프백 인터페이스 (lo)를 제외한 **네트워크 인터페이스가 없습니다**. 이는 새로운 네트워크 네임스페이스에서 실행되는 프로세스가 기본적으로 다른 네임스페이스나 호스트 시스템의 프로세스와 통신할 수 없음을 의미합니다.
2. veth 쌍과 같은 **가상 네트워크 인터페이스**는 네트워크 네임스페이스 간 또는 네임스페이스와 호스트 시스템 간의 네트워크 연결을 설정할 수 있습니다. 예를 들어, veth 쌍의 한쪽 끝을 컨테이너의 네트워크 네임스페이스에 배치하고 다른쪽 끝을 호스트 네임스페이스의 **브리지** 또는 다른 네트워크 인터페이스에 연결하여 컨테이너에 네트워크 연결을 제공할 수 있습니다.
3. 네임스페이스 내의 네트워크 인터페이스는 다른 네임스페이스와 독립적으로 **고유한 IP 주소, 라우팅 테이블 및 방화벽 규칙**을 가질 수 있습니다. 이를 통해 서로 다른 네트워크 네임스페이스의 프로세스는 서로 다른 네트워크 구성을 가지고 별도의 네트워크 시스템에서 실행되는 것처럼 작동할 수 있습니다.
4. 프로세스는 `setns()` 시스템 호출을 사용하여 네임스페이스 간 이동하거나 `unshare()` 또는 `clone()` 시스템 호출을 사용하여 `CLONE_NEWNET` 플래그와 함께 새로운 네임스페이스를 생성할 수 있습니다. 프로세스가 새로운 네임스페이스로 이동하거나 생성할 때 해당 네임스페이스와 관련된 네트워크 구성 및 인터페이스를 사용하기 시작합니다.

## Lab:

### 다른 네임스페이스 생성

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
`--mount-proc` 매개변수를 사용하여 `/proc` 파일 시스템의 새로운 인스턴스를 마운트함으로써, 새로운 마운트 네임스페이스가 해당 네임스페이스에 특정한 프로세스 정보의 정확하고 격리된 뷰를 가지도록 보장합니다.

<details>

<summary>오류: bash: fork: 메모리 할당 불가능</summary>

`unshare`를 `-f` 옵션 없이 실행하면, Linux가 새로운 PID (프로세스 ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 주요 세부 정보와 해결 방법은 아래에 설명되어 있습니다:

1. **문제 설명**:
- Linux 커널은 `unshare` 시스템 호출을 사용하여 프로세스가 새로운 네임스페이스를 생성할 수 있게 합니다. 그러나 새로운 PID 네임스페이스를 생성하는 프로세스( "unshare" 프로세스라고 함)는 새로운 네임스페이스로 진입하지 않습니다. 오직 그 자식 프로세스들만이 진입합니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스들은 원래의 PID 네임스페이스에 속합니다.
- 새로운 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없다면 네임스페이스를 정리하게 되는데, PID 1은 고아 프로세스를 책임지는 특별한 역할을 가지고 있습니다. Linux 커널은 그런 다음 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:
- 새로운 네임스페이스에서 PID 1이 종료되면 `PIDNS_HASH_ADDING` 플래그가 정리되어버립니다. 이로 인해 `alloc_pid` 함수가 새로운 프로세스를 생성할 때 새로운 PID를 할당하지 못하고 "메모리 할당 불가능" 오류가 발생합니다.

3. **해결 방법**:
- `unshare`와 함께 `-f` 옵션을 사용하여 이 문제를 해결할 수 있습니다. 이 옵션은 `unshare`가 새로운 PID 네임스페이스를 생성한 후에 새로운 프로세스를 포크합니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령 자체가 새로운 네임스페이스에서 PID 1이 되도록 보장됩니다. 그러면 `/bin/bash`와 그 자식 프로세스들은 이 새로운 네임스페이스 안에 안전하게 포함되어, PID 1의 조기 종료를 방지하고 정상적인 PID 할당이 가능해집니다.

`unshare`가 `-f` 플래그와 함께 실행되도록 보장함으로써, 새로운 PID 네임스페이스가 올바르게 유지되어 `/bin/bash`와 그 하위 프로세스들이 메모리 할당 오류를 겪지 않고 작동할 수 있습니다.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;현재 프로세스가 어떤 네임스페이스에 있는지 확인하기

To check which namespace your process is in, you can use the `lsns` command. This command lists all the namespaces on the system along with the processes associated with each namespace.

네임스페이스에 속한 현재 프로세스를 확인하려면 `lsns` 명령어를 사용할 수 있습니다. 이 명령어는 시스템의 모든 네임스페이스와 각 네임스페이스에 연결된 프로세스를 나열합니다.

```bash
lsns
```

The output will display information about each namespace, including the namespace ID, type, and number of processes associated with it. Look for the process with the same PID as your current process to determine which namespace it belongs to.

출력 결과에는 각 네임스페이스에 대한 정보가 표시됩니다. 이 정보에는 네임스페이스 ID, 유형 및 해당 네임스페이스에 연결된 프로세스 수가 포함됩니다. 현재 프로세스와 동일한 PID를 가진 프로세스를 찾아 해당 프로세스가 속한 네임스페이스를 확인할 수 있습니다.
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### 모든 네트워크 네임스페이스 찾기

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### 네트워크 네임스페이스 안으로 들어가기

{% endcode %}

To enter inside a network namespace, you can use the `ip` command with the `netns` option. First, list the available network namespaces using the command:

```bash
ip netns list
```

Then, choose the desired network namespace and enter it using the following command:

```bash
ip netns exec <namespace> <command>
```

Replace `<namespace>` with the name of the network namespace you want to enter, and `<command>` with the command you want to execute inside the namespace.

For example, to enter the network namespace named "ns1" and execute the command "ifconfig" inside it, use the following command:

```bash
ip netns exec ns1 ifconfig
```

This will allow you to interact with the network namespace and perform actions as if you were inside it.
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
또한, 당신은 root 권한이 있어야만 다른 프로세스 네임스페이스로 진입할 수 있습니다. 그리고 `/proc/self/ns/net`과 같은 디스크립터가 가리키는 다른 네임스페이스로 들어가지 않으면 안됩니다.

## 참고 자료
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 당신의 해킹 기법을 공유하세요.

</details>
