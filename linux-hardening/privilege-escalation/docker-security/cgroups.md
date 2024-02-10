# CGroups

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

## 기본 정보

**Linux Control Groups** 또는 **cgroups**는 Linux 커널의 기능으로, CPU, 메모리 및 디스크 I/O와 같은 시스템 리소스의 할당, 제한 및 우선 순위 설정을 가능하게 합니다. 이들은 프로세스 그룹 간의 **리소스 사용량을 관리하고 격리하는 메커니즘**을 제공하여 리소스 제한, 작업 부하 격리 및 다른 프로세스 그룹 간의 리소스 우선 순위 설정과 같은 목적에 유용합니다.

**cgroups에는 두 가지 버전**이 있습니다: 버전 1과 버전 2. 이 두 가지는 시스템에서 동시에 사용할 수 있습니다. 주요한 차이점은 **cgroups 버전 2**가 **계층적인 트리 구조**를 도입하여 프로세스 그룹 간의 더 세밀하고 자세한 리소스 분배를 가능하게 한다는 것입니다. 또한 버전 2는 다음과 같은 다양한 개선 사항을 포함하여 여러 가지 개선 사항을 가져왔습니다:

새로운 계층 구조 외에도 cgroups 버전 2는 **다른 여러 변경 사항과 개선 사항**을 도입했습니다. 이에는 **새로운 리소스 컨트롤러 지원**, 레거시 애플리케이션에 대한 더 나은 지원 및 성능 향상이 포함됩니다.

전반적으로 cgroups **버전 2는 버전 1보다 더 많은 기능과 더 나은 성능**을 제공하지만, 이전 시스템과의 호환성이 문제가 되는 경우에는 여전히 버전 1을 사용할 수 있습니다.

/proc/\<pid>의 cgroup 파일을 확인하여 어떤 프로세스의 v1 및 v2 cgroups를 나열할 수 있습니다. 다음 명령을 사용하여 셸의 cgroups를 확인할 수 있습니다:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
출력 구조는 다음과 같습니다:

- **숫자 2-12**: 각 줄은 다른 cgroup을 나타내며, 이들에 대한 컨트롤러는 숫자 옆에 지정됩니다.
- **숫자 1**: 또한 cgroups v1이지만, 관리 목적으로만 사용되며 (예: systemd에 의해 설정됨), 컨트롤러가 없습니다.
- **숫자 0**: cgroups v2를 나타냅니다. 컨트롤러가 나열되지 않으며, 이 줄은 cgroups v2만 실행되는 시스템에서만 사용됩니다.
- **이름은 계층적**으로 구성되어 있으며, 파일 경로와 유사하게 나열되어 다른 cgroup 간의 구조와 관계를 나타냅니다.
- **/user.slice 또는 /system.slice와 같은 이름**은 cgroup의 분류를 지정하며, 일반적으로 user.slice는 systemd에 의해 관리되는 로그인 세션에 사용되고, system.slice는 시스템 서비스에 사용됩니다.

### cgroups 보기

파일 시스템은 일반적으로 커널 상호작용에 전통적으로 사용되는 Unix 시스템 호출 인터페이스와 달리, **cgroups에 액세스하기 위해 사용**됩니다. 셸의 cgroup 구성을 조사하려면, **/proc/self/cgroup** 파일을 확인해야 합니다. 이 파일은 셸의 cgroup을 나타냅니다. 그런 다음, **/sys/fs/cgroup** (또는 **`/sys/fs/cgroup/unified`**) 디렉토리로 이동하여 cgroup의 이름을 공유하는 디렉토리를 찾으면, 해당 cgroup과 관련된 다양한 설정 및 리소스 사용 정보를 확인할 수 있습니다.

![Cgroup Filesystem](../../../.gitbook/assets/image%20(10)%20(2)%20(2).png)

cgroups의 주요 인터페이스 파일은 **cgroup**로 접두사가 붙습니다. 일반적인 cat과 같은 명령을 사용하여 볼 수 있는 **cgroup.procs** 파일은 cgroup 내의 프로세스를 나열합니다. 또 다른 파일인 **cgroup.threads**에는 스레드 정보가 포함되어 있습니다.

![Cgroup Procs](../../../.gitbook/assets/image%20(1)%20(1)%20(5).png)

셸을 관리하는 cgroups는 일반적으로 메모리 사용량과 프로세스 수를 조절하는 두 개의 컨트롤러를 포함합니다. 컨트롤러와 상호작용하기 위해서는 해당 컨트롤러의 접두사를 가진 파일을 참조해야 합니다. 예를 들어, **pids.current**는 cgroup 내의 스레드 수를 확인하기 위해 참조될 수 있습니다.

![Cgroup Memory](../../../.gitbook/assets/image%20(3)%20(5).png)

값에 **max**가 표시되면, 해당 cgroup에 특정 제한이 없음을 나타냅니다. 그러나 cgroups의 계층적 특성으로 인해, 제한은 디렉토리 계층 구조의 하위 수준에서 cgroup에 의해 부과될 수 있습니다.


### cgroups 조작 및 생성

프로세스는 **`cgroup.procs` 파일에 프로세스 ID (PID)를 작성함으로써** cgroups에 할당됩니다. 이 작업은 root 권한이 필요합니다. 예를 들어, 프로세스를 추가하려면:
```bash
echo [pid] > cgroup.procs
```
마찬가지로, **PID 제한 설정과 같은 cgroup 속성 수정**은 해당 파일에 원하는 값을 작성하여 수행됩니다. cgroup에 최대 3,000개의 PID를 설정하려면 다음과 같이 합니다:
```bash
echo 3000 > pids.max
```
**새로운 cgroups 생성**은 cgroup 계층 내에서 새로운 하위 디렉토리를 만드는 것을 의미하며, 이로 인해 커널은 필요한 인터페이스 파일을 자동으로 생성합니다. 프로세스가 없는 cgroups는 `rmdir`을 사용하여 제거할 수 있지만, 다음과 같은 제약 사항을 유의해야 합니다:

- **프로세스는 leaf cgroups에만 배치될 수 있습니다** (즉, 계층 구조에서 가장 중첩된 cgroup).
- **cgroup은 부모에게 없는 컨트롤러를 가질 수 없습니다**.
- **자식 cgroup의 컨트롤러는 명시적으로 `cgroup.subtree_control` 파일에 선언되어야 합니다**. 예를 들어, CPU와 PID 컨트롤러를 자식 cgroup에서 활성화하려면:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**루트 cgroup**은 이러한 규칙에서 예외로, 직접적인 프로세스 배치를 허용합니다. 이를 통해 프로세스를 systemd 관리에서 제거하는 데 사용할 수 있습니다.

cgroup 내에서 **CPU 사용량 모니터링**은 `cpu.stat` 파일을 통해 가능하며, 총 CPU 사용 시간을 표시하여 서비스의 하위 프로세스 간 사용량을 추적하는 데 도움이 됩니다:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption>cpu.stat 파일에 표시된 CPU 사용량 통계</figcaption></figure>

## 참고 자료
* **책: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
