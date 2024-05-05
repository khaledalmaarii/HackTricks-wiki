# CGroups

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 영웅까지 AWS 해킹 배우기</strong>!</summary>

다른 방법으로 HackTricks를 지원하는 방법:

- **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks 다운로드**를 원한다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 기본 정보

**Linux Control Groups** 또는 **cgroups**는 Linux 커널의 기능으로, CPU, 메모리 및 디스크 I/O와 같은 시스템 리소스의 할당, 제한 및 우선 순위를 프로세스 그룹 간에 허용합니다. 이들은 프로세스 모음의 **리소스 사용량을 관리하고 격리하는 메커니즘**을 제공하여 리소스 제한, 작업 부분 격리 및 다른 프로세스 그룹 간의 리소스 우선 순위 설정과 같은 목적에 유용합니다.

**cgroups에는 두 가지 버전**이 있습니다: 버전 1과 버전 2. 두 버전을 시스템에서 동시에 사용할 수 있습니다. 주요 차이점은 **cgroups 버전 2**가 **계층적인 트리 구조**를 도입하여 프로세스 그룹 간에 더 세밀하고 자세한 리소스 분배를 가능하게 한다는 것입니다. 또한 버전 2는 다음과 같은 여러 개선 사항을 포함한 다양한 향상을 가져왔습니다:

새로운 계층적 구성뿐만 아니라 cgroups 버전 2는 **다른 여러 변경 사항과 개선 사항**을 도입했으며, **새로운 리소스 컨트롤러 지원**, 레거시 응용 프로그램에 대한 더 나은 지원 및 향상된 성능을 제공합니다.

전반적으로 **cgroups 버전 2는 버전 1보다 더 많은 기능과 성능을 제공**하지만, 호환성 문제로 인해 일부 구형 시스템과의 호환성이 필요한 특정 시나리오에서는 여전히 버전 1을 사용할 수 있습니다.

모든 프로세스의 v1 및 v2 cgroups를 나열하려면 /proc/\<pid>의 cgroup 파일을 확인하여 시작할 수 있습니다. 이 명령을 사용하여 셸의 cgroups를 확인할 수 있습니다:
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
### cgroups 보기

파일 시스템은 일반적으로 **cgroups**에 액세스하는 데 사용되며, 일반적으로 커널 상호 작용에 사용되는 Unix 시스템 호출 인터페이스와 다릅니다. 셸의 cgroup 구성을 조사하려면 셸의 cgroup을 나타내는 **/proc/self/cgroup** 파일을 확인해야 합니다. 그런 다음 **/sys/fs/cgroup** (또는 **`/sys/fs/cgroup/unified`**) 디렉토리로 이동하여 cgroup 이름을 공유하는 디렉토리를 찾으면 해당 cgroup에 관련된 다양한 설정 및 리소스 사용 정보를 확인할 수 있습니다.

![Cgroup 파일 시스템](<../../../.gitbook/assets/image (1128).png>)

cgroups의 주요 인터페이스 파일은 **cgroup**로 접두사가 붙습니다. 일반적인 명령어인 cat과 같은 표준 명령어로 볼 수 있는 **cgroup.procs** 파일은 cgroup 내의 프로세스를 나열합니다. 다른 파일인 **cgroup.threads**에는 스레드 정보가 포함됩니다.

![Cgroup 프로세스](<../../../.gitbook/assets/image (281).png>)

셸을 관리하는 cgroups는 일반적으로 메모리 사용량과 프로세스 수를 규제하는 두 개의 컨트롤러를 포함합니다. 컨트롤러와 상호 작용하려면 컨트롤러의 접두사가 붙은 파일을 참조해야 합니다. 예를 들어 **pids.current**는 cgroup 내 스레드 수를 확인하기 위해 참조될 것입니다.

![Cgroup 메모리](<../../../.gitbook/assets/image (677).png>)

값에 **max**가 표시되면 cgroup에 특정 제한이 없음을 나타냅니다. 그러나 cgroups의 계층 구조로 인해 디렉토리 계층 구조의 낮은 수준에서 cgroup에 의해 제한이 가해질 수 있습니다.

### cgroups 조작 및 생성

프로세스는 **그들의 프로세스 ID (PID)를 `cgroup.procs` 파일에 쓰는 것**으로 cgroups에 할당됩니다. 이 작업에는 루트 권한이 필요합니다. 예를 들어, 프로세스를 추가하려면:
```bash
echo [pid] > cgroup.procs
```
비슷하게, **PID 제한을 설정하는 것과 같이 cgroup 속성을 수정**하려면 원하는 값을 관련 파일에 작성하여 수행됩니다. cgroup에 3,000개의 PID를 최대로 설정하려면:
```bash
echo 3000 > pids.max
```
**새 cgroups 생성**은 cgroup 계층 구조 내에서 새 하위 디렉토리를 만드는 것을 포함하며, 이는 커널이 필요한 인터페이스 파일을 자동으로 생성하도록 합니다. 활성 프로세스가 없는 cgroups는 `rmdir`로 제거할 수 있지만 다음과 같은 제약 사항을 인지해야 합니다:

* **프로세스는 leaf cgroups에만 배치될 수 있습니다** (즉, 계층 구조에서 가장 중첩된 cgroups).
* **cgroup은 부모에 없는 컨트롤러를 가질 수 없습니다**.
* **자식 cgroups의 컨트롤러는** `cgroup.subtree_control` **파일에서 명시적으로 선언되어야 합니다**. 예를 들어, 자식 cgroup에서 CPU 및 PID 컨트롤러를 활성화하려면:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**루트 cgroup**은 이러한 규칙의 예외로, 직접 프로세스 배치를 허용합니다. 이를 사용하여 프로세스를 systemd 관리에서 제거할 수 있습니다.

cgroup 내에서 **CPU 사용량 모니터링**은 `cpu.stat` 파일을 통해 가능하며, 총 CPU 시간이 표시되어 서비스의 하위 프로세스 간 사용량을 추적하는 데 도움이 됩니다:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>cpu.stat 파일에 표시된 CPU 사용량 통계</p></figcaption></figure>

## 참고 자료

* **책: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**
