# CGroups

{% hint style="success" %}
AWS 해킹을 배우고 실습하세요: [**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)\
GCP 해킹을 배우고 실습하세요: [**HackTricks Training GCP Red Team Expert (GRTE)**](https://training.hacktricks.xyz/courses/grte)
</details>
{% endhint %}

## 기본 정보

**Linux Control Groups**, 또는 **cgroups**,는 Linux 커널의 기능으로, CPU, 메모리 및 디스크 I/O와 같은 시스템 리소스의 할당, 제한 및 우선 순위를 프로세스 그룹 간에 허용합니다. 이들은 프로세스 모음의 **리소스 사용을 관리하고 격리하는 메커니즘**을 제공하여 리소스 제한, 작업 부분 격리 및 다른 프로세스 그룹 간의 리소스 우선 순위 설정과 같은 목적에 유용합니다.

**cgroups에는 두 가지 버전**이 있습니다: 버전 1과 버전 2. 두 버전을 시스템에서 동시에 사용할 수 있습니다. 주요 차이점은 **cgroups 버전 2**가 **계층적인 트리 구조**를 도입하여 프로세스 그룹 간에 더 세밀하고 자세한 리소스 분배를 가능케 한다는 것입니다. 또한 버전 2는 다음과 같은 여러 향상된 기능을 포함하여 다양한 개선 사항을 가져왔습니다:

새로운 계층적 구성뿐만 아니라 cgroups 버전 2는 **다른 여러 변경 사항과 개선 사항**을 도입했으며, 새로운 리소스 컨트롤러 지원, 레거시 응용 프로그램에 대한 더 나은 지원 및 향상된 성능을 포함합니다.

전반적으로, cgroups **버전 2는 버전 1보다 더 많은 기능과 성능을 제공**하지만, 이후자는 호환성 문제로 인해 일부 구형 시스템과의 호환성이 필요한 특정 시나리오에서 여전히 사용될 수 있습니다.

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
* **숫자 2-12**: cgroups v1, 각 줄은 다른 cgroup을 나타냅니다. 해당 cgroup의 컨트롤러는 숫자 옆에 지정됩니다.
* **숫자 1**: 또한 cgroups v1이지만, 주로 관리 목적으로 사용됩니다 (예: systemd에 의해 설정됨) 그리고 컨트롤러가 없습니다.
* **숫자 0**: cgroups v2를 나타냅니다. 컨트롤러가 나열되지 않으며, 이 줄은 cgroups v2만 실행되는 시스템에서만 사용됩니다.
* **이름은 계층적**이며 파일 경로와 유사하여 다른 cgroups 간의 구조와 관계를 나타냅니다.
* **/user.slice 또는 /system.slice**와 같은 이름은 cgroups의 분류를 지정하며, user.slice는 주로 systemd에 의해 관리되는 로그인 세션에 대한 것이고, system.slice는 시스템 서비스에 대한 것입니다.

### cgroups 보기

파일 시스템은 일반적으로 커널 상호작용에 전통적으로 사용되던 Unix 시스템 호출 인터페이스에서 벗어나 **cgroups**에 액세스하는 데 사용됩니다. 셸의 cgroup 구성을 조사하려면 셸의 cgroup을 나타내는 **/proc/self/cgroup** 파일을 살펴봐야 합니다. 그런 다음 **/sys/fs/cgroup** (또는 **`/sys/fs/cgroup/unified`**) 디렉토리로 이동하여 cgroup 이름을 공유하는 디렉토리를 찾으면 해당 cgroup에 관련된 다양한 설정 및 리소스 사용 정보를 확인할 수 있습니다.

![Cgroup Filesystem](<../../../.gitbook/assets/image (1128).png>)

cgroups의 주요 인터페이스 파일은 **cgroup**로 접두사가 붙습니다. 일반적인 명령어인 cat과 같은 표준 명령을 사용하여 볼 수 있는 **cgroup.procs** 파일은 cgroup 내의 프로세스를 나열합니다. 또 다른 파일인 **cgroup.threads**에는 스레드 정보가 포함되어 있습니다.

![Cgroup Procs](<../../../.gitbook/assets/image (281).png>)

셸을 관리하는 cgroups는 일반적으로 메모리 사용량과 프로세스 수를 규제하는 두 개의 컨트롤러를 포함합니다. 컨트롤러와 상호작용하려면 해당 컨트롤러의 접두사가 붙은 파일을 참조해야 합니다. 예를 들어, **pids.current**는 cgroup 내 스레드 수를 확인하기 위해 참조될 수 있습니다.

![Cgroup Memory](<../../../.gitbook/assets/image (677).png>)

값에 **max**가 표시되면 해당 cgroup에 특정 제한이 없음을 나타냅니다. 그러나 cgroups의 계층적 특성으로 인해 제한이 디렉토리 계층 구조의 낮은 수준에서 적용될 수 있습니다.

### cgroups 조작 및 생성

프로세스는 **그들의 프로세스 ID (PID)를 `cgroup.procs` 파일에 쓰는 것**으로 cgroups에 할당됩니다. 이 작업에는 루트 권한이 필요합니다. 예를 들어, 프로세스를 추가하려면:
```bash
echo [pid] > cgroup.procs
```
비슷하게, **PID 제한을 설정하는 것과 같이 cgroup 속성을 수정**하려면 원하는 값을 관련 파일에 작성하여 수행됩니다. cgroup에 3,000개의 PID를 최대로 설정하려면:
```bash
echo 3000 > pids.max
```
**새 cgroups 생성**은 cgroup 계층 구조 내에서 새 하위 디렉토리를 만드는 것을 의미하며, 이는 커널이 필요한 인터페이스 파일을 자동으로 생성하도록 합니다. 활성 프로세스가 없는 cgroups는 `rmdir`로 제거할 수 있지만 다음과 같은 제약 사항을 인지해야 합니다:

* **프로세스는 리프 cgroups에만 배치될 수 있습니다** (즉, 계층 구조에서 가장 중첩된 위치).
* **cgroup은 부모에게 없는 컨트롤러를 가질 수 없습니다**.
* **자식 cgroups의 컨트롤러는 `cgroup.subtree_control` 파일에서 명시적으로 선언되어야 합니다**. 예를 들어, 자식 cgroup에서 CPU 및 PID 컨트롤러를 활성화하려면:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**루트 cgroup**은 이러한 규칙의 예외로, 직접 프로세스 배치를 허용합니다. 이를 사용하여 프로세스를 systemd 관리에서 제거할 수 있습니다.

cgroup 내에서 **CPU 사용량 모니터링**은 `cpu.stat` 파일을 통해 가능하며, 총 CPU 시간 소비를 표시하여 서비스의 하위 프로세스 간 사용량을 추적하는 데 도움이 됩니다:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>cpu.stat 파일에 표시된 CPU 사용량 통계</p></figcaption></figure>

## 참고 자료

* **책: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**
