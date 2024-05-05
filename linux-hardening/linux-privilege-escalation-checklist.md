# 체크리스트 - Linux 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원하신다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **우리와 함께하세요** 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하고 싶다면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

경험 많은 해커 및 버그 바운티 헌터들과 소통하려면 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 가입하세요!

**해킹 통찰력**\
해킹의 즐거움과 도전에 대해 탐구하는 콘텐츠와 상호 작용

**실시간 해킹 뉴스**\
빠르게 변화하는 해킹 세계의 최신 뉴스와 통찰력을 유지하세요

**최신 공지**\
출시되는 최신 버그 바운티 및 중요한 플랫폼 업데이트에 대해 알아두세요

**우리와 함께** [**Discord**](https://discord.com/invite/N3FrSbmwdy)에 가입하여 최고의 해커들과 협업을 시작하세요!

### **Linux 로컬 권한 상승 벡터를 찾는 데 가장 좋은 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [시스템 정보](privilege-escalation/#system-information)

* [ ] **OS 정보** 가져오기
* [ ] [**PATH**](privilege-escalation/#path) 확인, **쓰기 가능한 폴더**가 있는지 확인
* [ ] [**환경 변수**](privilege-escalation/#env-info) 확인, 민감한 세부 정보가 있는지 확인
* [**스크립트를 사용하여**](privilege-escalation/#kernel-exploits) **커널 익스플로잇** 검색 (DirtyCow?)
* [ ] [**sudo 버전**이 취약한지 확인](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** 서명 검증 실패](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] 추가 시스템 열거 ([날짜, 시스템 통계, CPU 정보, 프린터](privilege-escalation/#more-system-enumeration))
* [ ] [방어 기능 추가 열거](privilege-escalation/#enumerate-possible-defenses)

### [드라이브](privilege-escalation/#drives)

* [ ] 마운트된 드라이브 목록
* [ ] 마운트되지 않은 드라이브가 있나요?
* [ ] fstab에 자격 증명이 있나요?

### [**설치된 소프트웨어**](privilege-escalation/#installed-software)

* [**설치된 유용한 소프트웨어**](privilege-escalation/#useful-software) 확인
* [**설치된 취약한 소프트웨어**](privilege-escalation/#vulnerable-software-installed) 확인

### [프로세스](privilege-escalation/#processes)

* [ ] 알 수 없는 소프트웨어가 실행 중인가요?
* [ ] 권한보다 더 많은 권한으로 실행 중인 소프트웨어가 있나요?
* [ ] 실행 중인 프로세스의 **익스플로잇** 검색 (특히 실행 중인 버전)
* [ ] 실행 중인 프로세스의 **바이너리**를 수정할 수 있나요?
* [ ] 프로세스를 **모니터링**하고 자주 실행되는 흥미로운 프로세스가 있는지 확인하세요.
* [ ] 흥미로운 **프로세스 메모리**를 읽을 수 있나요 (비밀번호가 저장될 수 있는 위치)?

### [예약/Cron 작업?](privilege-escalation/#scheduled-jobs)

* [ ] 어떤 cron이 [**PATH**](privilege-escalation/#cron-path)를 수정하고 쓸 수 있는지 확인하세요.
* [ ] 크론 작업에 **와일드카드**가 있나요?
* [ ] 실행 중인 **스크립트**가 있거나 **수정 가능한 폴더**에 있는 스크립트가 실행 중인가요?
* [ ] 어떤 **스크립트**가 매우 **자주 실행**되고 있는지 감지했나요? (1, 2 또는 5분마다)

### [서비스](privilege-escalation/#services)

* [ ] **쓰기 가능한 .service** 파일이 있나요?
* [ ] **서비스**에 의해 실행되는 **쓰기 가능한 바이너리**가 있나요?
* [ ] systemd PATH에 **쓰기 가능한 폴더**가 있나요?

### [타이머](privilege-escalation/#timers)

* [ ] **쓰기 가능한 타이머**가 있나요?

### [소켓](privilege-escalation/#sockets)

* [ ] **쓰기 가능한 .socket** 파일이 있나요?
* [ ] 어떤 소켓과 **통신**할 수 있나요?
* [ ] 흥미로운 정보가 있는 **HTTP 소켓**이 있나요?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] 어떤 D-Bus와 **통신**할 수 있나요?

### [네트워크](privilege-escalation/#network)

* 네트워크를 열거하여 현재 위치를 파악하세요
* 쉘을 획들한 후 **접근할 수 없었던 포트**를 열었나요?
* `tcpdump`를 사용하여 **트래픽을 스니핑**할 수 있나요?

### [사용자](privilege-escalation/#users)

* 일반 사용자/그룹 **열거**
* **매우 큰 UID**를 가지고 있나요? **머신**이 **취약**한가요?
* 소속한 그룹을 통해 **권한 상승**할 수 있나요?
* **클립보드** 데이터?
* 암호 정책?
* 이전에 발견한 모든 **알려진 암호**를 사용하여 각 **가능한 사용자**로 로그인해 보세요. 암호 없이도 로그인을 시도해 보세요.

### [쓰기 가능한 PATH](privilege-escalation/#writable-path-abuses)

* **PATH의 일부 폴더에 쓰기 권한**이 있다면 권한 상승이 가능할 수 있습니다

### [SUDO 및 SUID 명령](privilege-escalation/#sudo-and-suid)

* **sudo로** **명령을 실행**할 수 있나요? ROOT로 **읽기, 쓰기 또는 실행**할 수 있나요? ([**GTFOBins**](https://gtfobins.github.io))
* **익스플로잇 가능한 SUID 바이너리**가 있나요? ([**GTFOBins**](https://gtfobins.github.io))
* [**sudo 명령이 경로로 제한**되었나요? 제한을 **우회**할 수 있나요](privilege-escalation/#sudo-execution-bypassing-paths)?
* [**명령 경로를 지정하지 않은 sudo/SUID 바이너리**가 있나요](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [**경로를 지정한 SUID 바이너리**](privilege-escalation/#suid-binary-with-command-path)? 우회
* [**LD\_PRELOAD 취약점**](privilege-escalation/#ld\_preload)
* 쓰기 가능한 폴더에서 **SUID 바이너리에 .so 라이브러리가 없는 경우**](privilege-escalation/#suid-binary-so-injection)가 있나요?
* [**SUDO 토큰**을 사용할 수 있나요](privilege-escalation/#reusing-sudo-tokens)? [**SUDO 토큰을 생성**할 수 있나요](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [**sudoers 파일을 읽거나 수정**할 수 있나요](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [**/etc/ld.so.conf.d/**를 수정할 수 있나요](privilege-escalation/#etc-ld-so-conf-d)?
* [**OpenBSD DOAS**](privilege-escalation/#doas) 명령
### [권한](privilege-escalation/#capabilities)

* [ ] 어떤 이진 파일이 **예상치 못한 권한**을 갖고 있습니까?

### [ACLs](privilege-escalation/#acls)

* [ ] 어떤 파일이 **예상치 못한 ACL**을 갖고 있습니까?

### [열린 쉘 세션](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH 흥미로운 구성 값**](privilege-escalation/#ssh-interesting-configuration-values)

### [흥미로운 파일](privilege-escalation/#interesting-files)

* [ ] **프로필 파일** - 민감한 데이터 읽기? 권한 상승을 위해 쓰기?
* [ ] **passwd/shadow 파일** - 민감한 데이터 읽기? 권한 상승을 위해 쓰기?
* [ ] **민감한 데이터가 있는 일반적으로 흥미로운 폴더** 확인
* [ ] **이상한 위치/소유 파일**, 실행 파일에 액세스하거나 변경할 수 있음
* [ ] **최근 수정됨**
* [ ] **Sqlite DB 파일**
* [ ] **숨겨진 파일**
* [ ] **경로에 있는 스크립트/바이너리**
* [ ] **웹 파일** (비밀번호?)
* [ ] **백업**?
* [ ] **비밀번호를 포함하는 알려진 파일**: **Linpeas** 및 **LaZagne** 사용
* [ ] **일반적인 검색**

### [**쓰기 가능한 파일**](privilege-escalation/#writable-files)

* [ ] **파이썬 라이브러리 수정**하여 임의 명령 실행 가능?
* [ ] **로그 파일 수정** 가능한가? **Logtotten** exploit
* [ ] **/etc/sysconfig/network-scripts/**를 **수정**할 수 있나요? Centos/Redhat exploit
* [ ] [**ini, int.d, systemd 또는 rc.d 파일에 쓸 수 있나요**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**기타 요령**](privilege-escalation/#other-tricks)

* [ ] [**권한 상승을 위해 NFS 남용 가능**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] **제한적인 쉘에서 탈출**해야 하나요?
