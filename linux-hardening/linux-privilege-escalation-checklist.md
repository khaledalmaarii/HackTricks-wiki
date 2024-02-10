# 체크리스트 - Linux 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요. 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

경험있는 해커와 버그 바운티 헌터와 소통하기 위해 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

**해킹 인사이트**\
해킹의 스릴과 도전을 다루는 콘텐츠와 상호 작용하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계를 따라가세요.

**최신 공지사항**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대한 정보를 받아보세요.

**[Discord](https://discord.com/invite/N3FrSbmwdy)에 참여하여 최고의 해커들과 협업을 시작하세요!**

### **Linux 로컬 권한 상승 벡터를 찾기 위한 최고의 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [시스템 정보](privilege-escalation/#system-information)

* [ ] **OS 정보** 가져오기
* [ ] [**PATH**](privilege-escalation/#path) 확인, **쓰기 가능한 폴더**가 있는지 확인
* [ ] [**환경 변수**](privilege-escalation/#env-info) 확인, 민감한 세부 정보가 있는지 확인
* [ ] 스크립트를 사용하여 [**커널 취약점**](privilege-escalation/#kernel-exploits) 검색 (DirtyCow 등)
* [ ] [**sudo 버전**이 취약한지 확인](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** 서명 검증 실패](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] 추가 시스템 열거 (날짜, 시스템 통계, CPU 정보, 프린터 등)(privilege-escalation/#more-system-enumeration)
* [ ] [더 많은 방어 기능 열거](privilege-escalation/#enumerate-possible-defenses)

### [드라이브](privilege-escalation/#drives)

* [ ] 마운트된 드라이브 목록 확인
* [ ] 마운트되지 않은 드라이브가 있는지 확인
* [ ] fstab에 자격 증명이 있는지 확인

### [설치된 소프트웨어](privilege-escalation/#installed-software)

* [ ] [설치된 유용한 소프트웨어](privilege-escalation/#useful-software) 확인
* [ ] [취약한 소프트웨어](privilege-escalation/#vulnerable-software-installed) 확인

### [프로세스](privilege-escalation/#processes)

* [ ] 알 수 없는 소프트웨어가 실행 중인지 확인
* [ ] 소프트웨어가 **해당하는 것보다 더 많은 권한으로 실행**되고 있는지 확인
* [ ] 실행 중인 프로세스의 취약점 (특히 버전) 검색
* [ ] 실행 중인 프로세스의 이진 파일을 수정할 수 있는지 확인
* [ ] 프로세스를 모니터링하고 자주 실행되는 흥미로운 프로세스가 있는지 확인
* [ ] 패스워드가 저장될 수 있는 흥미로운 프로세스 메모리를 **읽을 수** 있는지 확인

### [예약된/Cron 작업](privilege-escalation/#scheduled-jobs)

* [ ] 어떤 cron에서 [**PATH**](privilege-escalation/#cron-path)가 수정되어 **쓰기**가 가능한지 확인할 수 있나요?
* [ ] 크론 작업에 [**와일드카드**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)가 있나요?
* [ ] **실행 중인 스크립트**가 있거나 **수정 가능한 폴더**에 있는지 확인할 수 있나요?
* [ ] 어떤 스크립트가 매우 **자주 실행**되고 있는지 감지했나요? (1분, 2분 또는 5분마다)

### [서비스](privilege-escalation/#services)

* [ ] **쓰기 가능한 .service** 파일이 있나요?
* [ ] **서비스**에 의해 실행되는 **쓰기 가능한 이진 파일**이 있나요?
* [ ] **systemd PATH**에 **쓰기 가능한 폴더**가 있나요?

### [타이머](privilege-escalation/#timers)

* [ ] **쓰기 가능한 타이머**가 있나요?

### [소켓](privilege-escalation/#sockets)

* [ ] **쓰기 가능한 .socket** 파일이 있나요?
* [ ] **소켓**과 통신할 수 있나요?
* [ ] 흥미로운 정보가 있는 **HTTP 소켓**이 있나요?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] **D-Bus**와 통신할 수 있나요?

### [네트워크](privilege-escalation/#network)

* [ ] 현재 위치를 알기 위해 네트워크 열거
* [ ] 쉘을 획득하기 전에 액세스할 수 없었던 **열린 포트**가 있나요?
* [ ] `tcpdump`를 사용하여 트래픽을 **스니핑**할 수 있나요?

### [사용자](privilege-escalation/#users)

* [ ] 일반 사용자/그룹 **열거**
* [ ] **매우 큰 UID
### [Capabilities](privilege-escalation/#capabilities)

* [ ] 어떤 이진 파일이 **예상치 못한 능력**을 가지고 있나요?

### [ACLs](privilege-escalation/#acls)

* [ ] 어떤 파일이 **예상치 못한 ACL**을 가지고 있나요?

### [Open Shell sessions](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH 흥미로운 구성 값**](privilege-escalation/#ssh-interesting-configuration-values)

### [흥미로운 파일들](privilege-escalation/#interesting-files)

* [ ] **프로필 파일** - 민감한 데이터를 읽을 수 있나요? 권한 상승을 위해 쓸 수 있나요?
* [ ] **passwd/shadow 파일** - 민감한 데이터를 읽을 수 있나요? 권한 상승을 위해 쓸 수 있나요?
* [ ] **흥미로운 폴더들**에서 민감한 데이터를 확인하세요.
* [ ] **이상한 위치/소유 파일** - 실행 파일에 액세스하거나 변경할 수 있습니다.
* [ ] **최근에 수정된** 파일
* [ ] **Sqlite DB 파일**
* [ ] **숨겨진 파일**
* [ ] **PATH에 있는 스크립트/바이너리**
* [ ] **웹 파일** (비밀번호?)
* [ ] **백업**?
* [ ] **비밀번호를 포함하는 알려진 파일**: **Linpeas**와 **LaZagne**을 사용하세요.
* [ ] **일반적인 검색**

### [**쓰기 가능한 파일들**](privilege-escalation/#writable-files)

* [ ] 임의의 명령을 실행하기 위해 **파이썬 라이브러리를 수정**할 수 있나요?
* [ ] **로그 파일을 수정**할 수 있나요? **Logtotten** exploit
* [ ] **/etc/sysconfig/network-scripts/를 수정**할 수 있나요? Centos/Redhat exploit
* [ ] [**ini, int.d, systemd 또는 rc.d 파일에 쓸 수 있나요**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**기타 트릭**](privilege-escalation/#other-tricks)

* [ ] 권한 상승을 위해 **NFS를 악용**할 수 있나요? (privilege-escalation/#nfs-privilege-escalation)
* [ ] **제한적인 쉘에서 탈출**해야 하나요? (privilege-escalation/#escaping-from-restricted-shells)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

경험있는 해커와 버그 바운티 헌터와 소통하려면 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

**해킹 인사이트**\
해킹의 스릴과 도전을 다루는 콘텐츠에 참여하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계를 따라가세요.

**최신 공지사항**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대해 알아두세요.

**[Discord](https://discord.com/invite/N3FrSbmwdy)**에 가입하여 최고의 해커들과 협업을 시작하세요!

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
