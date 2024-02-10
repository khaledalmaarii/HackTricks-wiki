# 체크리스트 - 로컬 Windows 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

### **Windows 로컬 권한 상승 벡터를 찾는 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [시스템 정보](windows-local-privilege-escalation/#system-info)

* [ ] [**시스템 정보**](windows-local-privilege-escalation/#system-info)를 얻으세요.
* [ ] 스크립트를 사용하여 **커널** [**exploit을 검색**](windows-local-privilege-escalation/#version-exploits)하세요.
* **Google을 사용하여** 커널 **exploit을 검색**하세요.
* **searchsploit을 사용하여** 커널 **exploit을 검색**하세요.
* [**환경 변수**](windows-local-privilege-escalation/#environment)에 흥미로운 정보가 있나요?
* [**PowerShell 히스토리**](windows-local-privilege-escalation/#powershell-history)에 비밀번호가 있나요?
* [**인터넷 설정**](windows-local-privilege-escalation/#internet-settings)에 흥미로운 정보가 있나요?
* [**드라이브**](windows-local-privilege-escalation/#drives)를 확인하세요.
* [**WSUS exploit**](windows-local-privilege-escalation/#wsus)을 확인하세요.
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)을 확인하세요.

### [로그/AV 열거](windows-local-privilege-escalation/#enumeration)

* [**감사**](windows-local-privilege-escalation/#audit-settings) 및 [**WEF**](windows-local-privilege-escalation/#wef) 설정을 확인하세요.
* [**LAPS**](windows-local-privilege-escalation/#laps)를 확인하세요.
* [**WDigest**](windows-local-privilege-escalation/#wdigest)가 활성화되어 있는지 확인하세요.
* [**LSA Protection**](windows-local-privilege-escalation/#lsa-protection)을 확인하세요.
* [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)를 확인하세요.
* [**Cached Credentials**](windows-local-privilege-escalation/#cached-credentials)를 확인하세요.
* 어떤 [**AV**](windows-av-bypass)가 있는지 확인하세요.
* [**AppLocker 정책**](authentication-credentials-uac-and-efs#applocker-policy)을 확인하세요.
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)을 확인하세요.
* [**사용자 권한**](windows-local-privilege-escalation/#users-and-groups)을 확인하세요.
* [**현재 사용자 권한**](windows-local-privilege-escalation/#users-and-groups)을 확인하세요.
* 어떤 **특권 그룹의 구성원**인지 확인하세요.
* 다음 토큰 중 하나가 활성화되어 있는지 확인하세요: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [**사용자 세션**](windows-local-privilege-escalation/#logged-users-sessions)을 확인하세요.
* [**사용자 홈**](windows-local-privilege-escalation/#home-folders)을 확인하세요. (접근 가능한지?)
* [**비밀번호 정책**](windows-local-privilege-escalation/#password-policy)을 확인하세요.
* [**클립보드 내용**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)은 무엇인가요?

### [네트워크](windows-local-privilege-escalation/#network)

* [**현재 네트워크 정보**](windows-local-privilege-escalation/#network)를 확인하세요.
* 외부에 제한된 **숨겨진 로컬 서비스**를 확인하세요.

### [실행 중인 프로세스](windows-local-privilege-escalation/#running-processes)

* 프로세스 이진 파일과 폴더의 [**파일 및 폴더 권한**](windows-local-privilege-escalation/#file-and-folder-permissions)을 확인하세요.
* [**메모리 비밀번호 마이닝**](windows-local-privilege-escalation/#memory-password-mining)을 확인하세요.
* [**보안이 취약한 GUI 앱**](windows-local-privilege-escalation/#insecure-gui-apps)을 확인하세요.

### [서비스](windows-local-privilege-escalation/#services)

* [**서비스를 수정**할 수 있나요?](windows-local-privilege-escalation#permissions)
* [**서비스**가 **실행**하는 **바이너리**를 **수정**할 수 있나요?](windows-local-privilege-escalation/#modify-service-binary-path)
* [**서비스**의 **레지스트리**를 **수정**할 수 있나요?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [**unquoted service** 바이너리 **경로**를 이용할 수 있나요?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**응용 프로그램**](windows-local-privilege-escalation/#applications)

* 설치된 응용 프로그램의 [**쓰기 권한**](windows-local-privilege-escalation/#write-permissions)을 확인하세요.
* [**시작 프로그램**](windows-local-privilege-escalation/#run-at-startup)을 확인하세요.
* [**취약한 드라이버**](windows-local-privilege-escalation/#drivers)를 확인하세요.

### [DLL 하이재킹](windows-local-privilege-escalation/#path-dll-hijacking)

* **PATH 내의 어떤 폴더에 쓸 수 있나요**?
* 알려진 서비스 바이너리 중에서 **존재하지 않는 DLL을 로드**하려고 하는 것이 있나요?
* **바이너리 폴더**에 **쓸 수 있나요**?
### [네트워크](windows-local-privilege-escalation/#network)

* [ ] 네트워크 열거하기 (공유, 인터페이스, 경로, 이웃 등)
* [ ] 로컬호스트(127.0.0.1)에서 수신 대기 중인 네트워크 서비스에 특별히 주목하기

### [Windows 자격 증명](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)자격 증명
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault)에서 사용할 수 있는 자격 증명?
* [ ] 흥미로운 [**DPAPI 자격 증명**](windows-local-privilege-escalation/#dpapi)?
* [ ] 저장된 [**Wifi 네트워크의 비밀번호**](windows-local-privilege-escalation/#wifi)?
* [ ] [**저장된 RDP 연결**](windows-local-privilege-escalation/#saved-rdp-connections)에 흥미로운 정보가 있나요?
* [ ] [**최근 실행한 명령어**](windows-local-privilege-escalation/#recently-run-commands)에 비밀번호가 있나요?
* [ ] [**원격 데스크톱 자격 증명 관리자**](windows-local-privilege-escalation/#remote-desktop-credential-manager)의 비밀번호?
* [ ] [**AppCmd.exe**가 존재](windows-local-privilege-escalation/#appcmd-exe)하는가? 자격 증명?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL 사이드 로딩?

### [파일 및 레지스트리 (자격 증명)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**자격 증명**](windows-local-privilege-escalation/#putty-creds) **및** [**SSH 호스트 키**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] 레지스트리에 있는 [**SSH 키**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] [**자동화되지 않은 파일**](windows-local-privilege-escalation/#unattended-files)에 비밀번호가 있나요?
* [ ] [**SAM 및 SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) 백업이 있나요?
* [ ] [**클라우드 자격 증명**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) 파일?
* [ ] [**Cached GPP Password**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] [**IIS 웹 구성 파일**](windows-local-privilege-escalation/#iis-web-config)에 비밀번호가 있나요?
* [ ] [**웹 로그**](windows-local-privilege-escalation/#logs)에 흥미로운 정보가 있나요?
* [ ] 사용자에게 [**자격 증명을 요청**](windows-local-privilege-escalation/#ask-for-credentials)하고 싶나요?
* [ ] [**휴지통에 있는 파일**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)에 흥미로운 파일이 있나요?
* [ ] [**자격 증명을 포함하는 레지스트리**](windows-local-privilege-escalation/#inside-the-registry)가 있나요?
* [ ] [**브라우저 데이터**](windows-local-privilege-escalation/#browsers-history) (데이터베이스, 기록, 즐겨찾기 등) 안에 흥미로운 정보가 있나요?
* [ ] 파일 및 레지스트리에서의 [**일반적인 비밀번호 검색**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)
* [ ] 비밀번호를 자동으로 검색하는 [**도구**](windows-local-privilege-escalation/#tools-that-search-for-passwords)

### [유출된 핸들러](windows-local-privilege-escalation/#leaked-handlers)

* [ ] 관리자가 실행한 프로세스의 핸들러에 액세스할 수 있나요?

### [파이프 클라이언트 위장](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] 이를 악용할 수 있는지 확인하기

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks를 다운로드**하려면 [**구독 플랜**](https://github.com/sponsors/carlospolop)을 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
