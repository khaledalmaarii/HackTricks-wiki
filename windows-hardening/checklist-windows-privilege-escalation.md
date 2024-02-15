# 체크리스트 - 로컬 Windows 권한 상슨

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 AWS 해킹을 제로부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원하신다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* 여러분의 해킹 요령을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소로 PR을 제출하세요.

</details>

### **Windows 로컬 권한 상슨 벡터를 찾는 데 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [시스템 정보](windows-local-privilege-escalation/#system-info)

* [ ] [**시스템 정보**](windows-local-privilege-escalation/#system-info) 획득
* [ ] **스크립트를 사용하여** **커널** [**악용 찾기**](windows-local-privilege-escalation/#version-exploits)
* **Google을 사용하여** 커널 **악용 검색**
* **searchsploit을 사용하여** 커널 **악용 검색**
* [**환경 변수**](windows-local-privilege-escalation/#environment)에 흥미로운 정보?
* [**PowerShell 히스토리**](windows-local-privilege-escalation/#powershell-history)에 비밀번호?
* [**인터넷 설정**](windows-local-privilege-escalation/#internet-settings)에 흥미로운 정보?
* [**드라이브**](windows-local-privilege-escalation/#drives)?
* [**WSUS 악용**](windows-local-privilege-escalation/#wsus)?
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [로깅/AV 열거](windows-local-privilege-escalation/#enumeration)

* [**감사**](windows-local-privilege-escalation/#audit-settings) 및 [**WEF**](windows-local-privilege-escalation/#wef) 설정 확인
* [**LAPS**](windows-local-privilege-escalation/#laps) 확인
* [**WDigest**](windows-local-privilege-escalation/#wdigest)가 활성화되어 있는지 확인
* [**LSA 보호**](windows-local-privilege-escalation/#lsa-protection)?
* [**자격 증명 보호**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [**캐시된 자격 증명**](windows-local-privilege-escalation/#cached-credentials) 확인?
* 어떤 [**AV**](windows-av-bypass)가 있는지 확인
* [**AppLocker 정책**](authentication-credentials-uac-and-efs#applocker-policy) 확인?
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control) 확인
* [**사용자 권한**](windows-local-privilege-escalation/#users-and-groups) 확인
* [**현재** 사용자 **권한**](windows-local-privilege-escalation/#users-and-groups) 확인
* [**특권 그룹의 구성원**](windows-local-privilege-escalation/#privileged-groups)인지 확인
* **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** 중 어떤 토큰이 활성화되어 있는지 확인?
* [**사용자 세션**](windows-local-privilege-escalation/#logged-users-sessions) 확인?
* [**사용자 홈**](windows-local-privilege-escalation/#home-folders) 확인 (접근?)
* [**암호 정책**](windows-local-privilege-escalation/#password-policy) 확인
* [**클립보드 내용**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) 확인?

### [네트워크](windows-local-privilege-escalation/#network)

* **현재** [**네트워크 정보**](windows-local-privilege-escalation/#network) 확인
* 외부로 제한된 **숨겨진 로컬 서비스** 확인

### [실행 중인 프로세스](windows-local-privilege-escalation/#running-processes)

* 프로세스 이진 파일 및 폴더 권한 [**확인**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**메모리 암호 채굴**](windows-local-privilege-escalation/#memory-password-mining)
* [**보안되지 않은 GUI 앱**](windows-local-privilege-escalation/#insecure-gui-apps)
* `ProcDump.exe`를 통해 **흥미로운 프로세스**에서 자격 증명을 도용할 수 있나요? (firefox, chrome 등...)

### [서비스](windows-local-privilege-escalation/#services)

* [**서비스를 수정할 수 있는지**](windows-local-privilege-escalation#permissions) 확인
* **서비스**가 실행하는 **이진 파일을 수정할 수 있는지** 확인
* **서비스**의 **레지스트리를 수정할 수 있는지** 확인
* **언인용된 서비스** 이진 **경로를 이용할 수 있는지** 확인

### [**응용 프로그램**](windows-local-privilege-escalation/#applications)

* 설치된 응용 프로그램에 대한 **쓰기 권한** 확인
* [**시작 프로그램**](windows-local-privilege-escalation/#run-at-startup) 확인
* **취약한** [**드라이버**](windows-local-privilege-escalation/#drivers) 확인

### [DLL 하이재킹](windows-local-privilege-escalation/#path-dll-hijacking)

* **PATH 내의 모든 폴더에 쓸 수 있는지** 확인
* 알려진 서비스 이진 파일 중 **존재하지 않는 DLL을 로드하려고 하는 것이 있는지** 확인
* **바이너리 폴더**에 **쓸 수 있는지** 확인
### [네트워크](windows-local-privilege-escalation/#network)

* [ ] 네트워크 열거 (공유, 인터페이스, 경로, 이웃, ...)
* [ ] 로컬호스트(127.0.0.1)에서 수신 대기 중인 네트워크 서비스를 특별히 확인

### [Windows 자격 증명](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials) 자격 증명
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) 사용 가능한 자격 증명?
* [ ] 흥미로운 [**DPAPI 자격 증명**](windows-local-privilege-escalation/#dpapi)?
* [ ] 저장된 [**Wifi 네트워크**](windows-local-privilege-escalation/#wifi)의 비밀번호?
* [ ] 저장된 RDP 연결에서 흥미로운 정보?
* [ ] [**최근 실행된 명령어**](windows-local-privilege-escalation/#recently-run-commands)에서의 비밀번호?
* [ ] [**원격 데스크톱 자격 증명 관리자**](windows-local-privilege-escalation/#remote-desktop-credential-manager) 비밀번호?
* [ ] [**AppCmd.exe**가 존재](windows-local-privilege-escalation/#appcmd-exe)하는지 확인? 자격 증명?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL 사이드 로딩?

### [파일 및 레지스트리 (자격 증명)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**자격 증명**](windows-local-privilege-escalation/#putty-creds) 및 [**SSH 호스트 키**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] 레지스트리에 있는 [**SSH 키**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] [**자동화 파일**](windows-local-privilege-escalation/#unattended-files)에서의 비밀번호?
* [ ] [**SAM 및 SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) 백업이 있는지 확인?
* [ ] [**클라우드 자격 증명**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) 파일?
* [**캐시된 GPP 비밀번호**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [**IIS 웹 구성 파일**](windows-local-privilege-escalation/#iis-web-config)에서의 비밀번호?
* [**웹 로그**](windows-local-privilege-escalation/#logs)에서 흥미로운 정보?
* 사용자에게 [**자격 증명 요청**](windows-local-privilege-escalation/#ask-for-credentials)을 하고 싶은가?
* 휴지통에 있는 [**파일**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)에서 흥미로운 정보?
* 다른 [**자격 증명이 포함된 레지스트리**](windows-local-privilege-escalation/#inside-the-registry)?
* [**브라우저 데이터**](windows-local-privilege-escalation/#browsers-history) 내부 (데이터베이스, 히스토리, 즐겨찾기, ...)?
* 파일 및 레지스트리에서의 [**일반적인 비밀번호 검색**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)
* 자동으로 비밀번호를 검색하는 [**도구**](windows-local-privilege-escalation/#tools-that-search-for-passwords)

### [유출된 핸들러](windows-local-privilege-escalation/#leaked-handlers)

* [ ] 관리자가 실행한 프로세스의 핸들러에 액세스할 수 있는가?

### [파이프 클라이언트 위장](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] 남용할 수 있는지 확인하기
