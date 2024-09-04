# 체크리스트 - 로컬 Windows 권한 상승

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

### **Windows 로컬 권한 상승 벡터를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [시스템 정보](windows-local-privilege-escalation/#system-info)

* [ ] [**시스템 정보**](windows-local-privilege-escalation/#system-info) 얻기
* [ ] **커널** [**익스플로잇을 스크립트로 검색**](windows-local-privilege-escalation/#version-exploits)
* [ ] **Google로 커널 익스플로잇 검색하기**
* [ ] **searchsploit로 커널 익스플로잇 검색하기**
* [ ] [**환경 변수**](windows-local-privilege-escalation/#environment)에서 흥미로운 정보?
* [ ] [**PowerShell 기록**](windows-local-privilege-escalation/#powershell-history)에서 비밀번호?
* [ ] [**인터넷 설정**](windows-local-privilege-escalation/#internet-settings)에서 흥미로운 정보?
* [ ] [**드라이브**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS 익스플로잇**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [로그/AV 열거](windows-local-privilege-escalation/#enumeration)

* [ ] [**감사**](windows-local-privilege-escalation/#audit-settings) 및 [**WEF**](windows-local-privilege-escalation/#wef) 설정 확인
* [ ] [**LAPS**](windows-local-privilege-escalation/#laps) 확인
* [ ] [**WDigest**](windows-local-privilege-escalation/#wdigest)가 활성화되어 있는지 확인
* [ ] [**LSA 보호**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**자격 증명 가드**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**캐시된 자격 증명**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) 확인
* [ ] [**AppLocker 정책**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
* [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
* [ ] [**사용자 권한**](windows-local-privilege-escalation/#users-and-groups)
* [ ] [**현재** 사용자 **권한**](windows-local-privilege-escalation/#users-and-groups) 확인
* [ ] [**특권 그룹의 구성원**](windows-local-privilege-escalation/#privileged-groups)인가요?
* [ ] [이 토큰 중 어떤 것이 활성화되어 있는지 확인](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**사용자 세션**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] [**사용자 홈**](windows-local-privilege-escalation/#home-folders) 확인 (접근 가능?)
* [ ] [**비밀번호 정책**](windows-local-privilege-escalation/#password-policy) 확인
* [ ] [**클립보드**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) 안에 무엇이 있나요?

### [네트워크](windows-local-privilege-escalation/#network)

* [ ] [**현재** 네트워크 **정보**](windows-local-privilege-escalation/#network) 확인
* [ ] 외부에 제한된 **숨겨진 로컬 서비스** 확인

### [실행 중인 프로세스](windows-local-privilege-escalation/#running-processes)

* [ ] 프로세스 바이너리 [**파일 및 폴더 권한**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**메모리 비밀번호 채굴**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**불안전한 GUI 앱**](windows-local-privilege-escalation/#insecure-gui-apps)
* [ ] `ProcDump.exe`를 통해 **흥미로운 프로세스**로 자격 증명 훔치기? (firefox, chrome 등 ...)

### [서비스](windows-local-privilege-escalation/#services)

* [ ] [어떤 **서비스**를 **수정**할 수 있나요?](windows-local-privilege-escalation/#permissions)
* [ ] [어떤 **서비스**에 의해 **실행되는** **바이너리**를 **수정**할 수 있나요?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [어떤 **서비스**의 **레지스트리**를 **수정**할 수 있나요?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [어떤 **인용되지 않은 서비스** 바이너리 **경로**를 이용할 수 있나요?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**응용 프로그램**](windows-local-privilege-escalation/#applications)

* [ ] **설치된 응용 프로그램에 대한** [**쓰기 권한**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**시작 응용 프로그램**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **취약한** [**드라이버**](windows-local-privilege-escalation/#drivers)

### [DLL 하이재킹](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] **PATH** 내의 어떤 폴더에 **쓰기**할 수 있나요?
* [ ] **존재하지 않는 DLL**을 **로드하려고 시도하는** 알려진 서비스 바이너리가 있나요?
* [ ] 어떤 **바이너리 폴더**에 **쓰기**할 수 있나요?

### [네트워크](windows-local-privilege-escalation/#network)

* [ ] 네트워크 열거 (공유, 인터페이스, 경로, 이웃 등 ...)
* [ ] 로컬호스트(127.0.0.1)에서 수신 대기 중인 네트워크 서비스에 특별히 주목하세요.

### [Windows 자격 증명](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials) 자격 증명
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) 자격 증명을 사용할 수 있나요?
* [ ] 흥미로운 [**DPAPI 자격 증명**](windows-local-privilege-escalation/#dpapi)?
* [ ] 저장된 [**Wifi 네트워크**](windows-local-privilege-escalation/#wifi) 비밀번호?
* [ ] [**저장된 RDP 연결**](windows-local-privilege-escalation/#saved-rdp-connections)에서 흥미로운 정보?
* [ ] [**최근 실행된 명령**](windows-local-privilege-escalation/#recently-run-commands)에서 비밀번호?
* [ ] [**원격 데스크톱 자격 증명 관리자**](windows-local-privilege-escalation/#remote-desktop-credential-manager) 비밀번호?
* [ ] [**AppCmd.exe** 존재](windows-local-privilege-escalation/#appcmd-exe)? 자격 증명?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL 사이드 로딩?

### [파일 및 레지스트리 (자격 증명)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**자격 증명**](windows-local-privilege-escalation/#putty-creds) **및** [**SSH 호스트 키**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**레지스트리의 SSH 키**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] [**비대면 파일**](windows-local-privilege-escalation/#unattended-files)에서 비밀번호?
* [ ] [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) 백업이 있나요?
* [ ] [**클라우드 자격 증명**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) 파일?
* [ ] [**캐시된 GPP 비밀번호**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] [**IIS 웹 구성 파일**](windows-local-privilege-escalation/#iis-web-config)에서 비밀번호?
* [ ] [**웹 로그**](windows-local-privilege-escalation/#logs)에서 흥미로운 정보?
* [ ] 사용자에게 [**자격 증명 요청**](windows-local-privilege-escalation/#ask-for-credentials)하고 싶나요?
* [ ] [**휴지통 안의 흥미로운 파일**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] [**자격 증명 포함 레지스트리**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] [**브라우저 데이터**](windows-local-privilege-escalation/#browsers-history) 안에 (dbs, 기록, 북마크 등)?
* [ ] [**파일 및 레지스트리에서 일반 비밀번호 검색**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry)
* [ ] 비밀번호를 자동으로 검색하는 [**도구**](windows-local-privilege-escalation/#tools-that-search-for-passwords)

### [유출된 핸들러](windows-local-privilege-escalation/#leaked-handlers)

* [ ] 관리자에 의해 실행된 프로세스의 핸들러에 접근할 수 있나요?

### [파이프 클라이언트 가장하기](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] 이를 악용할 수 있는지 확인하세요.

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
