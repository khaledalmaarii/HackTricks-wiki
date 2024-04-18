<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks를 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, 회사나 고객이 **스틸러 악성 코드**에 의해 **침해**되었는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보 도난 악성 코드로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하고 무료로 엔진을 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

---

# GUI 애플리케이션 내에서 가능한 작업 확인

**일반 대화 상자**는 **파일 저장**, **파일 열기**, 글꼴 선택, 색상 선택 등의 옵션입니다. 대부분의 경우 이러한 옵션을 통해 **탐색기 기능을 제공**합니다. 이는 다음 옵션에 액세스할 수 있다면 탐색기 기능에 액세스할 수 있음을 의미합니다:

* 닫기/닫기로
* 열기/열기로
* 인쇄
* 내보내기/가져오기
* 검색
* 스캔

다음을 확인해야 합니다:

* 파일 수정 또는 새 파일 생성
* 심볼릭 링크 생성
* 제한된 영역에 액세스
* 다른 앱 실행

## 명령 실행

아마도 **`열기로` 옵션을 사용**하여 어떤 종류의 셸을 열거나 실행할 수 있을 것입니다.

### Windows

예를 들어 _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ 여기에서 명령을 실행할 수 있는 더 많은 이진 파일을 찾을 수 있습니다: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ 여기에서 더 많은 것을 찾을 수 있습니다: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## 경로 제한 우회

* **환경 변수**: 특정 경로를 가리키는 많은 환경 변수가 있습니다.
* **기타 프로토콜**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **심볼릭 링크**
* **바로 가기**: CTRL+N (새 세션 열기), CTRL+R (명령 실행), CTRL+SHIFT+ESC (작업 관리자),  Windows+E (탐색기 열기), CTRL-B, CTRL-I (즐겨찾기), CTRL-H (기록), CTRL-L, CTRL-O (파일/열기 대화 상자), CTRL-P (인쇄 대화 상자), CTRL-S (다른 이름으로 저장)
* 숨겨진 관리 메뉴: CTRL-ALT-F8, CTRL-ESC-F9
* **쉘 URI**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC 경로**: 공유 폴더에 연결하는 경로. 로컬 머신의 C$에 연결을 시도해야 합니다 ("\\\127.0.0.1\c$\Windows\System32")
* **더 많은 UNC 경로:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

## 이진 파일 다운로드

콘솔: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
탐색기: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
레지스트리 편집기: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## 브라우저에서 파일 시스템에 액세스

| 경로                | 경로              | 경로               | 경로                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## 바로 가기

* Sticky Keys – SHIFT 5번 누르기
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – NUMLOCK 5초간 누르기
* Filter Keys – 오른쪽 SHIFT 12초간 누르기
* WINDOWS+F1 – Windows 검색
* WINDOWS+D – 데스크톱 보기
* WINDOWS+E – Windows 탐색기 실행
* WINDOWS+R – 실행
* WINDOWS+U – 접근성 센터
* WINDOWS+F – 검색
* SHIFT+F10 – 컨텍스트 메뉴
* CTRL+SHIFT+ESC – 작업 관리자
* CTRL+ALT+DEL – 최신 Windows 버전의 시작 화면
* F1 – 도움말 F3 – 검색
* F6 – 주소 표시줄
* F11 – 인터넷 익스플로러 내에서 전체 화면 전환
* CTRL+H – 인터넷 익스플로러 기록
* CTRL+T – 인터넷 익스플로러 – 새 탭
* CTRL+N – 인터넷 익스플로러 – 새 페이지
* CTRL+O – 파일 열기
* CTRL+S – 저장 CTRL+N – 새 RDP / Citrix
## 스와이프

* 왼쪽에서 오른쪽으로 스와이프하여 모든 열린 창을 볼 수 있으며 KIOSK 앱을 최소화하고 전체 OS에 직접 액세스할 수 있습니다.
* 오른쪽에서 왼쪽으로 스와이프하여 작업 센터를 열고 KIOSK 앱을 최소화하고 전체 OS에 직접 액세스할 수 있습니다.
* 위쪽 가장자리에서 스와이프하여 전체 화면 모드로 열린 앱의 타이틀 바를 표시합니다.
* 아래쪽에서 위쪽으로 스와이프하여 전체 화면 앱에서 작업 표시줄을 표시합니다.

## 인터넷 익스플로러 팁

### '이미지 툴바'

클릭하면 이미지 상단 왼쪽에 나타나는 툴바입니다. 저장, 인쇄, 메일 보내기, 탐색기에서 "내 사진" 열기 등이 가능합니다. 키오스크는 인터넷 익스플로러를 사용해야 합니다.

### 쉘 프로토콜

탐색기 보기를 얻으려면 다음 URL을 입력하십시오:

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> 제어판
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> 내 컴퓨터
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> 내 네트워크 위치
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> 인터넷 익스플로러

## 파일 확장자 표시

자세한 정보는 다음 페이지를 확인하십시오: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# 브라우저 트릭

iKat 버전을 백업합니다:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScript를 사용하여 공통 대화 상자를 만들고 파일 탐색기에 액세스합니다: `document.write('<input/type=file>')`
출처: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## 제스처 및 버튼

* 네 손가락으로 위로 스와이프 / 홈 버튼을 두 번 탭: 멀티태스크 보기 및 앱 변경
* 네 손가락 또는 다섯 손가락으로 한쪽으로 스와이프: 다음/이전 앱으로 변경
* 다섯 손가락으로 화면을 집어넣거나 홈 버튼을 터치하거나 화면 하단에서 위쪽으로 빠르게 스와이프: 홈에 액세스
* 한 손가락으로 화면 하단에서 1-2인치 위로 느리게 스와이프: 독이 나타납니다.
* 한 손가락으로 화면 상단에서 아래로 스와이프: 알림 보기
* 한 손가락으로 화면 오른쪽 상단에서 아래로 스와이프: iPad Pro의 제어 센터 보기
* 화면 왼쪽에서 한 손가락으로 1-2인치 스와이프: 오늘 보기 보기
* 화면 중앙에서 빠르게 오른쪽이나 왼쪽으로 한 손가락으로 스와이프: 다음/이전 앱으로 변경
* iPad 오른쪽 상단의 전원/잠금/취침 버튼을 누르고 오른쪽으로 슬라이드하여 전원을 끕니다: 전원 끄기
* iPad 오른쪽 상단의 전원/잠금/취침 버튼을 누르고 홈 버튼을 몇 초 동안 누릅니다: 강제 종료
* iPad 오른쪽 상단의 전원/잠금/취침 버튼을 누르고 홈 버튼을 빠르게 누릅니다: 화면 하단 왼쪽에 팝업되는 스크린샷을 찍습니다. 두 버튼을 동시에 매우 짧게 누르면 몇 초 동안 강제 종료됩니다.

## 바로 가기

iPad 키보드 또는 USB 키보드 어댑터가 있어야 합니다. 애플리케이션에서 탈출하는 데 도움이 되는 바로 가기만 여기에 표시됩니다.

| 키  | 이름         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

### 시스템 바로 가기

이 바로 가기는 iPad의 시각적 설정 및 소리 설정에 따라 다릅니다.

| 바로 가기 | 동작              |
| -------- | ------------------ |
| F1       | 화면 어둡게 하기    |
| F2       | 화면 밝게 하기      |
| F7       | 이전 곡으로 돌아가기 |
| F8       | 재생/일시정지       |
| F9       | 다음 곡으로 건너뛰기 |
| F10      | 음소거             |
| F11      | 볼륨 낮추기        |
| F12      | 볼륨 높이기        |
| ⌘ Space  | 사용 가능한 언어 목록 표시; 선택하려면 다시 스페이스 바를 탭합니다. |

### iPad 탐색

| 바로 가기                                           | 동작                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | 홈으로 이동                                            |
| ⌘⇧H (Command-Shift-H)                              | 홈으로 이동                                            |
| ⌘ (Space)                                          | Spotlight 열기                                         |
| ⌘⇥ (Command-Tab)                                   | 마지막으로 사용한 10개의 앱 목록                      |
| ⌘\~                                                | 마지막 앱으로 이동                                    |
| ⌘⇧3 (Command-Shift-3)                              | 스크린샷 (하단 왼쪽에 떠서 저장하거나 조작)          |
| ⌘⇧4                                                | 스크린샷 찍고 편집기에서 열기                        |
| ⌘를 누르고 길게 누르기                                   | 앱에 대한 사용 가능한 바로 가기 목록 표시             |
| ⌘⌥D (Command-Option/Alt-D)                         | 독 표시                                               |
| ^⌥H (Control-Option-H)                             | 홈 버튼                                               |
| ^⌥H H (Control-Option-H-H)                         | 멀티태스크 바 표시                                    |
| ^⌥I (Control-Option-i)                             | 항목 선택기                                           |
| Escape                                             | 뒤로 버튼                                             |
| → (오른쪽 화살표)                                    | 다음 항목                                             |
| ← (왼쪽 화살표)                                      | 이전 항목                                             |
| ↑↓ (위 화살표, 아래 화살표)                          | 선택한 항목을 동시에 탭하기                          |
| ⌥ ↓ (Option-아래 화살표)                             | 아래로 스크롤                                        |
| ⌥↑ (Option-위 화살표)                               | 위로 스크롤                                          |
| ⌥← 또는 ⌥→ (Option-왼쪽 화살표 또는 Option-오른쪽 화살표) | 왼쪽 또는 오른쪽으로 스크롤                        |
| ^⌥S (Control-Option-S)                             | VoiceOver 음성 켜기/끄기                            |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 이전 앱으로 전환                                      |
| ⌘⇥ (Command-Tab)                                   | 원래 앱으로 전환                                      |
| ←+→, 그리고 Option + ← 또는 Option+→                   | 독을 통해 탐색                                        |
### Safari 단축키

| 단축키                | 동작                                             |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | 위치 열기                                        |
| ⌘T                      | 새 탭 열기                                       |
| ⌘W                      | 현재 탭 닫기                                     |
| ⌘R                      | 현재 탭 새로 고침                               |
| ⌘.                      | 현재 탭 로딩 중지                               |
| ^⇥                      | 다음 탭으로 전환                                 |
| ^⇧⇥ (Control-Shift-Tab) | 이전 탭으로 이동                                 |
| ⌘L                      | 텍스트 입력/URL 필드 선택하여 수정             |
| ⌘⇧T (Command-Shift-T)   | 마지막으로 닫은 탭 열기 (여러 번 사용 가능)     |
| ⌘\[                     | 브라우징 기록에서 이전 페이지로 이동            |
| ⌘]                      | 브라우징 기록에서 다음 페이지로 이동            |
| ⌘⇧R                     | 리더 모드 활성화                                 |

### 메일 단축키

| 단축키                   | 동작                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | 위치 열기                   |
| ⌘T                         | 새 탭 열기                  |
| ⌘W                         | 현재 탭 닫기                |
| ⌘R                         | 현재 탭 새로 고침          |
| ⌘.                         | 현재 탭 로딩 중지          |
| ⌘⌥F (Command-Option/Alt-F) | 메일함에서 검색             |

# 참고 자료

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, 회사나 고객이 **스틸러 악성 코드**에 의해 **침해**당했는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난하는 악성 코드로 인한 계정 탈취 및 랜섬웨어 공격에 대항하는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료로** 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>제로부터 AWS 해킹을 전문가로 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **HackTricks에 귀사를 광고하거나 PDF로 다운로드하려면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하세요.

</details>
