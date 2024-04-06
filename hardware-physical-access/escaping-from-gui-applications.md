<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>AWS 해킹을 처음부터 전문가까지 배워보세요</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왑**](https://peass.creator-spring.com)을 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요. 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


# GUI 애플리케이션 내에서 가능한 작업 확인하기

**일반 대화 상자**는 **파일 저장**, **파일 열기**, 글꼴 선택, 색상 선택 등의 옵션입니다. 대부분의 경우, 이러한 옵션을 통해 **탐색기 기능을 사용**할 수 있습니다. 따라서 다음 옵션에 액세스할 수 있다면 탐색기 기능에 액세스할 수 있습니다:

* 닫기/다른 이름으로 닫기
* 열기/다른 앱으로 열기
* 인쇄
* 내보내기/가져오기
* 검색
* 스캔

다음을 확인해야 합니다:

* 파일 수정 또는 생성
* 심볼릭 링크 생성
* 제한된 영역에 액세스
* 다른 앱 실행

## 명령 실행

아마도 **`열기`** 옵션을 사용하여 어떤 종류의 셸을 열거나 실행할 수 있을 것입니다.

### Windows

예를 들어 _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ 여기에서 명령을 실행할 수 있는 더 많은 이진 파일을 찾을 수 있습니다: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ 여기에서 더 많은 이진 파일을 찾을 수 있습니다: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## 경로 제한 우회

* **환경 변수**: 일부 경로를 가리키는 많은 환경 변수가 있습니다.
* **기타 프로토콜**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **심볼릭 링크**
* **바로 가기**: CTRL+N(새 세션 열기), CTRL+R(명령 실행), CTRL+SHIFT+ESC(작업 관리자),  Windows+E(탐색기 열기), CTRL-B, CTRL-I(즐겨찾기), CTRL-H(기록), CTRL-L, CTRL-O(파일/열기 대화 상자), CTRL-P(인쇄 대화 상자), CTRL-S(다른 이름으로 저장)
* 숨겨진 관리 메뉴: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URI**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC 경로**: 공유 폴더에 연결하기 위한 경로입니다. 로컬 머신의 C$에 연결해 보세요 ("\\\127.0.0.1\c$\Windows\System32")
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

## 브라우저에서 파일 시스템에 액세스하기

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

* Sticky Keys – SHIFT 키 5번 누르기
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – NUMLOCK 키 5초 동안 누르기
* Filter Keys – 오른쪽 SHIFT 키 12초 동안 누르기
* WINDOWS+F1 – Windows 검색
* WINDOWS+D – 데스크톱 보기
* WINDOWS+E – Windows 탐색기 실행
* WINDOWS+R – 실행
* WINDOWS+U – 접근성 센터
* WINDOWS+F – 검색
* SHIFT+F10 – 컨텍스트 메뉴
* CTRL+SHIFT+ESC – 작업 관리자
* CTRL+ALT+DEL – 최신 Windows 버전의 대문 화면
* F1 – 도움말 F3 – 검색
* F6 – 주소 표시줄
* F11 – 인터넷 익스플로러에서 전체 화면 전환
* CTRL+H – 인터넷 익스플로러 기록
* CTRL+T – 인터넷 익스플로러 – 새 탭
* CTRL+N – 인터넷 익스플로러 – 새 페이지
* CTRL+O – 파일 열기
* CTRL+S – 저장 CTRL+N – 새 RDP / Citrix
## 스와이프

* 왼쪽에서 오른쪽으로 스와이프하여 모든 열린 창을 볼 수 있으며, KIOSK 앱을 최소화하고 전체 OS에 직접 액세스할 수 있습니다.
* 오른쪽에서 왼쪽으로 스와이프하여 작업 센터를 열고, KIOSK 앱을 최소화하고 전체 OS에 직접 액세스할 수 있습니다.
* 위쪽 가장자리에서 스와이프하여 전체 화면 모드에서 열린 앱의 타이틀 바를 표시합니다.
* 아래에서 위로 스와이프하여 전체 화면 앱에서 작업 표시줄을 표시합니다.

## 인터넷 익스플로러 팁

### '이미지 도구 모음'

이미지를 클릭하면 이미지의 왼쪽 상단에 나타나는 도구 모음입니다. 저장, 인쇄, 메일 보내기, 탐색기에서 "내 사진" 열기가 가능합니다. Kiosk는 인터넷 익스플로러를 사용해야 합니다.

### 쉘 프로토콜

다음 URL을 사용하여 탐색기 보기를 얻을 수 있습니다:

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

자세한 정보는 다음 페이지를 참조하세요: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# 브라우저 팁

iKat 버전을 백업하세요:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScript를 사용하여 공통 대화 상자를 만들고 파일 탐색기에 액세스하세요: `document.write('<input/type=file>')`
출처: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## 제스처 및 버튼

* 네 개(또는 다섯 개)의 손가락으로 위로 스와이프 / 홈 버튼을 두 번 누름: 멀티태스킹 보기를 보고 앱을 변경합니다.

* 네 개 또는 다섯 개의 손가락으로 한쪽으로 스와이프: 다음/이전 앱으로 변경합니다.

* 다섯 손가락으로 화면을 확대하거나 홈 버튼을 터치하거나 화면 아래에서 위로 빠르게 스와이프하여 홈에 액세스합니다.

* 한 손가락으로 화면 아래에서 천천히 1-2 인치만 스와이프: 도크가 나타납니다.

* 한 손가락으로 화면 위쪽에서 아래로 스와이프: 알림을 보려면.

* 한 손가락으로 화면 오른쪽 위 모서리에서 아래로 스와이프: iPad Pro의 제어 센터를 볼 수 있습니다.

* 화면 왼쪽에서 한 손가락으로 1-2 인치 스와이프: 오늘 보기를 볼 수 있습니다.

* 화면 중앙에서 빠르게 오른쪽 또는 왼쪽으로 한 손가락으로 스와이프: 다음/이전 앱으로 변경합니다.

* 오른쪽 상단 모서리의 전원/최대화 버튼을 누르고 윗쪽으로 슬라이드하여 오른쪽 끝까지 이동: 전원을 끕니다.

* 오른쪽 상단 모서리의 전원/최대화 버튼을 누르고 홈 버튼을 몇 초 동안 누릅니다: 강제 종료합니다.

* 오른쪽 상단 모서리의 전원/최대화 버튼을 누르고 홈 버튼을 빠르게 누릅니다: 하단 왼쪽에 팝업되는 스크린샷을 찍습니다. 버튼을 동시에 매우 짧게 누르면 몇 초 동안 누르는 것처럼 강제 종료됩니다.

## 바로 가기

iPad 키보드 또는 USB 키보드 어댑터가 필요합니다. 애플리케이션에서 탈출하는 데 도움이 되는 바로 가기만 여기에 표시됩니다.

| 키   | 이름          |
| ---- | ------------- |
| ⌘    | Command       |
| ⌥    | Option (Alt)  |
| ⇧    | Shift         |
| ↩    | Return        |
| ⇥    | Tab           |
| ^    | Control       |
| ←    | Left Arrow    |
| →    | Right Arrow   |
| ↑    | Up Arrow      |
| ↓    | Down Arrow    |

### 시스템 바로 가기

이 바로 가기는 iPad의 시각 설정 및 소리 설정에 대한 것입니다.

| 바로 가기 | 동작                                                         |
| ---------- | ------------------------------------------------------------ |
| F1         | 화면 어둡게하기                                              |
| F2         | 화면 밝게하기                                               |
| F7         | 이전 곡으로 돌아가기                                         |
| F8         | 재생/일시정지                                                |
| F9         | 다음 곡으로 이동                                             |
| F10        | 음소거                                                        |
| F11        | 볼륨 감소                                                     |
| F12        | 볼륨 증가                                                     |
| ⌘ Space    | 사용 가능한 언어 목록 표시; 선택하려면 스페이스 바를 다시 누릅니다. |

### iPad 탐색

| 바로 가기                                           | 동작                                                         |
| -------------------------------------------------- | ------------------------------------------------------------ |
| ⌘H                                                 | 홈으로 이동                                                 |
| ⌘⇧H (Command-Shift-H)                              | 홈으로 이동                                                 |
| ⌘ (Space)                                          | Spotlight 열기                                              |
| ⌘⇥ (Command-Tab)                                   | 최근에 사용한 10개의 앱 목록 표시                           |
| ⌘\~                                                | 마지막 앱으로 이동                                          |
| ⌘⇧3 (Command-Shift-3)                              | 스크린샷 (하단 왼쪽에 저장하거나 작업을 수행할 수 있음)    |
| ⌘⇧4                                                | 스크린샷 찍고 편집기에서 열기                               |
| ⌘를 누르고 누르고 있기                              | 앱에 대한 사용 가능한 바로 가기 목록 표시                   |
| ⌘⌥D (Command-Option/Alt-D)                         | 도크 표시                                                   |
| ^⌥H (Control-Option-H)                             | 홈 버튼                                                      |
| ^⌥H H (Control-Option-H-H)                         | 멀티태스킹 바 표시                                          |
| ^⌥I (Control-Option-i)                             | 항목 선택기                                                  |
| Escape                                             | 뒤로 가기                                                    |
| → (Right arrow)                                    | 다음 항목으로 이동                                           |
| ← (Left arrow)                                     | 이전 항목으로 이동                                           |
| ↑↓ (Up arrow, Down arrow)                          | 선택한 항목을 동시에 탭                                      |
| ⌥ ↓ (Option-Down arrow)                            | 아래로 스크롤
### Safari 바로 가기

| 바로 가기                | 동작                                              |
| ----------------------- | ------------------------------------------------- |
| ⌘L (Command-L)          | 위치 열기                                          |
| ⌘T                      | 새 탭 열기                                         |
| ⌘W                      | 현재 탭 닫기                                       |
| ⌘R                      | 현재 탭 새로 고침                                 |
| ⌘.                      | 현재 탭 로딩 중지                                 |
| ^⇥                      | 다음 탭으로 전환                                  |
| ^⇧⇥ (Control-Shift-Tab) | 이전 탭으로 이동                                  |
| ⌘L                      | 텍스트 입력/URL 필드 선택하여 수정                |
| ⌘⇧T (Command-Shift-T)   | 마지막으로 닫은 탭 열기 (여러 번 사용 가능)      |
| ⌘\[                     | 브라우징 기록에서 이전 페이지로 이동              |
| ⌘]                      | 브라우징 기록에서 다음 페이지로 이동              |
| ⌘⇧R                     | 리더 모드 활성화                                  |

### 메일 바로 가기

| 바로 가기                   | 동작                           |
| -------------------------- | ---------------------------- |
| ⌘L                         | 위치 열기                      |
| ⌘T                         | 새 탭 열기                     |
| ⌘W                         | 현재 탭 닫기                   |
| ⌘R                         | 현재 탭 새로 고침             |
| ⌘.                         | 현재 탭 로딩 중지             |
| ⌘⌥F (Command-Option/Alt-F) | 메일함에서 검색                |

# 참고 자료

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 PDF로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 팁을 공유**하세요.

</details>
