{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


# GUI 애플리케이션 내에서 가능한 작업 확인하기

**일반 대화상자**는 **파일 저장**, **파일 열기**, 글꼴 선택, 색상 선택 등의 옵션입니다. 이들 대부분은 **전체 탐색기 기능을 제공합니다**. 이는 이러한 옵션에 접근할 수 있다면 탐색기 기능에 접근할 수 있음을 의미합니다:

* 닫기/다른 이름으로 저장
* 열기/다른 프로그램으로 열기
* 인쇄
* 내보내기/가져오기
* 검색
* 스캔

다음 사항을 확인해야 합니다:

* 파일 수정 또는 새 파일 생성
* 심볼릭 링크 생성
* 제한된 영역에 접근
* 다른 앱 실행

## 명령 실행

아마도 **`Open with`** 옵션을 사용하여 어떤 종류의 셸을 열거나 실행할 수 있습니다.

### Windows

예를 들어 _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ 명령을 실행하고 예상치 못한 작업을 수행하는 데 사용할 수 있는 더 많은 바이너리를 여기에서 찾으세요: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ 더 많은 정보는 여기에서: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## 경로 제한 우회

* **환경 변수**: 특정 경로를 가리키는 많은 환경 변수가 있습니다.
* **다른 프로토콜**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **심볼릭 링크**
* **바로 가기**: CTRL+N (새 세션 열기), CTRL+R (명령 실행), CTRL+SHIFT+ESC (작업 관리자), Windows+E (탐색기 열기), CTRL-B, CTRL-I (즐겨찾기), CTRL-H (기록), CTRL-L, CTRL-O (파일/열기 대화상자), CTRL-P (인쇄 대화상자), CTRL-S (다른 이름으로 저장)
* 숨겨진 관리 메뉴: CTRL-ALT-F8, CTRL-ESC-F9
* **셸 URI**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC 경로**: 공유 폴더에 연결하는 경로. 로컬 머신의 C$에 연결해 보세요 ("\\\127.0.0.1\c$\Windows\System32")
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

## 바이너리 다운로드

콘솔: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
탐색기: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
레지스트리 편집기: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## 브라우저에서 파일 시스템 접근

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## 단축키

* 스티키 키 – SHIFT 5회 누르기
* 마우스 키 – SHIFT+ALT+NUMLOCK
* 고대비 – SHIFT+ALT+PRINTSCN
* 토글 키 – NUMLOCK 5초 동안 누르기
* 필터 키 – 오른쪽 SHIFT 12초 동안 누르기
* WINDOWS+F1 – Windows 검색
* WINDOWS+D – 바탕화면 표시
* WINDOWS+E – Windows 탐색기 실행
* WINDOWS+R – 실행
* WINDOWS+U – 접근성 센터
* WINDOWS+F – 검색
* SHIFT+F10 – 컨텍스트 메뉴
* CTRL+SHIFT+ESC – 작업 관리자
* CTRL+ALT+DEL – 최신 Windows 버전의 스플래시 화면
* F1 – 도움말 F3 – 검색
* F6 – 주소 표시줄
* F11 – Internet Explorer에서 전체 화면 전환
* CTRL+H – Internet Explorer 기록
* CTRL+T – Internet Explorer – 새 탭
* CTRL+N – Internet Explorer – 새 페이지
* CTRL+O – 파일 열기
* CTRL+S – 저장 CTRL+N – 새 RDP / Citrix

## 스와이프

* 왼쪽에서 오른쪽으로 스와이프하여 모든 열린 Windows를 보고 KIOSK 앱을 최소화하고 전체 OS에 직접 접근합니다;
* 오른쪽에서 왼쪽으로 스와이프하여 작업 센터를 열고 KIOSK 앱을 최소화하고 전체 OS에 직접 접근합니다;
* 상단 가장자리에서 아래로 스와이프하여 전체 화면 모드로 열린 앱의 제목 표시줄을 표시합니다;
* 아래에서 위로 스와이프하여 전체 화면 앱에서 작업 표시줄을 표시합니다.

## Internet Explorer 트릭

### '이미지 도구 모음'

이미지를 클릭할 때 왼쪽 상단에 나타나는 도구 모음입니다. 저장, 인쇄, 메일 보내기, 탐색기에서 "내 사진" 열기를 할 수 있습니다. Kiosk는 Internet Explorer를 사용해야 합니다.

### 셸 프로토콜

탐색기 보기를 얻으려면 이 URL을 입력하세요:

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
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## 파일 확장자 표시

더 많은 정보는 이 페이지를 확인하세요: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# 브라우저 트릭

iKat 버전 백업:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScript를 사용하여 일반 대화상자를 만들고 파일 탐색기에 접근하기: `document.write('<input/type=file>')`
출처: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## 제스처 및 버튼

* 네 손가락(또는 다섯 손가락)으로 위로 스와이프 / 홈 버튼 두 번 탭: 멀티태스킹 보기 및 앱 변경

* 네 손가락 또는 다섯 손가락으로 한쪽 방향으로 스와이프: 다음/이전 앱으로 변경

* 다섯 손가락으로 화면을 집게 / 홈 버튼 터치 / 화면 하단에서 한 손가락으로 빠르게 위로 스와이프: 홈에 접근

* 화면 하단에서 한 손가락으로 1-2인치 스와이프(느리게): 도크가 나타납니다.

* 화면 상단에서 한 손가락으로 아래로 스와이프: 알림 보기

* 화면 오른쪽 상단에서 한 손가락으로 아래로 스와이프: iPad Pro의 제어 센터 보기

* 화면 왼쪽에서 한 손가락으로 1-2인치 스와이프: 오늘 보기 보기

* 화면 중앙에서 한 손가락으로 빠르게 오른쪽 또는 왼쪽으로 스와이프: 다음/이전 앱으로 변경

* 오른쪽 상단 모서리의 전원/슬립 버튼을 누르고 **전원 끄기** 슬라이더를 오른쪽으로 모두 이동: 전원 끄기

* 오른쪽 상단 모서리의 전원/슬립 버튼과 홈 버튼을 몇 초 동안 누르기: 강제로 전원 끄기

* 오른쪽 상단 모서리의 전원/슬립 버튼과 홈 버튼을 빠르게 누르기: 화면 왼쪽 하단에 팝업되는 스크린샷을 찍습니다. 두 버튼을 동시에 아주 짧게 누르세요. 몇 초 동안 누르면 강제로 전원 꺼짐이 수행됩니다.

## 단축키

iPad 키보드 또는 USB 키보드 어댑터가 있어야 합니다. 애플리케이션에서 탈출하는 데 도움이 될 수 있는 단축키만 여기에 표시됩니다.

| Key | Name         |
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

### 시스템 단축키

이 단축키는 iPad의 사용에 따라 시각적 설정 및 소리 설정을 위한 것입니다.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 화면 밝기 낮추기                                                            |
| F2       | 화면 밝기 높이기                                                            |
| F7       | 한 곡 뒤로 가기                                                               |
| F8       | 재생/일시 정지                                                               |
| F9       | 곡 건너뛰기                                                                  |
| F10      | 음소거                                                                         |
| F11      | 볼륨 줄이기                                                                  |
| F12      | 볼륨 높이기                                                                  |
| ⌘ Space  | 사용 가능한 언어 목록 표시; 하나를 선택하려면 스페이스 바를 다시 누르세요. |

### iPad 탐색

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | 홈으로 이동                                            |
| ⌘⇧H (Command-Shift-H)                              | 홈으로 이동                                            |
| ⌘ (Space)                                          | Spotlight 열기                                         |
| ⌘⇥ (Command-Tab)                                   | 최근 사용한 앱 10개 목록                              |
| ⌘\~                                                | 마지막 앱으로 이동                                     |
| ⌘⇧3 (Command-Shift-3)                              | 스크린샷 (저장하거나 작업하기 위해 하단 왼쪽에 떠 있습니다) |
| ⌘⇧4                                                | 스크린샷을 찍고 편집기로 열기                         |
| ⌘을 누르고 유지                                   | 앱에 대한 사용 가능한 단축키 목록 표시               |
| ⌘⌥D (Command-Option/Alt-D)                         | 도크 표시                                              |
| ^⌥H (Control-Option-H)                             | 홈 버튼                                               |
| ^⌥H H (Control-Option-H-H)                         | 멀티태스킹 바 표시                                     |
| ^⌥I (Control-Option-i)                             | 항목 선택기                                           |
| Escape                                             | 뒤로 버튼                                             |
| → (오른쪽 화살표)                                  | 다음 항목                                             |
| ← (왼쪽 화살표)                                    | 이전 항목                                             |
| ↑↓ (위쪽 화살표, 아래쪽 화살표)                    | 선택한 항목을 동시에 탭                                |
| ⌥ ↓ (Option-Down arrow)                            | 아래로 스크롤                                         |
| ⌥↑ (Option-Up arrow)                               | 위로 스크롤                                           |
| ⌥← 또는 ⌥→ (Option-Left arrow 또는 Option-Right arrow) | 왼쪽 또는 오른쪽으로 스크롤                           |
| ^⌥S (Control-Option-S)                             | VoiceOver 음성 켜기 또는 끄기                          |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 이전 앱으로 전환                                      |
| ⌘⇥ (Command-Tab)                                   | 원래 앱으로 다시 전환                                  |
| ←+→, 그 다음 Option + ← 또는 Option+→             | 도크를 통해 탐색                                      |

### Safari 단축키

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | 위치 열기                                      |
| ⌘T                      | 새 탭 열기                                     |
| ⌘W                      | 현재 탭 닫기                                   |
| ⌘R                      | 현재 탭 새로 고침                              |
| ⌘.                      | 현재 탭 로딩 중지                              |
| ^⇥                      | 다음 탭으로 전환                               |
| ^⇧⇥ (Control-Shift-Tab) | 이전 탭으로 이동                               |
| ⌘L                      | 텍스트 입력/URL 필드를 선택하여 수정          |
| ⌘⇧T (Command-Shift-T)   | 마지막으로 닫은 탭 열기 (여러 번 사용할 수 있음) |
| ⌘\[                     | 탐색 기록에서 한 페이지 뒤로 가기              |
| ⌘]                      | 탐색 기록에서 한 페이지 앞으로 가기            |
| ⌘⇧R                     | 리더 모드 활성화                               |

### 메일 단축키

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | 위치 열기                   |
| ⌘T                         | 새 탭 열기                  |
| ⌘W                         | 현재 탭 닫기                |
| ⌘R                         | 현재 탭 새로 고침           |
| ⌘.                         | 현재 탭 로딩 중지           |
| ⌘⌥F (Command-Option/Alt-F) | 메일박스에서 검색           |

# 참고 문헌

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
