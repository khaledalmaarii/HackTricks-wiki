# macOS Office Sandbox Bypasses

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 히어로까지 AWS 해킹 배우기</strong>를 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 해킹 기법을 공유하세요.

</details>

### Word Sandbox 우회 - Launch Agents를 통한 우회

이 응용 프로그램은 **`com.apple.security.temporary-exception.sbpl`** 허용권한을 사용하는 **사용자 정의 Sandbox**를 사용하며, 이 사용자 정의 Sandbox는 파일 이름이 `~$`로 시작하는 경우 어디에서든 파일을 작성할 수 있도록 허용합니다: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

따라서, 우회는 `plist` 형식의 LaunchAgent를 `~/Library/LaunchAgents/~$escape.plist`에 작성하는 것만으로도 쉽게 이루어질 수 있습니다.

[**원본 보고서는 여기에서 확인**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox 우회 - Login Items 및 zip을 통한 우회

첫 번째 우회에서 Word는 `~$`로 시작하는 임의의 파일을 작성할 수 있지만, 이전 취약점 패치 이후에는 `/Library/Application Scripts` 또는 `/Library/LaunchAgents`에 작성할 수 없습니다.

그러나 Sandbox 내에서는 사용자가 로그인할 때 실행되는 **Login Item** (사용자가 로그인할 때 실행되는 앱)을 생성할 수 있음이 발견되었습니다. 그러나 이러한 앱은 **노타라이즈(notarized)**되지 않으면 실행되지 않으며, **인수(argument)를 추가할 수 없습니다**(`bash`를 사용하여 역쉘이 실행되지 않습니다).

이전 Sandbox 우회에서 Microsoft는 `~/Library/LaunchAgents`에 파일을 작성하는 옵션을 비활성화했습니다. 그러나 기본적으로 `~/Library`의 `LaunchAgents` 폴더가 생성되지 않기 때문에, `LaunchAgents/~$escape.plist`에 plist를 압축하여 **zip 파일을 `~/Library`에 배치**하면 압축 해제될 때 영속성 대상에 도달할 수 있습니다.

[**원본 보고서는 여기에서 확인**](https://objective-see.org/blog/blog\_0x4B.html).

### Word Sandbox 우회 - Login Items 및 .zshenv을 통한 우회

(첫 번째 우회에서 Word는 `~$`로 시작하는 임의의 파일을 작성할 수 있음을 기억하세요).

그러나 이전 기술에는 제한이 있었습니다. `~/Library/LaunchAgents` 폴더가 이미 다른 소프트웨어에 의해 생성된 경우 실패할 수 있습니다. 따라서 이를 위해 다른 Login Items 체인이 발견되었습니다.

공격자는 실행할 페이로드를 포함하는 **`.bash_profile`** 및 **`.zshenv`** 파일을 생성한 다음, 이를 압축하여 피해자의 사용자 폴더인 **`~/~$escape.zip`**에 작성할 수 있습니다.

그런 다음, zip 파일을 **Login Items**에 추가한 다음 **`Terminal`** 앱을 추가합니다. 사용자가 다시 로그인하면 zip 파일이 사용자 파일에 압축 해제되어 **`.bash_profile`** 및 **`.zshenv`**를 덮어씁니다. 따라서 터미널은 이러한 파일 중 하나를 실행합니다(bash 또는 zsh에 따라 다릅니다).

[**원본 보고서는 여기에서 확인**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox 우회 - Open 및 환경 변수를 사용한 우회

Sandboxed 프로세스에서는 여전히 **`open`** 유틸리티를 사용하여 다른 프로세스를 호출할 수 있습니다. 또한, 이러한 프로세스는 **자체 Sandbox 내에서 실행**됩니다.

`open` 유틸리티에는 **`--env`** 옵션이 있어 특정 환경 변수로 앱을 실행할 수 있습니다. 따라서 Sandbox 내부의 폴더에 **`.zshenv` 파일**을 생성하고 `open`을 사용하여 `--env`를 설정하여 **`HOME` 변수**를 해당 폴더로 설정하여 해당 `Terminal` 앱을 열 수 있습니다. 이렇게 하면 `.zshenv` 파일이 실행됩니다(어떤 이유로 `__OSINSTALL_ENVIROMENT` 변수를 설정해야 하는 경우도 있습니다).

[**원본 보고서는 여기에서 확인**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox 우회 - Open 및 stdin을 사용한 우회

**`open`** 유틸리티는 **`--stdin`** 매개변수도 지원합니다(이전 우회에서는 `--env`를 사용할 수 없었습니다).

문제는 **`python`**이 Apple에 의해 서명되었더라도 **`quarantine`** 속성이 있는 스크립트를 실행하지 않습니다. 그러나 stdin에서 스크립트를 전달하여 quarantine 여부를 확인하지 않도록 할 수 있습니다:&#x20;

1. 임의의 Python 명령을 포함하는 **`~$exploit.py`** 파일을 생성합니다.
2. _open_ **`–stdin='~$exploit.py' -a Python`**을 실행하여 우리가 생성한 파일을 표준 입력으로 사용하여 Python 앱을 실행합니다. Python은 우리의 코드를 기쁘게 실행하며, _launchd_의 자식 프로세스이므로 Word의 Sandbox 규칙에 바인딩되지 않습니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 히어로까지 AWS 해킹 배우기</strong>를 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소
