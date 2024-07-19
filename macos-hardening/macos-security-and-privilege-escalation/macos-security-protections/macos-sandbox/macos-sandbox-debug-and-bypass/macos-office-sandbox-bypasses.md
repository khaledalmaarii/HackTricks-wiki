# macOS Office Sandbox Bypasses

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

### Word Sandbox bypass via Launch Agents

응용 프로그램은 **`com.apple.security.temporary-exception.sbpl`** 권한을 사용하여 **커스텀 샌드박스**를 사용하며, 이 커스텀 샌드박스는 파일 이름이 `~$`로 시작하는 한 어디에나 파일을 쓸 수 있도록 허용합니다: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

따라서 탈출은 **`~/Library/LaunchAgents/~$escape.plist`**에 **`plist`** LaunchAgent를 작성하는 것만큼 쉬웠습니다.

[**원본 보고서 확인하기**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)를 확인하세요.

### Word Sandbox bypass via Login Items and zip

첫 번째 탈출에서 Word는 이름이 `~$`로 시작하는 임의의 파일을 쓸 수 있지만, 이전 취약점의 패치 이후 `/Library/Application Scripts` 또는 `/Library/LaunchAgents`에 쓸 수는 없었습니다.

샌드박스 내에서 **로그인 항목**(사용자가 로그인할 때 실행되는 앱)을 생성할 수 있다는 것이 발견되었습니다. 그러나 이러한 앱은 **인증되지 않은 경우**에만 **실행되지 않습니다**. 또한 **인수 추가는 불가능합니다**(따라서 **`bash`**를 사용하여 리버스 셸을 실행할 수 없습니다).

이전 샌드박스 우회로 인해 Microsoft는 `~/Library/LaunchAgents`에 파일을 쓸 수 있는 옵션을 비활성화했습니다. 그러나 **로그인 항목으로 zip 파일을 넣으면** `Archive Utility`가 현재 위치에서 **압축을 풀기만 합니다**. 따라서 기본적으로 `~/Library`의 `LaunchAgents` 폴더가 생성되지 않기 때문에 **`LaunchAgents/~$escape.plist`**에 plist를 압축하고 **`~/Library`**에 zip 파일을 **배치**하면 압축 해제 시 지속성 목적지에 도달할 수 있었습니다.

[**원본 보고서 확인하기**](https://objective-see.org/blog/blog\_0x4B.html)를 확인하세요.

### Word Sandbox bypass via Login Items and .zshenv

(첫 번째 탈출에서 Word는 이름이 `~$`로 시작하는 임의의 파일을 쓸 수 있습니다).

그러나 이전 기술에는 제한이 있었습니다. **`~/Library/LaunchAgents`** 폴더가 다른 소프트웨어에 의해 생성된 경우 실패할 수 있습니다. 그래서 이를 위한 다른 로그인 항목 체인이 발견되었습니다.

공격자는 **`.bash_profile`** 및 **`.zshenv`** 파일을 생성하여 실행할 페이로드를 넣고, 이를 압축한 후 **희생자의** 사용자 폴더에 **`~/~$escape.zip`**로 작성할 수 있습니다.

그런 다음 zip 파일을 **로그인 항목**에 추가하고 **`Terminal`** 앱을 추가합니다. 사용자가 다시 로그인하면 zip 파일이 사용자의 파일에 압축 해제되어 **`.bash_profile`** 및 **`.zshenv`**를 덮어쓰게 되며, 따라서 터미널은 이 파일 중 하나를 실행하게 됩니다(사용되는 셸에 따라 다름).

[**원본 보고서 확인하기**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)를 확인하세요.

### Word Sandbox Bypass with Open and env variables

샌드박스화된 프로세스에서 여전히 **`open`** 유틸리티를 사용하여 다른 프로세스를 호출할 수 있습니다. 게다가 이러한 프로세스는 **자신의 샌드박스 내에서 실행됩니다**.

open 유틸리티에는 **특정 env** 변수를 사용하여 앱을 실행하는 **`--env`** 옵션이 있다는 것이 발견되었습니다. 따라서 **샌드박스** 내의 폴더에 **`.zshenv` 파일**을 생성하고 `--env`로 **`HOME` 변수를** 해당 폴더로 설정하여 `Terminal` 앱을 열면 `.zshenv` 파일이 실행됩니다(어떤 이유로 인해 `__OSINSTALL_ENVIROMENT` 변수를 설정해야 했습니다).

[**원본 보고서 확인하기**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)를 확인하세요.

### Word Sandbox Bypass with Open and stdin

**`open`** 유틸리티는 **`--stdin`** 매개변수도 지원했습니다(이전 우회 이후 `--env`를 사용할 수 없게 되었습니다).

문제는 **`python`**이 Apple에 의해 서명되었더라도 **`quarantine`** 속성이 있는 스크립트를 **실행하지 않습니다**. 그러나 stdin에서 스크립트를 전달할 수 있었기 때문에, 그것이 격리되었는지 여부를 확인하지 않았습니다:&#x20;

1. 임의의 Python 명령이 포함된 **`~$exploit.py`** 파일을 드롭합니다.
2. _open_ **`–stdin='~$exploit.py' -a Python`**을 실행하여 Python 앱을 우리의 드롭된 파일을 표준 입력으로 사용하여 실행합니다. Python은 우리의 코드를 기꺼이 실행하며, 이는 _launchd_의 자식 프로세스이므로 Word의 샌드박스 규칙에 구속되지 않습니다.

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
