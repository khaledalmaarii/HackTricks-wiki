# macOS 샌드박스

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 기본 정보

MacOS 샌드박스(초기에는 Seatbelt라고 불렸음)은 샌드박스 프로필에서 지정된 허용된 작업으로 샌드박스 내에서 실행되는 애플리케이션을 **제한**합니다. 이를 통해 **애플리케이션이 예상된 리소스에만 액세스**하도록 보장합니다.

**`com.apple.security.app-sandbox`** **엔타이틀먼트**를 가진 **어떤 앱이든 샌드박스 내에서 실행**됩니다. **Apple 바이너리**는 일반적으로 샌드박스 내에서 실행되며 **App Store**에 게시하기 위해서는 **이 엔타이틀먼트가 필수**입니다. 따라서 대부분의 애플리케이션은 샌드박스 내에서 실행됩니다.

프로세스가 수행할 수 있는 작업을 제어하기 위해 **샌드박스에는 커널 전체의 모든 시스콜에 후크**가 있습니다. 앱의 **엔타이틀먼트**에 따라 샌드박스는 특정 작업을 **허용**할 수 있습니다.

샌드박스의 몇 가지 중요한 구성 요소는 다음과 같습니다:

* **커널 확장** `/System/Library/Extensions/Sandbox.kext`
* **개인 프레임워크** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* 사용자 영역에서 실행되는 **데몬** `/usr/libexec/sandboxd`
* **컨테이너** `~/Library/Containers`

컨테이너 폴더 내에서는 **번들 ID의 이름으로 샌드박스에서 실행되는 각 앱의 폴더**를 찾을 수 있습니다:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
각 번들 ID 폴더 안에는 앱의 **plist**와 **데이터 디렉토리**가 있습니다:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
주의하세요. 심볼릭 링크가 존재하여 샌드박스를 "탈출"하고 다른 폴더에 접근할 수 있더라도, 앱은 여전히 해당 폴더에 접근할 **권한**이 있어야 합니다. 이러한 권한은 **`.plist`** 파일 내에 있습니다.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
모든 샌드박스 애플리케이션에서 생성/수정된 모든 것은 **격리 속성**을 가집니다. 이는 샌드박스 앱이 **`open`**을 사용하여 무언가를 실행하려고 할 때 게이트키퍼를 트리거하여 샌드박스 공간을 방지합니다.
{% endhint %}

### 샌드박스 프로필

샌드박스 프로필은 해당 **샌드박스**에서 허용/금지되는 내용을 나타내는 구성 파일입니다. 이는 **샌드박스 프로필 언어 (SBPL)**를 사용하며, [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) 프로그래밍 언어를 사용합니다.

여기에 예제를 찾을 수 있습니다:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
더 많은 허용 또는 거부될 수 있는 작업을 확인하려면 [**이 연구**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)를 확인하세요.
{% endhint %}

중요한 **시스템 서비스**들도 자체적인 **사용자 정의 샌드박스** 내에서 실행됩니다. 예를 들어 `mdnsresponder` 서비스가 있습니다. 이러한 사용자 정의 **샌드박스 프로필**은 다음 경로에서 확인할 수 있습니다:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* 다른 샌드박스 프로필은 [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)에서 확인할 수 있습니다.

**앱 스토어** 앱은 **프로필** **`/System/Library/Sandbox/Profiles/application.sb`**를 사용합니다. 이 프로필에서 **`com.apple.security.network.server`**와 같은 권한을 확인할 수 있습니다. 이 권한은 프로세스가 네트워크를 사용할 수 있도록 허용합니다.

SIP는 /System/Library/Sandbox/rootless.conf에 있는 platform\_profile이라는 샌드박스 프로필입니다.

### 샌드박스 프로필 예제

특정 샌드박스 프로필로 애플리케이션을 시작하려면 다음을 사용할 수 있습니다:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}

```plaintext
(version 1)
(deny default)
(import "sandbox.sb")

;; Allow read access to the file
(allow file-read-metadata (literal "/path/to/file"))

;; Allow write access to the file
(allow file-write-data (literal "/path/to/file"))

;; Allow network access
(allow network-outbound)

;; Allow executing touch command
(allow process-exec (literal "/usr/bin/touch"))
```

{% endcode %}
{% endtab %}

{% tab title="ls" %}
{% code title="ls.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}

```plaintext
;; Allow touch to write to files in the user's home directory
(version 1)
(deny default)
(allow file-write* (subpath "/Users/" (home-subpath)))
```

이 스크립트는 사용자의 홈 디렉토리에 있는 파일에 touch가 쓰도록 허용합니다.
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Windows에서 실행되는 Apple이 작성한 소프트웨어는 추가적인 보안 조치** (예: 응용 프로그램 샌드박싱)를 가지고 있지 않습니다.
{% endhint %}

우회 예시:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (샌드박스 외부에 `~$`로 시작하는 파일을 작성할 수 있습니다).

### MacOS 샌드박스 프로필

macOS는 시스템 샌드박스 프로필을 **/usr/share/sandbox/** 및 **/System/Library/Sandbox/Profiles** 두 위치에 저장합니다.

또한 타사 응용 프로그램이 _**com.apple.security.app-sandbox**_ 권한을 가지고 있다면, 시스템은 해당 프로세스에 **/System/Library/Sandbox/Profiles/application.sb** 프로필을 적용합니다.

### **iOS 샌드박스 프로필**

기본 프로필은 **container**이며 SBPL 텍스트 표현이 없습니다. 메모리에서 이 샌드박스는 샌드박스의 각 권한에 대해 허용/거부 이진 트리로 표시됩니다.

### 샌드박스 디버그 및 우회

macOS에서는 iOS와 달리 프로세스가 커널에 의해 시작될 때부터 샌드박스에 의해 샌드박스화되지 않으며, **프로세스는 스스로 샌드박스에 참여하기로 결정할 때까지 제한되지 않습니다**.

프로세스는 `com.apple.security.app-sandbox` 권한이 있으면 시작할 때 사용자 공간에서 자동으로 샌드박스화됩니다. 이 프로세스에 대한 자세한 설명은 다음을 참조하십시오:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PID 권한 확인**

[**이에 따르면**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (이것은 `__mac_syscall`입니다)는 특정 PID에서 샌드박스에 의해 허용되는지 여부를 확인할 수 있습니다.

[**도구 sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c)은 PID가 특정 작업을 수행할 수 있는지 확인할 수 있습니다.
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### App Store 앱에서 사용자 정의 SBPL

회사들은 앱을 기본적인 것이 아닌 **사용자 정의 Sandbox 프로필**로 실행할 수 있습니다. 이를 위해 Apple의 승인이 필요한 **`com.apple.security.temporary-exception.sbpl`** 권한을 사용해야 합니다.

이 권한의 정의는 **`/System/Library/Sandbox/Profiles/application.sb:`**에서 확인할 수 있습니다.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
이것은 **이 entitlement 이후의 문자열을 Sandbox 프로필로 평가**합니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>
