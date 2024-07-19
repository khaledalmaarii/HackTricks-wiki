# macOS Sandbox

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

## Basic Information

MacOS Sandbox (초기 이름: Seatbelt) **는 샌드박스 내에서 실행되는 애플리케이션의** **허용된 작업을 샌드박스 프로필에 지정된 대로 제한**합니다. 이는 **애플리케이션이 예상된 리소스만 접근하도록 보장하는 데 도움**이 됩니다.

**`com.apple.security.app-sandbox`** 권한을 가진 모든 앱은 샌드박스 내에서 실행됩니다. **Apple 바이너리**는 일반적으로 샌드박스 내에서 실행되며, **App Store**에 배포하기 위해서는 **이 권한이 필수적**입니다. 따라서 대부분의 애플리케이션은 샌드박스 내에서 실행됩니다.

프로세스가 할 수 있는 것과 할 수 없는 것을 제어하기 위해 **샌드박스는 커널 전역의 모든** **syscalls**에 후크를 가지고 있습니다. **앱의 권한에 따라** 샌드박스는 특정 작업을 **허용**합니다.

샌드박스의 몇 가지 중요한 구성 요소는 다음과 같습니다:

* **커널 확장** `/System/Library/Extensions/Sandbox.kext`
* **프라이빗 프레임워크** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* 사용자 공간에서 실행되는 **데몬** `/usr/libexec/sandboxd`
* **컨테이너** `~/Library/Containers`

컨테이너 폴더 내에는 **샌드박스에서 실행되는 각 앱에 대한 폴더**가 번들 ID 이름으로 있습니다:
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
각 번들 ID 폴더 안에는 앱의 **plist**와 **데이터 디렉토리**를 찾을 수 있습니다:
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
주의: 심볼릭 링크가 Sandbox에서 "탈출"하여 다른 폴더에 접근하기 위해 존재하더라도, 앱은 여전히 **접근할 수 있는 권한**이 필요합니다. 이러한 권한은 **`.plist`** 안에 있습니다.
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
Sandboxed 애플리케이션에 의해 생성/수정된 모든 항목은 **격리 속성**을 갖게 됩니다. 이는 샌드박스 앱이 **`open`**으로 무언가를 실행하려고 할 때 Gatekeeper를 트리거하여 샌드박스 공간을 방지합니다.
{% endhint %}

### 샌드박스 프로필

샌드박스 프로필은 해당 **샌드박스**에서 **허용/금지**될 항목을 나타내는 구성 파일입니다. 이는 [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) 프로그래밍 언어를 사용하는 **샌드박스 프로필 언어(SBPL)**를 사용합니다.

여기 예시를 찾을 수 있습니다:
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
이 [**연구**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **를 확인하여 허용되거나 거부될 수 있는 추가 작업을 확인하세요.**
{% endhint %}

중요한 **시스템 서비스**는 `mdnsresponder` 서비스와 같은 자체 맞춤 **샌드박스** 내에서 실행됩니다. 이러한 맞춤 **샌드박스 프로필**은 다음 위치에서 확인할 수 있습니다:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* 다른 샌드박스 프로필은 [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)에서 확인할 수 있습니다.

**App Store** 앱은 **프로필** **`/System/Library/Sandbox/Profiles/application.sb`**를 사용합니다. 이 프로필에서 **`com.apple.security.network.server`**와 같은 권한이 프로세스가 네트워크를 사용할 수 있도록 허용하는 방법을 확인할 수 있습니다.

SIP는 /System/Library/Sandbox/rootless.conf에 있는 platform\_profile이라는 샌드박스 프로필입니다.

### 샌드박스 프로필 예시

특정 샌드박스 프로필로 애플리케이션을 시작하려면 다음을 사용할 수 있습니다:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
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
{% endcode %}

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
**Apple이 작성한** **소프트웨어**는 **Windows**에서 **추가적인 보안 조치**가 없으며, 애플리케이션 샌드박싱과 같은 기능이 없습니다.
{% endhint %}

우회 예시:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (그들은 `~$`로 시작하는 이름의 파일을 샌드박스 외부에 쓸 수 있습니다).

### MacOS 샌드박스 프로파일

macOS는 시스템 샌드박스 프로파일을 두 위치에 저장합니다: **/usr/share/sandbox/** 및 **/System/Library/Sandbox/Profiles**.

그리고 서드파티 애플리케이션이 _**com.apple.security.app-sandbox**_ 권한을 가지고 있다면, 시스템은 해당 프로세스에 **/System/Library/Sandbox/Profiles/application.sb** 프로파일을 적용합니다.

### **iOS 샌드박스 프로파일**

기본 프로파일은 **container**라고 하며, SBPL 텍스트 표현이 없습니다. 메모리에서 이 샌드박스는 샌드박스의 각 권한에 대해 허용/거부 이진 트리로 표현됩니다.

### 디버그 및 샌드박스 우회

macOS에서는 iOS와 달리 프로세스가 커널에 의해 처음부터 샌드박스에 격리되지 않으며, **프로세스가 스스로 샌드박스에 참여해야 합니다**. 이는 macOS에서 프로세스가 적극적으로 샌드박스에 들어가기로 결정할 때까지 샌드박스에 의해 제한되지 않음을 의미합니다.

프로세스는 `com.apple.security.app-sandbox` 권한이 있을 경우 사용자 공간에서 시작할 때 자동으로 샌드박스화됩니다. 이 프로세스에 대한 자세한 설명은 다음을 확인하십시오:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PID 권한 확인**

[**이것에 따르면**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (이는 `__mac_syscall`입니다)는 특정 PID에 대해 **작업이 허용되는지 여부**를 확인할 수 있습니다.

[**도구 sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c)은 PID가 특정 작업을 수행할 수 있는지 확인할 수 있습니다:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Custom SBPL in App Store apps

회사가 **사용자 정의 샌드박스 프로필**로 앱을 실행할 수 있을 가능성이 있습니다 (기본 프로필 대신). 그들은 Apple에 의해 승인되어야 하는 권한 **`com.apple.security.temporary-exception.sbpl`**을 사용해야 합니다.

이 권한의 정의는 **`/System/Library/Sandbox/Profiles/application.sb:`**에서 확인할 수 있습니다.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
이 권한 이후의 문자열은 Sandbox 프로필로 **eval**됩니다.

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
