# macOS 보안 보호 기능

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>를 통해 AWS 해킹을 배우세요</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식으로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

## Gatekeeper

Gatekeeper는 일반적으로 **Quarantine + Gatekeeper + XProtect**의 조합을 가리키는 데 사용되며, 이는 사용자가 **잠재적으로 악성 소프트웨어를 실행하는 것을 막으려고 하는 3가지 macOS 보안 모듈**입니다.

더 많은 정보:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## 프로세스 제한

### SIP - 시스템 무결성 보호

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### 샌드박스

MacOS 샌드박스는 샌드박스 프로필에서 지정된 **허용된 작업에만 애플리케이션을 제한**하여 **샌드박스 내에서 실행되는 응용 프로그램을 제한**합니다. 이는 **응용 프로그램이 예상된 리소스에만 액세스하도록 보장**하는 데 도움이 됩니다.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **투명성, 동의 및 제어**

**TCC (투명성, 동의 및 제어)**는 보안 프레임워크입니다. 이는 **응용 프로그램의 권한을 관리**하도록 설계되었으며, 특히 민감한 기능에 대한 액세스를 규제함으로써 **위치 서비스, 연락처, 사진, 마이크로폰, 카메라, 접근성 및 전체 디스크 액세스**에 대한 애플리케이션의 액세스를 규제합니다. TCC는 앱이 명시적 사용자 동의를 얻은 후에만 이러한 기능에 액세스할 수 있도록 보장하여 개인 데이터의 개인 정보 보호 및 제어를 강화합니다.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### 시작/환경 제약 및 신뢰 캐시

macOS의 시작 제약은 **프로세스 시작을 규제**하는 보안 기능으로, **누가**, **어떻게**, **어디서** 프로세스를 시작할 수 있는지 정의합니다. macOS Ventura에서 소개된 **신뢰 캐시** 내에서 시스템 이진 파일을 제한 범주로 분류합니다. 각 실행 가능한 바이너리에는 **자체**, **부모**, **책임** 제약 조건을 포함한 **시작**에 대한 규칙이 있습니다. macOS Sonoma에서 타사 앱으로 확장된 **환경** 제약으로, 이러한 기능은 프로세스 시작 조건을 조절하여 시스템 악용 가능성을 완화하는 데 도움이 됩니다.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - 악성 코드 제거 도구

악성 코드 제거 도구 (MRT)는 macOS의 보안 인프라의 일부입니다. 이름에서 알 수 있듯이, MRT의 주요 기능은 감염된 시스템에서 **알려진 악성 코드를 제거하는 것**입니다.

Mac에서 악성 코드가 감지되면 (XProtect 또는 다른 방법으로), MRT를 사용하여 악성 코드를 자동으로 **제거**할 수 있습니다. MRT는 백그라운드에서 조용히 작동하며 일반적으로 시스템이 업데이트될 때 또는 새로운 악성 코드 정의가 다운로드될 때 실행됩니다 (악성 코드를 감지하는 MRT의 규칙은 이진 파일 내에 있습니다).

XProtect와 MRT는 macOS의 보안 조치의 일부이지만 다른 기능을 수행합니다:

* **XProtect**는 예방 도구입니다. **다운로드된 파일을 확인**하고 (특정 응용 프로그램을 통해), 알려진 유형의 악성 코드를 감지하면 **파일을 열지 못하도록**하여 시스템에 악성 코드가 처음부터 감염되는 것을 방지합니다.
* 반면에 **MRT**는 **반응 도구**입니다. 시스템에서 악성 코드가 감지된 후에 작동하며, 시스템을 정리하기 위해 문제가 되는 소프트웨어를 제거하는 것을 목표로 합니다.

MRT 애플리케이션은 **`/Library/Apple/System/Library/CoreServices/MRT.app`**에 위치합니다.

## 백그라운드 작업 관리

**macOS**는 이제 **툴이 코드 실행을 지속하는 잘 알려진 기술** (예: 로그인 항목, 데몬 등)을 사용할 때마다 사용자에게 **알림**을 표시하여 **어떤 소프트웨어가 지속되는지** 더 잘 알 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

이는 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`에 위치한 **데몬**과 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`에 위치한 **에이전트**에서 실행됩니다.

**`backgroundtaskmanagementd`**가 지속 폴더에 설치된 것을 알 수 있는 방법은 **FSEvents를 가져와서** 일부 **핸들러**를 생성하는 것입니다.

또한, 애플이 유지하는 **잘 알려진 응용 프로그램**을 포함하는 plist 파일이 있으며, 이 파일은 다음 위치에 있습니다: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### 열거

Apple cli 도구를 사용하여 구성된 모든 백그라운드 항목을 **열거**할 수 있습니다:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
게다가, 이 정보를 [**DumpBTM**](https://github.com/objective-see/DumpBTM)을 사용하여 목록화하는 것도 가능합니다.
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
이 정보는 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**에 저장되며 터미널에 FDA가 필요합니다.

### BTM 조작

새로운 지속성이 발견되면 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 유형의 이벤트가 발생합니다. 따라서, 이 **이벤트**가 전송되는 것을 **방지**하거나 **에이전트가 사용자에게 경고하는 것을 막는** 방법은 공격자가 BTM을 _**우회**_하는 데 도움이 됩니다.

* **데이터베이스 재설정**: 다음 명령을 실행하면 데이터베이스가 재설정됩니다 (기초부터 다시 빌드해야 함), 그러나 이후 이를 실행한 후 **시스템이 다시 부팅될 때까지 새로운 지속성이 경고되지 않습니다**.
* **루트** 권한이 필요합니다.
```bash
# Reset the database
sfltool resettbtm
```
* **에이전트 중지**: 에이전트에 중지 신호를 보내어 새로운 탐지가 발견될 때 사용자에게 경고되지 않도록 할 수 있습니다.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **버그**: 만약 **지속성을 만든 프로세스가 바로 뒤에 빠르게 종료된다면**, 데몬은 그에 대한 **정보를 가져오려고 시도할 것**이고, **실패**하여 새로운 것이 지속되고 있다는 이벤트를 보낼 수 없게 될 것입니다.

BTM에 대한 **참고 및 자세한 정보**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
