# macOS 보안 보호 기능

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## Gatekeeper

Gatekeeper는 일반적으로 **Quarantine + Gatekeeper + XProtect**의 조합을 가리키며, 이는 macOS 보안 모듈로 사용자가 **잠재적으로 악성 소프트웨어를 실행하지 못하도록** 시도합니다.

자세한 정보는 다음에서 확인할 수 있습니다:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## 프로세스 제한

### SIP - 시스템 무결성 보호

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### 샌드박스

MacOS 샌드박스는 샌드박스 프로필로 실행되는 앱이 **허용된 작업에만 액세스**하도록 제한하여 **애플리케이션이 예상된 리소스에만 액세스**하도록 도와줍니다.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - 투명성, 동의 및 제어

**TCC (투명성, 동의 및 제어)**는 보안 프레임워크입니다. 이는 애플리케이션의 **허가를 관리**하기 위해 설계되었으며, 특히 애플리케이션이 민감한 기능에 대한 액세스를 규제합니다. 이에는 **위치 서비스, 연락처, 사진, 마이크, 카메라, 접근성 및 전체 디스크 액세스**와 같은 요소가 포함됩니다. TCC는 앱이 명시적인 사용자 동의를 얻은 후에만 이러한 기능에 액세스할 수 있도록 보장하여 개인 데이터의 개인 정보 보호와 제어를 강화합니다.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### 시작/환경 제약 및 신뢰 캐시

macOS의 시작 제약은 프로세스 시작을 규제하기 위한 보안 기능으로, 프로세스를 **누가**, **어떻게** 및 **어디서** 시작할 수 있는지를 정의합니다. macOS Ventura에서 도입된 이 기능은 시스템 이진 파일을 **신뢰 캐시** 내의 제약 조건 범주로 분류합니다. 각 실행 가능한 이진 파일은 **자체**, **부모** 및 **책임** 제약 조건을 포함한 **시작**에 대한 규칙을 갖습니다. macOS Sonoma에서 타사 앱으로 확장된 **환경** 제약 조건으로 이러한 기능은 프로세스 시작 조건을 통제함으로써 잠재적인 시스템 악용을 완화하는 데 도움이 됩니다.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - 악성 소프트웨어 제거 도구

악성 소프트웨어 제거 도구(MRT)는 macOS의 보안 인프라의 일부입니다. 이름에서 알 수 있듯이, MRT의 주요 기능은 감염된 시스템에서 **알려진 악성 소프트웨어를 제거하는 것**입니다.

Mac에서 악성 소프트웨어가 감지되면(XProtect 또는 다른 방법으로), MRT를 사용하여 자동으로 **악성 소프트웨어를 제거**할 수 있습니다. MRT는 백그라운드에서 조용히 작동하며 일반적으로 시스템이 업데이트되거나 새로운 악성 소프트웨어 정의가 다운로드될 때 실행됩니다(MRT가 악성 소프트웨어를 감지하기 위한 규칙은 이진 파일 내에 있는 것처럼 보입니다).

XProtect와 MRT는 macOS의 보안 조치의 일부이지만, 다른 기능을 수행합니다:

* **XProtect**는 예방 도구입니다. 파일이 다운로드될 때(특정 애플리케이션을 통해) **파일을 확인**하고 알려진 악성 소프트웨어 유형을 감지하면 **파일을 열지 못하도록**하여 시스템에 악성 소프트웨어가 감염되는 것을 방지합니다.
* **MRT**는 **반응형 도구**입니다. 시스템에서 악성 소프트웨어가 감지된 후에 작동하며, 시스템을 정리하기 위해 문제가 있는 소프트웨어를 제거하는 것을 목표로 합니다.

MRT 애플리케이션은 **`/Library/Apple/System/Library/CoreServices/MRT.app`**에 위치합니다.

## 백그라운드 작업 관리

**macOS**는 이제 **도구가 코드 실행을 유지하는 잘 알려진 기술(로그인 항목, 데몬 등)**을 사용할 때마다 **알림**을 표시하여 사용자가 **어떤 소프트웨어가 지속되고 있는지** 더 잘 알 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

이는 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`에 위치한 **데몬**과 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`에 위치한 **에이전트**와 함께 실행됩니다.

**`backgroundtaskmanagementd`**가 지속적인 폴더에 설치된 것을 알 수 있는 방법은 **FSEvents를 가져오고** 이를 위한 **핸들러**를 생성하는 것입니다.

또한, 애플이 유지 관리하는 **잘 알려진 애플리케이션**을 포함하는 plist 파일이 있으며, 이 파일은 다음 위치에 있습니다: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

Apple cli 도구를 사용하여 구성된 모든 백그라운드 항목을 열거할 수 있습니다:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
또한 [**DumpBTM**](https://github.com/objective-see/DumpBTM)을 사용하여 이 정보를 나열하는 것도 가능합니다.
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
이 정보는 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**에 저장되며, 터미널에 FDA가 필요합니다.

### BTM 조작

새로운 지속성이 발견되면 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 유형의 이벤트가 발생합니다. 따라서, 이 **이벤트**가 전송되지 않거나 **에이전트가 사용자에게 경고하지 않도록** 방지하는 방법은 공격자가 BTM을 _**우회**_하는 데 도움이 될 것입니다.

* **데이터베이스 재설정**: 다음 명령을 실행하면 데이터베이스가 재설정됩니다(기초부터 다시 빌드될 것입니다). 그러나 어떤 이유에서인지, 이를 실행한 후에는 **시스템이 재부팅될 때까지 새로운 지속성이 경고되지 않습니다**.
* **루트** 권한이 필요합니다.
```bash
# Reset the database
sfltool resettbtm
```
* **에이전트 중지**: 새로운 탐지가 발견될 때 사용자에게 알림을 보내지 않도록 에이전트에 중지 신호를 보낼 수 있습니다.
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
* **버그**: 만약 **지속성을 생성한 프로세스가 바로 뒤에 존재한다면**, 데몬은 그에 대한 **정보를 가져오려 시도**하고, **실패**하며, 새로운 지속성이 유지되고 있다는 이벤트를 **전송할 수 없게 됩니다**.

BTM에 대한 **추가 정보 및 참고 자료**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* 여러분의 해킹 기술을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
