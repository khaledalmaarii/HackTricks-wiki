# macOS 실행/환경 제약 및 신뢰 캐시

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **해킹 트릭을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.
*
* .

</details>

## 기본 정보

macOS에서의 실행 제약은 **프로세스가 어떻게, 누구에 의해, 어디에서 시작될 수 있는지를 규제**하여 보안을 강화하기 위해 도입되었습니다. macOS Ventura에서 시작된 이러한 제약은 **시스템 바이너리를 서로 다른 제약 범주로 분류**하는 프레임워크를 제공하며, 이는 시스템 바이너리와 해당 해시를 포함하는 **신뢰 캐시** 내에서 정의됩니다. 이러한 제약은 시스템 내의 모든 실행 가능한 바이너리에 적용되며, 특정 바이너리를 실행하기 위한 요구 사항을 나타내는 **규칙** 집합으로 구성됩니다. 이 규칙은 바이너리가 만족해야 하는 자체 제약, 부모 프로세스가 충족해야 하는 부모 제약, 그리고 기타 관련 엔티티가 준수해야 하는 책임 제약을 포함합니다.

이 메커니즘은 macOS Sonoma부터 **환경 제약**을 통해 제3자 앱에 확장됩니다. 이를 통해 개발자는 **환경 제약을 위한 키와 값 집합**을 지정하여 앱을 보호할 수 있습니다.

**실행 환경 및 라이브러리 제약**은 **`launchd` 속성 목록 파일**에 저장하거나 코드 서명에 사용하는 **별도의 속성 목록** 파일에 정의합니다.

제약에는 4가지 유형이 있습니다:

* **자체 제약**: 실행 중인 바이너리에 적용되는 제약 사항입니다.
* **부모 프로세스**: 프로세스의 부모에 적용되는 제약 사항입니다 (예: XP 서비스를 실행하는 **`launchd`**).
* **책임 제약**: XPC 통신에서 서비스를 호출하는 프로세스에 적용되는 제약 사항입니다.
* **라이브러리 로드 제약**: 로드할 수 있는 코드를 선택적으로 설명하기 위해 라이브러리 로드 제약을 사용합니다.

따라서 프로세스가 다른 프로세스를 실행하려고 할 때 - `execve(_:_:_:)` 또는 `posix_spawn(_:_:_:_:_:_:)`를 호출함으로써 - 운영 체제는 **실행 파일이 자체 제약을 만족하는지** 확인합니다. 또한 **부모 프로세스의 실행 파일이 실행 파일의 부모 제약을 만족하고**, **책임 프로세스의 실행 파일이 실행 파일의 책임 프로세스 제약을 만족하는지** 확인합니다. 이러한 실행 제약 중 하나라도 만족되지 않으면 운영 체제는 프로그램을 실행하지 않습니다.

라이브러리를 로드할 때 **라이브러리 제약의 일부가 참이 아니면** 프로세스는 라이브러리를 **로드하지 않습니다**.

## LC 카테고리

LC는 **사실**과 **논리 연산**(and, or 등)으로 구성된 제약 조합입니다.

[**LC가 사용할 수 있는 사실은 문서화**되어 있습니다](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). 예를 들어:

* is-init-proc: 실행 파일이 운영 체제의 초기화 프로세스(`launchd`)여야 하는지 여부를 나타내는 부울 값입니다.
* is-sip-protected: 실행 파일이 시스템 무결성 보호(SIP)로 보호된 파일이어야 하는지 여부를 나타내는 부울 값입니다.
* `on-authorized-authapfs-volume:` 운영 체제가 권한이 부여된 인증된 APFS 볼륨에서 실행 파일을 로드했는지 여부를 나타내는 부울 값입니다.
* `on-authorized-authapfs-volume`: 운영 체제가 권한이 부여된 인증된 APFS 볼륨에서 실행 파일을 로드했는지 여부를 나타내는 부울 값입니다.
* Cryptexes 볼륨
* `on-system-volume:` 운영 체제가 현재 부팅된 시스템 볼륨에서 실행 파일을 로드했는지 여부를 나타내는 부울 값입니다.
* /System 내부...
* ...

Apple 바이너리가 서명되면 **LC 카테고리에 할당**됩니다. 

* **iOS 16 LC 카테고리**는 [**여기에서 역으로 추적되고 문서화**되어 있습니다](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* 현재 **LC 카테고리 (macOS 14** - Somona)는 역으로 추적되어 [**여기에서 설명을 찾을 수 있습니다**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

예를 들어 카테고리 1은:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: 시스템 또는 Cryptexes 볼륨에 있어야 함.
* `launch-type == 1`: 시스템 서비스여야 함 (LaunchDaemons의 plist).
* `validation-category == 1`: 운영 체제 실행 파일.
* `is-init-proc`: Launchd

### LC 카테고리 역추적

[**여기에서 더 자세한 정보**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints)를 확인할 수 있지만, 기본적으로 이들은 **AMFI (AppleMobileFileIntegrity)**에서 정의되므로 **Kernel Development Kit**을 다운로드하여 **KEXT**를 얻어야 합니다. **`kConstraintCategory`**로 시작하는 심볼들이 **흥미로운** 심볼들입니다. 이들을 추출하면 DER (ASN.1)로 인코딩된 스트림을 얻게 되는데, 이를 [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) 또는 python-asn1 라이브러리와 그것의 `dump.py` 스크립트, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master)을 사용하여 해독해야 합니다. 이를 통해 더 이해하기 쉬운 문자열을 얻을 수 있습니다.

## 환경 제약 조건

이들은 **제3자 애플리케이션**에서 구성된 Launch 제약 조건입니다. 개발자는 자신의 애플리케이션에서 사용할 **사실**과 **논리 연산자**를 선택하여 액세스를 제한할 수 있습니다.

애플리케이션의 환경 제약 조건을 열거하는 것이 가능합니다.
```bash
codesign -d -vvvv app.app
```
## Trust Caches

**macOS**에는 몇 가지 신뢰 캐시가 있습니다:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

iOS에서는 **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**에 위치합니다.

{% hint style="warning" %}
Apple Silicon 기기에서 실행되는 macOS에서 Apple이 서명한 이진 파일이 신뢰 캐시에 없으면 AMFI가 로드를 거부합니다.
{% endhint %}

### 신뢰 캐시 열거

이전의 신뢰 캐시 파일은 **IMG4** 및 **IM4P** 형식입니다. 여기서 IM4P는 IMG4 형식의 페이로드 섹션입니다.

[**pyimg4**](https://github.com/m1stadev/PyIMG4)를 사용하여 데이터베이스의 페이로드를 추출할 수 있습니다:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(다른 옵션으로는 [**img4tool**](https://github.com/tihmstar/img4tool) 도구를 사용하는 것이 있습니다. 이 도구는 M1에서도 실행될 수 있으며, 적절한 위치에 설치하면 오래된 버전이나 x86\_64용으로도 작동합니다).

이제 도구 [**trustcache**](https://github.com/CRKatri/trustcache)를 사용하여 정보를 읽기 쉬운 형식으로 얻을 수 있습니다:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
신뢰 캐시는 다음과 같은 구조를 따릅니다. 따라서 **LC 카테고리는 4번째 열**입니다.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
다음은 데이터를 추출하기 위해 [**이 스크립트**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)와 같은 스크립트를 사용할 수 있습니다.

그 데이터에서 **`0`** 값의 **launch constraints**를 가진 앱을 확인할 수 있습니다. 이 값은 제약이 없는 앱을 나타냅니다 ([**여기에서**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) 각 값에 대한 확인).

## 공격 방지

Launch Constraints는 여러 오래된 공격을 방지함으로써 **프로세스가 예상치 않은 조건에서 실행되지 않도록**합니다. 예를 들어 예상치 않은 위치에서 실행되거나 예상치 않은 부모 프로세스에 의해 호출되는 경우 (launchd만이 실행해야하는 경우).

또한, Launch Constraints는 **다운그레이드 공격을 방지**합니다.

그러나, 일반적인 XPC 남용, Electron 코드 주입 또는 라이브러리 유효성 검사 없는 dylib 주입 (로드할 수 있는 팀 ID가 알려져 있는 경우를 제외하고)는 방지하지 않습니다.

### XPC 데몬 보호

Sonoma 릴리스에서 주목할만한 점은 데몬 XPC 서비스의 **책임 구성**입니다. XPC 서비스는 연결된 클라이언트가 책임을 질 필요가 없고, 자체적으로 책임을 집니다. 이는 피드백 보고서 FB13206884에 문서화되어 있습니다. 이 설정은 결함이 있는 것처럼 보일 수 있지만, 다음과 같은 XPC 서비스와의 상호작용을 허용합니다.

- **XPC 서비스 실행**: 버그로 간주된다면, 이 설정은 공격자 코드를 통해 XPC 서비스를 시작하는 것을 허용하지 않습니다.
- **활성 서비스에 연결**: XPC 서비스가 이미 실행 중인 경우 (원래 애플리케이션에 의해 활성화 될 수 있음), 연결에 대한 장벽이 없습니다.

XPC 서비스에 제약을 가하는 것은 **잠재적인 공격 창을 좁히는 데 도움**이 될 수 있지만, 주요 관심사에 대한 대응은 아닙니다. XPC 서비스의 보안을 보장하기 위해서는 **연결된 클라이언트를 효과적으로 검증**하는 것이 필요합니다. 이것은 서비스의 보안을 강화하기 위한 유일한 방법입니다. 또한, 언급된 책임 구성은 현재 운영 중인 상태이며, 의도된 설계와 일치하지 않을 수 있음을 주목해야 합니다.


### Electron 보호

애플리케이션이 **LaunchService에 의해 열려야 한다는** 요구사항이 있습니다 (부모 제약 조건에서). 이는 **`open`**을 사용하여 (환경 변수를 설정할 수 있는) 또는 **Launch Services API**를 사용하여 (환경 변수를 지정할 수 있는) 방식으로 달성할 수 있습니다.

## 참고 자료

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하고 계신가요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **자신의 해킹 기법을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.
*
* .

</details>
