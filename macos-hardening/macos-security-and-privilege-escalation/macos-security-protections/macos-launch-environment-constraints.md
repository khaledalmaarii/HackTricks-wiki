# macOS Launch/Environment Constraints & Trust Cache

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

macOS의 실행 제약은 **프로세스가 어떻게, 누구에 의해, 어디서 시작될 수 있는지를 규제하여 보안을 강화하기 위해 도입되었습니다**. macOS Ventura에서 시작된 이들은 **각 시스템 바이너리를 별개의 제약 카테고리로 분류하는 프레임워크**를 제공합니다. 이 카테고리는 시스템 바이너리와 해당 해시를 포함하는 **신뢰 캐시** 내에 정의됩니다. 이러한 제약은 시스템 내의 모든 실행 가능한 바이너리에 적용되며, **특정 바이너리를 실행하기 위한 요구 사항을 설명하는 규칙** 세트를 포함합니다. 규칙은 바이너리가 충족해야 하는 자기 제약, 부모 프로세스가 충족해야 하는 부모 제약, 그리고 관련된 다른 엔티티가 준수해야 하는 책임 제약을 포함합니다.

이 메커니즘은 macOS Sonoma부터 **환경 제약**을 통해 서드파티 앱으로 확장되어, 개발자가 **환경 제약을 위한 키와 값의 세트를 지정하여 앱을 보호할 수 있도록 합니다.**

**`launchd` 속성 목록 파일**에 저장하거나 코드 서명에 사용하는 **별도의 속성 목록** 파일에 제약 사전에서 **실행 환경 및 라이브러리 제약**을 정의합니다.

제약의 종류는 4가지입니다:

* **자기 제약**: **실행 중인** 바이너리에 적용되는 제약.
* **부모 프로세스**: **프로세스의 부모**에 적용되는 제약 (예: **`launchd`**가 XP 서비스를 실행하는 경우)
* **책임 제약**: XPC 통신에서 **서비스를 호출하는 프로세스**에 적용되는 제약
* **라이브러리 로드 제약**: 로드할 수 있는 코드를 선택적으로 설명하기 위해 라이브러리 로드 제약을 사용합니다.

따라서 프로세스가 다른 프로세스를 시작하려고 할 때 — `execve(_:_:_:)` 또는 `posix_spawn(_:_:_:_:_:_:)`를 호출하여 — 운영 체제는 **실행 파일이** **자기 제약**을 **충족하는지** 확인합니다. 또한 **부모 프로세스의** 실행 파일이 **부모 제약**을 **충족하는지** 확인하고, **책임 프로세스의** 실행 파일이 **책임 프로세스 제약**을 **충족하는지** 확인합니다. 이러한 실행 제약 중 하나라도 충족되지 않으면 운영 체제는 프로그램을 실행하지 않습니다.

라이브러리를 로드할 때 **라이브러리 제약**의 일부가 **참이 아닐 경우**, 프로세스는 **라이브러리를 로드하지 않습니다**.

## LC Categories

LC는 **사실**과 **논리 연산**(and, or..)으로 구성되어 사실을 결합합니다.

[**LC가 사용할 수 있는 사실은 문서화되어 있습니다**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). 예를 들어:

* is-init-proc: 실행 파일이 운영 체제의 초기화 프로세스(`launchd`)여야 하는지를 나타내는 부울 값.
* is-sip-protected: 실행 파일이 시스템 무결성 보호(SIP)로 보호된 파일이어야 하는지를 나타내는 부울 값.
* `on-authorized-authapfs-volume:` 운영 체제가 인증된 APFS 볼륨에서 실행 파일을 로드했는지를 나타내는 부울 값.
* `on-authorized-authapfs-volume`: 운영 체제가 인증된 APFS 볼륨에서 실행 파일을 로드했는지를 나타내는 부울 값.
* Cryptexes 볼륨
* `on-system-volume:` 운영 체제가 현재 부팅된 시스템 볼륨에서 실행 파일을 로드했는지를 나타내는 부울 값.
* /System 내부...
* ...

Apple 바이너리가 서명되면 **신뢰 캐시** 내의 **LC 카테고리에 할당됩니다**.

* **iOS 16 LC 카테고리**는 [**여기에서 역추적되고 문서화되었습니다**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* 현재 **LC 카테고리 (macOS 14 - Sonoma)**는 역추적되었으며 [**설명은 여기에서 찾을 수 있습니다**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

예를 들어 카테고리 1은:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: 시스템 또는 Cryptexes 볼륨에 있어야 합니다.
* `launch-type == 1`: 시스템 서비스여야 합니다 (LaunchDaemons의 plist).
* `validation-category == 1`: 운영 체제 실행 파일입니다.
* `is-init-proc`: Launchd

### LC 카테고리 리버싱

여기에 대한 더 많은 정보는 [**여기에서**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints) 확인할 수 있지만, 기본적으로 **AMFI (AppleMobileFileIntegrity)**에 정의되어 있으므로 **KEXT**를 얻기 위해 Kernel Development Kit을 다운로드해야 합니다. **`kConstraintCategory`**로 시작하는 기호들이 **흥미로운** 것들입니다. 이들을 추출하면 DER (ASN.1) 인코딩 스트림을 얻을 수 있으며, 이를 [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) 또는 python-asn1 라이브러리와 그 `dump.py` 스크립트를 사용하여 디코드해야 합니다. [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master)로 더 이해하기 쉬운 문자열을 얻을 수 있습니다.

## 환경 제약

이것들은 **서드파티 애플리케이션**에서 설정된 Launch Constraints입니다. 개발자는 애플리케이션에서 자신에게 접근을 제한하기 위해 사용할 **사실**과 **논리 연산자**를 선택할 수 있습니다.

애플리케이션의 환경 제약을 나열하는 것은 가능합니다:
```bash
codesign -d -vvvv app.app
```
## 신뢰 캐시

**macOS**에는 몇 가지 신뢰 캐시가 있습니다:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

iOS에서는 **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**에 있는 것 같습니다.

{% hint style="warning" %}
Apple Silicon 장치에서 실행되는 macOS에서는 Apple 서명 이진 파일이 신뢰 캐시에 없으면 AMFI가 이를 로드하는 것을 거부합니다.
{% endhint %}

### 신뢰 캐시 열거

이전 신뢰 캐시 파일은 **IMG4** 및 **IM4P** 형식이며, IM4P는 IMG4 형식의 페이로드 섹션입니다.

데이터베이스의 페이로드를 추출하려면 [**pyimg4**](https://github.com/m1stadev/PyIMG4)를 사용할 수 있습니다:

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

(또 다른 옵션은 도구 [**img4tool**](https://github.com/tihmstar/img4tool)를 사용하는 것입니다. 이 도구는 M1에서도 실행되며, 릴리스가 오래되었더라도 x86\_64에서 적절한 위치에 설치하면 실행됩니다).

이제 도구 [**trustcache**](https://github.com/CRKatri/trustcache)를 사용하여 읽기 쉬운 형식으로 정보를 얻을 수 있습니다:
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
신뢰 캐시는 다음 구조를 따릅니다. 따라서 **LC 카테고리는 4번째 열입니다.**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
그런 다음, [**이 스크립트**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)를 사용하여 데이터를 추출할 수 있습니다.

그 데이터에서 **launch constraints 값이 `0`인 앱**을 확인할 수 있으며, 이는 제약이 없는 앱입니다 ([**여기에서 확인**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) 각 값이 무엇인지).

## 공격 완화

Launch Constraints는 **프로세스가 예상치 못한 조건에서 실행되지 않도록 보장함으로써** 여러 오래된 공격을 완화했을 것입니다: 예를 들어 예상치 못한 위치에서 실행되거나 예상치 못한 부모 프로세스에 의해 호출되는 경우(launchd만이 이를 실행해야 하는 경우).

게다가, Launch Constraints는 **다운그레이드 공격도 완화합니다.**

하지만, **일반적인 XPC** 남용, **Electron** 코드 주입 또는 **dylib 주입**(라이브러리 검증 없이)은 완화하지 않습니다(라이브러리를 로드할 수 있는 팀 ID가 알려지지 않는 한).

### XPC 데몬 보호

소노마 릴리스에서 주목할 점은 데몬 XPC 서비스의 **책임 구성**입니다. XPC 서비스는 연결된 클라이언트가 책임지는 것이 아니라 스스로 책임을 집니다. 이는 피드백 보고서 FB13206884에 문서화되어 있습니다. 이 설정은 XPC 서비스와의 특정 상호작용을 허용하므로 결함이 있는 것처럼 보일 수 있습니다:

- **XPC 서비스 시작**: 버그로 간주된다면, 이 설정은 공격자 코드로 XPC 서비스를 시작하는 것을 허용하지 않습니다.
- **활성 서비스에 연결**: XPC 서비스가 이미 실행 중인 경우(원래 애플리케이션에 의해 활성화되었을 가능성이 있음), 연결하는 데 장애물이 없습니다.

XPC 서비스에 대한 제약을 구현하는 것은 **잠재적 공격의 창을 좁힘으로써** 유익할 수 있지만, 주요 문제를 해결하지는 않습니다. XPC 서비스의 보안을 보장하려면 **연결 클라이언트를 효과적으로 검증하는 것**이 근본적으로 필요합니다. 이는 서비스의 보안을 강화하는 유일한 방법입니다. 또한, 언급된 책임 구성은 현재 작동 중이며, 이는 의도된 설계와 일치하지 않을 수 있습니다.

### Electron 보호

애플리케이션이 **LaunchService에 의해 열려야 한다는** 요구가 있더라도(부모 제약에서). 이는 **`open`**을 사용하여(env 변수를 설정할 수 있음) 또는 **Launch Services API**를 사용하여(env 변수를 지정할 수 있음) 달성할 수 있습니다.

## 참고 문헌

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

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
