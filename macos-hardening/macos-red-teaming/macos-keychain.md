# macOS 키체인

{% hint style="success" %}
AWS 해킹 배우고 실습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 실습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop) 확인하기!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 가입하거나 [**텔레그램 그룹**](https://t.me/peass) 가입하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 팔로우하기.
* [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 요령 공유하기.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, 회사나 고객이 **스틸러 악성 코드**에 의해 **침해**당했는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보 탈취 악성 코드로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료로** 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

***

## 주요 키체인

* **사용자 키체인** (`~/Library/Keychains/login.keycahin-db`)은 애플리케이션 비밀번호, 인터넷 비밀번호, 사용자 생성 인증서, 네트워크 비밀번호 및 사용자 생성 공개/비공개 키와 같은 **사용자별 자격 증명**을 저장하는 데 사용됩니다.
* **시스템 키체인** (`/Library/Keychains/System.keychain`)은 WiFi 비밀번호, 시스템 루트 인증서, 시스템 비공개 키 및 시스템 애플리케이션 비밀번호와 같은 **시스템 전체 자격 증명**을 저장합니다.

### 비밀번호 키체인 액세스

이러한 파일들은 본질적인 보호가 없지만 **다운로드**할 수 있으며, **사용자의 일반 텍스트 비밀번호가 해독**되어야 합니다. [**Chainbreaker**](https://github.com/n0fate/chainbreaker)와 같은 도구를 사용하여 해독할 수 있습니다.

## 키체인 항목 보호

### ACLs

키체인의 각 항목은 **액세스 제어 목록 (ACLs)**에 의해 관리되며, 키체인 항목에 대해 다양한 작업을 수행할 수 있는 사용자를 규정합니다. 이에는 다음이 포함됩니다:

* **ACLAuhtorizationExportClear**: 보유자가 비밀번호의 평문을 가져올 수 있도록 합니다.
* **ACLAuhtorizationExportWrapped**: 보유자가 다른 제공된 비밀번호로 암호화된 평문을 가져올 수 있도록 합니다.
* **ACLAuhtorizationAny**: 보유자가 모든 작업을 수행할 수 있도록 합니다.

ACLs는 **프롬프트 없이** 이러한 작업을 수행할 수 있는 **신뢰할 수 있는 응용 프로그램 목록**과 함께 제공됩니다. 이는 다음과 같을 수 있습니다:

* **N`il`** (인증 필요 없음, **모두 신뢰함**)
* **빈** 목록 (**아무도 신뢰하지 않음**)
* 특정 **응용 프로그램** 목록.

또한 항목에는 **`ACLAuthorizationPartitionID`**가 포함될 수 있으며, 이는 **teamid, apple,** 및 **cdhash**를 식별하는 데 사용됩니다.

* **teamid**가 지정된 경우, 항목 값을 **프롬프트 없이** 액세스하려면 사용된 응용 프로그램은 **동일한 teamid**를 가져야 합니다.
* **apple**이 지정된 경우, 앱은 **Apple**에 의해 **서명**되어야 합니다.
* **cdhash**가 표시된 경우, **앱**은 특정 **cdhash**를 가져야 합니다.

### 키체인 항목 생성

**`Keychain Access.app`**을 사용하여 **새로운 항목**을 만들 때 다음 규칙이 적용됩니다:

* 모든 앱은 암호화할 수 있습니다.
* **어떤 앱도** 내보내기/해독할 수 없습니다 (사용자에게 프롬프트 없이).
* 모든 앱은 무결성 검사를 볼 수 있습니다.
* 어떤 앱도 ACL을 변경할 수 없습니다.
* **partitionID**는 **`apple`**로 설정됩니다.

**응용 프로그램이 키체인에 항목을 만드는 경우**, 규칙은 약간 다릅니다:

* 모든 앱은 암호화할 수 있습니다.
* 항목을 내보내기/해독할 수 있는 것은 **생성 응용 프로그램** (또는 명시적으로 추가된 다른 앱)만 가능합니다 (사용자에게 프롬프트 없이).
* 모든 앱은 무결성 검사를 볼 수 있습니다.
* 어떤 앱도 ACL을 변경할 수 없습니다.
* **partitionID**는 **`teamid:[teamID here]`**로 설정됩니다.

## 키체인 액세스

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### API

{% hint style="success" %}
**키체인 열거 및 덤프**는 **프롬프트를 생성하지 않는** 비밀을 수행할 수 있습니다. 이 작업은 [**LockSmith**](https://github.com/its-a-feature/LockSmith) 도구를 사용하여 수행할 수 있습니다.
{% endhint %}

각 키체인 항목에 대한 **정보**를 나열하고 가져옵니다:

* API **`SecItemCopyMatching`**은 각 항목에 대한 정보를 제공하며 사용할 때 설정할 수 있는 몇 가지 속성이 있습니다:
* **`kSecReturnData`**: true로 설정하면 데이터를 복호화하려고 시도합니다 (잠재적인 팝업을 피하려면 false로 설정)
* **`kSecReturnRef`**: 키체인 항목에 대한 참조도 가져옵니다 (나중에 팝업 없이 복호화할 수 있는 경우 true로 설정)
* **`kSecReturnAttributes`**: 항목에 대한 메타데이터 가져오기
* **`kSecMatchLimit`**: 반환할 결과 수
* **`kSecClass`**: 어떤 종류의 키체인 항목

각 항목의 **ACL** 가져오기:

* API **`SecAccessCopyACLList`**를 사용하여 **키체인 항목의 ACL**을 가져올 수 있으며 각 목록에는 다음과 같은 ACL 목록이 반환됩니다 (`ACLAuhtorizationExportClear` 및 이전에 언급된 기타 항목):
* 설명
* **신뢰할 수 있는 응용 프로그램 목록**. 이것은 다음과 같을 수 있습니다:
* 응용 프로그램: /Applications/Slack.app
* 이진 파일: /usr/libexec/airportd
* 그룹: group://AirPort

데이터 내보내기:

* API **`SecKeychainItemCopyContent`**는 평문을 가져옵니다
* API **`SecItemExport`**는 키 및 인증서를 내보내지만 내보낼 내용을 암호화하려면 암호를 설정해야 할 수도 있습니다

**프롬프트 없이 비밀을 내보내기**하려면 다음이 **요구 사항**입니다:

* **1개 이상의 신뢰할 수 있는** 앱이 목록에 나열된 경우:
* 적절한 **권한**이 필요합니다 (**`Nil`**, 또는 비밀 정보에 액세스하기 위한 권한이 허용된 앱 목록의 일부여야 함)
* 코드 서명이 **PartitionID**와 일치해야 합니다
* 코드 서명이 **신뢰할 수 있는 앱** 중 하나와 일치해야 합니다 (또는 올바른 KeychainAccessGroup의 구성원이어야 함)
* **모든 응용 프로그램이 신뢰할 경우**:
* 적절한 **권한**이 필요합니다
* 코드 서명이 **PartitionID**와 일치해야 합니다
* **PartitionID가 없는 경우** 이는 필요하지 않습니다

{% hint style="danger" %}
따라서 **1개의 응용 프로그램이 나열**된 경우 해당 응용 프로그램에 **코드를 삽입**해야 합니다.

**PartitionID**에 **apple**이 표시된 경우 **`osascript`**를 사용하여 해당 PartitionID에 apple이 포함된 모든 응용 프로그램에 액세스할 수 있습니다. **`Python`**도 이에 사용할 수 있습니다.
{% endhint %}

### 두 가지 추가 속성

* **Invisible**: UI 키체인 앱에서 항목을 **숨기는** 부울 플래그입니다
* **General**: **메타데이터**를 저장하는 데 사용됩니다 (따라서 **암호화되지 않음**)
* Microsoft는 모든 민감한 엔드포인트에 액세스하기 위한 모든 리프레시 토큰을 평문으로 저장했습니다.

## 참고 자료

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 통해 제공되는 검색 엔진으로, 회사 또는 그 고객이 **스틸러 악성 코드**에 의해 **침해**당했는지 확인하는 **무료** 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보 탈취 악성 코드로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 **무료**로 엔진을 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃헙 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
