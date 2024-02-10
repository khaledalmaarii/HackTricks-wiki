# macOS 키체인

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기술을 공유하세요.

</details>

## 주요 키체인

* **사용자 키체인** (`~/Library/Keychains/login.keycahin-db`)은 **사용자별 자격 증명** (애플리케이션 비밀번호, 인터넷 비밀번호, 사용자 생성 인증서, 네트워크 비밀번호 및 사용자 생성 공개/비공개 키)을 저장하는 데 사용됩니다.
* **시스템 키체인** (`/Library/Keychains/System.keychain`)은 WiFi 비밀번호, 시스템 루트 인증서, 시스템 개인 키 및 시스템 애플리케이션 비밀번호와 같은 **시스템 전체 자격 증명**을 저장합니다.

### 비밀번호 키체인 액세스

이러한 파일은 **내재적인 보호 기능은 없지만** 암호화되어 있으며 **사용자의 평문 암호를 복호화**하는 데 필요합니다. [**Chainbreaker**](https://github.com/n0fate/chainbreaker)와 같은 도구를 사용하여 복호화할 수 있습니다.

## 키체인 항목 보호

### ACLs

키체인의 각 항목은 **접근 제어 목록 (ACLs)**에 의해 관리됩니다. 이는 키체인 항목에서 수행할 수 있는 다양한 작업을 지시합니다. 이 작업에는 다음이 포함됩니다:

* **ACLAuhtorizationExportClear**: 보안 정보의 평문을 가져올 수 있도록 허용합니다.
* **ACLAuhtorizationExportWrapped**: 다른 제공된 암호로 암호화된 평문을 가져올 수 있도록 허용합니다.
* **ACLAuhtorizationAny**: 모든 작업을 수행할 수 있도록 허용합니다.

ACLs는 이러한 작업을 프롬프트 없이 수행할 수 있는 **신뢰할 수 있는 애플리케이션 목록**과 함께 제공됩니다. 이 목록은 다음과 같을 수 있습니다:

* **N`il`** (인증이 필요하지 않음, **모두 신뢰함**)
* **빈** 목록 (**아무도 신뢰하지 않음**)
* 특정 **애플리케이션**의 **목록**

또한 항목에는 **`ACLAuthorizationPartitionID`** 키가 포함될 수 있으며, 이는 **teamid, apple** 및 **cdhash**를 식별하는 데 사용됩니다.

* **teamid**가 지정된 경우 사용된 애플리케이션이 **동일한 teamid**를 가져야 항목에 **프롬프트 없이** 액세스할 수 있습니다.
* **apple**이 지정된 경우 앱은 **Apple**에 의해 **서명**되어야 합니다.
* **cdhash**가 표시된 경우 **앱**은 특정 **cdhash**를 가져야 합니다.

### 키체인 항목 생성

**`Keychain Access.app`**을 사용하여 **새로운 항목**을 생성할 때 다음 규칙이 적용됩니다:

* 모든 앱은 암호화할 수 있습니다.
* **앱은** (사용자에게 프롬프트 없이) **내보내기/복호화할 수 없습니다**.
* 모든 앱은 무결성 검사를 볼 수 있습니다.
* 앱은 ACL을 변경할 수 없습니다.
* **partitionID**는 **`apple`**로 설정됩니다.

**애플리케이션이 키체인에 항목을 생성**하는 경우 규칙이 약간 다릅니다:

* 모든 앱은 암호화할 수 있습니다.
* **생성 애플리케이션** (또는 명시적으로 추가된 다른 앱)만 내보내기/복호화할 수 있습니다 (사용자에게 프롬프트 없이).
* 모든 앱은 무결성 검사를 볼 수 있습니다.
* 앱은 ACL을 변경할 수 없습니다.
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
### APIs

{% hint style="success" %}
**LockSmith**라는 도구를 사용하여 **프롬프트를 생성하지 않는** **키체인 열거 및 덤프**를 수행할 수 있습니다. [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

각 키체인 항목에 대한 **정보**를 나열하고 가져옵니다:

* **`SecItemCopyMatching`** API는 각 항목에 대한 정보를 제공하며 사용할 때 설정할 수 있는 몇 가지 속성이 있습니다:
* **`kSecReturnData`**: true로 설정하면 데이터를 복호화하려고 시도합니다 (팝업을 피하려면 false로 설정)
* **`kSecReturnRef`**: 키체인 항목에 대한 참조도 가져옵니다 (나중에 팝업없이 복호화할 수 있는 경우 true로 설정)
* **`kSecReturnAttributes`**: 항목에 대한 메타데이터 가져오기
* **`kSecMatchLimit`**: 반환할 결과 수
* **`kSecClass`**: 어떤 종류의 키체인 항목인지

각 항목의 **ACL(Access Control List)**을 가져옵니다:

* **`SecAccessCopyACLList`** API를 사용하여 키체인 항목의 **ACL**을 가져올 수 있으며, 각 목록에는 다음과 같은 ACL(예: `ACLAuhtorizationExportClear` 및 이전에 언급된 기타 항목)이 포함됩니다:
* 설명
* **신뢰할 수 있는 애플리케이션 목록**. 이는 다음과 같을 수 있습니다:
* 앱: /Applications/Slack.app
* 이진 파일: /usr/libexec/airportd
* 그룹: group://AirPort

데이터 내보내기:

* **`SecKeychainItemCopyContent`** API는 평문을 가져옵니다
* **`SecItemExport`** API는 키와 인증서를 내보내지만 내용을 암호화하여 내보내려면 비밀번호를 설정해야 할 수도 있습니다

그리고 **프롬프트를 생성하지 않고 비밀을 내보낼 수 있는** **요구 사항**은 다음과 같습니다:

* **1개 이상의 신뢰할 수 있는** 앱이 목록에 나열된 경우:
* 적절한 **권한**이 필요합니다 (**`Nil`** 또는 비밀 정보에 액세스하기 위한 권한이 허용된 앱 목록에 속해야 함)
* 코드 서명이 **PartitionID**와 일치해야 합니다
* 코드 서명이 **신뢰할 수 있는 앱** 중 하나와 일치해야 합니다 (또는 올바른 KeychainAccessGroup의 구성원이어야 함)
* **모든 애플리케이션이 신뢰**된 경우:
* 적절한 **권한**이 필요합니다
* 코드 서명이 **PartitionID**와 일치해야 합니다
* **PartitionID**가 없는 경우 이는 필요하지 않습니다

{% hint style="danger" %}
따라서 **1개의 애플리케이션이 나열**된 경우 해당 애플리케이션에 **코드를 주입**해야 합니다.

**partitionID**에 **apple**이 지정된 경우 **`osascript`**를 사용하여 해당 partitionID에 apple이 포함된 모든 애플리케이션에 액세스할 수 있습니다. 이를 위해 **`Python`**도 사용할 수 있습니다.
{% endhint %}

### 두 가지 추가 속성

* **Invisible**: UI 키체인 앱에서 항목을 **숨기는** 불리언 플래그입니다.
* **General**: **메타데이터**를 저장하는 데 사용됩니다 (따라서 암호화되지 않음)
* Microsoft는 모든 민감한 엔드포인트에 액세스하기 위한 갱신 토큰을 평문으로 저장하고 있었습니다.

## 참고 자료

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로에서 영웅까지 AWS 해킹 배우기**<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
