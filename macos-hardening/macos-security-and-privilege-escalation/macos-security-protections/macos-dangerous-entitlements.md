# macOS 위험한 엔타이틀먼트 및 TCC 권한

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

{% hint style="warning" %}
**`com.apple`**으로 시작하는 엔타이틀먼트는 **제3자에게 사용할 수 없으며**, **Apple만이 부여**할 수 있음을 유의하세요.
{% endhint %}

## 높음

### `com.apple.rootless.install.heritable`

엔티틀먼트 **`com.apple.rootless.install.heritable`**은 **SIP 우회**를 허용합니다. 자세한 내용은 [여기를 참조하세요](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

엔티틀먼트 **`com.apple.rootless.install`**은 **SIP 우회**를 허용합니다. 자세한 내용은 [여기를 참조하세요](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (이전에 `task_for_pid-allow`로 불렸음)**

이 엔티틀먼트는 **커널을 제외한 모든** 프로세스의 **작업 포트를 가져올 수 있게** 합니다. 자세한 내용은 [**여기를 참조하세요**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

이 엔티틀먼트는 **`com.apple.security.cs.debugger`** 엔티틀먼트를 가진 다른 프로세스가 이 엔티틀먼트를 가진 이진 파일로 실행된 프로세스의 작업 포트를 가져와 **코드를 삽입**할 수 있게 합니다. 자세한 내용은 [**여기를 참조하세요**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

디버깅 도구 엔티틀먼트를 가진 앱은 `Get Task Allow` 엔티틀먼트가 `true`로 설정된 미인증 및 제3자 앱에 대해 `task_for_pid()`를 호출하여 유효한 작업 포트를 검색할 수 있습니다. 그러나 디버깅 도구 엔티틀먼트가 있더라도 디버거는 **`Get Task Allow` 엔티틀먼트가 없는 프로세스의 작업 포트**를 가져올 수 없으며, 따라서 시스템 무결성 보호로 보호되는 프로세스의 작업 포트를 가져올 수 없습니다. 자세한 내용은 [**여기를 참조하세요**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

이 엔티틀먼트는 **Apple에 의해 서명되거나 주 실행 파일과 동일한 팀 ID로 서명되지 않은** 프레임워크, 플러그인 또는 라이브러리를 로드할 수 있게 하므로 공격자가 일부 임의의 라이브러리 로드를 통해 코드를 삽입할 수 있습니다. 자세한 내용은 [**여기를 참조하세요**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

이 엔티틀먼트는 **`com.apple.security.cs.disable-library-validation`**과 매우 유사하지만 **라이브러리 유효성 검사를 직접 비활성화하는 대신** 프로세스가 **`csops` 시스템 호출을 사용하여 비활성화**할 수 있게 합니다.\
자세한 내용은 [**여기를 참조하세요**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

이 엔티틀먼트는 라이브러리 및 코드를 삽입하는 데 사용될 수 있는 **DYLD 환경 변수**를 사용할 수 있게 합니다. 자세한 내용은 [**여기를 참조하세요**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` 또는 `com.apple.rootless.storage`.`TCC`

[**이 블로그**](https://objective-see.org/blog/blog\_0x4C.html) 및 [**이 블로그**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)에 따르면 이러한 엔티틀먼트는 **TCC** 데이터베이스를 **수정**할 수 있게 합니다.

### **`system.install.apple-software`** 및 **`system.install.apple-software.standar-user`**

이러한 엔티틀먼트는 사용자에게 **권한을 요청하지 않고 소프트웨어를 설치**할 수 있게 합니다. 이는 **권한 상승**에 도움이 될 수 있습니다.

### `com.apple.private.security.kext-management`

커널에 **커널 익스텐션을 로드하도록** 요청하는 엔티틀먼트가 필요합니다.

### **`com.apple.private.icloud-account-access`**

엔티틀먼트 **`com.apple.private.icloud-account-access`**를 통해 **`com.apple.iCloudHelper`** XPC 서비스와 통신하여 **iCloud 토큰을 제공**할 수 있습니다.

**iMovie** 및 **Garageband**에는 이 엔티틀먼트가 있었습니다.

해당 엔티틀먼트에서 **icloud 토큰을 가져오는** 악용에 대한 자세한 내용은 다음 발표를 확인하세요: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: 이 엔티틀먼트가 허용하는 작업을 모르겠습니다

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**이 보고서**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 이를 통해 부팅 후 SSV로 보호된 콘텐츠를 업데이트할 수 있다고 언급합니다. 알고 계시면 PR을 보내주세요!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**이 보고서**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 이를 통해 부팅 후 SSV로 보호된 콘텐츠를 업데이트할 수 있다고 언급합니다. 알고 계시면 PR을 보내주세요!

### `keychain-access-groups`

이 엔티틀먼트는 애플리케이션이 액세스할 수 있는 **키체인** 그룹 목록입니다:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

**전체 디스크 액세스** 권한을 부여하며, 가질 수 있는 TCC에서 가장 높은 권한 중 하나입니다.

### **`kTCCServiceAppleEvents`**

앱이 **작업 자동화**에 일반적으로 사용되는 다른 애플리케이션에 이벤트를 보낼 수 있도록 합니다. 다른 앱을 제어하여 이러한 다른 앱에 부여된 권한을 남용할 수 있습니다.

사용자에게 비밀번호를 요청하도록 만드는 것과 같은 작업을 수행할 수 있습니다:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

또는 그들로 **임의의 작업**을 수행하게 만듭니다.

### **`kTCCServiceEndpointSecurityClient`**

다른 권한 중 하나로 **사용자 TCC 데이터베이스를 쓸 수 있게 합니다**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

사용자의 홈 폴더 경로를 변경하는 사용자의 **`NFSHomeDirectory`** 속성을 **변경**할 수 있게 합니다. 따라서 TCC를 **우회**할 수 있습니다.

### **`kTCCServiceSystemPolicyAppBundles`**

기본적으로 **허용되지 않는** 앱 번들 내의 파일을 수정할 수 있습니다 (app.app 내부).

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

이 권한을 가진 사용자를 확인할 수 있습니다. _시스템 환경설정_ > _개인 정보 및 보안_ > _앱 관리._

### `kTCCServiceAccessibility`

프로세스는 **macOS 접근성 기능을 남용**할 수 있게 되며, 이는 예를 들어 키 입력을 누를 수 있게 됨을 의미합니다. 따라서 Finder와 같은 앱을 제어하도록 액세스를 요청하고 이 권한으로 대화 상자를 승인할 수 있습니다.

## 중간

### `com.apple.security.cs.allow-jit`

이 권한은 `mmap()` 시스템 함수에 `MAP_JIT` 플래그를 전달하여 **쓰기 및 실행 가능한 메모리를 생성**할 수 있게 합니다. 자세한 정보는 [**여기를 참조하세요**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

이 권한은 **C 코드를 무시하거나 수정**하거나, 기본적으로 보안에 취약한 **`NSCreateObjectFileImageFromMemory`**를 사용하거나, **DVDPlayback** 프레임워크를 사용할 수 있게 합니다. 자세한 정보는 [**여기를 참조하세요**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
이 권한을 포함하면 앱이 메모리 안전하지 않은 코드 언어의 일반적인 취약점에 노출됩니다. 앱이 이 예외를 필요로 하는지 신중히 고려하십시오.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

이 권한은 **디스크의 자체 실행 파일 섹션을 수정**하여 강제 종료할 수 있게 합니다. 자세한 정보는 [**여기를 참조하세요**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
실행 파일 페이지 보호 비활성화 권한은 앱에서 기본 보안 보호를 제거하는 극단적인 권한으로, 앱의 실행 코드를 감지하지 않고 공격자가 앱의 실행 코드를 재작성할 수 있게 합니다. 가능하면 더 좁은 범위의 권한을 선호하십시오.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

이 권한은 기본적으로 금지된 nullfs 파일 시스템을 마운트할 수 있게 합니다. 도구: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

이 블로그 게시물에 따르면, 이 TCC 권한은 일반적으로 다음 형식으로 발견됩니다:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
프로세스가 **모든 TCC 권한을 요청하도록 허용**합니다.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 제출하세요.

</details>
