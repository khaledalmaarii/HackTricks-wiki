# macOS 커널 확장

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하고 계신가요? **회사를 HackTricks에서 홍보**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 계획**](https://github.com/sponsors/carlospolop)을 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. [**NFT**](https://opensea.io/collection/the-peass-family)의 독점 컬렉션입니다.
* [**PEASS와 HackTricks의 공식 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) **Discord 그룹** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 팔로우하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* [**hacktricks repo**](https://github.com/carlospolop/hacktricks)와 [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)로 **해킹 팁을 공유**해주세요.

</details>

## 기본 정보

커널 확장(Kexts)은 **`.kext`** 확장자를 가진 **패키지**로, macOS 커널 공간에 **직접 로드**되어 주요 운영 체제에 추가 기능을 제공합니다.

### 요구 사항

당연히, 이는 **커널 확장을 로드하기 어렵게 만드는** 매우 강력한 기능입니다. 커널 확장이 로드되기 위해 충족해야 하는 **요구 사항**은 다음과 같습니다:

* **복구 모드에 진입**할 때 커널 **확장 로드가 허용**되어야 합니다:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* 커널 확장은 **커널 코드 서명 인증서로 서명**되어야 하며, 이는 **Apple**만이 부여할 수 있습니다. Apple은 회사와 그 필요성을 자세히 검토합니다.
* 커널 확장은 또한 **노타라이즈(notarized)**되어야 하며, Apple은 악성 코드를 확인할 수 있습니다.
* 그런 다음, **root** 사용자가 커널 확장을 **로드**할 수 있으며, 패키지 내의 파일은 **root에 속해** 있어야 합니다.
* 업로드 과정에서 패키지는 **보호된 비루트 위치**인 `/Library/StagedExtensions`에 준비되어야 합니다(`com.apple.rootless.storage.KernelExtensionManagement` 권한이 필요함).
* 마지막으로, 로드를 시도할 때 사용자는 [**확인 요청을 받게**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) 되며, 수락하면 컴퓨터를 **재시작**하여 로드해야 합니다.

### 로드 과정

Catalina에서는 다음과 같았습니다: **검증** 프로세스는 **유저 랜드(userland)**에서 발생한다는 점에 주목할 가치가 있습니다. 그러나 **`com.apple.private.security.kext-management`** 권한을 가진 애플리케이션만이 **커널에 확장을 로드하도록 요청**할 수 있습니다: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI는 확장을 로드하기 위한 **검증** 프로세스를 **시작**합니다.
* **Mach 서비스**를 사용하여 **`kextd`**와 통신합니다.
2. **`kextd`**는 **서명**과 같은 여러 가지를 확인합니다.
* **`syspolicyd`**와 통신하여 확장이 **로드**될 수 있는지 **확인**합니다.
3. **`syspolicyd`**는 확장이 이전에 로드되지 않았다면 **사용자에게 확인 요청**을 합니다.
* **`syspolicyd`**는 결과를 **`kextd`**에 보고합니다.
4. **`kextd`**는 마침내 커널에 확장을 **로드**하도록 알릴 수 있습니다.

**`kextd`**가 사용 불가능한 경우 **`kextutil`**은 동일한 검사를 수행할 수 있습니다.

## 참고 자료

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하고 계신가요? **회사를 HackTricks에서 홍보**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 계획**](https://github.com/sponsors/carlospolop)을 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. [**NFT**](https://opensea.io/collection/the-peass-family)의 독점 컬렉션입니다.
* [**PEASS와 HackTricks의 공식 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) **Discord 그룹** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 팔로우하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* [**hacktricks repo**](https://github.com/carlospolop/hacktricks)와 [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)로 **해킹 팁을 공유**해주세요.

</details>
