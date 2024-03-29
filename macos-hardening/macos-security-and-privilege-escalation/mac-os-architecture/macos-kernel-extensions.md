# macOS 커널 확장자

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 히어로까지 AWS 해킹을 배우세요!</summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 홍보**하고 싶으신가요? 아니면 **PEASS의 최신 버전을 보거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점적인 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS 및 HackTricks 스왹**](https://peass.creator-spring.com)을 획득하세요
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **그룹에 가입**하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **Hacktricks 저장소**([**hacktricks repo**](https://github.com/carlospolop/hacktricks)) 및 **Hacktricks 클라우드 저장소**([**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud))로 **PR을 보내** 헤킹 팁을 공유하세요.

</details>

## 기본 정보

커널 확장자(Kexts)는 **`.kext`** 확장자를 가진 **패키지**로, **macOS 커널 공간에 직접 로드**되어 주요 운영 체제에 추가 기능을 제공합니다.

### 요구 사항

당연히, 이는 **커널 확장자를 로드하는 것이 복잡**하기 때문에 해당 **요구 사항**을 충족해야 합니다:

* **복구 모드 진입 시**, 커널 **확장자를 로드할 수 있어야** 합니다:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* 커널 확장자는 **커널 코드 서명 인증서로 서명**되어야 하며, 이는 **Apple에서만 부여**할 수 있습니다. 회사와 필요한 이유를 자세히 검토할 것입니다.
* 커널 확장자는 **노타라이즈드**되어야 하며, Apple은 악성 코드를 확인할 수 있습니다.
* 그런 다음, **루트** 사용자가 커널 확장자를 **로드**할 수 있으며 패키지 내의 파일은 **루트에 속해** 있어야 합니다.
* 업로드 프로세스 중에 패키지는 **보호된 비루트 위치**인 `/Library/StagedExtensions`에 준비되어야 합니다(`com.apple.rootless.storage.KernelExtensionManagement` 권한 필요).
* 마지막으로, 로드를 시도할 때 사용자는 [**확인 요청을 받게**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) 되며, 수락하면 컴퓨터를 **재부팅**하여 로드해야 합니다.

### 로드 프로세스

Catalina에서는 다음과 같았습니다: **검증** 프로세스가 **사용자 영역**에서 발생한다는 점이 흥미롭습니다. 그러나 **`com.apple.private.security.kext-management`** 권한이 있는 애플리케이션만 **커널에 확장자를 로드 요청**할 수 있습니다: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli는 확장자를 로드하기 위한 **검증** 프로세스를 **시작**합니다
* **Mach 서비스**를 사용하여 **`kextd`**에게 메시지를 보냅니다.
2. **`kextd`**는 **서명**과 같은 여러 가지를 확인합니다.
* **`syspolicyd`**에게 확장자를 **로드할 수 있는지 확인**하도록 요청합니다.
3. **`syspolicyd`**는 확장자가 이전에 로드되지 않았다면 **사용자에게 프롬프트**를 표시합니다.
* **`syspolicyd`**는 결과를 **`kextd`**에게 보고합니다.
4. **`kextd`**는 마침내 커널에 확장자를 **로드하도록 지시**할 수 있습니다.

**`kextd`**를 사용할 수 없는 경우 **`kextutil`**이 동일한 확인을 수행할 수 있습니다.

## References

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 히어로까지 AWS 해킹을 배우세요!</summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 홍보**하고 싶으신가요? 아니면 **PEASS의 최신 버전을 보거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점적인 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS 및 HackTricks 스왹**](https://peass.creator-spring.com)을 획득하세요
* **Discord** [**💬**](https://emojipedia.org/speech-balloon/) **그룹에 가입**하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **Hacktricks 저장소**([**hacktricks repo**](https://github.com/carlospolop/hacktricks)) 및 **Hacktricks 클라우드 저장소**([**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud))로 **PR을 보내** 헤킹 팁을 공유하세요.

</details>
