# macOS Kernel Extensions

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

커널 확장(Kexts)은 **`.kext`** 확장자를 가진 **패키지**로, **macOS 커널 공간에 직접 로드**되어 주요 운영 체제에 추가 기능을 제공합니다.

### Requirements

명백히, 이것은 매우 강력하여 **커널 확장을 로드하는 것이 복잡합니다**. 커널 확장이 로드되기 위해 충족해야 할 **요구 사항**은 다음과 같습니다:

* **복구 모드에 들어갈 때**, 커널 **확장이 로드될 수 있도록 허용되어야 합니다**:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* 커널 확장은 **커널 코드 서명 인증서로 서명되어야 하며**, 이는 **Apple에 의해 부여될 수 있습니다**. 누가 회사와 그 필요성에 대해 자세히 검토할 것입니다.
* 커널 확장은 또한 **노타리제이션**되어야 하며, Apple은 이를 악성 소프트웨어에 대해 확인할 수 있습니다.
* 그런 다음, **root** 사용자만이 **커널 확장을 로드할 수 있으며** 패키지 내의 파일은 **root에 속해야 합니다**.
* 업로드 과정 중, 패키지는 **보호된 비루트 위치**에 준비되어야 합니다: `/Library/StagedExtensions` (requires the `com.apple.rootless.storage.KernelExtensionManagement` grant).
* 마지막으로, 로드하려고 할 때 사용자는 [**확인 요청을 받게 됩니다**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) 그리고, 수락되면 컴퓨터는 **재시작되어야** 합니다.

### Loading process

Catalina에서는 다음과 같았습니다: **검증** 과정이 **사용자 공간**에서 발생한다는 점이 흥미롭습니다. 그러나 **`com.apple.private.security.kext-management`** 권한이 있는 애플리케이션만이 **커널에 확장을 로드하도록 요청할 수 있습니다**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **가** 확장을 로드하기 위한 **검증** 과정을 **시작합니다**
* **Mach 서비스**를 사용하여 **`kextd`**와 통신합니다.
2. **`kextd`**는 **서명**과 같은 여러 가지를 확인합니다.
* **`syspolicyd`**와 통신하여 확장이 **로드될 수 있는지 확인합니다**.
3. **`syspolicyd`**는 확장이 이전에 로드되지 않았다면 **사용자에게 요청**합니다.
* **`syspolicyd`**는 결과를 **`kextd`**에 보고합니다.
4. **`kextd`**는 마지막으로 **커널에 확장을 로드하라고 지시할 수 있습니다**.

**`kextd`**가 사용 불가능한 경우, **`kextutil`**이 동일한 검사를 수행할 수 있습니다.

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
