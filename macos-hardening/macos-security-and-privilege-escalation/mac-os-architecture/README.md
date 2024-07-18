# macOS 커널 및 시스템 확장

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

## XNU 커널

**macOS의 핵심은 XNU**로, "X is Not Unix"의 약자입니다. 이 커널은 기본적으로 **Mach 마이크로커널**(나중에 설명됨)과 **버클리 소프트웨어 배포(BSD)**의 요소로 구성됩니다. XNU는 또한 **I/O Kit이라는 시스템을 통해 커널 드라이버에 대한 플랫폼을 제공**합니다. XNU 커널은 Darwin 오픈 소스 프로젝트의 일부이며, **소스 코드가 자유롭게 접근 가능**합니다.

보안 연구원이나 Unix 개발자의 관점에서 볼 때, **macOS**는 우아한 GUI와 다양한 사용자 정의 애플리케이션을 갖춘 **FreeBSD** 시스템과 매우 **유사**할 수 있습니다. BSD용으로 개발된 대부분의 애플리케이션은 수정 없이 macOS에서 컴파일 및 실행될 수 있습니다. Unix 사용자에게 익숙한 명령줄 도구들이 macOS에 모두 포함되어 있기 때문입니다. 그러나 XNU 커널에는 Mach가 포함되어 있기 때문에 전통적인 Unix와 macOS 간에는 몇 가지 중요한 차이가 있으며, 이러한 차이로 인해 잠재적인 문제가 발생하거나 독특한 장점을 제공할 수 있습니다.

XNU의 오픈 소스 버전: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach는 **UNIX 호환성**을 갖춘 **마이크로커널**입니다. 그 중요한 설계 원칙 중 하나는 **커널 공간에서 실행되는 코드 양을 최소화**하고 파일 시스템, 네트워킹, I/O와 같은 일반적인 커널 기능을 **사용자 수준 작업으로 실행**할 수 있도록 하는 것입니다.

XNU에서 Mach는 **프로세서 스케줄링, 멀티태스킹 및 가상 메모리 관리**와 같은 커널이 일반적으로 처리하는 많은 중요한 저수준 작업을 담당합니다.

### BSD

XNU **커널**은 또한 **FreeBSD** 프로젝트에서 파생된 상당한 양의 코드를 **통합**합니다. 이 코드는 Mach와 함께 **커널의 일부로 실행**됩니다. 그러나 XNU 내의 FreeBSD 코드는 Mach와의 호환성을 보장하기 위해 수정이 필요했기 때문에 원래 FreeBSD 코드와 상당히 다를 수 있습니다. FreeBSD는 다음을 포함한 많은 커널 작업에 기여합니다:

* 프로세스 관리
* 시그널 처리
* 사용자 및 그룹 관리를 포함한 기본 보안 메커니즘
* 시스템 콜 인프라
* TCP/IP 스택 및 소켓
* 방화벽 및 패킷 필터링

BSD와 Mach 간의 상호 작용을 이해하는 것은 그들의 다른 개념적 프레임워크 때문에 복잡할 수 있습니다. 예를 들어, BSD는 프로세스를 기본 실행 단위로 사용하고, Mach는 스레드를 기반으로 작동합니다. 이 불일치는 XNU에서 **각 BSD 프로세스를 정확히 하나의 Mach 스레드를 포함하는 Mach 태스크와 연관**시킴으로써 조화됩니다. BSD의 fork() 시스템 호출을 사용할 때, 커널 내의 BSD 코드는 Mach 함수를 사용하여 태스크와 스레드 구조를 만듭니다.

또한, **Mach와 BSD는 각각 다른 보안 모델을 유지**합니다: **Mach의** 보안 모델은 **포트 권한**에 기반하며, BSD의 보안 모델은 **프로세스 소유권**에 기반합니다. 이 두 모델 간의 불일치로 인해 로컬 권한 상승 취약점이 가끔 발생했습니다. 일반 시스템 호출 외에도 **Mach 트랩**이 있어 사용자 공간 프로그램이 커널과 상호 작용할 수 있습니다. 이러한 다른 요소들이 함께 조합되어 macOS 커널의 다면적이고 하이브리드 아키텍처를 형성합니다.

### I/O Kit - 드라이버

I/O Kit은 XNU 커널의 오픈 소스, 객체 지향 **장치 드라이버 프레임워크**로, **동적으로 로드되는 장치 드라이버**를 처리합니다. 이를 통해 다양한 하드웨어를 지원하기 위해 커널에 모듈식 코드를 실시간으로 추가할 수 있습니다.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - 프로세스 간 통신

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### 커널캐시

**커널캐시**는 XNU 커널의 **미리 컴파일 및 미리 연결된 버전**으로, 필수 장치 **드라이버** 및 **커널 확장**을 포함합니다. 이는 **압축된** 형식으로 저장되며 부팅 프로세스 중에 메모리로 압축 해제됩니다. 커널캐시는 부팅 시 동적으로 이러한 구성 요소를 로드하고 연결하는 데 소요되는 시간과 리소스를 줄여줌으로써 **빠른 부팅 시간**을 지원합니다.

iOS에서는 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**에 위치하며 macOS에서는 **`find / -name kernelcache 2>/dev/null`** 또는 **`mdfind kernelcache | grep kernelcache`**로 찾을 수 있습니다.

**`kextstat`**를 실행하여 로드된 커널 확장을 확인할 수 있습니다.

#### IMG4

IMG4 파일 형식은 Apple이 iOS 및 macOS 장치에서 **펌웨어 구성 요소**(예: **커널캐시**)를 안전하게 **저장하고 확인**하기 위해 사용하는 컨테이너 형식입니다. IMG4 형식에는 헤더와 실제 페이로드(커널 또는 부트로더와 같은)를 포함하는 여러 태그가 포함되어 있으며, 서명, 일련의 매니페스트 속성을 포함합니다. 이 형식은 암호화 검증을 지원하여 장치가 실행하기 전에 펌웨어 구성 요소의 진위성과 무결성을 확인할 수 있습니다.

일반적으로 다음 구성 요소로 구성됩니다:

* **페이로드 (IM4P)**:
* 종종 압축됨 (LZFSE4, LZSS 등)
* 선택적으로 암호화됨
* **매니페스트 (IM4M)**:
* 서명 포함
* 추가 키/값 사전
* **복원 정보 (IM4R)**:
* APNonce로도 알려짐
* 일부 업데이트의 재생 방지
* 선택 사항: 일반적으로 이것은 찾을 수 없음

커널캐시를 압축 해제하세요:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### 커널캐시 심볼

가끔 애플은 **심볼**이 포함된 **커널캐시**를 공개합니다. [https://theapplewiki.com](https://theapplewiki.com/)의 링크를 따라가면 심볼이 포함된 펌웨어를 다운로드할 수 있습니다.

### IPSW

이것들은 애플 **펌웨어**로 [**https://ipsw.me/**](https://ipsw.me/)에서 다운로드할 수 있습니다. 다른 파일들 중에 **커널캐시**가 포함되어 있을 것입니다.\
파일을 **추출**하려면 그냥 **압축을 푸세요**.

펌웨어를 추출한 후에는 다음과 같은 파일이 나올 것입니다: **`kernelcache.release.iphone14`**. 이것은 **IMG4** 형식이며, 다음과 같은 명령으로 관련 정보를 추출할 수 있습니다:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
다음 명령어를 사용하여 추출된 커널캐시의 심볼을 확인할 수 있습니다: **`nm -a kernelcache.release.iphone14.e | wc -l`**

이제 우리는 **모든 익스텐션** 또는 **관심 있는 하나를 추출**할 수 있습니다:
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## macOS 커널 확장자

macOS는 코드가 실행될 때 높은 권한으로 실행되기 때문에 **커널 확장자**(.kext)를 로드하는 것에 매우 제한적입니다. 사실, 기본적으로는 사실상 불가능합니다(우회 방법을 찾지 않는 이상).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS 시스템 확장자

커널 확장자 대신 macOS는 시스템 확장자를 만들었는데, 이는 사용자 수준 API를 제공하여 커널과 상호 작용할 수 있습니다. 이렇게 함으로써 개발자는 커널 확장자를 사용하지 않을 수 있습니다.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## 참고 자료

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하려면 PR을 제출하여** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 공유하세요.

</details>
{% endhint %}
