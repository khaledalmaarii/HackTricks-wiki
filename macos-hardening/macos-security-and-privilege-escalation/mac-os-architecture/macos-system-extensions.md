# macOS 시스템 확장

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 시스템 확장 / 엔드포인트 보안 프레임워크

커널 확장과 달리, **시스템 확장은 커널 공간이 아닌 사용자 공간에서 실행**되므로 확장 기능 오작동으로 인한 시스템 충돌 위험을 줄일 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

시스템 확장에는 **DriverKit** 확장, **Network** 확장 및 **Endpoint Security** 확장 세 가지 유형이 있습니다.

### **DriverKit 확장**

DriverKit은 **하드웨어 지원을 제공하는 커널 확장 대체**입니다. 이를 통해 장치 드라이버(USB, Serial, NIC 및 HID 드라이버와 같은)가 커널 공간이 아닌 사용자 공간에서 실행될 수 있습니다. DriverKit 프레임워크에는 특정 I/O Kit 클래스의 사용자 공간 버전이 포함되어 있으며, 커널은 일반적인 I/O Kit 이벤트를 사용자 공간으로 전달하여 이러한 드라이버가 실행되는 데 안전한 환경을 제공합니다.

### **Network 확장**

Network 확장은 네트워크 동작을 사용자 정의할 수 있는 기능을 제공합니다. 다음과 같은 여러 유형의 Network 확장이 있습니다:

* **App Proxy**: 이는 연결(또는 플로우) 단위로 네트워크 트래픽을 처리하는 흐름 지향적인 사용자 정의 VPN 클라이언트를 생성하는 데 사용됩니다.
* **Packet Tunnel**: 이는 개별 패킷을 기반으로 네트워크 트래픽을 처리하는 패킷 지향적인 사용자 정의 VPN 클라이언트를 생성하는 데 사용됩니다.
* **Filter Data**: 이는 네트워크 "플로우"를 필터링하는 데 사용됩니다. 플로우 수준에서 네트워크 데이터를 모니터링하거나 수정할 수 있습니다.
* **Filter Packet**: 이는 개별 네트워크 패킷을 필터링하는 데 사용됩니다. 패킷 수준에서 네트워크 데이터를 모니터링하거나 수정할 수 있습니다.
* **DNS Proxy**: 이는 사용자 정의 DNS 공급자를 생성하는 데 사용됩니다. DNS 요청 및 응답을 모니터링하거나 수정하는 데 사용할 수 있습니다.

## 엔드포인트 보안 프레임워크

Endpoint Security는 애플이 macOS에서 제공하는 시스템 보안을 위한 API 세트입니다. 이는 **보안 공급업체 및 개발자가 악성 활동을 식별하고 방지하기 위해 시스템 활동을 모니터링하고 제어할 수 있는 제품을 개발하는 데 사용**됩니다.

이 프레임워크는 프로세스 실행, 파일 시스템 이벤트, 네트워크 및 커널 이벤트와 같은 **시스템 활동을 모니터링하고 제어하기 위한 API 모음**을 제공합니다.

이 프레임워크의 핵심은 커널에서 구현된 커널 확장(KEXT)인 **`/System/Library/Extensions/EndpointSecurity.kext`**에 구현되어 있습니다. 이 KEXT는 여러 핵심 구성 요소로 구성됩니다:

* **EndpointSecurityDriver**: 이는 커널 확장의 "진입점"으로 작동합니다. 이는 OS와 Endpoint Security 프레임워크 간의 주요 상호작용 지점입니다.
* **EndpointSecurityEventManager**: 이 구성 요소는 커널 후킹을 구현하는 데 책임이 있습니다. 커널 후킹을 통해 프레임워크는 시스템 호출을 가로채어 시스템 이벤트를 모니터링할 수 있습니다.
* **EndpointSecurityClientManager**: 이는 사용자 공간 클라이언트와의 통신을 관리하며, 연결된 클라이언트를 추적하고 이벤트 알림을 받아야 하는지 추적합니다.
* **EndpointSecurityMessageManager**: 이는 메시지와 이벤트 알림을 사용자 공간 클라이언트로 전송합니다.

Endpoint Security 프레임워크가 모니터링할 수 있는 이벤트는 다음과 같이 분류됩니다:

* 파일 이벤트
* 프로세스 이벤트
* 소켓 이벤트
* 커널 이벤트 (커널 확장 로드/언로드 또는 I/O Kit 장치 열기와 같은)

### 엔드포인트 보안 프레임워크 아키텍처

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

엔드포인트 보안 프레임워크와의 **사용자 공간 통신**은 IOUserClient 클래스를 통해 이루어집니다. 호출자의 유형에 따라 두 가지 다른 하위 클래스가 사용됩니다:

* **EndpointSecurityDriverClient**: 이는 `com.apple.private.endpoint-security.manager` 권한이 필요하며, 이 권한은 시스템 프로세스인 `endpointsecurityd`에만 부여됩니다.
* **EndpointSecurityExternalClient**: 이는 `com.apple.developer.endpoint-security.client` 권한이 필요합니다. 이는 일반적으로 엔드포인트 보안 프레임워크와 상호작용해야 하는 타사 보안 소프트웨어에서 사용됩니다.

Endpoint Security 확장인 **`libEndpointSecurity.dylib`**는 시스템 확장이 커널과 통신하는 데 사용하는 C 라이브러리입니다. 이 라이브러리는 I/O Kit (`IOKit`)을 사용하여 Endpoint Security KEXT와 통신합니다.

**`endpointsecurityd`**는 엔드포인트 보안 시스템 확장을 관리하고 시작하는 데 관여하는 중요한 시스템 데몬입니다. **`Info.plist`** 파일에서 **`NSEndpointSecurityEarlyBoot`**로 표시된 **시스템 확장만** 이 초기 부팅 처리를 받습니다.

다른 시스템 데몬인 **`sysextd`**는 시스템 확장을 유효성 검사하고 적절한 시스템 위치로 이동시킵니다. 그런 다음 해당 데몬에 확장을 로드하도록 요청합니다. **`SystemExtensions.framework`**는 시스템 확장을 활성화하고 비활성화하는 역할을 담당합니다.

## ESF 우회

ESF는 레드 팀원을 감지하려는 보안 도구에서 사용되므로 이를 피할 수 있는 정보는 흥미로울 수 있습니다.

### CVE-2021-30965

문제는 보안 애플리케이션이 **전체 디스크 액세스 권한**을 가져야 한다는 것입니다. 따라서 공격자가 해당 권한을 제거하면 소프트웨어가 실행되지 않도록 할 수 있습니다:
```bash
tccutil reset All
```
**더 많은 정보**와 관련된 내용은 다음 발표를 확인하세요. [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

마지막으로, 이 문제는 **`tccd`**가 관리하는 보안 앱에 새로운 권한 **`kTCCServiceEndpointSecurityClient`**을 부여함으로써 해결되었습니다. 이렇게 하면 `tccutil`이 권한을 지우지 않고 보안 앱을 실행할 수 있게 됩니다.

## 참고 자료

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
