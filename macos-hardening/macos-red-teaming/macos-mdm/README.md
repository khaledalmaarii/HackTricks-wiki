# macOS MDM

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

**macOS MDM에 대해 알아보세요:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 기본 사항

### **MDM (Mobile Device Management) 개요**
[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM)은 스마트폰, 노트북, 태블릿과 같은 다양한 엔드 유저 장치를 관리하기 위해 사용됩니다. 특히 Apple의 플랫폼 (iOS, macOS, tvOS)의 경우, 특수한 기능, API 및 관행을 포함합니다. MDM의 작동은 상용 또는 오픈 소스인 호환 가능한 MDM 서버에 의존하며 [MDM 프로토콜](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)을 지원해야 합니다. 주요 포인트는 다음과 같습니다:

- 장치에 대한 중앙 집중식 제어.
- MDM 프로토콜을 준수하는 MDM 서버에 의존.
- MDM 서버가 장치로 다양한 명령을 전송할 수 있는 능력, 예를 들어 원격 데이터 삭제 또는 구성 설치.

### **DEP (Device Enrollment Program) 기본 사항**
Apple이 제공하는 [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP)은 iOS, macOS 및 tvOS 장치의 Mobile Device Management (MDM) 통합을 간소화하기 위해 제공됩니다. DEP는 등록 프로세스를 자동화하여 장치가 최소한의 사용자 또는 관리자 개입으로 즉시 사용 가능하도록 합니다. 주요 측면은 다음과 같습니다:

- 장치가 초기 활성화 시 미리 정의된 MDM 서버에 자동으로 등록될 수 있도록 합니다.
- 주로 새로운 장치에 유용하지만 재구성 중인 장치에도 적용할 수 있습니다.
- 간단한 설정을 용이하게 만들어 조직에서 빠르게 사용할 수 있도록 합니다.

### **보안 고려 사항**
DEP가 제공하는 간편한 등록 기능은 보안 위험을 초래할 수 있습니다. MDM 등록에 충분한 보호 조치가 적용되지 않으면 공격자는 기업 장치로 위장하여 조직의 MDM 서버에 장치를 등록할 수 있습니다.

{% hint style="danger" %}
**보안 경고**: 간소화된 DEP 등록은 적절한 보호 조치가 없는 경우 조직의 MDM 서버에 무단 장치 등록을 허용할 수 있습니다.
{% endhint %}

### 기본 사항 SCEP (Simple Certificate Enrolment Protocol)이란 무엇인가요?

* 상대적으로 오래된 프로토콜로, TLS와 HTTPS가 보급되기 전에 만들어졌습니다.
* 클라이언트가 인증서를 부여받기 위해 **인증서 서명 요청** (CSR)을 표준화된 방식으로 보낼 수 있도록 합니다. 클라이언트는 서버에게 서명된 인증서를 제공해 달라고 요청합니다.

구성 프로필 (mobileconfigs)이란 무엇인가요?

* Apple의 공식적인 **시스템 구성 설정/강제화 방법**입니다.
* 여러 페이로드를 포함할 수 있는 파일 형식입니다.
* 속성 목록에 기반한 형식입니다 (XML 형식).
* "출처를 검증하고 무결성을 보장하며 내용을 보호하기 위해 서명 및 암호화될 수 있습니다." Basics — Page 70, iOS Security Guide, January 2018.

## 프로토콜

### MDM

* APNs (**Apple 서버**) + RESTful API (**MDM 공급업체** 서버)의 조합
* **장치**와 **장치 관리** **제품**에 연결된 서버 간의 **통신**
* **명령**은 MDM에서 장치로 **plist로 인코딩된 사전**으로 전달됩니다.
* 모두 **HTTPS**를 통해 이루어집니다. MDM 서버는 (일반적으로) 고정될 수 있습니다.
* Apple은 MDM 공급업체에게 인증을 위한 **APNs 인증서**를 부여합니다.

### DEP

* **3개의 API**: 리셀러용 1개, MDM 공급업체용 1개, 장치 식별용 1개 (문서화되지 않음):
* [DEP "클라우드 서비스" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)라고 불리는 것. 이는 MDM 서버가 DEP 프로필을 특정 장치와 연결하기 위해 사용됩니다.
* [Apple 공인 리셀러가 사용하는 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)는 장치 등록, 등록 상태 확인 및 거래 상태 확인을 위해 사용됩니다.
* 문서화되지 않은 개인 DEP API. 이는 Apple 장치가 DEP 프로필을 요청하는 데 사용됩니다. macOS에서는 `cloudconfigurationd` 이진 파일이 이 API를 통해 통신합니다.
* 더 현대적이며 **JSON** 기반 (plist 대비)
* Apple은 MDM 공급업체에게 **OAuth 토큰**을 부여합니다.

**DEP "클라우드 서비스" API**

* RESTful
* Apple에서 MDM 서버로 장치 레코드 동기화
* Apple에서 장치로 DEP 프로필 동기화 (나중에 장치에 전달됨)
* DEP "프로필"에는 다음이 포함됩니다:
* MDM 공급업체 서버 URL
* 서버 URL에 대한 추가 신뢰할 수 있는 인증서 (선택적 핀닝)
* 추가 설정 (예: 설정 도우미에서 건너뛸 화면)

## 일련 번호

2010년 이후에 제조된 Apple 장치는 일반적으로 **12자리 알파벳과 숫자**로 이루어진 일련 번호를 가지며, **첫 세 자리는 제조 위치**를 나타내고, 다음 **두 자리는 제조 연도와 주**를 나타내
### 단계 4: DEP 체크인 - 활성화 레코드 가져오기

이 과정은 **사용자가 Mac을 처음으로 부팅**할 때(또는 완전한 초기화 후) 발생합니다.

![](<../../../.gitbook/assets/image (568).png>)

또는 `sudo profiles show -type enrollment`을 실행할 때

* **장치가 DEP 활성화되었는지** 확인
* 활성화 레코드는 DEP "프로필"의 내부 이름입니다.
* 장치가 인터넷에 연결되면 시작됩니다.
* **`CPFetchActivationRecord`**에 의해 구동됩니다.
* **`cloudconfigurationd`**를 통해 구현됩니다. 장치가 처음으로 부팅될 때 "설정 도우미" 또는 `profiles` 명령이이 데몬에 연락하여 활성화 레코드를 검색합니다.
* LaunchDaemon (항상 root로 실행)

**`MCTeslaConfigurationFetcher`**에 의해 수행되는 활성화 레코드를 가져오기 위해 몇 가지 단계를 따릅니다. 이 프로세스는 **Absinthe**라는 암호화를 사용합니다.

1. **인증서** 가져오기
1. [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)에서 GET
2. 인증서에서 상태 **초기화** (**`NACInit`**)
1. 다양한 장치별 데이터 사용 (예: **`IOKit`을 통한 일련 번호**)
3. **세션 키** 가져오기
1. [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)에 POST
4. 세션 설정 (**`NACKeyEstablishment`**)
5. 요청 만들기
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)에 데이터 `{ "action": "RequestProfileConfiguration", "sn": "" }`를 보내는 POST
2. JSON 페이로드는 Absinthe (**`NACSign`**)를 사용하여 암호화됩니다.
3. 모든 요청은 HTTPs를 통해 전송되며 내장 루트 인증서가 사용됩니다.

![](<../../../.gitbook/assets/image (566).png>)

응답은 다음과 같은 중요한 데이터가 포함된 JSON 사전입니다.

* **url**: 활성화 프로필을 위한 MDM 공급업체 호스트의 URL
* **anchor-certs**: 신뢰할 수 있는 앵커로 사용되는 DER 인증서 배열

### **단계 5: 프로필 검색**

![](<../../../.gitbook/assets/image (567).png>)

* DEP 프로필에서 제공된 **url**로 요청을 보냅니다.
* 제공된 경우 **앵커 인증서**를 사용하여 신뢰를 **평가**합니다.
* 알림: DEP 프로필의 **anchor\_certs** 속성
* 요청은 장치 식별을 포함한 간단한 .plist입니다.
* 예: **UDID, OS 버전**.
* CMS로 서명되고 DER로 인코딩됨
* 장치 신원 인증서(애플 APNS에서 가져옴)를 사용하여 서명됨
* **인증서 체인**에는 만료된 **Apple iPhone Device CA**가 포함됩니다.

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (7).png>)

### 단계 6: 프로필 설치

* 검색한 후, **프로필은 시스템에 저장**됩니다.
* 이 단계는 자동으로 시작됩니다(설정 도우미에 있는 경우).
* **`CPInstallActivationProfile`**에 의해 구동됩니다.
* XPC를 통해 mdmclient에 의해 구현됨
* LaunchDaemon (root로 실행) 또는 LaunchAgent (사용자로 실행), 상황에 따라 다름
* 구성 프로필에는 설치할 여러 페이로드가 있습니다.
* 프로필 설치를 위한 플러그인 기반 아키텍처를 가지고 있습니다.
* 각 페이로드 유형은 플러그인과 연결됩니다.
* XPC(프레임워크 내) 또는 클래식 Cocoa(ManagedClient.app 내)일 수 있습니다.
* 예:
* 인증서 페이로드는 CertificateService.xpc를 사용합니다.

일반적으로 MDM 공급업체가 제공하는 **활성화 프로필**에는 다음과 같은 페이로드가 포함됩니다:

* `com.apple.mdm`: 장치를 MDM에 **등록**합니다.
* `com.apple.security.scep`: 장치에 **클라이언트 인증서**를 안전하게 제공합니다.
* `com.apple.security.pem`: 장치의 시스템 키 체인에 **신뢰할 수 있는 CA 인증서**를 **설치**합니다.
* MDM 페이로드를 설치하는 것은 **문서의 MDM 체크인**과 동등합니다.
* 페이로드에는 다음과 같은 **중요한 속성**이 포함됩니다:
*
* MDM 체크인 URL (**`CheckInURL`**)
* MDM 명령 폴링 URL (**`ServerURL`**) + 트리거하기 위한 APNs 주제
* MDM 페이로드를 설치하기 위해 요청이 **`CheckInURL`**로 전송됩니다.
* **`mdmclient`**에서 구현됩니다.
* MDM 페이로드는 다른 페이로드에 의존할 수 있습니다.
* 요청을 특정 인증서에 고정할 수 있게 합니다:
* 속성: **`CheckInURLPinningCertificateUUIDs`**
* 속성: **`ServerURLPinningCertificateUUIDs`**
* PEM 페이로드를 통해 전달됩니다.
* 장치에 신원 인증서를 할당할 수 있게 합니다:
* 속성: IdentityCertificateUUID
* SCEP 페이로드를 통해 전달됩니다.

### **단계 7: MDM 명령 수신 대기**

MDM 체크인이 완료되면 공급업체는 APNs를 사용하여 푸시 알림을 **발행**할 수 있습니다.
수신 시 **`mdmclient`**가 처리합니다.
MDM 명령을 폴링하기 위해 요청이 ServerURL로 전송됩니다.
이전에 설치된 MDM 페이로드를 사용합니다:
요청 고정을 위한 **`ServerURLPinningCertificateUUIDs`**
TLS 클라이언트 인증서를 위한 **`IdentityCertificateUUID`**

## 공격

### 다른 조직에 장치 등록

이전에 언급한 대로, 조직에 장치를 등록하려면 해당 조직에 속하는 **일련 번호만 필요**합니다. 장치가 등록되면 여러 조직에서 새 장치에 민감한 데이터를 설치할 수 있습니다: 인증서, 애플리케이션, WiFi 암호, VPN 구성 등 [자세한 내용](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)을 참조하십시오.\
따라서, 등록 프로세스가 올바르게 보호되지 않은 경우 공격자에게 위험한 진입점이 될 수 있습니다:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-
