# macOS MDM

{% hint style="success" %}
**AWS 해킹 학습 및 실습:** [**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)

**GCP 해킹 학습 및 실습:** [**HackTricks Training GCP Red Team Expert (GRTE)**](https://training.hacktricks.xyz/courses/grte)
{% endhint %}

**macOS MDM에 대해 알아보려면:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 기초

### **MDM (Mobile Device Management) 개요**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM)은 스마트폰, 랩톱, 태블릿과 같은 다양한 종단 사용자 장치를 관리하는 데 사용됩니다. 특히 Apple의 플랫폼(iOS, macOS, tvOS)에는 특수 기능, API 및 관행이 포함됩니다. MDM의 작동은 호환되는 MDM 서버에 의존하며, 해당 서버는 상용이나 오픈 소스이어야 하며 [MDM 프로토콜](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)을 지원해야 합니다. 주요 포인트는 다음과 같습니다:

- 장치에 대한 중앙 집중식 제어.
- MDM 프로토콜을 준수하는 MDM 서버에 의존.
- MDM 서버가 장치로 다양한 명령을 전송할 수 있는 능력, 예를 들어 원격 데이터 삭제 또는 구성 설치.

### **DEP (Device Enrollment Program) 기초**

Apple이 제공하는 [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP)은 iOS, macOS 및 tvOS 장치에 대한 제로 터치 구성을 용이하게 하여 Mobile Device Management (MDM)의 통합을 간소화합니다. DEP는 등록 프로세스를 자동화하여 장치가 최소한의 사용자 또는 관리자 개입으로 즉시 사용 가능하도록 합니다. 주요 측면은 다음과 같습니다:

- 장치가 초기 활성화 시 미리 정의된 MDM 서버에 자동으로 등록되도록 함.
- 주로 새로운 장치에 유용하지만 재구성 중인 장치에도 적용 가능.
- 간단한 설정을 용이하게 하여 장치를 조직적으로 신속하게 사용할 수 있도록 함.

### **보안 고려 사항**

DEP가 제공하는 쉬운 등록의 중요성을 강조하지만, 적절한 보호 조치가 MDM 등록에 충분히 시행되지 않으면 공격자가 이 간소화된 프로세스를 이용하여 기업 장치로 위장한 장치를 조직의 MDM 서버에 등록할 수 있습니다.

{% hint style="danger" %}
**보안 경고**: 간소화된 DEP 등록은 적절한 보호 조치가 없으면 비인가된 장치가 조직의 MDM 서버에 등록될 수 있습니다.
{% endhint %}

### **SCEP (Simple Certificate Enrolment Protocol)란 무엇인가?**

- TLS 및 HTTPS가 보급되기 전에 만들어진 상대적으로 오래된 프로토콜.
- 클라이언트에게 인증서를 부여받기 위한 **Certificate Signing Request** (CSR)를 표준화된 방법으로 보내줍니다. 클라이언트는 서버에게 서명된 인증서를 제공해 달라고 요청합니다.

### **구성 프로필이란 무엇인가? (모바일 구성 파일이라고도 함)**

- Apple의 **시스템 구성 설정/강제화**의 공식적인 방법.
- 여러 페이로드를 포함할 수 있는 파일 형식.
- 속성 목록( XML 유형)을 기반으로 함.
- "출처를 확인하고 무결성을 보장하며 내용을 보호하기 위해 서명 및 암호화될 수 있습니다." 기초 — 2018년 1월 iOS 보안 가이드, 70페이지.

## 프로토콜

### MDM

- APNs (**Apple 서버**) + RESTful API (**MDM 공급업체** 서버)의 조합
- **장치**와 **장치 관리 제품**과 관련된 서버 간 **통신**
- MDM에서 장치로 **plist로 인코딩된 사전**을 통해 명령 전달
- 모두 **HTTPS**를 통해 이루어짐. MDM 서버는 (일반적으로) 고정될 수 있음.
- Apple은 MDM 공급업체에 **APNs 인증서**를 부여함

### DEP

- **3개의 API**: 리셀러용 1개, MDM 공급업체용 1개, 장치 식별용 1개 (문서화되지 않음):
- **DEP "클라우드 서비스" API**. 이는 MDM 서버가 DEP 프로필을 특정 장치에 연결하는 데 사용됨.
- [Apple 권한을 받은 리셀러가 사용하는 DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html). 장치 등록, 등록 상태 확인 및 거래 상태 확인에 사용됨.
- 문서화되지 않은 개인 DEP API. 이는 Apple 장치가 DEP 프로필을 요청하는 데 사용됨. macOS에서 `cloudconfigurationd` 이진 파일이 이 API를 통해 통신함.
- 더 현대적이며 **JSON** 기반 (plist 대비)
- Apple은 MDM 공급업체에 **OAuth 토큰**을 부여함

**DEP "클라우드 서비스" API**

- RESTful
- Apple에서 MDM 서버로 장치 레코드 동기화
- MDM 서버에서 Apple로 DEP 프로필 동기화 (나중에 장치에 의해 전달됨)
- DEP "프로필"에는 다음이 포함됨:
  - MDM 공급업체 서버 URL
  - 서버 URL에 대한 추가 신뢰할 수 있는 인증서 (선택적 핀닝)
  - 추가 설정 (예: 설정 도우미에서 건너뛸 화면)

## 일련 번호

2010년 이후에 제조된 Apple 장치는 일반적으로 **12자리 알파벳과 숫자의** 일련 번호를 가지며, **첫 세 자리는 제조 위치**를 나타내고, 다음 **두 자리는 제조 연도와 주**를 나타내며, 다음 **세 자리는 고유 식별자**를 제공하고, **마지막 네 자리는 모델 번호**를 나타냅니다.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## 등록 및 관리 단계

1. 장치 레코드 생성 (리셀러, Apple): 새로운 장치 레코드 생성
2. 장치 레코드 할당 (고객): 장치를 MDM 서버에 할당
3. 장치 레코드 동기화 (MDM 공급업체): MDM이 장치 레코드를 동기화하고 DEP 프로필을 Apple에 푸시
4. DEP 체크인 (장치): 장치가 DEP 프로필을 받음
5. 프로필 검색 (장치)
6. 프로필 설치 (장치) a. MDM, SCEP 및 루트 CA 페이로드 포함
7. MDM 명령 발행 (장치)

![](<../../../.gitbook/assets/image (694).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` 파일은 등록 프로세스의 **고수준 "단계"**로 간주될 수 있는 함수를 내보냅니다.
### 단계 4: DEP 체크인 - 활성화 레코드 가져오기

이 프로세스의 일부는 **사용자가 Mac을 처음 부팅할 때** 발생합니다 (또는 완전한 삭제 후)

![](<../../../.gitbook/assets/image (1044).png>)

또는 `sudo profiles show -type enrollment`을 실행할 때

* **장치가 DEP 활성화되어 있는지** 확인
* 활성화 레코드는 **DEP "프로필"의 내부 이름**입니다
* 장치가 인터넷에 연결되면 시작됨
* **`CPFetchActivationRecord`**에 의해 구동됨
* **`cloudconfigurationd`**를 통해 구현됨. **"설정 도우미**" (장치가 처음 부팅될 때) 또는 **`profiles`** 명령은 **이 데몬에 연락**하여 활성화 레코드를 검색합니다.
* LaunchDaemon (항상 root로 실행)

**`MCTeslaConfigurationFetcher`**에 의해 수행되는 활성화 레코드 가져오기를 위해 몇 가지 단계를 따릅니다. 이 프로세스는 **Absinthe**라는 암호화를 사용합니다

1. **인증서** 검색
1. [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)에서 GET
2. 인증서에서 상태 **초기화** (**`NACInit`**)
1. 다양한 장치별 데이터 사용 (즉, **`IOKit`**을 통한 일련 번호)
3. **세션 키** 검색
1. [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)에 POST
4. 세션 설정 (**`NACKeyEstablishment`**)
5. 요청 생성
1. 데이터 `{ "action": "RequestProfileConfiguration", "sn": "" }`를 보내는 [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile)에 POST
2. JSON 페이로드는 Absinthe를 사용하여 암호화됨 (**`NACSign`**)
3. 모든 요청은 HTTPs를 통해 이루어지며, 내장 루트 인증서가 사용됨

![](<../../../.gitbook/assets/image (566) (1).png>)

응답은 다음과 같은 중요한 데이터가 포함된 JSON 사전입니다:

* **url**: 활성화 프로필을 위한 MDM 벤더 호스트의 URL
* **anchor-certs**: 신뢰할 수 있는 앵커로 사용되는 DER 인증서 배열

### **단계 5: 프로필 검색**

![](<../../../.gitbook/assets/image (444).png>)

* DEP 프로필에서 제공된 **URL**로 요청을 보냄
* 제공된 경우 **앵커 인증서**를 사용하여 **신뢰 평가**를 수행
* 알림: DEP 프로필의 **anchor\_certs** 속성
* 요청은 장치 식별 정보를 포함하는 간단한 .plist임
* 예: **UDID, OS 버전**.
* CMS로 서명된 DER 인코딩
* **APNS에서의 장치 식별 인증서를 사용하여** 서명됨
* **인증서 체인**에 만료된 **Apple iPhone Device CA**가 포함됨

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### 단계 6: 프로필 설치

* 검색한 후, **프로필이 시스템에 저장**됨
* 이 단계는 자동으로 시작됨 (**설정 도우미**에 있을 경우)
* **`CPInstallActivationProfile`**에 의해 구동됨
* mdmclient를 통해 XPC로 구현됨
* LaunchDaemon (root로) 또는 LaunchAgent (사용자로), 상황에 따라 다름
* 구성 프로필에는 설치할 여러 페이로드가 포함됨
* 프레임워크는 프로핸드 설치를 위한 플러그인 기반 아키텍처를 가짐
* 각 페이로드 유형은 플러그인과 연결됨
* XPC (프레임워크 내) 또는 클래식 Cocoa (ManagedClient.app 내)일 수 있음
* 예:
* 인증서 페이로드는 CertificateService.xpc를 사용함

일반적으로 MDM 벤더가 제공하는 **활성화 프로필**에는 다음과 같은 페이로드가 포함될 수 있습니다:

* `com.apple.mdm`: 장치를 MDM에 **등록**함
* `com.apple.security.scep`: 장치에 **클라이언트 인증서**를 안전하게 제공함
* `com.apple.security.pem`: 장치의 시스템 키체인에 **신뢰할 수 있는 CA 인증서를 설치**함
* MDM 페이로드 설치는 문서에서의 **MDM 체크인**과 동등함
* 페이로드에는 다음과 같은 주요 속성이 포함됨:
*
* MDM 체크인 URL (**`CheckInURL`**)
* MDM 명령 폴링 URL (**`ServerURL`**) + 트리거하기 위한 APNs 주제
* MDM 페이로드를 설치하려면 요청이 **`CheckInURL`**로 전송됨
* **`mdmclient`**에서 구현됨
* MDM 페이로드는 다른 페이로드에 의존할 수 있음
* **특정 인증서에 요청을 고정**할 수 있음:
* 속성: **`CheckInURLPinningCertificateUUIDs`**
* 속성: **`ServerURLPinningCertificateUUIDs`**
* PEM 페이로드를 통해 전달됨
* 장치에 식별 인증서를 부여할 수 있음:
* 속성: IdentityCertificateUUID
* SCEP 페이로드를 통해 전달됨

### **단계 7: MDM 명령 수신 대기**

MDM 체크인이 완료되면 벤더는 APNs를 사용하여 푸시 알림을 **발행**할 수 있음
수신하면 **`mdmclient`**가 처리함
MDM 명령을 폴링하기 위해 요청이 **ServerURL**로 전송됨
이전에 설치된 MDM 페이로드를 사용함:
**`ServerURLPinningCertificateUUIDs`**는 요청을 고정하는 데 사용됨
**`IdentityCertificateUUID`**는 TLS 클라이언트 인증서를 위해 사용됨

## 공격

### 다른 조직에 장치 등록

이전에 언급한 대로, 조직에 장치를 등록하려면 해당 조직에 속한 **일련 번호만 필요**합니다. 장치가 등록되면 여러 조직이 새 장치에 민감한 데이터를 설치할 수 있습니다: 인증서, 애플리케이션, WiFi 암호, VPN 구성 [등](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
따라서, 등록 프로세스가 올바르게 보호되지 않은 경우 공격자에게 위험한 진입점이 될 수 있습니다:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop) 확인!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass) 참여 또는 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 팔로우**.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 트릭 공유.

</details>
{% endhint %}
