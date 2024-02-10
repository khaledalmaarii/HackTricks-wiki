# 다른 조직에 장치 등록하기

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출**하세요**.

</details>

## 소개

[**이전에 언급한 것처럼**](./#what-is-mdm-mobile-device-management)**,** 조직에 장치를 등록하려면 해당 조직에 속하는 일련 번호만 필요합니다. 장치가 등록되면 여러 조직에서 새 장치에 민감한 데이터를 설치할 수 있습니다: 인증서, 애플리케이션, WiFi 비밀번호, VPN 구성 [등등](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
따라서, 등록 프로세스가 올바르게 보호되지 않은 경우 공격자에게 위험한 진입점이 될 수 있습니다.

**다음은 연구 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)의 요약입니다. 자세한 기술적인 세부 정보는 해당 연구를 확인하세요!**

## DEP 및 MDM 이진 분석 개요

이 연구는 macOS의 Device Enrollment Program (DEP) 및 Mobile Device Management (MDM)과 관련된 이진 파일을 탐구합니다. 주요 구성 요소는 다음과 같습니다:

- **`mdmclient`**: macOS 10.13.4 이전 버전에서 MDM 서버와 통신하고 DEP 체크인을 트리거합니다.
- **`profiles`**: 구성 프로필을 관리하고 macOS 10.13.4 이후 버전에서 DEP 체크인을 트리거합니다.
- **`cloudconfigurationd`**: DEP API 통신을 관리하고 장치 등록 프로필을 검색합니다.

DEP 체크인은 `CPFetchActivationRecord` 및 `CPGetActivationRecord` 함수를 사용하여 개인 Configuration Profiles 프레임워크에서 Activation Record를 가져옵니다. `CPFetchActivationRecord`는 XPC를 통해 `cloudconfigurationd`와 협력하여 작동합니다.

## Tesla 프로토콜 및 Absinthe 스키마 역공학

DEP 체크인은 `cloudconfigurationd`가 암호화되고 서명된 JSON 페이로드를 _iprofiles.apple.com/macProfile_로 전송하는 것을 포함합니다. 페이로드에는 장치의 일련 번호와 "RequestProfileConfiguration" 작업이 포함됩니다. 사용되는 암호화 방식은 내부적으로 "Absinthe"로 참조됩니다. 이 방식을 해체하는 것은 복잡하며 여러 단계를 거치게 되었으며, Activation Record 요청에 임의의 일련 번호를 삽입하기 위한 대안적인 방법을 탐구하게 되었습니다.

## DEP 요청 프록시

Charles Proxy와 같은 도구를 사용하여 _iprofiles.apple.com_으로의 DEP 요청을 가로채고 수정하려는 시도는 페이로드 암호화 및 SSL/TLS 보안 조치로 인해 방해를 받았습니다. 그러나 `MCCloudConfigAcceptAnyHTTPSCertificate` 구성을 활성화하면 서버 인증서 유효성 검사를 우회할 수 있지만, 페이로드의 암호화된 특성으로 인해 복호화 키 없이 일련 번호를 수정할 수 없습니다.

## DEP와 상호 작용하는 시스템 이진 파일에 대한 Instrumentation

`cloudconfigurationd`와 같은 시스템 이진 파일에 Instrumentation을 적용하려면 macOS에서 System Integrity Protection (SIP)를 비활성화해야 합니다. SIP가 비활성화된 경우 LLDB와 같은 도구를 사용하여 시스템 프로세스에 연결하고 DEP API 상호 작용에 사용되는 일련 번호를 수정할 수 있습니다. 이 방법은 권한과 코드 서명의 복잡성을 피할 수 있기 때문에 선호됩니다.

**이진 Instrumentation 악용:**
`cloudconfigurationd`에서 JSON 직렬화 이전에 DEP 요청 페이로드를 수정하는 것이 효과적이었습니다. 이 과정은 다음과 같이 진행되었습니다:

1. LLDB를 `cloudconfigurationd`에 연결합니다.
2. 시스템 일련 번호를 가져오는 지점을 찾습니다.
3. 페이로드가 암호화되고 전송되기 전에 메모리에 임의의 일련 번호를 삽입합니다.

이 방법을 사용하면 임의의 일련 번호에 대한 완전한 DEP 프로필을 검색할 수 있으며, 잠재적인 취약점을 보여줍니다.

### Python을 사용한 Instrumentation 자동화

LLDB API를 사용하여 악용 과정을 Python으로 자동화하여 임의의 일련 번호를 프로그래밍적으로 삽입하고 해당하는 DEP 프로필을 검색할 수 있게 되었습니다.

### DEP 및 MDM 취약점의 잠재적인 영향

이 연구는 중요한 보안 문제를 강조했습니다:

1. **정보 노출**: DEP 등록된 일련 번호를 제공함으로써 DEP 프로필에 포함된 민감한 조직 정보를 검색할 수 있습니다.
2. **악의적인 DEP 등록**: 적절한 인증 없이 DEP 등록된 일련 번호를 가진 공격자는 조직의 MDM 서버에 악의적인 장치를 등록할 수 있으며, 민감한 데이터와 네트워크 리소스에 접근할 수 있습니다.

결론적으로, DEP와 MDM은 기업 환경에서 Apple 장치를 관리하기 위한 강력한 도구를 제공하지만, 보안 및 모니터링이 필요한 잠재적인 공격 경로도 존재합니다.
