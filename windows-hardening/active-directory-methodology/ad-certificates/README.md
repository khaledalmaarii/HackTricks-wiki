# AD 인증서

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 소개

### 인증서의 구성 요소

- 인증서의 **Subject**는 소유자를 나타냅니다.
- **공개 키**는 인증서를 소유자와 연결하기 위해 개인 키와 짝을 이룹니다.
- **NotBefore** 및 **NotAfter** 날짜로 정의된 **유효 기간**은 인증서의 유효 기간을 나타냅니다.
- 인증 기관 (CA)에서 제공하는 고유한 **일련 번호**는 각 인증서를 식별합니다.
- **발급자**는 인증서를 발급한 CA를 가리킵니다.
- **SubjectAlternativeName**은 주체에 대한 추가 이름을 허용하여 식별 유연성을 향상시킵니다.
- **Basic Constraints**는 인증서가 CA인지 또는 종단 엔티티인지를 식별하고 사용 제한을 정의합니다.
- **확장 키 사용 (EKUs)**는 개체 식별자 (OID)를 통해 코드 서명 또는 이메일 암호화와 같은 인증서의 특정 용도를 구분합니다.
- **서명 알고리즘**은 인증서에 대한 서명 방법을 지정합니다.
- 발급자의 개인 키로 생성된 **서명**은 인증서의 신뢰성을 보장합니다.

### 특별한 고려 사항

- **Subject Alternative Names (SANs)**은 인증서의 적용 범위를 여러 신원에 확장하여 다중 도메인을 가진 서버에 필수적입니다. SAN 사양을 조작하여 위조 위험을 피하기 위해 안전한 발급 프로세스가 필수적입니다.

### Active Directory (AD)의 인증 기관 (CAs)

AD CS는 AD 포레스트에서 CA 인증서를 인정하기 위해 고유한 역할을 수행하는 지정된 컨테이너를 통해 CA 인증서를 인정합니다.

- **Certification Authorities** 컨테이너는 신뢰할 수 있는 루트 CA 인증서를 보유합니다.
- **Enrolment Services** 컨테이너는 Enterprise CA 및 해당 인증서 템플릿에 대한 세부 정보를 제공합니다.
- **NTAuthCertificates** 개체는 AD 인증에 사용되는 CA 인증서를 포함합니다.
- **AIA (Authority Information Access)** 컨테이너는 중간 및 교차 CA 인증서를 사용하여 인증서 체인 유효성 검사를 용이하게 합니다.

### 인증서 획득: 클라이언트 인증서 요청 흐름

1. 클라이언트는 Enterprise CA를 찾아 인증서 요청 프로세스를 시작합니다.
2. 공개-개인 키 쌍을 생성한 후, 공개 키와 기타 세부 정보를 포함하는 CSR을 생성합니다.
3. CA는 CSR을 사용 가능한 인증서 템플릿과 비교하여 템플릿의 권한에 따라 인증서를 발급합니다.
4. 승인되면 CA는 개인 키로 인증서에 서명하고 클라이언트에게 반환합니다.

### 인증서 템플릿

AD 내에서 정의된 이러한 템플릿은 인증서 발급에 대한 설정 및 권한을 개요화하며, 허용된 EKU 및 인증서 서비스에 대한 액세스 또는 수정 권한을 포함하여 인증서 서비스에 대한 액세스를 관리하는 데 중요합니다.

## 인증서 등록

인증서의 등록 프로세스는 관리자가 **인증서 템플릿을 생성**한 다음 Enterprise 인증 기관 (CA)에서 **게시**함으로써 시작됩니다. 이렇게 하면 템플릿의 이름이 Active Directory 개체의 `certificatetemplates` 필드에 추가되어 클라이언트 등록에 사용할 수 있게 됩니다.

인증서를 요청하려면 클라이언트에게 **등록 권한**이 부여되어야 합니다. 이 권한은 인증서 템플릿과 Enterprise CA 자체의 보안 기술자에 의해 정의됩니다. 요청이 성공하려면 두 위치에서 권한이 부여되어야 합니다.

### 템플릿 등록 권한

이러한 권한은 액세스 제어 항목 (ACE)을 통해 지정되며 다음과 같은 권한을 상세히 설명합니다:
- **Certificate-Enrollment** 및 **Certificate-AutoEnrollment** 권한은 각각 특정 GUID와 관련이 있습니다.
- 모든 확장 권한을 허용하는 **ExtendedRights**.
- 템플릿에 대한 완전한 제어를 제공하는 **FullControl/GenericAll**.

### Enterprise CA 등록 권한

CA의 권한은 인증 기관 관리 콘솔을 통해 액세스할 수 있는 보안 기술자에게서 설명되어 있습니다. 일부 설정은 권한이 낮은 사용자가 원격 액세스를 허용할 수 있으므로 보안에 대한 고려 사항이 될 수 있습니다.

### 추가 발급 제어

다음과 같은 특정 제어가 적용될 수 있습니다:
- **관리자 승인**: 인증서 관리자의 승인을 받기 전까지 요청을 대기 상태로 유지합니다.
- **등록 에이전트 및 승인 서명**: CSR에 필요한 서명 수와 필요한 Application Policy OID를 지정합니다.

### 인증서 요청 방법

인증서는 다음을 통해 요청할 수 있습니다:
1. DCOM 인터페이스를 사용하는 **Windows 클라이언트 인증서 등록 프로토콜** (MS-WCCE).
2. 명명된 파이프 또는 TCP/IP를 통한 **ICertPassage 원격 프로토콜** (MS-ICPR).
3. **인증서 등록 웹 인터페이스** (Certificate Authority Web Enrollment 역할이 설치된 경우).
4. **인증서 등록 서비스** (CES)와 **인증서 등록 정책** (CEP) 서비스를 함께 사용합니다.
5. **네트워크 장치 등록 서비스** (NDES)는 Simple Certificate Enrollment Protocol (SCEP)를 사용하여 네트워크 장치에 대해 인증서를 요청합니다.

Windows 사용자는 GUI (`certmgr.msc` 또는 `certlm.msc`) 또는 명령 줄 도구 (`certreq.exe` 또는 PowerShell의 `Get-Certificate` 명령)를 통해 인증서를 요청할 수도 있습니다.
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 인증서 인증

Active Directory (AD)는 주로 **Kerberos** 및 **Secure Channel (Schannel)** 프로토콜을 사용하여 인증서 인증을 지원합니다.

### Kerberos 인증 과정

Kerberos 인증 과정에서 사용자의 Ticket Granting Ticket (TGT) 요청은 사용자의 인증서의 **개인 키**를 사용하여 서명됩니다. 이 요청은 도메인 컨트롤러에 의해 여러 가지 유효성 검사를 거칩니다. 이 유효성 검사에는 인증서의 **유효성**, **경로**, **폐지 상태**가 포함됩니다. 유효성 검사에는 신뢰할 수 있는 출처에서 인증서가 왔는지 확인하고, **NTAUTH 인증서 저장소**에 발급자가 존재하는지 확인하는 것도 포함됩니다. 성공적인 유효성 검사는 TGT의 발급으로 이어집니다. AD의 **`NTAuthCertificates`** 객체는 다음 경로에서 찾을 수 있습니다:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
인증서 인증을 위한 신뢰를 확립하는 데 중요합니다.

### Secure Channel (Schannel) 인증

Schannel은 안전한 TLS/SSL 연결을 용이하게 해주며, 핸드셰이크 중에 클라이언트가 인증서를 제시하면, 성공적으로 유효성이 검증되면 액세스가 허가됩니다. 인증서를 AD 계정에 매핑하는 작업은 Kerberos의 **S4U2Self** 함수나 인증서의 **Subject Alternative Name (SAN)** 등의 방법을 사용할 수 있습니다.

### AD 인증서 서비스 열거

AD의 인증서 서비스는 LDAP 쿼리를 통해 열거할 수 있으며, 이를 통해 **Enterprise Certificate Authorities (CAs)** 및 그 구성에 대한 정보를 확인할 수 있습니다. 이는 특별한 권한 없이도 도메인 인증된 사용자에게 접근 가능합니다. **[Certify](https://github.com/GhostPack/Certify)** 및 **[Certipy](https://github.com/ly4k/Certipy)**와 같은 도구는 AD CS 환경에서 열거 및 취약성 평가에 사용됩니다.

이러한 도구를 사용하는 명령어는 다음과 같습니다:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## 참고 자료

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
