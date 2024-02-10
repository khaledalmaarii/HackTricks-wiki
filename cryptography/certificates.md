# 인증서

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급스러운 커뮤니티 도구**를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 인증서란

**공개 키 인증서**는 암호학에서 사용되는 디지털 ID로, 누군가가 공개 키를 소유하고 있음을 증명하는 데 사용됩니다. 이 인증서에는 키의 세부 정보, 소유자의 신원 (주체) 및 신뢰할 수 있는 기관 (발급자)의 디지털 서명이 포함됩니다. 소프트웨어가 발급자를 신뢰하고 서명이 유효하다면, 키의 소유자와 안전한 통신이 가능합니다.

인증서는 대부분 [인증 기관](https://en.wikipedia.org/wiki/Certificate_authority) (CAs)에 의해 [공개 키 인프라](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI) 설정에서 발급됩니다. 다른 방법은 [신뢰의 웹](https://en.wikipedia.org/wiki/Web_of_trust)으로, 사용자가 서로의 키를 직접 확인합니다. 인증서의 일반적인 형식은 [X.509](https://en.wikipedia.org/wiki/X.509)이며, RFC 5280에서 설명된대로 특정 요구 사항에 맞게 조정할 수 있습니다.

## x509 공통 필드

### **x509 인증서의 공통 필드**

x509 인증서에서 여러 **필드**는 인증서의 유효성과 보안을 보장하는 데 중요한 역할을 합니다. 이러한 필드의 내용은 다음과 같습니다:

- **버전 번호**는 x509 형식의 버전을 나타냅니다.
- **일련 번호**는 주로 폐지 추적을 위해 인증 기관 (CA) 시스템 내에서 인증서를 고유하게 식별합니다.
- **주체** 필드는 인증서의 소유자를 나타내며, 기계, 개인 또는 조직일 수 있습니다. 다음과 같은 자세한 식별 정보가 포함됩니다:
- **공통 이름 (CN)**: 인증서로 커버되는 도메인.
- **국가 (C)**, **지역 (L)**, **주 또는 도 (ST, S 또는 P)**, **조직 (O)** 및 **조직 단위 (OU)**는 지리적 및 조직적 세부 정보를 제공합니다.
- **식별 이름 (DN)**은 전체 주체 식별 정보를 캡슐화합니다.
- **발급자**는 인증서를 검증하고 서명한 사람을 나타내며, CA의 경우 주체와 유사한 하위 필드를 포함합니다.
- **유효 기간**은 **Not Before** 및 **Not After** 타임스탬프로 표시되며, 특정 날짜 이전이나 이후에 인증서를 사용하지 않도록 보장합니다.
- **공개 키** 섹션은 인증서의 보안에 중요한 역할을 하는 공개 키의 알고리즘, 크기 및 기타 기술적 세부 정보를 지정합니다.
- **x509v3 확장**은 인증서의 기능을 향상시키며, **키 사용**, **확장 키 사용**, **대체 주체 이름** 및 기타 속성을 지정하여 인증서의 응용 프로그램을 세밀하게 조정합니다.

#### **키 사용 및 확장**

- **키 사용**은 공개 키의 암호학적 응용 프로그램 (예: 디지털 서명 또는 키 암호화)을 식별합니다.
- **확장 키 사용**은 인증서의 사용 사례를 더 좁게 정의합니다. 예를 들어, TLS 서버 인증에 사용됩니다.
- **대체 주체 이름** 및 **기본 제약 조건**은 인증서로 커버되는 추가 호스트 이름 및 CA 또는 종단 개체 인증서 여부를 정의합니다.
- **Subject Key Identifier** 및 **Authority Key Identifier**와 같은 식별자는 키의 고유성과 추적 가능성을 보장합니다.
- **권한 정보 액세스** 및 **CRL 배포 지점**은 발급 CA를 확인하고 인증서 폐지 상태를 확인하기 위한 경로를 제공합니다.
- **CT Precertificate SCTs**는 인증서에 대한 공개 신뢰에 중요한 투명성 로그를 제공합니다.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **OCSP와 CRL Distribution Points의 차이점**

**OCSP** (**RFC 2560**)는 디지털 공개키 인증서가 폐기되었는지 확인하기 위해 클라이언트와 응답자가 함께 작동하는 방식으로, 전체 **CRL**을 다운로드할 필요 없이 확인하는 것입니다. 이 방법은 폐기된 인증서 일련번호 목록을 제공하지만 잠재적으로 큰 파일을 다운로드해야 하는 전통적인 **CRL**보다 효율적입니다. CRL에는 최대 512개의 항목이 포함될 수 있습니다. 자세한 내용은 [여기](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm)에서 확인할 수 있습니다.

### **인증서 투명성(Certificate Transparency)이란?**

인증서 투명성은 도메인 소유자, CA 및 사용자가 SSL 인증서의 발급 및 존재를 확인할 수 있도록하여 인증서 관련 위협에 대응하는 데 도움이 됩니다. 인증서 투명성의 목표는 다음과 같습니다:

* 도메인 소유자의 동의 없이 CA가 도메인을 위한 SSL 인증서를 발급하는 것을 방지합니다.
* 잘못 발급되거나 악의적으로 발급된 인증서를 추적하기 위한 개방형 감사 시스템을 구축합니다.
* 사용자를 사기적인 인증서로부터 보호합니다.

#### **인증서 로그**

인증서 로그는 네트워크 서비스에 의해 유지되는 인증서의 공개 감사 가능한 추가 전용 레코드입니다. 이러한 로그는 감사 목적을 위한 암호학적 증명을 제공합니다. 발급 기관과 일반 사용자 모두 이러한 로그에 인증서를 제출하거나 검증을 위해 쿼리할 수 있습니다. 로그 서버의 정확한 수는 고정되어 있지 않지만, 전 세계적으로 천 개 미만으로 예상됩니다. 이러한 서버는 CA, ISP 또는 관련된 기관에 의해 독립적으로 관리될 수 있습니다.

#### **쿼리**

어떤 도메인에 대한 인증서 투명성 로그를 탐색하려면 [https://crt.sh/](https://crt.sh)를 방문하세요.

인증서를 저장하는 다양한 형식이 있으며, 각각의 사용 사례와 호환성이 있습니다. 이 요약에서는 주요 형식을 다루고 이들 간의 변환에 대한 안내를 제공합니다.

## **형식**

### **PEM 형식**
- 인증서에 가장 널리 사용되는 형식입니다.
- 인증서와 개인 키를 별도의 파일로 요구하며, Base64 ASCII로 인코딩됩니다.
- 일반적인 확장자: .cer, .crt, .pem, .key.
- 주로 Apache 및 유사한 서버에서 사용됩니다.

### **DER 형식**
- 인증서의 이진 형식입니다.
- PEM 파일에 있는 "BEGIN/END CERTIFICATE" 문이 없습니다.
- 일반적인 확장자: .cer, .der.
- 주로 Java 플랫폼과 함께 사용됩니다.

### **P7B/PKCS#7 형식**
- Base64 ASCII로 저장되며, 확장자는 .p7b 또는 .p7c입니다.
- 개인 키를 제외한 인증서 및 체인 인증서만 포함합니다.
- Microsoft Windows 및 Java Tomcat에서 지원됩니다.

### **PFX/P12/PKCS#12 형식**
- 서버 인증서, 중간 인증서 및 개인 키를 하나의 파일에 캡슐화하는 이진 형식입니다.
- 확장자: .pfx, .p12.
- 주로 Windows에서 인증서를 가져오고 내보내는 데 사용됩니다.

### **형식 변환**

호환성을 위해 **PEM 변환**이 필수적입니다:

- **x509에서 PEM으로 변환**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM을 DER로 변환하기**

PEM 형식의 인증서를 DER 형식으로 변환하는 방법은 다음과 같습니다:

1. OpenSSL을 사용하여 PEM 파일을 DER 파일로 변환합니다.
   ```plaintext
   openssl x509 -outform der -in certificate.pem -out certificate.der
   ```

2. 변환된 DER 파일은 이제 DER 형식의 인증서로 사용할 수 있습니다.
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER를 PEM으로 변환하기**

DER 형식의 인증서를 PEM 형식으로 변환하는 방법은 다음과 같습니다:

1. OpenSSL을 사용하여 DER 파일을 PEM 파일로 변환합니다.
   ```plaintext
   openssl x509 -inform der -in certificate.der -out certificate.pem
   ```

2. 변환된 PEM 파일을 확인합니다.
   ```plaintext
   cat certificate.pem
   ```

이제 DER 형식의 인증서를 PEM 형식으로 변환할 수 있습니다.
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM을 P7B로 변환하기**

PEM 형식의 인증서를 P7B 형식으로 변환하는 방법을 알아보겠습니다.

1. OpenSSL을 사용하여 PEM 파일을 P7B 파일로 변환할 수 있습니다. 다음 명령어를 사용하세요.

   ```plaintext
   openssl crl2pkcs7 -nocrl -certfile certificate.pem -out certificate.p7b -certfile ca.pem
   ```

   - `certificate.pem`: 변환할 PEM 파일의 경로와 파일 이름을 입력하세요.
   - `certificate.p7b`: 변환된 P7B 파일의 경로와 파일 이름을 입력하세요.
   - `ca.pem`: PEM 파일에 대한 CA(인증 기관) 인증서 파일의 경로와 파일 이름을 입력하세요.

2. 명령어를 실행하면 PEM 파일이 P7B 형식으로 변환됩니다. 변환된 P7B 파일은 `certificate.p7b`로 저장됩니다.

이제 PEM 형식의 인증서를 P7B 형식으로 변환하는 방법을 알게 되었습니다.
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7를 PEM으로 변환하기**

PKCS7 형식의 인증서를 PEM 형식으로 변환하는 방법은 다음과 같습니다:

1. PKCS7 형식의 인증서 파일을 엽니다.
2. OpenSSL 명령을 사용하여 다음 명령을 실행합니다:

```plaintext
openssl pkcs7 -print_certs -in input.p7b -out output.pem
```

여기서 `input.p7b`는 변환할 PKCS7 파일의 경로이고, `output.pem`은 변환된 PEM 파일의 경로입니다.

3. 변환된 PEM 파일을 확인하고 사용할 수 있습니다.

이렇게 하면 PKCS7 형식의 인증서를 PEM 형식으로 변환할 수 있습니다.
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX 변환**은 Windows에서 인증서를 관리하는 데 중요합니다:

- **PFX를 PEM으로 변환**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX를 PKCS#8로 변환**하는 데는 두 단계가 필요합니다:
1. PFX를 PEM으로 변환합니다.
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. PEM을 PKCS8로 변환하기

PEM 형식의 개인 키를 PKCS8 형식으로 변환하는 방법은 다음과 같습니다:

```bash
openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.pk8 -nocrypt
```

위 명령어를 사용하여 개인 키를 PKCS8 형식으로 변환할 수 있습니다. 변환된 개인 키는 `private_key.pk8` 파일에 저장됩니다.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B를 PFX로 변환**은 두 개의 명령어가 필요합니다:
1. P7B를 CER로 변환합니다.
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. CER 및 개인 키를 PFX로 변환하기

CER 파일과 개인 키를 PFX 형식으로 변환하는 방법을 알아보겠습니다. PFX 파일은 개인 키와 인증서를 함께 포함하는 형식입니다.

1. OpenSSL을 사용하여 CER 파일을 PEM 형식으로 변환합니다.
   ```
   openssl x509 -inform der -in certificate.cer -out certificate.pem
   ```

2. 개인 키를 PEM 형식으로 변환합니다.
   ```
   openssl rsa -in privatekey.key -out privatekey.pem
   ```

3. 변환된 CER 파일과 개인 키를 PFX 파일로 결합합니다.
   ```
   openssl pkcs12 -export -in certificate.pem -inkey privatekey.pem -out certificate.pfx
   ```

이제 CER 파일과 개인 키를 PFX 파일로 변환했습니다. PFX 파일은 다양한 용도로 사용될 수 있으며, 예를 들어 웹 서버에서 SSL/TLS 인증서를 설치하는 데 사용될 수 있습니다.
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 사용하여 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
