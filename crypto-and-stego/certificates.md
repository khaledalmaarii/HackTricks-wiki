# 인증서

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates)를 사용하여 **세계에서 가장 고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

## 인증서란

**공개 키 인증서**는 암호학에서 사용되는 디지털 ID로, 누군가가 공개 키를 소유하고 있음을 증명하는 데 사용됩니다. 이는 키의 세부 정보, 소유자의 신원(주체) 및 신뢰할 수 있는 기관(발급자)의 디지털 서명을 포함합니다. 소프트웨어가 발급자를 신뢰하고 서명이 유효하다면, 해당 키의 소유자와 안전한 통신이 가능합니다.

인증서는 주로 [인증 기관](https://en.wikipedia.org/wiki/Certificate\_authority)(CAs)에 의해 [공개 키 인프라](https://en.wikipedia.org/wiki/Public-key\_infrastructure)(PKI) 설정에서 발급됩니다. 다른 방법은 사용자가 서로 키를 직접 확인하는 [신뢰 웹](https://en.wikipedia.org/wiki/Web\_of\_trust)입니다. 인증서의 일반적인 형식은 [X.509](https://en.wikipedia.org/wiki/X.509)이며, RFC 5280에서 개별 요구 사항에 맞게 조정할 수 있습니다.

## x509 공통 필드

### **x509 인증서의 공통 필드**

x509 인증서에서 여러 **필드**가 인증서의 유효성과 보안을 보장하는 데 중요한 역할을 합니다. 이러한 필드를 살펴보겠습니다:

* **버전 번호**는 x509 형식의 버전을 나타냅니다.
* **일련 번호**는 주로 폐기 추적을 위해 인증 기관(CA) 시스템 내에서 인증서를 고유하게 식별합니다.
* **주체** 필드는 인증서의 소유자를 나타내며, 기계, 개인 또는 조직일 수 있습니다. 다음과 같은 자세한 식별 정보를 포함합니다:
* **일반 이름 (CN)**: 인증서가 적용되는 도메인.
* **국가 (C)**, **지역 (L)**, **주 또는 지방 (ST, S 또는 P)**, **조직 (O)** 및 **조직 단위 (OU)**는 지리적 및 조직적 세부 정보를 제공합니다.
* **식별 이름 (DN)**은 전체 주체 식별을 캡슐화합니다.
* **발급자**는 인증서를 확인하고 서명한 사람을 나타내며, CA에 대한 주체와 유사한 하위 필드를 포함합니다.
* **유효 기간**은 **Not Before** 및 **Not After** 타임스탬프로 표시되어, 특정 날짜 이전 또는 이후에 인증서가 사용되지 않도록 합니다.
* 인증서의 보안에 중요한 **공개 키** 섹션은 공개 키의 알고리즘, 크기 및 기술적 세부 정보를 지정합니다.
* **x509v3 확장**은 인증서의 기능성을 향상시키며, **키 사용**, **확장 키 사용**, **주체 대체 이름** 및 인증서의 응용 프로그램을 세밀하게 조정하기 위한 기타 속성을 지정합니다.

#### **키 사용 및 확장**

* **키 사용**은 공개 키의 암호화 응용 프로그램을 식별합니다. 예: 디지털 서명 또는 키 암호화.
* **확장 키 사용**은 인증서의 사용 사례를 더 세분화합니다. 예: TLS 서버 인증용.
* **주체 대체 이름** 및 **기본 제약**은 인증서가 적용되는 추가 호스트 이름 및 CA 또는 종단 개체 인증서인지 여부를 정의합니다.
* **주체 키 식별자** 및 **발급자 키 식별자**는 키의 고유성과 추적 가능성을 보장합니다.
* **발급자 정보 액세스** 및 **CRL 배포 지점**은 발급 CA를 확인하고 인증서 폐기 상태를 확인하기 위한 경로를 제공합니다.
* **CT 사전 인증서 SCT**는 인증서에 대한 공개 신뢰에 중요한 투명성 로그를 제공합니다.
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
### **OCSP와 CRL 배포 지점의 차이점**

**OCSP** (**RFC 2560**)은 디지털 공개 키 인증서가 폐기되었는지 확인하기 위해 클라이언트와 응답기가 함께 작동하여 전체 **CRL**을 다운로드할 필요 없이 확인하는 방법입니다. 이 방법은 전통적인 **CRL**보다 효율적이며, 폐기된 인증서 일련 번호 목록을 제공하지만 잠재적으로 큰 파일을 다운로드해야 하는 **CRL**보다 더 효율적입니다. CRL에는 최대 512개의 항목이 포함될 수 있습니다. 자세한 내용은 [여기](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm)에서 확인할 수 있습니다.

### **인증서 투명성이란**

인증서 투명성은 SSL 인증서의 발급 및 존재가 도메인 소유자, CA 및 사용자에게 투명하게 보이도록하여 인증서 관련 위협에 대항하는 데 도움이 됩니다. 그 목표는 다음과 같습니다:

* 도메인 소유자의 동의 없이 CA가 도메인을 위한 SSL 인증서를 발급하는 것을 방지하는 것.
* 실수로나 악의적으로 발급된 인증서를 추적하기 위한 공개 감사 시스템 설정.
* 사용자를 사기적인 인증서로부터 보호하는 것.

#### **인증서 로그**

인증서 로그는 네트워크 서비스에 의해 유지되는 인증서의 공개 감사 가능한, 추가 전용 레코드입니다. 이러한 로그는 감사 목적을 위한 암호학적 증거를 제공합니다. 발급 기관과 일반인 모두 이러한 로그에 인증서를 제출하거나 검증을 위해 쿼리할 수 있습니다. 로그 서버의 정확한 수는 고정되어 있지 않지만 전 세계적으로 천 개 미만으로 예상됩니다. 이러한 서버는 주로 CA, ISP 또는 관련 기관에 의해 독립적으로 관리될 수 있습니다.

#### **쿼리**

어떤 도메인에 대한 인증서 투명성 로그를 탐색하려면 [https://crt.sh/](https://crt.sh)를 방문하십시오.

## **형식**

### **PEM 형식**

* 인증서에 가장 널리 사용되는 형식.
* Base64 ASCII로 인코딩된 인증서 및 개인 키를 위한 별도의 파일이 필요.
* 일반적인 확장자: .cer, .crt, .pem, .key.
* 주로 Apache 및 유사한 서버에서 사용됨.

### **DER 형식**

* 인증서의 이진 형식.
* PEM 파일에 있는 "BEGIN/END CERTIFICATE" 문이 없음.
* 일반적인 확장자: .cer, .der.
* Java 플랫폼과 함께 자주 사용됨.

### **P7B/PKCS#7 형식**

* Base64 ASCII에 저장된 형식으로, .p7b 또는 .p7c 확장자를 가짐.
* 개인 키를 제외한 인증서 및 체인 인증서만 포함.
* Microsoft Windows 및 Java Tomcat에서 지원됨.

### **PFX/P12/PKCS#12 형식**

* 서버 인증서, 중간 인증서 및 개인 키를 하나의 파일에 캡슐화하는 이진 형식.
* 확장자: .pfx, .p12.
* 주로 Windows에서 인증서 가져오기 및 내보내기에 사용됨.

### **형식 변환**

호환성을 위해 **PEM 변환**이 필수적입니다:

* **x509를 PEM으로**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM을 DER로 변환하기**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER를 PEM으로**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM을 P7B로 변환**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7를 PEM으로 변환**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX 변환**은 Windows에서 인증서를 관리하는 데 중요합니다:

* **PFX를 PEM으로**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX를 PKCS#8로 변환**에는 두 단계가 포함됩니다:
1. PFX를 PEM으로 변환
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. PEM을 PKCS8로 변환합니다.
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B를 PFX로** 변환하려면 두 개의 명령이 필요합니다:
1. P7B를 CER로 변환합니다.
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. CER 및 개인 키를 PFX로 변환합니다.
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates)를 사용하여 세계에서 **가장** **고급** 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축** 및 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com) 받기
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
