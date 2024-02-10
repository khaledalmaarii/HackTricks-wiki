# AD CS 계정 지속성

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

**이것은 [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**의 멋진 연구에서 기계 지속성 장에 대한 작은 요약입니다.


## **인증서를 사용한 활성 사용자 자격증명 도난 이해 - PERSIST1**

도메인 인증을 허용하는 인증서를 사용자가 요청할 수 있는 시나리오에서 공격자는 네트워크에서 **지속성을 유지**하기 위해 이 인증서를 **요청**하고 **도난**할 수 있는 기회를 갖습니다. Active Directory의 `User` 템플릿은 기본적으로 이러한 요청을 허용하지만 때로는 비활성화될 수도 있습니다.

[**Certify**](https://github.com/GhostPack/Certify)라는 도구를 사용하여 지속적인 액세스를 가능하게 하는 유효한 인증서를 검색할 수 있습니다:
```bash
Certify.exe find /clientauth
```
인증서의 힘은 해당 사용자로 **인증**할 수 있는 능력에 있다고 강조되었습니다. 인증서가 **유효**한 한, 비밀번호 변경 여부와 상관없이 사용자로 인증될 수 있습니다.

인증서는 `certmgr.msc`를 통해 그래픽 인터페이스로 요청하거나 `certreq.exe`를 통해 명령줄에서 요청할 수 있습니다. **Certify**를 사용하면 인증서 요청 프로세스가 다음과 같이 간소화됩니다:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
요청이 성공하면, `.pem` 형식으로 인증서와 해당 개인 키가 생성됩니다. 이를 Windows 시스템에서 사용할 수 있는 `.pfx` 파일로 변환하기 위해 다음 명령을 사용합니다:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
`.pfx` 파일은 대상 시스템에 업로드되어 [**Rubeus**](https://github.com/GhostPack/Rubeus)라는 도구와 함께 사용될 수 있으며, 이를 통해 사용자의 Ticket Granting Ticket (TGT)를 요청하여 공격자의 액세스를 인증서의 **유효 기간** (일반적으로 1년) 동안 연장할 수 있습니다.
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
## **인증서를 사용하여 기계 지속성 확보 - PERSIST2**

다른 방법은 기계 계정을 인증서에 등록하는 것으로, 기본적으로 이러한 작업을 허용하는 `Machine` 템플릿을 사용합니다. 공격자가 시스템에서 권한 상승을 얻으면 **SYSTEM** 계정을 사용하여 인증서를 요청할 수 있으며, 이는 **지속성**의 형태를 제공합니다:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
이 접근은 공격자가 기계 계정으로 **Kerberos**에 인증하고 **S4U2Self**를 활용하여 호스트의 모든 서비스에 대한 Kerberos 서비스 티켓을 얻을 수 있게 해줍니다. 이를 통해 공격자는 기계에 대한 지속적인 액세스 권한을 얻을 수 있습니다.

## **인증서 갱신을 통한 지속성 확장 - PERSIST3**

마지막으로 논의되는 방법은 인증서 템플릿의 **유효 기간**과 **갱신 기간**을 활용하는 것입니다. 인증서의 만료 전에 인증서를 **갱신**함으로써 공격자는 추가 티켓 등록이 필요하지 않고 Active Directory에 대한 인증을 유지할 수 있습니다. 이는 인증서 기관(CA) 서버에 추적을 남길 수 있는 추가 흔적을 방지합니다.

이 접근 방식은 **확장된 지속성** 방법을 제공하며, CA 서버와의 상호 작용이 적어져 탐지 위험을 최소화하고 침입에 대한 경고를 줄 수 있는 아티팩트 생성을 피할 수 있습니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
