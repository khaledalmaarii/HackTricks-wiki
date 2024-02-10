# 그림자 자격 증명

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하고 싶으신가요? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## 소개 <a href="#3f17" id="3f17"></a>

**이 기술에 대한 모든 정보는 [원본 게시물](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)을 확인하세요.**

요약하자면: 사용자/컴퓨터의 **msDS-KeyCredentialLink** 속성에 쓸 수 있다면, 해당 객체의 **NT 해시**를 검색할 수 있습니다.

게시물에서는 **공개-개인 키 인증 자격 증명**을 설정하여 대상의 NTLM 해시를 포함한 고유한 **서비스 티켓**을 얻는 방법이 설명되어 있습니다. 이 과정에는 암호화된 NTLM_SUPPLEMENTAL_CREDENTIAL이 Privilege Attribute Certificate (PAC) 내에 포함되어 있으며, 이를 복호화할 수 있습니다.

### 요구 사항

이 기술을 적용하려면 특정 조건을 충족해야 합니다:
- 최소한 하나의 Windows Server 2016 도메인 컨트롤러가 필요합니다.
- 도메인 컨트롤러에 서버 인증 디지털 인증서가 설치되어 있어야 합니다.
- Active Directory는 Windows Server 2016 기능 수준이어야 합니다.
- 대상 객체의 msDS-KeyCredentialLink 속성을 수정할 수 있는 위임된 권한을 가진 계정이 필요합니다.

## 남용

컴퓨터 객체에 대한 Key Trust의 남용은 TGT (Ticket Granting Ticket)와 NTLM 해시를 얻는 것 이상의 단계를 포함합니다. 옵션은 다음과 같습니다:
1. 특권 사용자로 작동하는 **RC4 실버 티켓** 생성.
2. **S4U2Self**를 사용하여 TGT를 사용하여 **특권 사용자**를 표현하며, 서비스 티켓에 서비스 클래스를 추가하기 위해 변경이 필요합니다.

Key Trust 남용의 중요한 장점은 공격자 생성 개인 키에 대한 제한으로, 잠재적으로 취약한 계정에 위임되지 않으며 컴퓨터 계정을 생성할 필요가 없어 제거하기 어려울 수 있는 점입니다.

## 도구

### [**Whisker**](https://github.com/eladshamir/Whisker)

이 공격에 대한 C# 인터페이스를 제공하는 DSInternals을 기반으로 합니다. Whisker와 그 파이썬 상대인 **pyWhisker**는 `msDS-KeyCredentialLink` 속성을 조작하여 Active Directory 계정을 제어할 수 있게 해줍니다. 이 도구는 대상 객체에서 키 자격 증명을 추가, 나열, 제거 및 지우는 등 다양한 작업을 지원합니다.

**Whisker** 기능은 다음과 같습니다:
- **Add**: 키 쌍을 생성하고 키 자격 증명을 추가합니다.
- **List**: 모든 키 자격 증명 항목을 표시합니다.
- **Remove**: 지정된 키 자격 증명을 삭제합니다.
- **Clear**: 모든 키 자격 증명을 지우며, 합법적인 WHfB 사용을 방해할 수 있습니다.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

이는 Impacket과 PyDSInternals를 활용하여 **UNIX 기반 시스템**에서 Whisker 기능을 확장하여 포괄적인 공격 기능을 제공합니다. 이에는 KeyCredentials의 목록화, 추가, 제거뿐만 아니라 JSON 형식으로 가져오기 및 내보내기도 포함됩니다.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray는 넓은 사용자 그룹이 도메인 객체에 대해 가질 수 있는 GenericWrite/GenericAll 권한을 악용하여 ShadowCredentials를 널리 적용하기 위해 개발되었습니다. 이는 도메인에 로그인하고 도메인의 기능 수준을 확인하며 도메인 객체를 열거하고 TGT 획득 및 NT 해시 공개를 위해 KeyCredentials를 추가하려는 것을 포함합니다. 정리 옵션과 재귀적인 악용 전술은 유틸리티를 향상시킵니다.


## 참고 자료

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>
