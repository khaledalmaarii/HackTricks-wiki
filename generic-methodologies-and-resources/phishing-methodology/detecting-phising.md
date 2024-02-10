# 피싱 감지

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 소개

피싱 시도를 감지하기 위해서는 **현재 사용되는 피싱 기술을 이해하는 것이 중요**합니다. 이 게시물의 부모 페이지에서 이 정보를 찾을 수 있으므로, 오늘날 사용되는 기술을 알지 못한다면 부모 페이지로 이동하여 해당 섹션을 읽는 것을 권장합니다.

이 게시물은 **공격자가 피해자의 도메인 이름을 어떤 방식으로든 모방하거나 사용하려고 할 것**이라는 아이디어를 기반으로 합니다. 예를 들어, 도메인이 `example.com`인 경우 `youwonthelottery.com`과 같이 완전히 다른 도메인 이름을 사용하여 피싱당하는 경우, 이러한 기술은 이를 발견하지 못할 것입니다.

## 도메인 이름 변형

이메일 내에서 **유사한 도메인** 이름을 사용하는 **피싱** 시도를 **발견하는 것은 어렵지 않습니다**.\
공격자가 사용할 수 있는 가장 가능성이 높은 피싱 이름 목록을 **생성**하고, 해당 이름이 **등록**되어 있는지 또는 해당 이름을 사용하는 **IP**가 있는지 **확인**하면 됩니다.

### 수상한 도메인 찾기

이를 위해 다음 도구 중 하나를 사용할 수 있습니다. 이 도구들은 도메인에 할당된 IP가 있는지 자동으로 DNS 요청도 수행합니다.

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### 비트 플리핑

**이 기술에 대한 간단한 설명은 부모 페이지에서 찾을 수 있습니다. 또는 원본 연구를 읽어보세요. [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**

예를 들어, 도메인 microsoft.com에서 1 비트 수정을 통해 _windnws.com._으로 변환될 수 있습니다.\
**공격자는 피해자와 관련된 가능한 한 많은 비트 플리핑 도메인을 등록하여 합법적인 사용자를 자신의 인프라로 리디렉션시킬 수 있습니다**.

**모든 가능한 비트 플리핑 도메인 이름도 모니터링해야 합니다**.

### 기본적인 확인

잠재적으로 수상한 도메인 이름 목록이 있다면 (주로 HTTP 및 HTTPS 포트) **확인**해야 합니다.\
또한 포트 3333을 확인하여 `gophish`의 인스턴스가 실행 중인지 확인할 수도 있습니다.\
또한 발견된 수상한 도메인의 **나이를 알아내는 것도 흥미로울 수 있습니다**. 나이가 어릴수록 위험합니다.\
HTTP 및/또는 HTTPS 수상한 웹 페이지의 **스크린샷**을 얻어서 수상한지 확인하고 그렇다면 **더 자세히 살펴보기 위해 해당 페이지에 액세스**하는 것도 흥미로울 수 있습니다.

### 고급 확인

한 단계 더 나아가려면 수상한 도메인을 **정기적으로 모니터링하고 추가로 검색**하는 것을 권장합니다(매일? 몇 초/분이 걸립니다). 관련된 IP의 **열린 포트**를 확인하고 `gophish` 또는 유사한 도구의 인스턴스를 **검색**해야 합니다(네, 공격자도 실수를 저지를 수 있습니다). 또한 수상한 도메인 및 하위 도메인의 **HTTP 및 HTTPS 웹 페이지를 모니터링**하여 피해자의 웹 페이지에서 로그인 양식을 복사한 것이 있는지 확인해야 합니다.\
이를 **자동화**하기 위해 피해자의 도메인의 로그인 양식 목록을 갖고 있고, 수상한 웹 페이지를 스파이더링하고 수상한 도메인의 각 로그인 양식을 피해자의 도메인의 각 로그인 양식과 `ssdeep`와 같은 도구를 사용하여 비교하는 것이 좋습니다.\
수상한 도메인의 로그인 양식을 찾았다면, **잘못된 자격 증명을 보내고 해당 자격 증명이 피해자의 도메인으로 리디렉션되는지 확인**해 볼 수 있습니다.

## 키워드를 사용한 도메인 이름

부모 페이지에서는 피해자의 도메인 이름을 더 큰 도메인 내에 넣는 도메인 이름 변형 기술도 언급합니다(예: paypal.com의 경우 paypal-financial.com).

### 인증서 투명성

이전의 "무차별 대입" 접근 방식은 불가능하지만, 인증서 투명성 덕분에 **이러한 피싱 시도를 발견하는 것이 가능**합니다. 인증서가 CA에 의해 발급될 때마다 세부 정보가 공개됩니다. 이는 인증서 투명성을 읽거나 모니터링함으로써 **이름 내에 키워드를 사용하는 도메인을 찾을 수 있다는 것을 의미**합니다. 예를 들어, 공격자가 [https://paypal-financial.com](https://paypal-financial.com)의 인증서를 생성한다면, 인증서를 보고 "paypal"이라는 키워드를 찾아 수상한 이메일이 사용되고 있는지 알 수 있습니다.

[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) 게시물은 Censys를 사용하여 특정 키워드를 검색하고 날짜(오직 "새로운" 인증서만)와 CA 발급자 "Let's Encrypt"로 필터링할 수 있다고 제안합니다:

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../.gitbook/assets/image (390).png>)

그러나 무료 웹 [**crt.sh**](https://crt.sh)를 사용하여 "동일한" 작업을 수행할 수 있습니다. **키워드를 검색**하고 결과를 원하는 경우 **날짜와 CA로 필터링**할 수 있습니다.

![](<../../.gitbook/assets/image (391).png>)

마지막 옵션을 사용하면 실제 도메인의 일치하는 신원이 수상한 도메인 중 어느 것과 일치하는지 확인할 수 있습니다(수
### **새로운 도메인**

**마지막 대안**은 몇 가지 TLD(최상위 도메인)에 대한 **새로 등록된 도메인 목록**을 수집하고, 이러한 도메인에서 **키워드를 확인하는 것**입니다 ([Whoxy](https://www.whoxy.com/newly-registered-domains/)가 이러한 서비스를 제공합니다). 그러나 긴 도메인은 일반적으로 하나 이상의 하위 도메인을 사용하므로 키워드는 FLD(First Level Domain) 내부에 나타나지 않으며, 피싱 하위 도메인을 찾을 수 없습니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
